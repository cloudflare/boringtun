use std::{
    future::Future,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use crate::packet::PacketBuf;

/// Implementations of UdpTransport for linux
#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;

/// Implementations of UdpTransport for all targets
#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod generic;

pub mod channel;

/// An abstraction of a UDP socket.
///
/// This allows us to, for example, swap out UDP sockets with a channel.
pub trait UdpTransport: Send + Sync {
    type SendManyBuf: Default + Send + Sync;

    /// Send a single UDP packet to `destination`.
    fn send_to(
        &self,
        packet: &[u8],
        destination: SocketAddr,
    ) -> impl Future<Output = io::Result<()>> + Send;

    /// Receive a single UDP packet.
    fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send;

    // --- Optional Methods ---

    /// Get the port in use, if any.
    ///
    /// This is applicable to UDP sockets, i.e. [tokio::net::UdpSocket].
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        Ok(None)
    }

    /// Set `fwmark`.
    ///
    /// This is applicable to UDP sockets, i.e. [tokio::net::UdpSocket].
    #[cfg(target_os = "linux")]
    fn set_fwmark(&self, _mark: u32) -> io::Result<()> {
        Ok(())
    }

    /// The maximum number of packets that can be passed to [UdpTransport::send_many_to].
    fn max_number_of_packets_to_send(&self) -> usize {
        1
    }

    /// The maximum number of packets that can be passed to [UdpTransport::recv_many_from].
    fn max_number_of_packets_to_recv(&self) -> usize {
        1
    }

    /// Send up to `x` UDP packets to the destination,
    /// where `x` is [UdpTransport::max_number_of_packets_to_send];
    // TODO: define how many packets are sent in case of an error.
    fn send_many_to(
        &self,
        _bufs: &mut Self::SendManyBuf,
        packets: &[(PacketBuf, SocketAddr)],
    ) -> impl Future<Output = io::Result<()>> + Send {
        generic_send_many_to(self, packets)
    }

    /// Receive up to `x` packets at once,
    /// where `x` is [UdpTransport::max_number_of_packets_to_recv].
    ///
    /// Returns the number of packets received.
    ///
    /// # Arguments
    /// - `bufs` - A slice of buffers that will receive UDP datagrams.
    /// - 'source_addrs' - Source addresses to receive. The length must equal that of 'bufs'.
    //
    // The default implementation always reads 1 packet.
    fn recv_many_from(
        &self,
        bufs: &mut [PacketBuf],
        source_addrs: &mut [Option<SocketAddr>],
    ) -> impl Future<Output = io::Result<usize>> + Send {
        async {
            let ([buf, ..], [source_addr_out, ..]) = (bufs, source_addrs) else {
                return Ok(0);
            };

            let (n, source_addr) = self.recv_from(buf.packet_mut()).await?;
            buf.set_packet_len(n);
            *source_addr_out = Some(source_addr);

            Ok(1)
        }
    }
}

async fn generic_send_many_to<U: UdpTransport + ?Sized>(
    transport: &U,
    packets: &[(PacketBuf, SocketAddr)],
) -> io::Result<()> {
    for (packet, target) in packets {
        transport.send_to(packet.packet(), *target).await?;
    }
    Ok(())
}

#[derive(Clone)]
pub struct UdpTransportFactoryParams {
    pub addr_v4: Ipv4Addr,
    pub addr_v6: Ipv6Addr,
    pub port: u16,

    #[cfg(target_os = "linux")]
    pub fwmark: Option<u32>,
}

/// An abstraction of `UdpSocket::bind`.
///
/// See [UdpTransport].
pub trait UdpTransportFactory: Send + Sync + 'static {
    type Transport: UdpTransport + 'static;

    /// Bind sockets for sending and receiving UDP.
    ///
    /// Returns two [UdpTransport]s, one for IPv4 and one for IPv6.
    fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> impl Future<Output = io::Result<(Arc<Self::Transport>, Arc<Self::Transport>)>> + Send;
}

pub struct UdpSocketFactory;

impl UdpTransportFactory for UdpSocketFactory {
    type Transport = tokio::net::UdpSocket;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<(Arc<Self::Transport>, Arc<Self::Transport>)> {
        fn bind(addr: SocketAddr) -> io::Result<Arc<tokio::net::UdpSocket>> {
            let domain = match addr {
                SocketAddr::V4(..) => socket2::Domain::IPV4,
                SocketAddr::V6(..) => socket2::Domain::IPV6,
            };

            // Construct the socket using `socket2` because we need to set the reuse_address flag.
            let udp_sock =
                socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
            udp_sock.set_nonblocking(true)?;
            udp_sock.set_reuse_address(true)?;
            udp_sock.bind(&addr.into())?;

            tokio::net::UdpSocket::from_std(udp_sock.into()).map(Arc::new)
        }

        let mut port = params.port;
        let udp_v4 = bind((params.addr_v4, port).into())?;
        if port == 0 {
            // The socket is using a random port, copy it so we can re-use it for IPv6.
            port = udp_v4.local_addr()?.port();
        }

        let udp_v6 = bind((params.addr_v6, port).into())?;

        #[cfg(target_os = "linux")]
        if let Some(mark) = params.fwmark {
            udp_v4.set_fwmark(mark)?;
            udp_v6.set_fwmark(mark)?;
        }

        Ok((udp_v4, udp_v6))
    }
}
