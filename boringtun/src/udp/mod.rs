use std::{
    future::Future,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    os::fd::AsFd,
    sync::Arc,
};

use crate::packet::Packet;

pub mod buffer;

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
pub trait UdpTransport: Send + Sync + Clone {
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
}

/// An abstraction of a UDP socket.
///
/// This allows us to, for example, swap out UDP sockets with a channel.
pub trait UdpRecv: Send + Sync {
    type RecvManyBuf: Default + Send;

    /// The maximum number of packets that can be passed to [UdpTransport::recv_many_from].
    fn max_number_of_packets_to_recv(&self) -> usize {
        1
    }

    /// Receive a single UDP packet.
    fn recv_from(
        &mut self,
        buf: &mut [u8],
    ) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send;

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
        &mut self,
        _recv_buf: &mut Self::RecvManyBuf,
        bufs: &mut [Packet],
        source_addrs: &mut [Option<SocketAddr>],
    ) -> impl Future<Output = io::Result<usize>> + Send {
        async {
            let ([buf, ..], [source_addr_out, ..]) = (bufs, source_addrs) else {
                return Ok(0);
            };

            let (n, source_addr) = self.recv_from(&mut buf[..]).await?;
            buf.truncate(n);
            *source_addr_out = Some(source_addr);

            Ok(1)
        }
    }
}

/// An abstraction of a UDP socket.
///
/// This allows us to, for example, swap out UDP sockets with a channel.
pub trait UdpSend: Send + Sync {
    type SendManyBuf: Default + Send + Sync;

    /// Send a single UDP packet to `destination`.
    fn send_to(
        &self,
        packet: Packet,
        destination: SocketAddr,
    ) -> impl Future<Output = io::Result<()>> + Send;

    /// The maximum number of packets that can be passed to [UdpTransport::send_many_to].
    fn max_number_of_packets_to_send(&self) -> usize {
        1
    }

    /// Send up to `x` UDP packets to the destination,
    /// where `x` is [UdpTransport::max_number_of_packets_to_send];
    // TODO: define how many packets are sent in case of an error.
    fn send_many_to(
        &self,
        _bufs: &mut Self::SendManyBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> impl Future<Output = io::Result<()>> + Send {
        generic_send_many_to(self, packets)
    }
}

async fn generic_send_many_to<U: UdpSend + ?Sized>(
    transport: &U,
    packets: &mut Vec<(Packet, SocketAddr)>,
) -> io::Result<()> {
    for (packet, target) in packets.drain(..) {
        transport.send_to(packet, target).await?;
    }
    Ok(())
}

/// Default UDP socket implementation
#[derive(Clone)]
pub struct UdpSocket {
    inner: Arc<tokio::net::UdpSocket>,
}

impl UdpSocket {
    pub fn bind(addr: SocketAddr) -> io::Result<Self> {
        let domain = match addr {
            SocketAddr::V4(..) => socket2::Domain::IPV4,
            SocketAddr::V6(..) => socket2::Domain::IPV6,
        };

        // Construct the socket using `socket2` because we need to set the reuse_address flag.
        let udp_sock =
            socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        udp_sock.set_nonblocking(true)?;
        udp_sock.set_reuse_address(true)?;
        udp_sock.set_recv_buffer_size(UDP_RECV_BUFFER_SIZE)?;
        udp_sock.set_send_buffer_size(UDP_SEND_BUFFER_SIZE)?;
        // TODO: set forced buffer sizes?

        udp_sock.bind(&addr.into())?;

        let inner = tokio::net::UdpSocket::from_std(udp_sock.into())?;

        Ok(Self {
            inner: Arc::new(inner),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }
}

impl AsFd for UdpSocket {
    fn as_fd(&self) -> std::os::unix::prelude::BorrowedFd<'_> {
        self.inner.as_fd()
    }
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
    type Send: UdpSend + UdpTransport + 'static;
    type Recv: UdpRecv + 'static;

    /// Bind sockets for sending and receiving UDP.
    ///
    /// Returns two [UdpTransport]s, one for IPv4 and one for IPv6.
    #[allow(clippy::type_complexity)]
    fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> impl Future<Output = io::Result<((Self::Send, Self::Recv), (Self::Send, Self::Recv))>> + Send;
}

pub struct UdpSocketFactory;

const UDP_RECV_BUFFER_SIZE: usize = 7 * 1024 * 1024;
const UDP_SEND_BUFFER_SIZE: usize = 7 * 1024 * 1024;

impl UdpTransportFactory for UdpSocketFactory {
    type Send = UdpSocket;
    type Recv = UdpSocket;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<((Self::Send, Self::Recv), (Self::Send, Self::Recv))> {
        let mut port = params.port;
        let udp_v4 = UdpSocket::bind((params.addr_v4, port).into())?;
        if port == 0 {
            // The socket is using a random port, copy it so we can re-use it for IPv6.
            port = UdpSocket::local_addr(&udp_v4)?.port();
        }

        let udp_v6 = UdpSocket::bind((params.addr_v6, port).into())?;

        #[cfg(target_os = "linux")]
        if let Some(mark) = params.fwmark {
            udp_v4.set_fwmark(mark)?;
            udp_v6.set_fwmark(mark)?;
        }

        Ok(((udp_v4.clone(), udp_v4), (udp_v6.clone(), udp_v6)))
    }
}
