//! Implementations of [UdpTransport] traits for [UdpSocket].

#[cfg(unix)]
use std::os::fd::AsFd;
use std::{io, net::SocketAddr, sync::Arc};

use super::{UdpSend, UdpTransportFactory, UdpTransportFactoryParams};

/// Implementations of UdpTransport for all targets
#[cfg(not(any(target_os = "linux", target_os = "android")))]
mod generic;

/// Implementations of UdpTransport for linux
#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;

pub struct UdpSocketFactory;

const UDP_RECV_BUFFER_SIZE: usize = 7 * 1024 * 1024;
const UDP_SEND_BUFFER_SIZE: usize = 7 * 1024 * 1024;

impl UdpTransportFactory for UdpSocketFactory {
    type Send = UdpSocket;
    type RecvV4 = UdpSocket;
    type RecvV6 = UdpSocket;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> io::Result<((Self::Send, Self::RecvV4), (Self::Send, Self::RecvV6))> {
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

        if let Err(err) = udp_v4.enable_udp_gro() {
            log::warn!("Failed to enable UDP GRO for IPv4 socket: {err}");
        }
        if let Err(err) = udp_v6.enable_udp_gro() {
            log::warn!("Failed to enable UDP GRO for IPv6 socket: {err}");
        }

        Ok(((udp_v4.clone(), udp_v4), (udp_v6.clone(), udp_v6)))
    }
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

#[cfg(unix)]
impl AsFd for UdpSocket {
    fn as_fd(&self) -> std::os::unix::prelude::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}
