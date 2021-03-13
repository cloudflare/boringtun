// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::Error;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{self, Shutdown, SocketAddr};
use std::os::unix::io::{AsRawFd, RawFd};

/// Receives and sends UDP packets over the network
#[derive(Debug)]
pub struct UDPSocket {
    socket: Socket,
    family: SocketFamily,
}

#[derive(Debug)]
enum SocketFamily {
    IpV4,
    IpV6,
}

impl UDPSocket {
    /// Create a new IPv4 UDP socket
    pub fn new() -> Result<UDPSocket, Error> {
        let socket = Socket::new(Domain::ipv4(), Type::dgram(), Some(Protocol::udp()))?;

        Ok(UDPSocket {
            socket,
            family: SocketFamily::IpV4,
        })
    }

    /// Create a new IPv6 UDP socket
    pub fn new6() -> Result<UDPSocket, Error> {
        let socket = Socket::new(Domain::ipv6(), Type::dgram(), Some(Protocol::udp()))?;

        Ok(UDPSocket {
            socket,
            family: SocketFamily::IpV6,
        })
    }

    /// Bind the socket to a local port
    pub fn bind(self, port: u16) -> Result<UDPSocket, Error> {
        let sockaddr = match self.family {
            SocketFamily::IpV4 => {
                SocketAddr::new(net::IpAddr::V4(net::Ipv4Addr::UNSPECIFIED), port)
            }
            SocketFamily::IpV6 => {
                SocketAddr::new(net::IpAddr::V6(net::Ipv6Addr::UNSPECIFIED), port)
            }
        };
        self.socket.bind(&sockaddr.into())?;
        Ok(self)
    }

    /// Connect a socket to a remote address, must call bind prior to connect
    /// # Panics
    /// When connecting an IPv4 socket to an IPv6 address and vice versa
    pub fn connect(self, dst: SocketAddr) -> Result<UDPSocket, Error> {
        self.socket.connect(&dst.into())?;
        Ok(self)
    }

    /// Set socket mode to non blocking
    pub fn set_non_blocking(self) -> Result<UDPSocket, Error> {
        self.socket.set_nonblocking(true)?;
        Ok(self)
    }

    /// Set the SO_REUSEPORT/SO_REUSEADDR option, so multiple sockets can bind on the same port
    pub fn set_reuse(self) -> Result<UDPSocket, Error> {
        // On Linux SO_REUSEPORT won't prefer a connected IPv6 socket
        #[cfg(target_os = "linux")]
        self.socket.set_reuse_address(true)?;

        #[cfg(not(target_os = "linux"))]
        self.socket.set_reuse_port(true)?;

        Ok(self)
    }

    #[cfg(target_os = "linux")]
    /// Set the mark on all packets sent by this socket using SO_MARK
    /// Only available on Linux
    pub fn set_fwmark(&self, mark: u32) -> Result<(), Error> {
        self.socket.set_mark(mark)?;
        Ok(())
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn set_fwmark(&self, _: u32) -> Result<(), Error> {
        Ok(())
    }

    /// Query the local port the socket is bound to
    /// # Panics
    /// If socket is IPv6
    pub fn port(&self) -> Result<u16, Error> {
        Ok(self
            .socket
            .local_addr()?
            .as_std()
            .expect("must be INET or INET6")
            .port())
    }

    /// Send buf to a remote address, returns 0 on error, or amount of data send on success
    /// # Panics
    /// When sending from an IPv4 socket to an IPv6 address and vice versa
    pub fn sendto(&self, buf: &[u8], dst: SocketAddr) -> Result<usize, Error> {
        Ok(self.socket.send_to(buf, &dst.into())?)
    }

    /// Receives a message on a non-connected UDP socket and returns its contents and origin address
    pub fn recvfrom<'a>(&self, buf: &'a mut [u8]) -> Result<(SocketAddr, &'a mut [u8]), Error> {
        let (len, addr) = self.socket.recv_from(buf)?;
        Ok((
            addr.as_std().expect("must be INET or INET6"),
            &mut buf[..len],
        ))
    }

    /// Receives a message on a connected UDP socket and returns its contents
    pub fn recv<'a>(&self, dst: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        let len = self.socket.recv(dst)?;
        Ok(&mut dst[..len])
    }

    /// Sends a message on a connected UDP socket. Returns number of bytes successfully sent.
    pub fn send(&self, src: &[u8]) -> Result<usize, Error> {
        Ok(self.socket.send(src)?)
    }

    /// Calls shutdown on a connected socket. This will trigger an EOF in the event queue.
    pub fn shutdown(&self) -> Result<(), Error> {
        Ok(self.socket.shutdown(Shutdown::Both)?)
    }

    pub fn as_raw_fd(&self) -> RawFd {
        self.socket.as_raw_fd()
    }
}
