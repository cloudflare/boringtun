// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::{errno, errno_str, Error};
use libc::*;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::{AsRawFd, RawFd};

/// Receives and sends UDP packets over the network
#[derive(Debug)]
pub struct UDPSocket {
    fd: RawFd,
    version: u8,
}

impl UDPSocket {
    fn bind4(self, port: u16) -> Result<UDPSocket, Error> {
        let addr = sockaddr_in {
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            sin_len: std::mem::size_of::<sockaddr_in>() as u8,
            sin_family: AF_INET as _,
            sin_port: port.to_be(),
            sin_addr: in_addr { s_addr: INADDR_ANY },
            sin_zero: [0; 8],
        };

        match unsafe {
            bind(
                self.fd,
                &addr as *const sockaddr_in as *const sockaddr,
                std::mem::size_of::<sockaddr_in>() as u32,
            )
        } {
            -1 => Err(Error::Bind(errno_str())),
            _ => Ok(self),
        }
    }

    fn bind6(self, port: u16) -> Result<UDPSocket, Error> {
        let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        addr.sin6_family = AF_INET6 as _;
        addr.sin6_port = port.to_be();

        match unsafe {
            bind(
                self.fd,
                &addr as *const sockaddr_in6 as *const sockaddr,
                std::mem::size_of::<sockaddr_in6>() as u32,
            )
        } {
            -1 => Err(Error::Bind(errno_str())),
            _ => Ok(self),
        }
    }

    fn connect4(self, dst: &SocketAddrV4) -> Result<UDPSocket, Error> {
        assert_eq!(self.version, 4);
        let addr = sockaddr_in {
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            sin_len: std::mem::size_of::<sockaddr_in>() as u8,
            sin_family: AF_INET as _,
            sin_port: dst.port().to_be(),
            sin_addr: in_addr {
                s_addr: u32::from(*dst.ip()).to_be(),
            },
            sin_zero: [0; 8],
        };

        match unsafe {
            connect(
                self.fd,
                &addr as *const sockaddr_in as *const sockaddr,
                std::mem::size_of::<sockaddr_in>() as u32,
            )
        } {
            -1 => Err(Error::Connect(errno_str())),
            _ => Ok(self),
        }
    }

    fn connect6(self, dst: &SocketAddrV6) -> Result<UDPSocket, Error> {
        assert_eq!(self.version, 6);
        let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        addr.sin6_family = AF_INET6 as _;
        addr.sin6_port = dst.port().to_be();
        addr.sin6_addr.s6_addr = dst.ip().octets();

        match unsafe {
            connect(
                self.fd,
                &addr as *const sockaddr_in6 as *const sockaddr,
                std::mem::size_of::<sockaddr_in6>() as u32,
            )
        } {
            -1 => Err(Error::Connect(errno_str())),
            _ => Ok(self),
        }
    }

    fn sendto4(&self, buf: &[u8], dst: SocketAddrV4) -> usize {
        assert_eq!(self.version, 4);
        let addr = sockaddr_in {
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            sin_len: std::mem::size_of::<sockaddr_in>() as _,
            sin_family: AF_INET as _,
            sin_port: dst.port().to_be(),
            sin_addr: in_addr {
                s_addr: u32::from(*dst.ip()).to_be(),
            },
            sin_zero: [0; 8],
        };

        match unsafe {
            sendto(
                self.fd,
                &buf[0] as *const u8 as _,
                buf.len() as _,
                0,
                &addr as *const sockaddr_in as _,
                std::mem::size_of::<sockaddr_in>() as _,
            )
        } {
            -1 => 0,
            n => n as usize,
        }
    }

    fn sendto6(&self, buf: &[u8], dst: SocketAddrV6) -> usize {
        assert_eq!(self.version, 6);
        let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        addr.sin6_family = AF_INET6 as _;
        addr.sin6_port = dst.port().to_be();
        addr.sin6_addr.s6_addr = dst.ip().octets();

        match unsafe {
            sendto(
                self.fd,
                &buf[0] as *const u8 as _,
                buf.len() as _,
                0,
                &addr as *const sockaddr_in6 as _,
                std::mem::size_of::<sockaddr_in6>() as _,
            )
        } {
            -1 => 0,
            n => n as usize,
        }
    }

    fn recvfrom6<'a>(&self, buf: &'a mut [u8]) -> Result<(SocketAddr, &'a mut [u8]), Error> {
        let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut addr_len: socklen_t = std::mem::size_of::<sockaddr_in6>() as socklen_t;

        let n = unsafe {
            recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
                &mut addr as *mut sockaddr_in6 as *mut sockaddr,
                &mut addr_len,
            )
        };

        if n == -1 {
            return Err(Error::UDPRead(errno()));
        }

        // This is the endpoint
        let origin = SocketAddrV6::new(
            std::net::Ipv6Addr::from(addr.sin6_addr.s6_addr),
            u16::from_be(addr.sin6_port),
            0,
            0,
        );

        Ok((SocketAddr::V6(origin), &mut buf[..n as usize]))
    }

    fn recvfrom4<'a>(&self, buf: &'a mut [u8]) -> Result<(SocketAddr, &'a mut [u8]), Error> {
        let mut addr = sockaddr_in {
            #[cfg(any(target_os = "macos", target_os = "ios"))]
            sin_len: 0,
            sin_family: 0,
            sin_port: 0,
            sin_addr: in_addr { s_addr: 0 },
            sin_zero: [0; 8],
        };
        let mut addr_len: socklen_t = std::mem::size_of::<sockaddr_in>() as socklen_t;

        let n = unsafe {
            recvfrom(
                self.fd,
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
                0,
                &mut addr as *mut sockaddr_in as *mut sockaddr,
                &mut addr_len,
            )
        };

        if n == -1 {
            return Err(Error::UDPRead(errno()));
        }

        // This is the endpoint
        let origin = SocketAddrV4::new(
            std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
            u16::from_be(addr.sin_port),
        );

        Ok((SocketAddr::V4(origin), &mut buf[..n as usize]))
    }

    fn write_fd(fd: RawFd, src: &[u8]) -> usize {
        match unsafe { send(fd, &src[0] as *const u8 as _, src.len(), 0) } {
            -1 => 0,
            n => n as usize,
        }
    }
}

/// Socket is closed when it goes out of scope
impl Drop for UDPSocket {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}

impl AsRawFd for UDPSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl UDPSocket {
    /// Create a new IPv4 UDP socket
    pub fn new() -> Result<UDPSocket, Error> {
        match unsafe { socket(AF_INET, SOCK_DGRAM, 0) } {
            -1 => Err(Error::Socket(errno_str())),
            fd => Ok(UDPSocket { fd, version: 4 }),
        }
    }

    /// Create a new IPv6 UDP socket
    pub fn new6() -> Result<UDPSocket, Error> {
        match unsafe { socket(AF_INET6, SOCK_DGRAM, 0) } {
            -1 => Err(Error::Socket(errno_str())),
            fd => Ok(UDPSocket { fd, version: 6 }),
        }
    }

    /// Bind the socket to a local port
    pub fn bind(self, port: u16) -> Result<UDPSocket, Error> {
        if self.version == 6 {
            return self.bind6(port);
        }

        self.bind4(port)
    }

    /// Connect a socket to a remote address, must call bind prior to connect
    /// # Panics
    /// When connecting an IPv4 socket to an IPv6 address and vice versa
    pub fn connect(self, dst: &SocketAddr) -> Result<UDPSocket, Error> {
        match dst {
            SocketAddr::V4(dst) => self.connect4(dst),
            SocketAddr::V6(dst) => self.connect6(dst),
        }
    }

    /// Set socket mode to non blocking
    pub fn set_non_blocking(self) -> Result<UDPSocket, Error> {
        match unsafe { fcntl(self.fd, F_GETFL) } {
            -1 => Err(Error::FCntl(errno_str())),
            flags => match unsafe { fcntl(self.fd, F_SETFL, flags | O_NONBLOCK) } {
                -1 => Err(Error::FCntl(errno_str())),
                _ => Ok(self),
            },
        }
    }

    /// Set the SO_REUSEPORT/SO_REUSEADDR option, so multiple sockets can bind on the same port
    pub fn set_reuse(self) -> Result<UDPSocket, Error> {
        match unsafe {
            setsockopt(
                self.fd,
                SOL_SOCKET,
                #[cfg(target_os = "linux")]
                SO_REUSEADDR, // On Linux SO_REUSEPORT won't prefer a connected IPv6 socket
                #[cfg(not(target_os = "linux"))]
                SO_REUSEPORT,
                &1u32 as *const u32 as *const c_void,
                std::mem::size_of::<u32>() as u32,
            )
        } {
            -1 => Err(Error::SetSockOpt(errno_str())),
            _ => Ok(self),
        }
    }

    #[cfg(target_os = "linux")]
    /// Set the mark on all packets sent by this socket using SO_MARK
    /// Only available on Linux
    pub fn set_fwmark(&self, mark: u32) -> Result<(), Error> {
        match unsafe {
            setsockopt(
                self.fd,
                SOL_SOCKET,
                SO_MARK,
                &mark as *const u32 as *const c_void,
                std::mem::size_of_val(&mark) as _,
            )
        } {
            -1 => Err(Error::SetSockOpt(errno_str())),
            _ => Ok(()),
        }
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    pub fn set_fwmark(&self, _: u32) -> Result<(), Error> {
        Ok(())
    }

    /// Query the local port the socket is bound to
    /// # Panics
    /// If socket is IPv6
    pub fn port(&self) -> Result<u16, Error> {
        if self.version != 4 {
            panic!("Can only query ports of IPv4 sockets");
        }
        let mut addr: sockaddr_in = unsafe { std::mem::zeroed() };
        let mut addr_len = std::mem::size_of_val(&addr) as _;
        match unsafe { getsockname(self.fd, &mut addr as *mut sockaddr_in as _, &mut addr_len) } {
            -1 => Err(Error::GetSockName(errno_str())),
            _ => Ok(u16::from_be(addr.sin_port)),
        }
    }

    /// Send buf to a remote address, returns 0 on error, or amount of data send on success
    /// # Panics
    /// When sending from an IPv4 socket to an IPv6 address and vice versa
    pub fn sendto(&self, buf: &[u8], dst: SocketAddr) -> usize {
        match dst {
            SocketAddr::V4(addr) => self.sendto4(buf, addr),
            SocketAddr::V6(addr) => self.sendto6(buf, addr),
        }
    }

    /// Receives a message on a non-connected UDP socket and returns its contents and origin address
    pub fn recvfrom<'a>(&self, buf: &'a mut [u8]) -> Result<(SocketAddr, &'a mut [u8]), Error> {
        match self.version {
            4 => self.recvfrom4(buf),
            _ => self.recvfrom6(buf),
        }
    }

    /// Receives a message on a connected UDP socket and returns its contents
    pub fn read<'a>(&self, dst: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        match unsafe { recv(self.fd, &mut dst[0] as *mut u8 as _, dst.len(), 0) } {
            -1 => Err(Error::UDPRead(errno())),
            n => Ok(&mut dst[..n as usize]),
        }
    }

    /// Sends a message on a connected UDP socket. Returns number of bytes successfully sent.
    pub fn write(&self, src: &[u8]) -> usize {
        UDPSocket::write_fd(self.fd, src)
    }

    /// Calls shutdown on a connected socket. This will trigger an EOF in the event queue.
    pub fn shutdown(&self) {
        unsafe { shutdown(self.fd, SHUT_RDWR) };
    }
}
