use super::{errno_str, Error};
use libc::*;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::unix::io::{AsRawFd, RawFd};

// Recieves and sends packets over the network
#[derive(Debug)]
pub struct UDPSocket {
    fd: RawFd,
    version: u8,
}

unsafe impl Send for UDPSocket {}
unsafe impl Sync for UDPSocket {}

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

impl Default for UDPSocket {
    fn default() -> UDPSocket {
        UDPSocket { fd: -1, version: 0 }
    }
}

impl UDPSocket {
    pub fn new() -> Result<UDPSocket, Error> {
        match unsafe { socket(AF_INET, SOCK_DGRAM, 0) } {
            -1 => Err(Error::Socket(errno_str())),
            fd @ _ => Ok(UDPSocket { fd, version: 4 }),
        }
    }

    pub fn new6() -> Result<UDPSocket, Error> {
        match unsafe { socket(AF_INET6, SOCK_DGRAM, 0) } {
            -1 => Err(Error::Socket(errno_str())),
            fd @ _ => Ok(UDPSocket { fd, version: 6 }),
        }
    }

    pub fn set_non_blocking(self) -> Result<UDPSocket, Error> {
        match unsafe { fcntl(self.fd, F_GETFL) } {
            -1 => Err(Error::FCntl(errno_str())),
            flags @ _ => match unsafe { fcntl(self.fd, F_SETFL, flags | O_NONBLOCK) } {
                -1 => Err(Error::FCntl(errno_str())),
                _ => Ok(self),
            },
        }
    }

    pub fn set_reuse_port(self) -> Result<UDPSocket, Error> {
        match unsafe {
            setsockopt(
                self.fd,
                SOL_SOCKET,
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

    #[cfg(target_os = "macos")]
    pub fn set_fwmark(&self, _: u32) -> Result<(), Error> {
        Ok(())
    }

    pub fn bind(self, port: u16) -> Result<UDPSocket, Error> {
        if self.version == 6 {
            return self.bind6(port);
        }

        assert_eq!(self.version, 4);

        let addr = sockaddr_in {
            #[cfg(target_os = "macos")]
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

    pub fn connect(self, dst: &SocketAddr) -> Result<UDPSocket, Error> {
        match dst {
            SocketAddr::V4(dst) => self.connect4(dst),
            SocketAddr::V6(dst) => self.connect6(dst),
        }
    }

    fn connect4(self, dst: &SocketAddrV4) -> Result<UDPSocket, Error> {
        assert_eq!(self.version, 4);
        let addr = sockaddr_in {
            #[cfg(target_os = "macos")]
            sin_len: std::mem::size_of::<sockaddr_in>() as u8,
            sin_family: AF_INET as _,
            sin_port: dst.port().to_be(),
            sin_addr: in_addr {
                s_addr: u32::from(dst.ip().clone()).to_be(),
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

    pub fn sendto(&self, buf: &[u8], dst: SocketAddr) -> usize {
        match dst {
            SocketAddr::V4(addr) => self.sendto4(buf, addr),
            SocketAddr::V6(addr) => self.sendto6(buf, addr),
        }
    }

    fn sendto4(&self, buf: &[u8], dst: SocketAddrV4) -> usize {
        assert_eq!(self.version, 4);
        let addr = sockaddr_in {
            #[cfg(target_os = "macos")]
            sin_len: std::mem::size_of::<sockaddr_in>() as _,
            sin_family: AF_INET as _,
            sin_port: dst.port().to_be(),
            sin_addr: in_addr {
                s_addr: u32::from(dst.ip().clone()).to_be(),
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
            n @ _ => n as usize,
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
            n @ _ => n as usize,
        }
    }

    pub fn recvfrom<'a>(&self, buf: &'a mut [u8]) -> Result<(SocketAddr, &'a mut [u8]), Error> {
        match self.version {
            4 => self.recvfrom4(buf),
            _ => self.recvfrom6(buf),
        }
    }

    // Receives a message on a non-connected UDP socket and returns its contents and origin address
    fn recvfrom6<'a>(&self, buf: &'a mut [u8]) -> Result<(SocketAddr, &'a mut [u8]), Error> {
        let mut addr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
        let mut addr_len: socklen_t = std::mem::size_of::<sockaddr_in6>() as socklen_t;

        let n = unsafe {
            recvfrom(
                self.fd,
                &mut buf[..] as *mut [u8] as *mut c_void,
                buf.len(),
                0,
                &mut addr as *mut sockaddr_in6 as *mut sockaddr,
                &mut addr_len,
            )
        };

        if n == -1 {
            return Err(Error::UDPRead(errno_str()));
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

    // Receives a message on a non-connected UDP socket and returns its contents and origin address
    fn recvfrom4<'a>(&self, buf: &'a mut [u8]) -> Result<(SocketAddr, &'a mut [u8]), Error> {
        let mut addr = sockaddr_in {
            #[cfg(target_os = "macos")]
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
                &mut buf[..] as *mut [u8] as *mut c_void,
                buf.len(),
                0,
                &mut addr as *mut sockaddr_in as *mut sockaddr,
                &mut addr_len,
            )
        };

        if n == -1 {
            return Err(Error::UDPRead(errno_str()));
        }

        // This is the endpoint
        let origin = SocketAddrV4::new(
            std::net::Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
            u16::from_be(addr.sin_port),
        );

        Ok((SocketAddr::V4(origin), &mut buf[..n as usize]))
    }

    pub fn read<'a>(&self, dst: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        match unsafe { recv(self.fd, &mut dst[0] as *mut u8 as _, dst.len(), 0) } {
            -1 => Err(Error::UDPRead(errno_str())),
            n @ _ => Ok(&mut dst[..n as usize]),
        }
    }

    pub fn write(&self, src: &[u8]) -> usize {
        UDPSocket::write_fd(self.fd, src)
    }

    pub fn write_fd(fd: RawFd, src: &[u8]) -> usize {
        match unsafe { send(fd, &src[0] as *const u8 as _, src.len(), 0) } {
            -1 => 0,
            n @ _ => n as usize,
        }
    }

    pub fn shutdown(&self) {
        unsafe { shutdown(self.fd, SHUT_RDWR) };
    }
}
