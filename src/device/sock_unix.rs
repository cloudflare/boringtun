use super::{errno_str, Descriptor, Error};
use libc::*;
use std::os::unix::io::RawFd;

// Accepts connections from the wg app
#[derive(Default, Debug)]
pub struct UNIXSocket {
    fd: RawFd,
}

// Handles the control messages from the wg app
pub struct UNIXConn {
    fd: RawFd,
}

impl Drop for UNIXSocket {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}

impl Drop for UNIXConn {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}

impl Descriptor for UNIXSocket {
    fn descriptor(&self) -> RawFd {
        self.fd
    }
}

impl Descriptor for UNIXConn {
    fn descriptor(&self) -> RawFd {
        self.fd
    }
}

impl UNIXSocket {
    pub fn new() -> Result<UNIXSocket, Error> {
        match unsafe { socket(AF_UNIX, SOCK_STREAM, 0) } {
            -1 => Err(Error::Socket(errno_str())),
            fd @ _ => Ok(UNIXSocket { fd }),
        }
    }

    pub fn set_non_blocking(self) -> Result<UNIXSocket, Error> {
        match unsafe { fcntl(self.fd, F_GETFL) } {
            -1 => Err(Error::FCntl(errno_str())),
            flags @ _ => match unsafe { fcntl(self.fd, F_SETFL, flags | O_NONBLOCK) } {
                -1 => Err(Error::FCntl(errno_str())),
                _ => Ok(self),
            },
        }
    }

    pub fn bind(self, address: &str) -> Result<UNIXSocket, Error> {
        assert!(address.len() < 108);
        let mut addr = sockaddr_un {
            #[cfg(target_os = "macos")]
            sun_len: std::mem::size_of::<sockaddr_un>() as u8,
            sun_family: AF_UNIX as _,
            #[cfg(target_os = "linux")]
            sun_path: [0; 108],
            #[cfg(target_os = "macos")]
            sun_path: [0; 104],
        };

        for (i, c) in address.chars().enumerate() {
            addr.sun_path[i] = c as i8;
        }

        match unsafe {
            unlink(&addr.sun_path as *const i8);
            bind(
                self.fd,
                &addr as *const sockaddr_un as *const sockaddr,
                std::mem::size_of::<sockaddr_un>() as u32,
            )
        } {
            -1 => Err(Error::Bind(errno_str())),
            _ => Ok(self),
        }
    }

    pub fn listen(self) -> Result<UNIXSocket, Error> {
        match unsafe { listen(self.fd, 50) } {
            -1 => Err(Error::Listen(errno_str())),
            _ => Ok(self),
        }
    }

    pub fn accept(&self) -> Result<UNIXConn, Error> {
        match unsafe { accept(self.fd, std::ptr::null_mut(), std::ptr::null_mut()) } {
            -1 => Err(Error::Accept(errno_str())),
            fd @ _ => Ok(UNIXConn { fd }),
        }
    }
}

impl UNIXConn {}
/*

use std::io::{self, Read, Write};
impl<'a> Read for &UNIXConn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match unsafe { read(self.fd, &mut buf[0] as *mut u8 as *mut c_void, buf.len()) } {
            -1 => Err(io::Error::new(io::ErrorKind::Other, "UNIXConn read error")),
            n @ _ => Ok(n as usize),
        }
    }
}

impl<'a> Write for &UNIXConn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match unsafe { write(self.fd, &buf[0] as *const u8 as *const c_void, buf.len()) } {
            -1 => Err(io::Error::new(io::ErrorKind::Other, "UNIXConn read error")),
            n @ _ => Ok(n as usize),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
*/
