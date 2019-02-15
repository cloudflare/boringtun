use super::{errno_str, Error};
use libc::*;
use std::fs::File;
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

/// Accepts UNIX connections from the wg app
pub struct UNIXSocket {
    fd: RawFd,
    path: Option<String>,
}

/// When goes out of scope the socket is closed and its file reference is removed
impl Drop for UNIXSocket {
    fn drop(&mut self) {
        if let Some(ref path) = self.path {
            let unlink_path = std::ffi::CString::new(path.as_str()).unwrap();
            unsafe { unlink(unlink_path.as_ptr()) };
        };

        unsafe { close(self.fd) };
    }
}

impl AsRawFd for UNIXSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl UNIXSocket {
    /// Create a new UNIX socket in stream mode
    pub fn new() -> Result<UNIXSocket, Error> {
        match unsafe { socket(AF_UNIX, SOCK_STREAM, 0) } {
            -1 => Err(Error::Socket(errno_str())),
            fd => Ok(UNIXSocket { fd, path: None }),
        }
    }

    /// Bind the packet to a path, if path already exists it will remove it before binding
    pub fn bind(mut self, address: &str) -> Result<UNIXSocket, Error> {
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
            addr.sun_path[i] = c as _;
        }

        match unsafe {
            unlink(&addr.sun_path as _);
            bind(
                self.fd,
                &addr as *const sockaddr_un as *const sockaddr,
                std::mem::size_of::<sockaddr_un>() as u32,
            )
        } {
            -1 => Err(Error::Bind(errno_str())),
            _ => {
                self.path = Some(address.to_owned());
                Ok(self)
            }
        }
    }

    /// Start accepting incoming connections on the socket
    pub fn listen(self) -> Result<UNIXSocket, Error> {
        match unsafe { listen(self.fd, 50) } {
            -1 => Err(Error::Listen(errno_str())),
            _ => Ok(self),
        }
    }

    /// Accept an incoming connections
    pub fn accept(&self) -> Result<File, Error> {
        match unsafe { accept(self.fd, std::ptr::null_mut(), std::ptr::null_mut()) } {
            -1 => Err(Error::Accept(errno_str())),
            fd => Ok(unsafe { File::from_raw_fd(fd) }),
        }
    }
}
