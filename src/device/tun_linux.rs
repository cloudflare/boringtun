use super::Error;
use libc::*;
use std::os::unix::io::{AsRawFd, RawFd};

pub fn errno_str() -> String {
    let strerr = unsafe { strerror(*__errno_location()) };
    let c_str = unsafe { std::ffi::CStr::from_ptr(strerr) };
    c_str.to_string_lossy().into_owned()
}

const TUNSETIFF: u64 = 0x400454ca;

#[repr(C)]
union IfrIfru {
    ifru_addr: sockaddr,
    ifru_addr_v4: sockaddr_in,
    ifru_addr_v6: sockaddr_in,
    ifru_dstaddr: sockaddr,
    ifru_broadaddr: sockaddr,
    ifru_flags: c_short,
    ifru_metric: c_int,
    ifru_mtu: c_int,
    ifru_phys: c_int,
    ifru_media: c_int,
    ifru_intval: c_int,
    //ifru_data: caddr_t,
    //ifru_devmtu: ifdevmtu,
    //ifru_kpi: ifkpi,
    ifru_wake_flags: uint32_t,
    ifru_route_refcnt: uint32_t,
    ifru_cap: [c_int; 2],
    ifru_functional_type: uint32_t,
}

#[repr(C)]
pub struct ifreq {
    ifr_name: [c_uchar; IFNAMSIZ],
    ifr_ifru: IfrIfru,
}

#[derive(Default, Debug)]
pub struct TunSocket {
    fd: RawFd,
    name: String,
}

impl Drop for TunSocket {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}

impl AsRawFd for TunSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl TunSocket {
    pub fn new(name: &str) -> Result<TunSocket, Error> {
        let fd = match unsafe { open(&b"/dev/net/tun\0"[0] as *const u8 as _, O_RDWR) } {
            -1 => return Err(Error::Socket(errno_str())),
            fd @ _ => fd,
        };

        let iface_name: &[u8] = name.as_ref();
        let mut ifr = ifreq {
            ifr_name: [0; IFNAMSIZ],
            ifr_ifru: IfrIfru {
                ifru_flags: IFF_TUN | IFF_NO_PI | IFF_MULTI_QUEUE,
            },
        };

        ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);

        if unsafe { ioctl(fd, TUNSETIFF, &ifr) } < 0 {
            return Err(Error::IOCtl(errno_str()));
        }

        let name = name.to_string();
        Ok(TunSocket { fd, name })
    }

    pub fn name(&self) -> Result<String, Error> {
        Ok(self.name.clone())
    }

    pub fn set_non_blocking(self) -> Result<TunSocket, Error> {
        match unsafe { fcntl(self.fd, F_GETFL) } {
            -1 => Err(Error::FCntl(errno_str())),
            flags @ _ => match unsafe { fcntl(self.fd, F_SETFL, flags | O_NONBLOCK) } {
                -1 => Err(Error::FCntl(errno_str())),
                _ => Ok(self),
            },
        }
    }

    pub fn write4(&self, src: &[u8]) -> usize {
        self.write(src)
    }

    pub fn write6(&self, src: &[u8]) -> usize {
        self.write(src)
    }

    fn write(&self, buf: &[u8]) -> usize {
        match unsafe { write(self.fd, &buf[0] as *const u8 as _, buf.len() as _) } {
            -1 => 0,
            n => n as usize,
        }
    }

    pub fn read<'a>(&self, dst: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        match unsafe { read(self.fd, &mut dst[0] as *mut u8 as _, dst.len()) } {
            -1 => Err(Error::IfaceRead(errno_str())),
            n @ _ => Ok(&mut dst[..n as usize]),
        }
    }
}
