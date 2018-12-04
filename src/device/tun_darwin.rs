use super::{Descriptor, Error};
use libc::*;
use std::os::unix::io::RawFd;

pub fn errno_str() -> String {
    let strerr = unsafe { strerror(*__error()) };
    let c_str = unsafe { std::ffi::CStr::from_ptr(strerr) };
    c_str.to_string_lossy().into_owned()
}

const CTRL_NAME: &[u8] = b"com.apple.net.utun_control";

#[repr(C)]
pub struct ctl_info {
    pub ctl_id: uint32_t,
    pub ctl_name: [c_uchar; 96],
}

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
    ifr_name: [c_uchar; IF_NAMESIZE],
    ifr_ifru: IfrIfru,
}

const CTLIOCGINFO: uint64_t = 0x00000000c0644e03;
const SIOCSIFMTU: uint64_t = 0x0000000080206934;
const _SIOCSIFADDR: uint64_t = 0x000000008020690c;
const _SIOGSIFMTU: uint64_t = 0x00000000c0206933;
const _SIOCSIFNETMASK: uint64_t = 0x0000000080206916;
const _SIOCGIFFLAGS: uint64_t = 0x00000000c0206911;
const _SIOCSIFDSTADDR: uint64_t = 0x000000008020690e;

#[derive(Default, Debug)]
pub struct TunSocket {
    fd: RawFd,
}

impl Drop for TunSocket {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
    }
}

impl Descriptor for TunSocket {
    fn descriptor(&self) -> RawFd {
        self.fd
    }
}

// On Darwin tunnel can only be named utunXXX
fn parse_utun_name(name: &str) -> Result<u32, Error> {
    if !name.starts_with("utun") {
        return Err(Error::InvalidTunnelName);
    }

    if name.len() == 4 {
        return Ok(0);
    }

    name[4..].parse().map_err(|_| Error::InvalidTunnelName)
}

impl TunSocket {
    pub fn new(name: &str) -> Result<TunSocket, Error> {
        let idx = parse_utun_name(name)?;

        let fd = match unsafe { socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) } {
            -1 => return Err(Error::Socket(errno_str())),
            fd @ _ => fd,
        };

        let mut info = ctl_info {
            ctl_id: 0,
            ctl_name: [0u8; 96],
        };
        info.ctl_name[..CTRL_NAME.len()].copy_from_slice(CTRL_NAME);

        if unsafe { ioctl(fd, CTLIOCGINFO, &mut info as *mut ctl_info) } < 0 {
            unsafe { close(fd) };
            return Err(Error::IOCtl(errno_str()));
        }

        let addr = sockaddr_ctl {
            sc_len: std::mem::size_of::<sockaddr_ctl>() as u8,
            sc_family: AF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL as u16,
            sc_id: info.ctl_id,
            sc_unit: idx,
            sc_reserved: Default::default(),
        };

        if unsafe {
            connect(
                fd,
                &addr as *const sockaddr_ctl as *const sockaddr,
                std::mem::size_of::<sockaddr_ctl>() as u32,
            )
        } < 0
        {
            unsafe { close(fd) };
            return Err(Error::Connect(errno_str()));
        }

        Ok(TunSocket { fd })
    }

    pub fn name(&self) -> Result<String, Error> {
        let mut tunnel_name = [0u8; 256];
        let mut tunnel_name_len: socklen_t = tunnel_name.len() as u32;
        if unsafe {
            getsockopt(
                self.fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                &mut tunnel_name[..] as *mut [u8] as *mut c_void,
                &mut tunnel_name_len,
            )
        } < 0
            || tunnel_name_len == 0
        {
            return Err(Error::GetSockOpt(errno_str()));
        }

        Ok(String::from_utf8_lossy(&tunnel_name[..(tunnel_name_len - 1) as usize]).to_string())
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

    pub fn set_mtu(&self, mtu: i32) -> Result<(), Error> {
        let fd = match unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_IP) } {
            -1 => return Err(Error::Socket(errno_str())),
            fd @ _ => fd,
        };

        let name = self.name()?;
        let iface_name: &[u8] = name.as_ref();
        let mut ifr = ifreq {
            ifr_name: [0; IF_NAMESIZE],
            ifr_ifru: IfrIfru { ifru_mtu: mtu },
        };

        ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);

        if unsafe { ioctl(fd, SIOCSIFMTU, &ifr) } < 0 {
            return Err(Error::IOCtl(errno_str()));
        }

        unsafe { close(fd) };

        Ok(())
    }

    fn write(&self, src: &[u8], af: u8) -> usize {
        let mut hdr = [0u8, 0u8, 0u8, af as u8];
        let mut iov = [
            iovec {
                iov_base: &mut hdr[0] as *mut u8 as _,
                iov_len: hdr.len(),
            },
            iovec {
                iov_base: &src[0] as *const u8 as _,
                iov_len: src.len(),
            },
        ];

        let mut msg_hdr = msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov[0],
            msg_iovlen: iov.len() as _,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        match unsafe { sendmsg(self.fd, &mut msg_hdr, 0) } {
            -1 => 0,
            n @ _ => n as usize,
        }
    }

    pub fn write4(&self, src: &[u8]) -> usize {
        self.write(src, AF_INET as u8)
    }

    pub fn write6(&self, src: &[u8]) -> usize {
        self.write(src, AF_INET6 as u8)
    }

    pub fn read<'a>(&self, dst: &'a mut [u8]) -> Result<&'a mut [u8], Error> {
        let mut hdr = [0u8; 4];

        let mut iov = [
            iovec {
                iov_base: &mut hdr[0] as *mut u8 as _,
                iov_len: hdr.len(),
            },
            iovec {
                iov_base: &mut dst[0] as *mut u8 as _,
                iov_len: dst.len(),
            },
        ];

        let mut msg_hdr = msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iov[0],
            msg_iovlen: iov.len() as _,
            msg_control: std::ptr::null_mut(),
            msg_controllen: 0,
            msg_flags: 0,
        };

        match unsafe { recvmsg(self.fd, &mut msg_hdr, 0) } {
            -1 => Err(Error::IfaceRead(errno_str())),
            0..=4 => Ok(&mut dst[..0]),
            n @ _ => Ok(&mut dst[..(n - 4) as usize]),
        }
    }
}
