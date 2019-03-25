// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::Error;
use libc::*;
use std::os::unix::io::{AsRawFd, RawFd};

pub fn errno() -> i32 {
    unsafe { *__error() }
}

pub fn errno_str() -> String {
    let strerr = unsafe { strerror(*__error()) };
    let c_str = unsafe { std::ffi::CStr::from_ptr(strerr) };
    c_str.to_string_lossy().into_owned()
}

#[cfg(target_os = "macos")]
const CTRL_NAME: &[u8] = b"com.apple.net.utun_control";

#[cfg(target_os = "macos")]
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
    ifru_data: *mut c_char,
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

#[cfg(target_os = "macos")]
const CTLIOCGINFO: uint64_t = 0xc064_4e03;
const SIOCGIFMTU: uint64_t = 0xc020_6933;
#[cfg(target_os = "freebsd")]
const TUNSIFHEAD: u64 = 0x8004_7460;
#[cfg(target_os = "freebsd")]
const SIOCIFDESTROY: u64 = 0x8020_6979;
#[cfg(target_os = "freebsd")]
const SIOCSIFNAME: u64 = 0x8020_6928;

#[cfg(target_os = "freebsd")]
extern "C" {
    fn fdevname(fd: RawFd) -> *mut c_char;
}

#[cfg(target_os = "freebsd")]
fn devname(fd: RawFd) -> String {
    let name = unsafe { fdevname(fd) };
    let c_str = unsafe { std::ffi::CStr::from_ptr(name) };
    c_str.to_string_lossy().into_owned()
}

#[derive(Default, Debug)]
pub struct TunSocket {
    fd: RawFd,
    name: String,
}

impl Drop for TunSocket {
    fn drop(&mut self) {
        unsafe { close(self.fd) };
        #[cfg(target_os = "freebsd")]
        // On FreeBSD we want to remove the tunnel manually
        TunSocket::remove(&self.name).ok();
    }
}

impl AsRawFd for TunSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

#[cfg(target_os = "macos")]
// On Darwin tunnel can only be named utunXXX
pub fn parse_utun_name(name: &str) -> Result<u32, Error> {
    if !name.starts_with("utun") {
        return Err(Error::InvalidTunnelName);
    }

    match name.get(4..) {
        None | Some("") => {
            // The name is simply "utun"
            Ok(0)
        }
        Some(idx) => {
            // Everything past utun should represent an integer index
            idx.parse::<u32>()
                .map_err(|_| Error::InvalidTunnelName)
                .map(|x| x + 1)
        }
    }
}

impl TunSocket {
    #[cfg(target_os = "macos")]
    pub fn new(name: &str) -> Result<TunSocket, Error> {
        let idx = parse_utun_name(name)?;

        let fd = match unsafe { socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL) } {
            -1 => return Err(Error::Socket(errno_str())),
            fd => fd,
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
                &addr as *const sockaddr_ctl as _,
                std::mem::size_of_val(&addr) as _,
            )
        } < 0
        {
            unsafe { close(fd) };
            let mut err_string = errno_str();
            err_string.push_str("(did you run with sudo?)");
            return Err(Error::Connect(err_string));
        }

        let name = TunSocket::get_name(fd)?;

        Ok(TunSocket { fd, name })
    }

    #[cfg(target_os = "freebsd")]
    pub fn new(name: &str) -> Result<TunSocket, Error> {
        let name_cstr = std::ffi::CString::new(name).unwrap();
        if unsafe { if_nametoindex(name_cstr.as_ptr()) } > 0 {
            // An interface with the desired name already exists, try to remove it first
            // it will only succeed if the interface is unused
            TunSocket::remove(name)?;
        }

        // Open a new tunnel
        let fd = match unsafe { open(b"/dev/tun\0".as_ptr() as _, O_RDWR) } {
            -1 => return Err(Error::Socket(errno_str())),
            fd => fd,
        };

        // This enables 4 byte header to allow ipv6 packets
        let enable: c_int = 1;
        if unsafe { ioctl(fd, TUNSIFHEAD, &enable) } < 0 {
            return Err(Error::IOCtl(errno_str()));
        }

        let name = TunSocket::set_name(&devname(fd), name)?;

        Ok(TunSocket { fd, name })
    }

    #[cfg(target_os = "macos")]
    fn get_name(fd: RawFd) -> Result<String, Error> {
        let mut tunnel_name = [0u8; 256];
        let mut tunnel_name_len: socklen_t = tunnel_name.len() as u32;
        if unsafe {
            getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                tunnel_name.as_mut_ptr() as _,
                &mut tunnel_name_len,
            )
        } < 0
            || tunnel_name_len == 0
        {
            return Err(Error::GetSockOpt(errno_str()));
        }

        Ok(String::from_utf8_lossy(&tunnel_name[..(tunnel_name_len - 1) as usize]).to_string())
    }

    #[cfg(target_os = "freebsd")]
    // Attempt to rename an interface
    fn set_name(old_name: &str, new_name: &str) -> Result<String, Error> {
        let fd = match unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_IP) } {
            -1 => return Err(Error::Socket(errno_str())),
            fd @ _ => fd,
        };

        let wanted_name = std::ffi::CString::new(new_name).unwrap();
        let iface_name: &[u8] = old_name.as_ref();
        let mut ifr = ifreq {
            ifr_name: [0; IF_NAMESIZE],
            ifr_ifru: IfrIfru {
                ifru_data: wanted_name.as_ptr() as _,
            },
        };

        if iface_name.len() >= ifr.ifr_name.len() {
            return Err(Error::InvalidTunnelName);
        }

        ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);

        if unsafe { ioctl(fd, SIOCSIFNAME, &ifr) } < 0 {
            return Err(Error::IOCtl(errno_str()));
        }

        unsafe { close(fd) };

        Ok(new_name.to_owned())
    }

    #[cfg(target_os = "freebsd")]
    // Attempt to remove an interface by name
    fn remove(name: &str) -> Result<(), Error> {
        let fd = match unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_IP) } {
            -1 => return Err(Error::Socket(errno_str())),
            fd @ _ => fd,
        };

        let iface_name: &[u8] = name.as_ref();
        let mut ifr = ifreq {
            ifr_name: [0; IF_NAMESIZE],
            ifr_ifru: IfrIfru { ifru_mtu: 0 },
        };

        if iface_name.len() >= ifr.ifr_name.len() {
            return Err(Error::InvalidTunnelName);
        }

        ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);

        if unsafe { ioctl(fd, SIOCIFDESTROY, &ifr) } < 0 {
            return Err(Error::IOCtl(errno_str()));
        }

        unsafe { close(fd) };

        Ok(())
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn set_non_blocking(self) -> Result<TunSocket, Error> {
        match unsafe { fcntl(self.fd, F_GETFL) } {
            -1 => Err(Error::FCntl(errno_str())),
            flags => match unsafe { fcntl(self.fd, F_SETFL, flags | O_NONBLOCK) } {
                -1 => Err(Error::FCntl(errno_str())),
                _ => Ok(self),
            },
        }
    }

    /// Get the current MTU value
    pub fn mtu(&self) -> Result<usize, Error> {
        let fd = match unsafe { socket(AF_INET, SOCK_STREAM, IPPROTO_IP) } {
            -1 => return Err(Error::Socket(errno_str())),
            fd => fd,
        };

        let iface_name: &[u8] = self.name.as_ref();
        let mut ifr = ifreq {
            ifr_name: [0; IF_NAMESIZE],
            ifr_ifru: IfrIfru { ifru_mtu: 0 },
        };

        ifr.ifr_name[..iface_name.len()].copy_from_slice(iface_name);

        if unsafe { ioctl(fd, SIOCGIFMTU, &ifr) } < 0 {
            return Err(Error::IOCtl(errno_str()));
        }

        unsafe { close(fd) };

        Ok(unsafe { ifr.ifr_ifru.ifru_mtu } as _)
    }

    fn write(&self, src: &[u8], af: u8) -> usize {
        let mut hdr = [0u8, 0u8, 0u8, af as u8];
        let iov = [
            iovec {
                iov_base: hdr.as_mut_ptr() as _,
                iov_len: hdr.len(),
            },
            iovec {
                iov_base: src.as_ptr() as _,
                iov_len: src.len(),
            },
        ];

        match unsafe { writev(self.fd, iov.as_ptr(), 2) } {
            -1 => 0,
            n => n as usize,
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
                iov_base: hdr.as_mut_ptr() as _,
                iov_len: hdr.len(),
            },
            iovec {
                iov_base: dst.as_mut_ptr() as _,
                iov_len: dst.len(),
            },
        ];

        match unsafe { readv(self.fd, iov.as_mut_ptr(), 2) } {
            -1 => Err(Error::IfaceRead(errno())),
            0..=4 => Ok(&mut dst[..0]),
            n => Ok(&mut dst[..(n - 4) as usize]),
        }
    }
}
