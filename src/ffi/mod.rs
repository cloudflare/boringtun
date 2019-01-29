/// C bindings for the WireGuard library
mod benchmark;
use self::benchmark::do_benchmark;
use super::crypto::x25519::x25519_public_key as pub_key;
use super::crypto::x25519::*;
use super::noise::*;
use base64::{decode, encode};
use hex::encode as encode_hex;
use std::ffi::{CStr, CString};
use std::mem;
use std::os::raw::c_char;
use std::ptr;
use std::slice;

#[allow(non_camel_case_types)]
#[repr(u32)]
/// Indicates the operation required from the caller
pub enum result_type {
    /// No operation is required.
    WIREGUARD_DONE = 0,
    /// Write dst buffer to network. Size indicates the number of bytes to write.
    WRITE_TO_NETWORK = 1,
    /// Some error occured, no operation is required. Size indicates error code.
    WIREGUARD_ERROR = 2,
    /// Write dst buffer to the interface as an ipv4 packet. Size indicates the number of bytes to write.
    WRITE_TO_TUNNEL_IPV4 = 4,
    /// Write dst buffer to the interface as an ipv6 packet. Size indicates the number of bytes to write.
    WRITE_TO_TUNNEL_IPV6 = 6,
}

/// The return type of WireGuard functions
#[repr(C)]
pub struct wireguard_result {
    /// The operation to be performed by the caller
    pub op: result_type,
    /// Additional information, required to perform the operation
    pub size: usize,
}

impl<'a> From<TunnResult<'a>> for wireguard_result {
    fn from(res: TunnResult<'a>) -> wireguard_result {
        match res {
            TunnResult::Done => wireguard_result {
                op: result_type::WIREGUARD_DONE,
                size: 0,
            },
            TunnResult::Err(e) => wireguard_result {
                op: result_type::WIREGUARD_ERROR,
                size: e as _,
            },
            TunnResult::WriteToNetwork(b) => wireguard_result {
                op: result_type::WRITE_TO_NETWORK,
                size: b.len(),
            },
            TunnResult::WriteToTunnelV4(b, _) => wireguard_result {
                op: result_type::WRITE_TO_TUNNEL_IPV4,
                size: b.len(),
            },
            TunnResult::WriteToTunnelV6(b, _) => wireguard_result {
                op: result_type::WRITE_TO_TUNNEL_IPV6,
                size: b.len(),
            },
        }
    }
}

impl From<u32> for Verbosity {
    fn from(num: u32) -> Self {
        match num {
            0 => Verbosity::None,
            1 => Verbosity::Info,
            2 => Verbosity::Debug,
            _ => Verbosity::All,
        }
    }
}

#[repr(C)]
pub struct x25519_key {
    pub key: [u8; 32],
}

/// Generates a new x25519 secret key.
#[no_mangle]
pub extern "C" fn x25519_secret_key() -> x25519_key {
    x25519_key {
        key: x25519_gen_secret_key(),
    }
}

/// Computes a public x25519 key from a secret key.
#[no_mangle]
pub extern "C" fn x25519_public_key(private_key: x25519_key) -> x25519_key {
    x25519_key {
        key: pub_key(&private_key.key),
    }
}

/// Returns the base64 encoding of a key as a UTF8 C-string.
///
/// The memory has to be freed by calling `x25519_key_to_str_free`
#[no_mangle]
pub extern "C" fn x25519_key_to_base64(key: x25519_key) -> *const c_char {
    let encoded_key = encode(&key.key);
    CString::into_raw(CString::new(encoded_key).unwrap())
}

/// Returns the hex encoding of a key as a UTF8 C-string.
///
/// The memory has to be freed by calling `x25519_key_to_str_free`
#[no_mangle]
pub extern "C" fn x25519_key_to_hex(key: x25519_key) -> *const c_char {
    let encoded_key = encode_hex(&key.key);
    CString::into_raw(CString::new(encoded_key).unwrap())
}

/// Frees memory of the string given by `x25519_key_to_hex` or `x25519_key_to_base64`
#[no_mangle]
pub unsafe extern "C" fn x25519_key_to_str_free(stringified_key: *mut c_char) {
    CString::from_raw(stringified_key);
}

/// Check if the input C-string represents a valid base64 encoded x25519 key.
/// Return 1 if valid 0 otherwise.
#[no_mangle]
pub unsafe extern "C" fn check_base64_encoded_x25519_key(key: *const c_char) -> i32 {
    let c_str = CStr::from_ptr(key);
    let utf8_key = match c_str.to_str() {
        Err(_) => return 0,
        Ok(string) => string,
    };

    if let Ok(key) = decode(&utf8_key) {
        let len = key.len();
        let mut zero = 0u8;
        for b in key {
            zero |= b
        }
        if len == 32 && zero != 0 {
            1
        } else {
            0
        }
    } else {
        0
    }
}

/// Allocate a new tunnel, return NULL on failure.
/// Keys must be valid base64 encoded 32-byte keys.
#[no_mangle]
pub unsafe extern "C" fn new_tunnel(
    static_private: *const c_char,
    server_static_public: *const c_char,
    log_printer: Option<unsafe extern "C" fn(*const c_char)>,
    log_level: u32,
) -> *mut Tunn {
    let c_str = CStr::from_ptr(static_private);
    let static_private = match c_str.to_str() {
        Err(_) => return ptr::null_mut(),
        Ok(string) => string,
    };

    let c_str = CStr::from_ptr(server_static_public);
    let server_static_public = match c_str.to_str() {
        Err(_) => return ptr::null_mut(),
        Ok(string) => string,
    };

    let private_key = match static_private.parse() {
        Err(_) => return ptr::null_mut(),
        Ok(key) => key,
    };

    let public_key = match server_static_public.parse() {
        Err(_) => return ptr::null_mut(),
        Ok(key) => key,
    };

    let mut tunnel = match Tunn::new(&private_key, &public_key, 0) {
        Ok(t) => t,
        Err(_) => return ptr::null_mut(),
    };

    if let Some(logger) = log_printer {
        tunnel.set_logger(
            Box::new(move |e: &str| logger(CString::new(e).unwrap().as_ptr())),
            Verbosity::from(log_level),
        );
    }

    Box::into_raw(tunnel)
}

/// Drops the Tunn object
#[no_mangle]
pub unsafe extern "C" fn tunnel_free(tunnel: *mut Tunn) {
    Box::from_raw(tunnel);
}

/// Write an IP packet from the tunnel interface.
/// For more details check noise::tunnel_to_network functions.
#[no_mangle]
pub unsafe extern "C" fn wireguard_write(
    tunnel: *mut Tunn,
    src: *const u8,
    src_size: u32,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    let tunnel = tunnel.as_ref().unwrap();
    // Slices are not owned, and therefore will not be freed by Rust
    let src = slice::from_raw_parts(src, src_size as usize);
    let dst = slice::from_raw_parts_mut(dst, dst_size as usize);
    wireguard_result::from(tunnel.tunnel_to_network(src, dst))
}

/// Read a UDP packet from the server.
/// For more details check noise::network_to_tunnel functions.
#[no_mangle]
pub unsafe extern "C" fn wireguard_read(
    tunnel: *mut Tunn,
    src: *const u8,
    src_size: u32,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    let tunnel = tunnel.as_ref().unwrap();
    // Slices are not owned, and therefore will not be freed by Rust
    let src = slice::from_raw_parts(src, src_size as usize);
    let dst = slice::from_raw_parts_mut(dst, dst_size as usize);
    wireguard_result::from(tunnel.network_to_tunnel(src, dst))
}

/// This is a state keeping function, that need to be called preriodically.
/// Recommended interavl: 100ms.
#[no_mangle]
pub unsafe extern "C" fn wireguard_tick(
    tunnel: *mut Tunn,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    let tunnel = tunnel.as_ref().unwrap();
    // Slices are not owned, and therefore will not be freed by Rust
    let dst = slice::from_raw_parts_mut(dst, dst_size as usize);
    wireguard_result::from(tunnel.update_timers(dst))
}

/// Performs an iternal benchmark, and returns its result as a C-string.
#[no_mangle]
pub extern "C" fn benchmark(name: i32, idx: u32) -> *const c_char {
    if let Some(s) = do_benchmark(name != 0, idx as usize) {
        let s = CString::new(s).unwrap();
        let v = s.as_ptr();
        mem::forget(s); // This is a memory leak, but we assume it is rearly used anyway
        v
    } else {
        ptr::null()
    }
}
