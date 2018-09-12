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
#[no_mangle]
pub extern "C" fn x25519_key_to_base64(key: x25519_key) -> *const i8 {
    let encoded_key = encode(&key.key);
    let c_string = CString::new(encoded_key).unwrap();
    let ptr = c_string.as_ptr();
    mem::forget(c_string);
    ptr
}

/// Returns the hex encoding of a key as a UTF8 C-string.
#[no_mangle]
pub extern "C" fn x25519_key_to_hex(key: x25519_key) -> *const i8 {
    let encoded_key = encode_hex(&key.key);
    let c_string = CString::new(encoded_key).unwrap();
    let ptr = c_string.as_ptr();
    mem::forget(c_string);
    ptr
}

/// Check if the input C-string represents a valid base64 encoded x25519 key.
/// Return 1 if valid 0 otherwise.
#[no_mangle]
pub extern "C" fn check_base64_encoded_x25519_key(key: *const c_char) -> i32 {
    let c_str = unsafe { CStr::from_ptr(key) };
    let utf8_key = match c_str.to_str() {
        Err(_) => return 0,
        Ok(string) => string,
    };

    let decoded_key = decode(&utf8_key);

    if let Ok(key) = decoded_key {
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
pub extern "C" fn new_tunnel(
    static_private: *const c_char,
    server_static_public: *const c_char,
    log_printer: Option<extern "C" fn(*const c_char)>,
    log_level: u32,
) -> *mut Tunn {
    let c_str = unsafe { CStr::from_ptr(static_private) };
    let static_private = match c_str.to_str() {
        Err(_) => return ptr::null_mut(),
        Ok(string) => string,
    };

    let c_str = unsafe { CStr::from_ptr(server_static_public) };
    let server_static_public = match c_str.to_str() {
        Err(_) => return ptr::null_mut(),
        Ok(string) => string,
    };

    let mut tunnel = match Tunn::new(static_private, server_static_public) {
        Ok(t) => t,
        Err(_) => return ptr::null_mut(),
    };

    if log_level > 0 {
        tunnel.set_log(log_printer, log_level);
    }

    return Box::into_raw(tunnel);
}

/// Write an IP packet from the tunnel interface.
/// For more details check noise::tunnel_to_network functions.
#[no_mangle]
pub extern "C" fn wireguard_write(
    tunnel: *mut Tunn,
    src: *const u8,
    src_size: u32,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    let tunnel = unsafe { Box::from_raw(tunnel) };
    // Slices are not owned, and therefore will not be freed by Rust
    let src = unsafe { slice::from_raw_parts(src, src_size as usize) };
    let dst = unsafe { slice::from_raw_parts_mut(dst, dst_size as usize) };
    let res = tunnel.tunnel_to_network(src, dst);
    mem::forget(tunnel); // Don't let Rust free the tunnel
    res
}

/// Read a UDP packet from the server.
/// For more details check noise::network_to_tunnel functions.
#[no_mangle]
pub extern "C" fn wireguard_read(
    tunnel: *mut Tunn,
    src: *const u8,
    src_size: u32,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    let tunnel = unsafe { Box::from_raw(tunnel) };
    // Slices are not owned, and therefore will not be freed by Rust
    let src = unsafe { slice::from_raw_parts(src, src_size as usize) };
    let dst = unsafe { slice::from_raw_parts_mut(dst, dst_size as usize) };
    let res = tunnel.network_to_tunnel(src, dst);
    mem::forget(tunnel); // Don't let Rust free the tunnel
    res
}

/// This is a state keeping function, that need to be called preriodically.
/// Recommended interavl: 100ms.
#[no_mangle]
pub extern "C" fn wireguard_tick(
    tunnel: *mut Tunn,
    dst: *mut u8,
    dst_size: u32,
) -> wireguard_result {
    let tunnel = unsafe { Box::from_raw(tunnel) };
    // Slices are not owned, and therefore will not be freed by Rust
    let dst = unsafe { slice::from_raw_parts_mut(dst, dst_size as usize) };
    let res = tunnel.update_timers(dst);
    mem::forget(tunnel); // Don't let Rust free the tunnel
    res
}

/// Performs an iternal benchmark, and returns its result as a C-string.
#[no_mangle]
pub extern "C" fn benchmark(name: i32, idx: u32) -> *const i8 {
    if let Some(s) = do_benchmark(name != 0, idx as usize) {
        let s = CString::new(s).unwrap();
        let v = s.as_ptr();
        mem::forget(s); // This is a memory leak, but we assume it is rearly used anyway
        v
    } else {
        ptr::null()
    }
}
