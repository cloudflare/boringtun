/// Simple implementation of the client side of the WireGuard protocol
extern crate base64;
extern crate hex;
#[cfg(target_os = "android")]
extern crate jni;
extern crate libc;
extern crate ring;
extern crate spin;

#[cfg(target_os = "android")]
pub mod cfjni;
pub mod crypto;
pub mod ffi;
pub mod noise;
