/// Simple implementation of the client side of the WireGuard protocol
extern crate base64;
extern crate hex;
extern crate libc;
extern crate rand;
extern crate ring;
extern crate spin;

pub mod crypto;
pub mod ffi;
pub mod noise;
