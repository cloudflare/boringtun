// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! Elliptic-curve Diffie-Hellman exchange over Curve25519.

mod tests;

use crate::noise::errors::WireGuardError;
use crate::noise::make_array;
use base64::decode;
use std::ops::Add;
use std::ops::Mul;
use std::ops::Sub;
use std::str::FromStr;

#[cfg(not(target_arch = "arm"))]
use ring::rand::*;

const MASK_63BITS: u128 = 0x7fff_ffff_ffff_ffff;
const MASK_64BITS: u128 = 0xffff_ffff_ffff_ffff;

#[cfg(target_arch = "arm")]
#[allow(non_snake_case)]
pub mod SystemRandom {
    use std::io::Read;
    use std::sync::Once;
    static INIT: Once = Once::new();

    static mut URAND: Option<std::fs::File> = None;

    // Workaround for ring not building nicely for arm7
    pub struct Urandom {}

    pub fn new() -> Urandom {
        INIT.call_once(|| unsafe {
            URAND = Some(std::fs::File::open("/dev/urandom").unwrap());
        });

        Urandom {}
    }

    impl Urandom {
        pub fn fill(&self, dest: &mut [u8]) -> Result<(), ()> {
            let mut local_urand = unsafe { URAND.as_ref().unwrap().try_clone().map_err(|_| ())? };
            local_urand.read_exact(dest).map(|_| ()).map_err(|_| (()))
        }
    }
}

#[repr(C)]
#[derive(Debug)]
/// A secret X25519 key.
pub struct X25519SecretKey {
    internal: [u8; 32],
}

#[allow(clippy::new_without_default)]
impl X25519SecretKey {
    /// Generate a new secret key using the OS rng.
    pub fn new() -> Self {
        let rng = SystemRandom::new();
        let mut private_key = [0u8; 32];
        rng.fill(&mut private_key[..]).unwrap();
        X25519SecretKey {
            internal: private_key,
        }
    }

    /// Compute the public key for this secret key.
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey {
            internal: x25519_public_key(&self.internal[..]),
        }
    }

    /// Derive a shared key from the secret key of this peer and the public key of a remote peer.
    pub fn shared_key(&self, peer_public: &X25519PublicKey) -> Result<[u8; 32], WireGuardError> {
        let shared_key = x25519_shared_key(&peer_public.internal[..], &self.internal[..]);

        constant_time_key_compare(&self.internal[..], &peer_public.internal[..], false)?;
        constant_time_zero_key_check(&shared_key[..])?;

        Ok(shared_key)
    }

    /// Return the private key represented as a byte array.
    pub fn as_bytes(&self) -> &[u8] {
        &self.internal[..]
    }
}

impl FromStr for X25519SecretKey {
    type Err = &'static str;

    /// Can parse a secret key from a hex or base64 encoded string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut key = X25519SecretKey {
            internal: [0u8; 32],
        };

        match s.len() {
            64 => {
                // Try to parse as hex
                for i in 0..32 {
                    key.internal[i] = u8::from_str_radix(&s[i * 2..=i * 2 + 1], 16)
                        .map_err(|_| "Illegal character in key")?;
                }
            }
            43 | 44 => {
                // Try to parse as base64
                if let Ok(decoded_key) = decode(s) {
                    if decoded_key.len() == key.internal.len() {
                        key.internal[..].copy_from_slice(&decoded_key);
                    } else {
                        return Err("Illegal character in key");
                    }
                }
            }
            _ => return Err("Illegal key size"),
        }

        Ok(key)
    }
}

impl Drop for X25519SecretKey {
    fn drop(&mut self) {
        // Force zero out of the memory on Drop
        unsafe { std::ptr::write_volatile(&mut self.internal, [0u8; 32]) }
    }
}

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Hash)]
/// A public X25519, derived from a secret key.
pub struct X25519PublicKey {
    internal: [u8; 32],
}

impl X25519PublicKey {
    // Check if this public key is equal to `other` in constant-time.
    pub fn constant_time_is_equal(&self, other: &X25519PublicKey) -> Result<(), WireGuardError> {
        constant_time_key_compare(&self.internal[..], &other.internal[..], true)
    }

    // Return the public key represented as a byte array.
    pub fn as_bytes(&self) -> &[u8] {
        &self.internal[..]
    }
}

/// Will panic if the slice.len() != 32.
impl<'a> From<&'a [u8]> for X25519PublicKey {
    fn from(slice: &[u8]) -> Self {
        let mut internal = [0u8; 32];
        internal[..].copy_from_slice(slice);
        X25519PublicKey { internal }
    }
}

impl Drop for X25519PublicKey {
    fn drop(&mut self) {
        // Force zero out of the memory on Drop
        unsafe { std::ptr::write_volatile(&mut self.internal, [0u8; 32]) }
    }
}

impl FromStr for X25519PublicKey {
    type Err = &'static str;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(X25519PublicKey {
            internal: X25519SecretKey::from_str(s)?.internal,
        })
    }
}

#[derive(Clone, Copy)]
// Internal structs for fast arithmetic
struct Felem([u64; 4]);
struct Felem2([u64; 8]);

#[cfg_attr(feature = "cargo-clippy", allow(clippy::suspicious_arithmetic_impl))]
impl Add for Felem {
    type Output = Felem;
    #[inline(always)]
    // Addition modulo 2^255 - 19
    fn add(self, other: Felem) -> Felem {
        let x0 = u128::from(self.0[0]);
        let x1 = u128::from(self.0[1]);
        let x2 = u128::from(self.0[2]);
        let x3 = u128::from(self.0[3]);

        let y0 = u128::from(other.0[0]);
        let y1 = u128::from(other.0[1]);
        let y2 = u128::from(other.0[2]);
        let y3 = u128::from(other.0[3]);

        let mut acc0 = x0.wrapping_add(y0);
        let mut acc1 = x1.wrapping_add(y1).wrapping_add(acc0 >> 64);
        let mut acc2 = x2.wrapping_add(y2).wrapping_add(acc1 >> 64);
        let mut acc3 = x3.wrapping_add(y3).wrapping_add(acc2 >> 64);

        let mut top = (acc3 >> 63) & 0xffff_ffff_ffff_ffff;
        acc0 &= 0xffff_ffff_ffff_ffff;
        acc1 &= 0xffff_ffff_ffff_ffff;
        acc2 &= 0xffff_ffff_ffff_ffff;
        acc3 &= 0x7fff_ffff_ffff_ffff;

        top = top.wrapping_mul(19);
        acc0 = acc0.wrapping_add(top);
        acc1 = acc1.wrapping_add(acc0 >> 64);
        acc2 = acc2.wrapping_add(acc1 >> 64);
        acc3 = acc3.wrapping_add(acc2 >> 64);

        Felem([acc0 as u64, acc1 as u64, acc2 as u64, acc3 as u64])
    }
}

#[cfg_attr(feature = "cargo-clippy", allow(clippy::suspicious_arithmetic_impl))]
impl Sub for Felem {
    type Output = Felem;
    #[inline(always)]
    // Subtraction modulo 2^255 - 19
    fn sub(self, other: Felem) -> Felem {
        static POLY_X4: [u128; 4] = [
            0x1_ffff_ffff_ffff_ffb4,
            0x1_ffff_ffff_ffff_fffe,
            0x1_ffff_ffff_ffff_fffe,
            0x1_ffff_ffff_ffff_fffe,
        ];

        let x0 = u128::from(self.0[0]);
        let x1 = u128::from(self.0[1]);
        let x2 = u128::from(self.0[2]);
        let x3 = u128::from(self.0[3]);

        let y0 = u128::from(other.0[0]);
        let y1 = u128::from(other.0[1]);
        let y2 = u128::from(other.0[2]);
        let y3 = u128::from(other.0[3]);

        let mut acc0 = POLY_X4[0].wrapping_sub(y0).wrapping_add(x0);
        let mut acc1 = POLY_X4[1]
            .wrapping_sub(y1)
            .wrapping_add(x1)
            .wrapping_add(acc0 >> 64);
        let mut acc2 = POLY_X4[2]
            .wrapping_sub(y2)
            .wrapping_add(x2)
            .wrapping_add(acc1 >> 64);
        let mut acc3 = POLY_X4[3]
            .wrapping_sub(y3)
            .wrapping_add(x3)
            .wrapping_add(acc2 >> 64);

        let mut top = (acc3 >> 63) & 0xffff_ffff_ffff_ffff;
        acc0 &= 0xffff_ffff_ffff_ffff;
        acc1 &= 0xffff_ffff_ffff_ffff;
        acc2 &= 0xffff_ffff_ffff_ffff;
        acc3 &= 0x7fff_ffff_ffff_ffff;

        top = top.wrapping_mul(19);
        acc0 = acc0.wrapping_add(top);
        acc1 = acc1.wrapping_add(acc0 >> 64);
        acc2 = acc2.wrapping_add(acc1 >> 64);
        acc3 = acc3.wrapping_add(acc2 >> 64);

        Felem([acc0 as u64, acc1 as u64, acc2 as u64, acc3 as u64])
    }
}

#[cfg_attr(feature = "cargo-clippy", allow(clippy::suspicious_arithmetic_impl))]
impl Mul for Felem {
    type Output = Felem;
    #[inline(always)]
    // Multiplication modulo 2^255 - 19
    fn mul(self, other: Felem) -> Felem {
        let x0 = u128::from(self.0[0]);
        let x1 = u128::from(self.0[1]);
        let x2 = u128::from(self.0[2]);
        let x3 = u128::from(self.0[3]);

        // y0
        let y0 = u128::from(other.0[0]);
        let mut t = x0.wrapping_mul(y0);
        let acc0 = t & 0xffff_ffff_ffff_ffff;
        let mut acc1 = t >> 64;

        t = x1.wrapping_mul(y0);
        acc1 = acc1.wrapping_add(t);
        let mut acc2 = acc1 >> 64;
        acc1 &= 0xffff_ffff_ffff_ffff;

        t = x2.wrapping_mul(y0);
        acc2 = acc2.wrapping_add(t);
        let mut acc3 = acc2 >> 64;
        acc2 &= 0xffff_ffff_ffff_ffff;

        t = x3.wrapping_mul(y0);
        acc3 = acc3.wrapping_add(t);
        let mut acc4 = acc3 >> 64;
        acc3 &= 0xffff_ffff_ffff_ffff;

        // y1
        let y1 = u128::from(other.0[1]);
        t = x0.wrapping_mul(y1);
        acc1 = acc1.wrapping_add(t);
        let mut top = acc1 >> 64;
        acc1 &= 0xffff_ffff_ffff_ffff;

        t = x1.wrapping_mul(y1);
        acc2 = acc2.wrapping_add(top);
        acc2 = acc2.wrapping_add(t);
        top = acc2 >> 64;
        acc2 &= 0xffff_ffff_ffff_ffff;

        t = x2.wrapping_mul(y1);
        acc3 = acc3.wrapping_add(top);
        acc3 = acc3.wrapping_add(t);
        top = acc3 >> 64;
        acc3 &= 0xffff_ffff_ffff_ffff;

        t = x3.wrapping_mul(y1);
        acc4 = acc4.wrapping_add(top);
        acc4 = acc4.wrapping_add(t);
        let mut acc5 = acc4 >> 64;
        acc4 &= 0xffff_ffff_ffff_ffff;

        // y2
        let y2 = u128::from(other.0[2]);
        t = x0.wrapping_mul(y2);
        acc2 = acc2.wrapping_add(t);
        top = acc2 >> 64;
        acc2 &= 0xffff_ffff_ffff_ffff;

        t = x1.wrapping_mul(y2);
        acc3 = acc3.wrapping_add(top);
        acc3 = acc3.wrapping_add(t);
        top = acc3 >> 64;
        acc3 &= 0xffff_ffff_ffff_ffff;

        t = x2.wrapping_mul(y2);
        acc4 = acc4.wrapping_add(top);
        acc4 = acc4.wrapping_add(t);
        top = acc4 >> 64;
        acc4 &= 0xffff_ffff_ffff_ffff;

        t = x3.wrapping_mul(y2);
        acc5 = acc5.wrapping_add(top);
        acc5 = acc5.wrapping_add(t);
        let mut acc6 = acc5 >> 64;
        acc5 &= 0xffff_ffff_ffff_ffff;

        // y3
        let y3 = u128::from(other.0[3]);
        t = x0.wrapping_mul(y3);
        acc3 = acc3.wrapping_add(t);
        top = acc3 >> 64;
        acc3 &= 0xffff_ffff_ffff_ffff;

        t = x1.wrapping_mul(y3);
        acc4 = acc4.wrapping_add(top);
        acc4 = acc4.wrapping_add(t);
        top = acc4 >> 64;
        acc4 &= 0xffff_ffff_ffff_ffff;

        t = x2.wrapping_mul(y3);
        acc5 = acc5.wrapping_add(top);
        acc5 = acc5.wrapping_add(t);
        top = acc5 >> 64;
        acc5 &= 0xffff_ffff_ffff_ffff;

        t = x3.wrapping_mul(y3);
        acc6 = acc6.wrapping_add(top);
        acc6 = acc6.wrapping_add(t);
        let acc7 = acc6 >> 64;
        acc6 &= 0xffff_ffff_ffff_ffff;

        // Modulo
        mod_25519(Felem2([
            acc0 as u64,
            acc1 as u64,
            acc2 as u64,
            acc3 as u64,
            acc4 as u64,
            acc5 as u64,
            acc6 as u64,
            acc7 as u64,
        ]))
    }
}

impl Felem {
    #[inline(always)]
    // Repeatedly square modulo 2^255 - 19
    fn sqr(self, mut rep: u32) -> Felem {
        let mut ret = self;
        while rep > 0 {
            ret = mod_25519(sqr_256(ret));
            rep -= 1;
        }
        ret
    }
}

#[inline(always)]
// Square modulo 2^255 - 19
fn sqr_256(x: Felem) -> Felem2 {
    let x0 = u128::from(x.0[0]);
    let x1 = u128::from(x.0[1]);
    let x2 = u128::from(x.0[2]);
    let x3 = u128::from(x.0[3]);

    // y0
    let mut acc1 = x1.wrapping_mul(x0);
    let mut acc2 = x2.wrapping_mul(x0);
    let mut acc3 = x3.wrapping_mul(x0);

    acc2 = acc2.wrapping_add(acc1 >> 64);
    acc3 = acc3.wrapping_add(acc2 >> 64);
    let mut acc4 = acc3 >> 64;

    acc1 &= 0xffff_ffff_ffff_ffff;
    acc2 &= 0xffff_ffff_ffff_ffff;
    acc3 &= 0xffff_ffff_ffff_ffff;

    // y1
    let mut t = x2.wrapping_mul(x1);
    acc3 = acc3.wrapping_add(t);

    t = x3.wrapping_mul(x1);
    acc4 = acc4.wrapping_add(acc3 >> 64).wrapping_add(t);

    let mut acc5 = acc4 >> 64;

    acc3 &= 0xffff_ffff_ffff_ffff;
    acc4 &= 0xffff_ffff_ffff_ffff;

    // y2
    t = x3.wrapping_mul(x2);
    acc5 = acc5.wrapping_add(t);

    let mut acc6 = acc5 >> 64;
    acc5 &= 0xffff_ffff_ffff_ffff;

    acc6 = acc6 << 1 | acc5 >> 63;
    acc5 = acc5 << 1 | acc4 >> 63;
    acc4 = acc4 << 1 | acc3 >> 63;
    acc3 = acc3 << 1 | acc2 >> 63;
    acc2 = acc2 << 1 | acc1 >> 63;
    acc1 <<= 1;

    let mut acc7 = acc6 >> 64;
    acc1 &= 0xffff_ffff_ffff_ffff;
    acc2 &= 0xffff_ffff_ffff_ffff;
    acc3 &= 0xffff_ffff_ffff_ffff;
    acc4 &= 0xffff_ffff_ffff_ffff;
    acc5 &= 0xffff_ffff_ffff_ffff;
    acc6 &= 0xffff_ffff_ffff_ffff;

    let acc0 = x0.wrapping_mul(x0);
    acc1 = acc1.wrapping_add(acc0 >> 64);

    t = x1.wrapping_mul(x1);
    acc2 = acc2.wrapping_add(acc1 >> 64).wrapping_add(t);
    acc3 = acc3.wrapping_add(acc2 >> 64);

    t = x2.wrapping_mul(x2);
    acc4 = acc4.wrapping_add(acc3 >> 64).wrapping_add(t);
    acc5 = acc5.wrapping_add(acc4 >> 64);

    t = x3.wrapping_mul(x3);
    acc6 = acc6.wrapping_add(acc5 >> 64).wrapping_add(t);
    acc7 = acc7.wrapping_add(acc6 >> 64);

    Felem2([
        acc0 as u64,
        acc1 as u64,
        acc2 as u64,
        acc3 as u64,
        acc4 as u64,
        acc5 as u64,
        acc6 as u64,
        acc7 as u64,
    ])

    // Modulo
}

#[inline(always)]
fn mod_25519(x: Felem2) -> Felem {
    let c38 = 38_u128;

    let mut acc0 = u128::from(x.0[0]);
    let mut acc1 = u128::from(x.0[1]);
    let mut acc2 = u128::from(x.0[2]);
    let mut acc3 = u128::from(x.0[3]);
    let mut acc4 = u128::from(x.0[4]);
    let mut acc5 = u128::from(x.0[5]);
    let mut acc6 = u128::from(x.0[6]);
    let mut acc7 = u128::from(x.0[7]);

    acc4 = acc4.wrapping_mul(c38);
    acc5 = acc5.wrapping_mul(c38);
    acc6 = acc6.wrapping_mul(c38);
    acc7 = acc7.wrapping_mul(c38);

    acc0 = acc0.wrapping_add(acc4);

    acc1 = acc1.wrapping_add(acc0 >> 64);
    acc1 = acc1.wrapping_add(acc5);

    acc2 = acc2.wrapping_add(acc1 >> 64);
    acc2 = acc2.wrapping_add(acc6);

    acc3 = acc3.wrapping_add(acc2 >> 64);
    acc3 = acc3.wrapping_add(acc7);

    let mut top = (acc3 >> 63) & 0xffff_ffff_ffff_ffff;

    acc0 &= 0xffff_ffff_ffff_ffff;
    acc1 &= 0xffff_ffff_ffff_ffff;
    acc2 &= 0xffff_ffff_ffff_ffff;
    acc3 &= 0x7fff_ffff_ffff_ffff;

    top = top.wrapping_mul(19);

    acc0 = acc0.wrapping_add(top);
    acc1 = acc1.wrapping_add(acc0 >> 64);
    acc2 = acc2.wrapping_add(acc1 >> 64);
    acc3 = acc3.wrapping_add(acc2 >> 64);

    Felem([acc0 as u64, acc1 as u64, acc2 as u64, acc3 as u64])
}

fn mod_final_25519(x: Felem) -> Felem {
    let mut acc0 = u128::from(x.0[0]);
    let mut acc1 = u128::from(x.0[1]);
    let mut acc2 = u128::from(x.0[2]);
    let mut acc3 = u128::from(x.0[3]);

    let mut top = acc3 >> 63;
    acc3 &= MASK_63BITS;
    top = top.wrapping_mul(19);
    acc0 = acc0.wrapping_add(top);
    acc1 = acc1.wrapping_add(acc0 >> 64);
    acc2 = acc2.wrapping_add(acc1 >> 64);
    acc3 = acc3.wrapping_add(acc2 >> 64);

    // Mask
    acc0 &= MASK_64BITS;
    acc1 &= MASK_64BITS;
    acc2 &= MASK_64BITS;
    acc3 &= MASK_64BITS;

    // At this point, acc{0-3} is in the range between 0 and 2^255 + 18, inclusively. It's not
    // under 2^255 - 19 yet. So we are doing another round of modulo operation.

    top = acc0.wrapping_add(19) >> 64;
    top = acc1.wrapping_add(top) >> 64;
    top = acc2.wrapping_add(top) >> 64;
    top = acc3.wrapping_add(top) >> 63;
    top = top.wrapping_mul(19);

    // top is 19 if acc{0-3} is between 2^255 - 19 and 2^255 + 18, inclusively. Otherwise, it's
    // zero.

    acc0 = acc0.wrapping_add(top);
    acc1 = acc1.wrapping_add(acc0 >> 64);
    acc2 = acc2.wrapping_add(acc1 >> 64);
    acc3 = acc3.wrapping_add(acc2 >> 64);
    acc3 &= MASK_63BITS;

    // Now acc{0-3} is between 0 and 2^255 - 20, inclusively.

    Felem([acc0 as u64, acc1 as u64, acc2 as u64, acc3 as u64])
}

// Modular inverse
fn mod_inv_25519(x: Felem) -> Felem {
    let m1 = x;
    let m10 = x.sqr(1);
    let m1001 = m10.sqr(2) * m1;
    let m1011 = m1001 * m10;

    let x5 = m1011.sqr(1) * m1001;
    let x10 = x5.sqr(5) * x5;
    let x20 = x10.sqr(10) * x10;
    let x40 = x20.sqr(20) * x20;
    let x50 = x40.sqr(10) * x10;
    let x100 = x50.sqr(50) * x50;

    let t = x100.sqr(100) * x100;
    let t2 = t.sqr(50) * x50;
    t2.sqr(5) * m1011
}

#[inline(always)]
// Swap two values a and b in constant time iff swap == 1
fn constant_time_swap(a: Felem, b: Felem, swap: u64) -> (Felem, Felem) {
    let mask = 0_u64.wrapping_sub(swap);

    let mut v = [0_u64; 4];
    let mut a_out = [0_u64; 4];
    let mut b_out = [0_u64; 4];

    v[0] = mask & (a.0[0] ^ b.0[0]);
    v[1] = mask & (a.0[1] ^ b.0[1]);
    v[2] = mask & (a.0[2] ^ b.0[2]);
    v[3] = mask & (a.0[3] ^ b.0[3]);

    a_out[0] = v[0] ^ a.0[0];
    a_out[1] = v[1] ^ a.0[1];
    a_out[2] = v[2] ^ a.0[2];
    a_out[3] = v[3] ^ a.0[3];

    b_out[0] = v[0] ^ b.0[0];
    b_out[1] = v[1] ^ b.0[1];
    b_out[2] = v[2] ^ b.0[2];
    b_out[3] = v[3] ^ b.0[3];

    (Felem(a_out), Felem(b_out))
}

fn x25519_public_key(secret_key: &[u8]) -> [u8; 32] {
    let u = [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    x25519_shared_key(&u, secret_key)
}

fn x25519_shared_key(peer_key: &[u8], secret_key: &[u8]) -> [u8; 32] {
    if peer_key.len() != 32 || secret_key.len() != 32 {
        panic!("Illegal values for x25519");
    }

    let mut scalar = [0_u8; 32];
    let mut shared_key = [0_u8; 32];
    scalar[..].copy_from_slice(secret_key);

    assert!(peer_key.len() == 32);
    let u = Felem([
        u64::from_le_bytes(make_array(&peer_key[0..])),
        u64::from_le_bytes(make_array(&peer_key[8..])),
        u64::from_le_bytes(make_array(&peer_key[16..])),
        u64::from_le_bytes(make_array(&peer_key[24..])),
    ]);

    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    let x_1 = u;
    let mut x_2 = Felem([1, 0, 0, 0]);
    let mut z_2 = Felem([0, 0, 0, 0]);
    let mut x_3 = u;
    let mut z_3 = Felem([1, 0, 0, 0]);
    let a24 = Felem([121_666, 0, 0, 0]);
    let mut swap = 0;

    for pos in (0..=254).rev() {
        let bit_val = u64::from((scalar[pos / 8] >> (pos & 7)) & 1);

        swap ^= bit_val;
        let (mut x2, mut x3) = constant_time_swap(x_2, x_3, swap);
        let (mut z2, mut z3) = constant_time_swap(z_2, z_3, swap);
        swap = bit_val;

        let mut tmp0 = x3 - z3;
        let mut tmp1 = x2 - z2;
        x2 = x2 + z2;
        z2 = x3 + z3;

        z3 = x2 * tmp0;
        z2 = z2 * tmp1;

        tmp0 = tmp1.sqr(1);
        tmp1 = x2.sqr(1);
        x3 = z3 + z2;
        z2 = z3 - z2;

        x_2 = tmp1 * tmp0;
        tmp1 = tmp1 - tmp0;
        z2 = z2.sqr(1);

        z3 = a24 * tmp1;
        x_3 = x3.sqr(1);
        tmp0 = tmp0 + z3;

        z_3 = x_1 * z2;
        z_2 = tmp1 * tmp0;
    }

    let (x2, _) = constant_time_swap(x_2, x_3, swap);
    let (z2, _) = constant_time_swap(z_2, z_3, swap);

    let key = mod_final_25519(x2 * mod_inv_25519(z2));

    shared_key[0..8].copy_from_slice(&key.0[0].to_le_bytes());
    shared_key[8..16].copy_from_slice(&key.0[1].to_le_bytes());
    shared_key[16..24].copy_from_slice(&key.0[2].to_le_bytes());
    shared_key[24..32].copy_from_slice(&key.0[3].to_le_bytes());

    shared_key
}

// Compare two 32 byte keys for equality.
//
// eq = true indicates we compare for equality (Err if not equal)
// eq = false indicates we compare for inequality (Err if equal)
fn constant_time_key_compare(key1: &[u8], key2: &[u8], eq: bool) -> Result<(), WireGuardError> {
    if key1.len() != 32 || key2.len() != 32 {
        return Err(WireGuardError::WrongKey);
    }

    let mut r = 0u8;
    for i in 0..32 {
        r |= key1[i] ^ key2[i];
    }

    if (r == 0) ^ eq {
        Err(WireGuardError::WrongKey)
    } else {
        Ok(())
    }
}

// Check if the slice is 32 byte long and is all zeroes.
fn constant_time_zero_key_check(key: &[u8]) -> Result<(), WireGuardError> {
    if key.len() != 32 {
        return Err(WireGuardError::WrongKey);
    }

    let mut r = 0u8;

    for b in key {
        r |= b;
    }

    if r == 0 {
        Err(WireGuardError::WrongKey)
    } else {
        Ok(())
    }
}
