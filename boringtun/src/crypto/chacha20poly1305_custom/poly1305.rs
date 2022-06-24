// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use std::ops::Add;
use std::ops::Mul;
use std::ops::Rem;

#[derive(Debug)]
pub struct Poly1305 {
    r_key: Poly1305R,
    s_key: Poly1305S,
    acc: Felem1305,
}

#[derive(Debug)]
struct Felem1305([u64; 3]);
#[derive(Debug)]
struct Poly1305R([u64; 2]);
#[derive(Debug)]
struct Poly1305S([u64; 2]);
struct Felem1305NonRed([u64; 4]);
struct Poly1305Poly;

impl Poly1305 {
    #[inline(always)]
    pub fn new(key_stream: &[u32]) -> Poly1305 {
        Poly1305 {
            r_key: Poly1305R([
                (u64::from(key_stream[0]) | (u64::from(key_stream[1]) << 32))
                    & 0x0FFF_FFFC_0FFF_FFFF,
                (u64::from(key_stream[2]) | (u64::from(key_stream[3]) << 32))
                    & 0x0FFF_FFFC_0FFF_FFFC,
            ]),
            s_key: Poly1305S([
                u64::from(key_stream[4]) | (u64::from(key_stream[5]) << 32),
                u64::from(key_stream[6]) | (u64::from(key_stream[7]) << 32),
            ]),
            acc: Felem1305([0u64; 3]),
        }
    }

    #[inline(always)]
    fn poly_step(&mut self, x: Felem1305) {
        self.acc = ((x + &self.acc) * &self.r_key) % Poly1305Poly;
    }

    #[inline(always)]
    pub fn hash_u8(&mut self, buf: &[u8]) {
        assert!(buf.len() >= 16);
        let x0 = u64::from_le_bytes([
            buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
        ]);

        let x1 = u64::from_le_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);

        let x_elem = Felem1305([x0, x1, 1]);
        self.poly_step(x_elem);
    }

    #[inline(always)]
    pub fn hash_u32(&mut self, buf: &[u32]) {
        assert!(buf.len() >= 4);
        let x0 = u64::from(buf[0]) | (u64::from(buf[1]) << 32);
        let x1 = u64::from(buf[2]) | (u64::from(buf[3]) << 32);
        let x_elem = Felem1305([x0, x1, 1]);
        self.poly_step(x_elem);
    }

    #[inline(always)]
    pub fn hash_u64(&mut self, buf: &[u64]) {
        assert!(buf.len() >= 2);
        let x_elem = Felem1305([buf[0], buf[1], 1]);
        self.poly_step(x_elem);
    }

    #[inline(always)]
    pub fn finalize(self) -> [u8; 16] {
        let mut ret = [0u8; 16];
        let acc = self.acc % Poly1305Poly; // Final reduction

        let mut acc0 = u128::from(acc.0[0]);
        let mut acc1 = u128::from(acc.0[1]);

        let s0 = u128::from(self.s_key.0[0]);
        let s1 = u128::from(self.s_key.0[1]);

        acc0 = acc0.wrapping_add(s0);
        acc1 = acc1.wrapping_add(acc0 >> 64).wrapping_add(s1);

        ret[0..8].copy_from_slice(&(acc0 as u64).to_le_bytes()[..]);
        ret[8..16].copy_from_slice(&(acc1 as u64).to_le_bytes()[..]);

        ret
    }
}

#[cfg_attr(feature = "cargo-clippy", allow(clippy::suspicious_arithmetic_impl))]
impl<'a> Add<&'a Felem1305> for Felem1305 {
    type Output = Felem1305;
    #[inline(always)]
    fn add(self, other: &'a Felem1305) -> Felem1305 {
        let acc0 = u128::from(self.0[0]);
        let acc1 = u128::from(self.0[1]);
        let acc2 = u128::from(self.0[2]);

        let x0 = u128::from(other.0[0]);
        let x1 = u128::from(other.0[1]);
        let x2 = u128::from(other.0[2]);

        let acc0 = acc0.wrapping_add(x0);
        let acc1 = acc1.wrapping_add(x1).wrapping_add(acc0 >> 64);
        let acc2 = acc2.wrapping_add(x2).wrapping_add(acc1 >> 64);

        Felem1305([acc0 as u64, acc1 as u64, acc2 as u64])
    }
}

#[cfg_attr(feature = "cargo-clippy", allow(clippy::suspicious_arithmetic_impl))]
impl<'a> Mul<&'a Poly1305R> for Felem1305 {
    type Output = Felem1305NonRed;
    #[inline(always)]
    fn mul(self, other: &'a Poly1305R) -> Felem1305NonRed {
        let acc0 = u128::from(self.0[0]);
        let acc1 = u128::from(self.0[1]);
        let acc2 = u128::from(self.0[2]);

        let k0 = u128::from(other.0[0]);
        let k1 = u128::from(other.0[1]);

        let mut t0 = acc0.wrapping_mul(k0);
        let t1 = acc1.wrapping_mul(k0);
        let mut t1 = t1.wrapping_add(t0 >> 64);
        let mut t2 = acc2.wrapping_mul(k0);

        t2 = t2.wrapping_add(t1 >> 64);
        t0 &= 0xffff_ffff_ffff_ffff;
        t1 &= 0xffff_ffff_ffff_ffff;
        t2 &= 0xffff_ffff_ffff_ffff;

        let mut t = acc0.wrapping_mul(k1);
        t1 = t1.wrapping_add(t);
        let top = t1 >> 64;
        t1 &= 0xffff_ffff_ffff_ffff;
        t = acc1.wrapping_mul(k1);
        t2 = t2.wrapping_add(top).wrapping_add(t);
        let mut t3 = t2 >> 64;
        t2 &= 0xffff_ffff_ffff_ffff;
        t = acc2.wrapping_mul(k1);
        t3 = t3.wrapping_add(t);

        Felem1305NonRed([t0 as u64, t1 as u64, t2 as u64, t3 as u64])
    }
}

impl Rem<Poly1305Poly> for Felem1305NonRed {
    type Output = Felem1305;
    #[inline(always)]
    fn rem(self, _: Poly1305Poly) -> Felem1305 {
        let mut acc0 = u128::from(self.0[0]);
        let mut acc1 = u128::from(self.0[1]);
        let mut acc2 = u128::from(self.0[2]);

        let t0 = acc2 & 0xffff_ffff_ffff_fffc;
        let t1 = u128::from(self.0[3]);
        let t2 = u128::from((self.0[2] >> 2) | (self.0[3] << 62));
        let t3 = t1 >> 2;

        acc2 &= 0x3;

        acc0 = acc0.wrapping_add(t0);
        acc1 = acc1.wrapping_add(t1).wrapping_add(acc0 >> 64);
        acc2 = acc2.wrapping_add(acc1 >> 64);

        acc0 &= 0xffff_ffff_ffff_ffff;
        acc1 &= 0xffff_ffff_ffff_ffff;
        acc2 &= 0xffff_ffff_ffff_ffff;

        acc0 = acc0.wrapping_add(t2);
        acc1 = acc1.wrapping_add(t3).wrapping_add(acc0 >> 64);
        acc2 = acc2.wrapping_add(acc1 >> 64);

        Felem1305([acc0 as u64, acc1 as u64, acc2 as u64])
    }
}

impl Rem<Poly1305Poly> for Felem1305 {
    type Output = Felem1305;
    #[inline(always)]
    fn rem(self, _: Poly1305Poly) -> Felem1305 {
        Felem1305NonRed([self.0[0], self.0[1], self.0[2], 0]).rem(Poly1305Poly)
    }
}
