// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

//! ChaCha20-Poly1305 authenticated encryption.

mod poly1305;
mod tests;

use self::poly1305::Poly1305;
use crate::noise::errors::WireGuardError;
use crate::noise::make_array;
use std::ops::AddAssign;
use std::ops::BitXorAssign;
use std::ops::ShlAssign;

/// An instance of the ChaCha20-Poly1305 AEAD with a fixed key.
pub struct ChaCha20Poly1305 {
    key: [u32; 8],
}

impl ChaCha20Poly1305 {
    /// Returns a new instance of the ChaCha20-Poly1305 AEAD with the key `key`, which must be 256
    /// bits.
    pub fn new_aead(key: &[u8]) -> ChaCha20Poly1305 {
        assert_eq!(key.len(), 32);
        ChaCha20Poly1305 {
            key: [
                u32::from_le_bytes(make_array(&key[0..])),
                u32::from_le_bytes(make_array(&key[4..])),
                u32::from_le_bytes(make_array(&key[8..])),
                u32::from_le_bytes(make_array(&key[12..])),
                u32::from_le_bytes(make_array(&key[16..])),
                u32::from_le_bytes(make_array(&key[20..])),
                u32::from_le_bytes(make_array(&key[24..])),
                u32::from_le_bytes(make_array(&key[28..])),
            ],
        }
    }

    fn seal_slow(&self, mut state: [u32; 16], aad: &[u8], mut pt: &[u8], ct: &mut [u8]) -> usize {
        let blk = chacha20_block(state, false);
        state[12] += 1;

        let mut poly1305 = Poly1305::new(&blk[0..8]);
        let mut hashed = 0;
        let mut enced = 0;

        while aad.len() >= hashed + 16 {
            let cur = &aad[hashed..hashed + 16];
            poly1305.hash_u8(cur);
            hashed += 16;
        }

        if aad.len() > hashed {
            let left = aad.len() - hashed;
            let mut arr = [0_u8; 16];
            arr[..left].copy_from_slice(&aad[hashed..aad.len()]);
            poly1305.hash_u8(&arr[..]);
            hashed = aad.len();
        }

        while pt.len() >= 128 {
            let [cipher_stream0, cipher_stream1] = chacha20_block_x2(state);
            state[12] += 2;

            let mut cur_pt = [0u8; 64];

            cur_pt.copy_from_slice(&pt[0..64]);
            let mut plaintext_stream = transmute_u8_u32(cur_pt);

            for i in 0..16 {
                plaintext_stream[i] ^= cipher_stream0[i];
            }

            poly1305.hash_u32(&plaintext_stream[0..]);
            poly1305.hash_u32(&plaintext_stream[4..]);
            poly1305.hash_u32(&plaintext_stream[8..]);
            poly1305.hash_u32(&plaintext_stream[12..]);

            let cur_ct = transmute_u32_u8(plaintext_stream);
            ct[enced..enced + 64].copy_from_slice(&cur_ct[..]);

            pt = &pt[64..];
            enced += 64;

            cur_pt.copy_from_slice(&pt[0..64]);
            let mut plaintext_stream = transmute_u8_u32(cur_pt);

            for i in 0..16 {
                plaintext_stream[i] ^= cipher_stream1[i];
            }

            poly1305.hash_u32(&plaintext_stream[0..]);
            poly1305.hash_u32(&plaintext_stream[4..]);
            poly1305.hash_u32(&plaintext_stream[8..]);
            poly1305.hash_u32(&plaintext_stream[12..]);

            let cur_ct = transmute_u32_u8(plaintext_stream);
            ct[enced..enced + 64].copy_from_slice(&cur_ct[..]);

            pt = &pt[64..];
            enced += 64;
        }

        while pt.len() >= 64 {
            let cipher_stream = chacha20_block(state, false);
            state[12] += 1;

            let mut cur_pt = [0u8; 64];
            cur_pt.copy_from_slice(&pt[0..64]);
            let mut plaintext_stream = transmute_u8_u32(cur_pt);

            for i in 0..16 {
                plaintext_stream[i] ^= cipher_stream[i];
            }

            poly1305.hash_u32(&plaintext_stream[0..]);
            poly1305.hash_u32(&plaintext_stream[4..]);
            poly1305.hash_u32(&plaintext_stream[8..]);
            poly1305.hash_u32(&plaintext_stream[12..]);

            let cur_ct = transmute_u32_u8(plaintext_stream);
            ct[enced..enced + 64].copy_from_slice(&cur_ct[..]);

            pt = &pt[64..];
            enced += 64;
        }

        if !pt.is_empty() {
            // Encrypt tail
            let remainder = pt.len();
            let cipher_stream = chacha20_block(state, false);

            let mut cur_pt = [0u8; 64];
            cur_pt[..pt.len()].copy_from_slice(pt);
            let mut plaintext_stream = transmute_u8_u32(cur_pt);

            for i in 0..16 {
                plaintext_stream[i] ^= cipher_stream[i];
            }

            plaintext_stream[remainder / 4] &=
                (0xffff_ffff_u64 >> (32 - (8 * (remainder as u32 % 4)))) as u32;

            for p in plaintext_stream.iter_mut().skip(remainder / 4 + 1) {
                *p = 0;
            }

            poly1305.hash_u32(&plaintext_stream[0..]);
            if remainder > 16 {
                poly1305.hash_u32(&plaintext_stream[4..]);
            }
            if remainder > 32 {
                poly1305.hash_u32(&plaintext_stream[8..]);
            }
            if remainder > 48 {
                poly1305.hash_u32(&plaintext_stream[12..]);
            }

            let cur_ct = transmute_u32_u8(plaintext_stream);
            ct[enced..enced + pt.len()].copy_from_slice(&cur_ct[..remainder]);

            enced += remainder;
        }

        poly1305.hash_u64(&[hashed as u64, enced as u64]);
        ct[enced..enced + 16].copy_from_slice(&poly1305.finalize()[..]);
        enced + 16
    }

    fn open_slow<'a>(
        &self,
        mut state: [u32; 16],
        aad: &[u8],
        mut ct: &[u8],
        pt: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        let blk = chacha20_block(state, false);
        state[12] += 1;

        let mut poly1305 = Poly1305::new(&blk[0..8]);
        let mut hashed = 0;
        let mut enced = 0;

        while aad.len() >= hashed + 16 {
            poly1305.hash_u8(&aad[hashed..]);
            hashed += 16;
        }

        if aad.len() > hashed {
            let left = aad.len() - hashed;
            let mut arr = [0_u8; 16];
            arr[..left].copy_from_slice(&aad[hashed..aad.len()]);
            poly1305.hash_u8(&arr[..]);
            hashed = aad.len();
        }

        while ct.len() >= 64 + 16 {
            let cipher_stream = chacha20_block(state, false);
            state[12] += 1;

            let mut cur_ct = [0u8; 64];
            cur_ct.copy_from_slice(&ct[0..64]);
            let mut ciphertext_stream = transmute_u8_u32(cur_ct);

            poly1305.hash_u32(&ciphertext_stream[0..]);
            poly1305.hash_u32(&ciphertext_stream[4..]);
            poly1305.hash_u32(&ciphertext_stream[8..]);
            poly1305.hash_u32(&ciphertext_stream[12..]);

            for i in 0..16 {
                ciphertext_stream[i] ^= cipher_stream[i];
            }

            let cur_pt = transmute_u32_u8(ciphertext_stream);
            pt[enced..enced + 64].copy_from_slice(&cur_pt[..]);

            ct = &ct[64..];
            enced += 64;
        }

        let remainder = ct.len() - 16;
        if remainder > 0 {
            // Decrypt tail
            let cipher_stream = chacha20_block(state, false);

            let mut cur_ct = [0u8; 64];
            cur_ct[..remainder].copy_from_slice(&ct[..remainder]);
            let mut ciphertext_stream = transmute_u8_u32(cur_ct);

            poly1305.hash_u32(&ciphertext_stream[0..]);
            if remainder > 16 {
                poly1305.hash_u32(&ciphertext_stream[4..]);
            }
            if remainder > 32 {
                poly1305.hash_u32(&ciphertext_stream[8..]);
            }
            if remainder > 48 {
                poly1305.hash_u32(&ciphertext_stream[12..]);
            }

            for i in 0..16 {
                ciphertext_stream[i] ^= cipher_stream[i];
            }

            let cur_pt = transmute_u32_u8(ciphertext_stream);
            pt[enced..enced + remainder].copy_from_slice(&cur_pt[..remainder]);

            ct = &ct[remainder..];
            enced += remainder;
        }

        poly1305.hash_u64(&[hashed as u64, enced as u64]);
        let hash = poly1305.finalize();

        let acc0 = u64::from_le_bytes(make_array(&hash[0..]));
        let acc1 = u64::from_le_bytes(make_array(&hash[8..]));

        let ref_acc0 = u64::from_le_bytes(make_array(&ct[0..]));
        let ref_acc1 = u64::from_le_bytes(make_array(&ct[8..]));

        let ok = ((ref_acc0 ^ acc0) | (ref_acc1 ^ acc1)) == 0;
        if ok {
            Ok(&mut pt[..enced])
        } else {
            for p in pt {
                *p = 0;
            }
            Err(WireGuardError::InvalidAeadTag)
        }
    }

    fn aead_init_wg(&self, nonce_ctr: u64) -> [u32; 16] {
        [
            0x6170_7865,
            0x3320_646e,
            0x7962_2d32,
            0x6b20_6574,
            self.key[0],
            self.key[1],
            self.key[2],
            self.key[3],
            self.key[4],
            self.key[5],
            self.key[6],
            self.key[7],
            0,
            0,
            nonce_ctr as u32,
            (nonce_ctr >> 32) as u32,
        ]
    }

    fn aead_init(&self, nonce: &[u8]) -> [u32; 16] {
        assert_eq!(nonce.len(), 12);
        [
            0x6170_7865,
            0x3320_646e,
            0x7962_2d32,
            0x6b20_6574,
            self.key[0],
            self.key[1],
            self.key[2],
            self.key[3],
            self.key[4],
            self.key[5],
            self.key[6],
            self.key[7],
            0,
            u32::from_le_bytes(make_array(&nonce[0..])),
            u32::from_le_bytes(make_array(&nonce[4..])),
            u32::from_le_bytes(make_array(&nonce[8..])),
        ]
    }

    fn xaead_init(&self, nonce: &[u8]) -> [u32; 16] {
        assert_eq!(nonce.len(), 24);
        let state = [
            0x6170_7865,
            0x3320_646e,
            0x7962_2d32,
            0x6b20_6574,
            self.key[0],
            self.key[1],
            self.key[2],
            self.key[3],
            self.key[4],
            self.key[5],
            self.key[6],
            self.key[7],
            u32::from_le_bytes(make_array(&nonce[0..])),
            u32::from_le_bytes(make_array(&nonce[4..])),
            u32::from_le_bytes(make_array(&nonce[8..])),
            u32::from_le_bytes(make_array(&nonce[12..])),
        ];

        let state = chacha20_block(state, true);

        // First 128 and last 128 bit form the key for XChaCha20
        [
            0x6170_7865,
            0x3320_646e,
            0x7962_2d32,
            0x6b20_6574,
            state[0],
            state[1],
            state[2],
            state[3],
            state[12],
            state[13],
            state[14],
            state[15],
            0,
            0,
            u32::from_le_bytes(make_array(&nonce[16..])),
            u32::from_le_bytes(make_array(&nonce[20..])),
        ]
    }

    /// Encrypts and authenticates `plaintext`, authenticates the additional data `aad`, and stores
    /// the result in `ciphertext` returning the number of bytes written.
    ///
    /// It simply unpacks the nonce as a 64-bit little endian counter.
    pub fn seal_wg(
        &self,
        nonce_ctr: u64,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> usize {
        assert!(plaintext.len() <= ciphertext.len() + 16);
        let state = self.aead_init_wg(nonce_ctr);
        self.seal_slow(state, aad, plaintext, ciphertext)
    }

    /// Decrypts and authenticates `ciphertext`, authenticates the additional data `aad`, and
    /// stores the result in `plaintext` returning the plaintext or an error.
    pub fn open_wg<'a>(
        &self,
        nonce_ctr: u64,
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        assert!(plaintext.len() + 16 >= ciphertext.len());
        let state = self.aead_init_wg(nonce_ctr);

        self.open_slow(state, aad, ciphertext, plaintext)
    }

    /// Encrypts and authenticates `plaintext`, authenticates the additional data `aad`, and stores
    /// the result in `ciphertext` returning the number of bytes written.
    ///
    /// The same nonce must not be used to encrypt multiple plaintexts.
    pub fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8]) -> usize {
        assert!(plaintext.len() <= ciphertext.len() + 16);

        let state = self.aead_init(nonce);
        self.seal_slow(state, aad, plaintext, ciphertext)
    }

    /// Decrypts and authenticates `ciphertext`, authenticates the additional data `aad`, and
    /// stores the result in `plaintext` returning the plaintext or an error.
    pub fn open<'a>(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        assert!(plaintext.len() + 16 >= ciphertext.len());
        let state = self.aead_init(nonce);

        self.open_slow(state, aad, ciphertext, plaintext)
    }

    /// Encrypts and authenticates `plaintext`, authenticates the additional data `aad`, and stores
    /// the result in `ciphertext` returning the number of bytes written.
    ///
    /// This should be preferred over `seal` when nonce uniqueness cannot be ensured, or whenever
    /// nonces are randomly generated.
    pub fn xseal(
        &self,
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> usize {
        assert!(plaintext.len() <= ciphertext.len() + 16);
        let state = self.xaead_init(nonce);
        self.seal_slow(state, aad, plaintext, ciphertext)
    }

    /// Decrypts and authenticates `ciphertext`, authenticates the additional data `aad`, and
    /// stores the result in `plaintext` returning the plaintext or an error.
    pub fn xopen<'a>(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        assert!(plaintext.len() + 16 >= ciphertext.len());
        let state = self.xaead_init(nonce);

        self.open_slow(state, aad, ciphertext, plaintext)
    }
}

fn chacha20_block_x2(state: [u32; 16]) -> [[u32; 16]; 2] {
    let a_block = Vec8([
        state[0], state[1], state[2], state[3], state[0], state[1], state[2], state[3],
    ]);
    let b_block = Vec8([
        state[4], state[5], state[6], state[7], state[4], state[5], state[6], state[7],
    ]);
    let c_block = Vec8([
        state[8], state[9], state[10], state[11], state[8], state[9], state[10], state[11],
    ]);
    let d_block = Vec8([
        state[12],
        state[13],
        state[14],
        state[15],
        state[12] + 1,
        state[13],
        state[14],
        state[15],
    ]);

    let mut a = a_block;
    let mut b = b_block;
    let mut c = c_block;
    let mut d = d_block;

    for _ in 0..10 {
        a += b;
        d ^= a;
        d <<= 16;

        c += d;
        b ^= c;
        b <<= 12;

        a += b;
        d ^= a;
        d <<= 8;

        c += d;
        b ^= c;
        b <<= 7;

        b.rotr1();
        c.rotr2();
        d.rotr3();

        a += b;
        d ^= a;
        d <<= 16;

        c += d;
        b ^= c;
        b <<= 12;

        a += b;
        d ^= a;
        d <<= 8;

        c += d;
        b ^= c;
        b <<= 7;

        b.rotr3();
        c.rotr2();
        d.rotr1();
    }

    a += a_block;
    b += b_block;
    c += c_block;
    d += d_block;

    [
        [
            a.0[0], a.0[1], a.0[2], a.0[3], b.0[0], b.0[1], b.0[2], b.0[3], c.0[0], c.0[1], c.0[2],
            c.0[3], d.0[0], d.0[1], d.0[2], d.0[3],
        ],
        [
            a.0[4], a.0[5], a.0[6], a.0[7], b.0[4], b.0[5], b.0[6], b.0[7], c.0[4], c.0[5], c.0[6],
            c.0[7], d.0[4], d.0[5], d.0[6], d.0[7],
        ],
    ]
}

#[inline(always)]
fn chacha20_block(state: [u32; 16], hchacha: bool) -> [u32; 16] {
    let a_block = Vec4([state[0], state[1], state[2], state[3]]);
    let b_block = Vec4([state[4], state[5], state[6], state[7]]);
    let c_block = Vec4([state[8], state[9], state[10], state[11]]);
    let d_block = Vec4([state[12], state[13], state[14], state[15]]);

    let mut a = a_block;
    let mut b = b_block;
    let mut c = c_block;
    let mut d = d_block;

    for _ in 0..10 {
        a += b;
        d ^= a;
        d <<= 16;

        c += d;
        b ^= c;
        b <<= 12;

        a += b;
        d ^= a;
        d <<= 8;

        c += d;
        b ^= c;
        b <<= 7;

        b.rotr1();
        c.rotr2();
        d.rotr3();

        a += b;
        d ^= a;
        d <<= 16;

        c += d;
        b ^= c;
        b <<= 12;

        a += b;
        d ^= a;
        d <<= 8;

        c += d;
        b ^= c;
        b <<= 7;

        b.rotr3();
        c.rotr2();
        d.rotr1();
    }

    if !hchacha {
        a += a_block;
        b += b_block;
        c += c_block;
        d += d_block;
    }

    [
        a.0[0], a.0[1], a.0[2], a.0[3], b.0[0], b.0[1], b.0[2], b.0[3], c.0[0], c.0[1], c.0[2],
        c.0[3], d.0[0], d.0[1], d.0[2], d.0[3],
    ]
}

#[inline(always)]
fn transmute_u8_u32(blk_in: [u8; 64]) -> [u32; 16] {
    [
        u32::from_le_bytes(make_array(&blk_in[0..])),
        u32::from_le_bytes(make_array(&blk_in[4..])),
        u32::from_le_bytes(make_array(&blk_in[8..])),
        u32::from_le_bytes(make_array(&blk_in[12..])),
        u32::from_le_bytes(make_array(&blk_in[16..])),
        u32::from_le_bytes(make_array(&blk_in[20..])),
        u32::from_le_bytes(make_array(&blk_in[24..])),
        u32::from_le_bytes(make_array(&blk_in[28..])),
        u32::from_le_bytes(make_array(&blk_in[32..])),
        u32::from_le_bytes(make_array(&blk_in[36..])),
        u32::from_le_bytes(make_array(&blk_in[40..])),
        u32::from_le_bytes(make_array(&blk_in[44..])),
        u32::from_le_bytes(make_array(&blk_in[48..])),
        u32::from_le_bytes(make_array(&blk_in[52..])),
        u32::from_le_bytes(make_array(&blk_in[56..])),
        u32::from_le_bytes(make_array(&blk_in[60..])),
    ]
}

#[inline(always)]
fn transmute_u32_u8(blk_in: [u32; 16]) -> [u8; 64] {
    let mut ret = [0u8; 64];
    for i in 0..16 {
        ret[i * 4..i * 4 + 4].copy_from_slice(&blk_in[i].to_le_bytes());
    }
    ret
}

#[derive(Clone, Copy)]
struct Vec4([u32; 4]);

impl AddAssign for Vec4 {
    fn add_assign(&mut self, other: Vec4) {
        for i in 0..4 {
            self.0[i] = self.0[i].wrapping_add(other.0[i]);
        }
    }
}

impl BitXorAssign for Vec4 {
    fn bitxor_assign(&mut self, other: Vec4) {
        for i in 0..4 {
            self.0[i] ^= other.0[i];
        }
    }
}

impl ShlAssign<u32> for Vec4 {
    fn shl_assign(&mut self, other: u32) {
        for i in 0..4 {
            self.0[i] = self.0[i].rotate_left(other);
        }
    }
}

impl Vec4 {
    fn rotr1(&mut self) {
        *self = Vec4([self.0[1], self.0[2], self.0[3], self.0[0]]);
    }

    fn rotr2(&mut self) {
        *self = Vec4([self.0[2], self.0[3], self.0[0], self.0[1]]);
    }

    fn rotr3(&mut self) {
        *self = Vec4([self.0[3], self.0[0], self.0[1], self.0[2]])
    }
}

#[derive(Clone, Copy)]
struct Vec8([u32; 8]);

impl AddAssign for Vec8 {
    fn add_assign(&mut self, other: Vec8) {
        for i in 0..8 {
            self.0[i] = self.0[i].wrapping_add(other.0[i]);
        }
    }
}

impl BitXorAssign for Vec8 {
    fn bitxor_assign(&mut self, other: Vec8) {
        for i in 0..8 {
            self.0[i] ^= other.0[i];
        }
    }
}

impl ShlAssign<u32> for Vec8 {
    fn shl_assign(&mut self, other: u32) {
        for i in 0..8 {
            self.0[i] = self.0[i].rotate_left(other);
        }
    }
}

impl Vec8 {
    fn rotr1(&mut self) {
        *self = Vec8([
            self.0[1], self.0[2], self.0[3], self.0[0], self.0[5], self.0[6], self.0[7], self.0[4],
        ]);
    }

    fn rotr2(&mut self) {
        *self = Vec8([
            self.0[2], self.0[3], self.0[0], self.0[1], self.0[6], self.0[7], self.0[4], self.0[5],
        ]);
    }

    fn rotr3(&mut self) {
        *self = Vec8([
            self.0[3], self.0[0], self.0[1], self.0[2], self.0[7], self.0[4], self.0[5], self.0[6],
        ])
    }
}
