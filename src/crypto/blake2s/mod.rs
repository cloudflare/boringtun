mod tests;
use super::super::noise::errors::*;
use std;
use std::mem;
use std::ops::AddAssign;
use std::ops::BitXorAssign;
use std::ops::ShrAssign;

#[derive(Debug, Clone, Copy)]
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

impl ShrAssign<u32> for Vec4 {
    fn shr_assign(&mut self, other: u32) {
        for i in 0..4 {
            self.0[i] = self.0[i].rotate_right(other);
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

#[inline(always)]
fn get_u32_le(m: &[u8]) -> u32 {
    assert!(m.len() >= 4);
    (m[0] as u32) | (m[1] as u32) << 8 | (m[2] as u32) << 16 | (m[3] as u32) << 24
}

static IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

pub struct Blake2s {
    state: [u32; 8],
    buf: [u8; 64],
    key: [u8; 64],
    used: usize,
    hashed: u64,
    outlen: usize,
    is_mac: bool,
}

macro_rules! ROUND {
    ($a:expr, $b:expr, $c:expr, $d:expr, $x1:expr, $y1:expr, $x2:expr, $y2:expr) => {
        $a += $x1;
        $a += $b;
        $d ^= $a;
        $d >>= 16;
        $c += $d;
        $b ^= $c;
        $b >>= 12;

        $a += $y1;
        $a += $b;
        $d ^= $a;
        $d >>= 8;
        $c += $d;
        $b ^= $c;
        $b >>= 7;

        $b.rotr1();
        $c.rotr2();
        $d.rotr3();

        $a += $x2;
        $a += $b;
        $d ^= $a;
        $d >>= 16;
        $c += $d;
        $b ^= $c;
        $b >>= 12;

        $a += $y2;
        $a += $b;
        $d ^= $a;
        $d >>= 8;
        $c += $d;
        $b ^= $c;
        $b >>= 7;

        $b.rotr3();
        $c.rotr2();
        $d.rotr1();
    };
}

impl Blake2s {
    fn new(key: &[u8], outlen: usize, mac: bool) -> Blake2s {
        let max_keylen = if mac { 64 } else { 32 }; // We truncate the key with no error, since the usage is internal

        let keylen = std::cmp::min(key.len(), max_keylen);
        let mut b = Blake2s {
            state: IV,
            buf: [0; 64],
            key: [0; 64],
            used: 0,
            hashed: 0,
            outlen: std::cmp::min(outlen, 32),
            is_mac: mac,
        };

        b.state[0] ^= 0x01010000 ^ (b.outlen as u32);

        if keylen > 0 {
            b.buf[..keylen].copy_from_slice(key);
            b.used = 64;

            if b.is_mac {
                b.key[..keylen].copy_from_slice(key);
                for i in 0..64 {
                    b.buf[i] = b.buf[i] ^ 0x36;
                    b.key[i] = b.key[i] ^ 0x5c;
                }
            } else {
                b.state[0] ^= (keylen as u32) << 8
            }
        }

        return b;
    }

    pub fn new_mac(key: &[u8]) -> Blake2s {
        Blake2s::new(key, 16, false)
    }

    pub fn new_hash() -> Blake2s {
        Blake2s::new(&[], 32, false)
    }

    pub fn new_hmac(key: &[u8]) -> Blake2s {
        Blake2s::new(key, 32, true)
    }

    fn hash_block(&mut self, last: bool) -> () {
        let m: [u32; 16] = [
            get_u32_le(&self.buf[0 * 4..]),
            get_u32_le(&self.buf[1 * 4..]),
            get_u32_le(&self.buf[2 * 4..]),
            get_u32_le(&self.buf[3 * 4..]),
            get_u32_le(&self.buf[4 * 4..]),
            get_u32_le(&self.buf[5 * 4..]),
            get_u32_le(&self.buf[6 * 4..]),
            get_u32_le(&self.buf[7 * 4..]),
            get_u32_le(&self.buf[8 * 4..]),
            get_u32_le(&self.buf[9 * 4..]),
            get_u32_le(&self.buf[10 * 4..]),
            get_u32_le(&self.buf[11 * 4..]),
            get_u32_le(&self.buf[12 * 4..]),
            get_u32_le(&self.buf[13 * 4..]),
            get_u32_le(&self.buf[14 * 4..]),
            get_u32_le(&self.buf[15 * 4..]),
        ];

        let s = &mut self.state;

        let h = Vec4([(self.hashed) as u32, (self.hashed >> 32) as u32, 0, 0]);

        let s0 = Vec4([s[0], s[1], s[2], s[3]]);
        let s1 = Vec4([s[4], s[5], s[6], s[7]]);

        let mut a = s0;
        let mut b = s1;
        let mut c = Vec4([IV[0], IV[1], IV[2], IV[3]]);
        let mut d = if !last {
            Vec4([IV[4], IV[5], IV[6], IV[7]])
        } else {
            Vec4([IV[4], IV[5], !IV[6], IV[7]])
        };

        d ^= h;

        //
        let x1 = Vec4([m[0], m[2], m[4], m[6]]);
        let y1 = Vec4([m[1], m[3], m[5], m[7]]);
        let x2 = Vec4([m[8], m[10], m[12], m[14]]);
        let y2 = Vec4([m[9], m[11], m[13], m[15]]);

        ROUND!(a, b, c, d, x1, y1, x2, y2);
        //
        let x1 = Vec4([m[14], m[4], m[9], m[13]]);
        let y1 = Vec4([m[10], m[8], m[15], m[6]]);
        let x2 = Vec4([m[1], m[0], m[11], m[5]]);
        let y2 = Vec4([m[12], m[2], m[7], m[3]]);

        ROUND!(a, b, c, d, x1, y1, x2, y2);
        //
        let x1 = Vec4([m[11], m[12], m[5], m[15]]);
        let y1 = Vec4([m[8], m[0], m[2], m[13]]);
        let x2 = Vec4([m[10], m[3], m[7], m[9]]);
        let y2 = Vec4([m[14], m[6], m[1], m[4]]);

        ROUND!(a, b, c, d, x1, y1, x2, y2);
        //
        let x1 = Vec4([m[7], m[3], m[13], m[11]]);
        let y1 = Vec4([m[9], m[1], m[12], m[14]]);
        let x2 = Vec4([m[2], m[5], m[4], m[15]]);
        let y2 = Vec4([m[6], m[10], m[0], m[8]]);

        ROUND!(a, b, c, d, x1, y1, x2, y2);
        //
        let x1 = Vec4([m[9], m[5], m[2], m[10]]);
        let y1 = Vec4([m[0], m[7], m[4], m[15]]);
        let x2 = Vec4([m[14], m[11], m[6], m[3]]);
        let y2 = Vec4([m[1], m[12], m[8], m[13]]);

        ROUND!(a, b, c, d, x1, y1, x2, y2);
        //
        let x1 = Vec4([m[2], m[6], m[0], m[8]]);
        let y1 = Vec4([m[12], m[10], m[11], m[3]]);
        let x2 = Vec4([m[4], m[7], m[15], m[1]]);
        let y2 = Vec4([m[13], m[5], m[14], m[9]]);

        ROUND!(a, b, c, d, x1, y1, x2, y2);
        //
        let x1 = Vec4([m[12], m[1], m[14], m[4]]);
        let y1 = Vec4([m[5], m[15], m[13], m[10]]);
        let x2 = Vec4([m[0], m[6], m[9], m[8]]);
        let y2 = Vec4([m[7], m[3], m[2], m[11]]);

        ROUND!(a, b, c, d, x1, y1, x2, y2);
        //
        let x1 = Vec4([m[13], m[7], m[12], m[3]]);
        let y1 = Vec4([m[11], m[14], m[1], m[9]]);
        let x2 = Vec4([m[5], m[15], m[8], m[2]]);
        let y2 = Vec4([m[0], m[4], m[6], m[10]]);

        ROUND!(a, b, c, d, x1, y1, x2, y2);
        //
        let x1 = Vec4([m[6], m[14], m[11], m[0]]);
        let y1 = Vec4([m[15], m[9], m[3], m[8]]);
        let x2 = Vec4([m[12], m[13], m[1], m[10]]);
        let y2 = Vec4([m[2], m[7], m[4], m[5]]);

        ROUND!(a, b, c, d, x1, y1, x2, y2);
        //
        let x1 = Vec4([m[10], m[8], m[7], m[1]]);
        let y1 = Vec4([m[2], m[4], m[6], m[5]]);
        let x2 = Vec4([m[15], m[9], m[3], m[13]]);
        let y2 = Vec4([m[11], m[14], m[12], m[0]]);

        ROUND!(a, b, c, d, x1, y1, x2, y2);

        a ^= c;
        b ^= d;

        a ^= s0;
        b ^= s1;

        s[0] = a.0[0];
        s[1] = a.0[1];
        s[2] = a.0[2];
        s[3] = a.0[3];
        s[4] = b.0[0];
        s[5] = b.0[1];
        s[6] = b.0[2];
        s[7] = b.0[3];
    }

    pub fn hash(&mut self, mut data: &[u8]) -> &mut Blake2s {
        while data.len() > 0 {
            while self.used == 0 && data.len() > 64 {
                self.buf[..].copy_from_slice(&data[..64]);
                self.hashed += 64;
                self.hash_block(false);
                data = &data[64..];
            }

            if self.used < 64 {
                let to_copy = std::cmp::min(64 - self.used, data.len());
                self.buf[self.used..self.used + to_copy].copy_from_slice(&data[..to_copy]);
                self.used += to_copy;
                data = &data[to_copy..]
            }

            if self.used == 64 && data.len() > 0 {
                self.hashed += 64;
                self.hash_block(false);
                self.used = 0;
            }
        }

        self
    }

    pub fn finalize(&mut self) -> [u8; 32] {
        self.hashed += self.used as u64;

        while self.used < 64 {
            self.buf[self.used] = 0;
            self.used += 1;
        }

        self.hash_block(true);

        let s = unsafe { mem::transmute::<[u32; 8], [u8; 32]>(self.state) };

        if self.is_mac {
            return Blake2s::new_hash().hash(&self.key).hash(&s).finalize();
        }

        return s;
    }
}

pub fn constant_time_mac_check(mac1: &[u8], mac2: &[u8]) -> Result<(), WireGuardError> {
    assert!(mac1.len() == 16);
    assert!(mac2.len() == 16);
    if mac1.len() != 16 || mac2.len() != 16 {
        return Err(WireGuardError::InvalidMac);
    }

    let mut r = 0u8;
    for i in 0..16 {
        r |= mac1[i] ^ mac2[i];
    }

    if r == 0 {
        Ok(())
    } else {
        Err(WireGuardError::InvalidMac)
    }
}
