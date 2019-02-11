mod tests;

use base64::decode;
use std::ops::Add;
use std::ops::Mul;
use std::ops::Sub;
use std::str::FromStr;
use ring::rand::*;

#[derive(Debug, Eq, PartialEq, Hash, Default, Clone)]
// TODO: implement Hash
pub struct X25519Key([u8; 32]);

#[derive(Clone, Copy)]
struct Felem([u64; 4]);
struct Felem2([u64; 8]);

impl FromStr for X25519Key {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut key = X25519Key([0u8; 32]);
        if s.len() != 64 {
            if let Ok(decoded_key) = decode(s) {
                if decoded_key.len() != key.0.len() {
                    return Err("Illegal key size".to_owned());
                } else {
                    &key.0[..].copy_from_slice(&decoded_key);
                    return Ok(key);
                }
            }
            // Try to parse as base 64

            return Err("Illegal key size".to_owned());
        }

        for i in 0..32 {
            key.0[i] = u8::from_str_radix(&s[i * 2..=i * 2 + 1], 16)
                .map_err(|_| "Illegal character in key".to_owned())?;
        }

        Ok(key)
    }
}

/// Will panic if the slice.len() != 32
impl<'a> From<&'a [u8]> for X25519Key {
    fn from(slice: &[u8]) -> Self {
        let mut key = [0u8; 32];
        &key[..].copy_from_slice(slice);
        X25519Key(key)
    }
}

impl From<[u8; 32]> for X25519Key {
    fn from(arr: [u8; 32]) -> Self {
        X25519Key(arr)
    }
}

impl X25519Key {
    pub fn public_key(&self) -> X25519Key {
        X25519Key(x25519_public_key(&self.0))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn inner(self) -> [u8; 32] {
        self.0
    }
}

impl Add for Felem {
    type Output = Felem;
    #[inline(always)]
    fn add(self, other: Felem) -> Felem {
        let x0 = self.0[0] as u128;
        let x1 = self.0[1] as u128;
        let x2 = self.0[2] as u128;
        let x3 = self.0[3] as u128;

        let y0 = other.0[0] as u128;
        let y1 = other.0[1] as u128;
        let y2 = other.0[2] as u128;
        let y3 = other.0[3] as u128;

        let mut acc0 = x0 + y0;
        let mut acc1 = x1 + y1 + (acc0 >> 64);
        acc0 = acc0 as u64 as u128;
        let mut acc2 = x2 + y2 + (acc1 >> 64);
        acc1 = acc1 as u64 as u128;
        let mut acc3 = x3 + y3 + (acc2 >> 64);
        acc2 = acc2 as u64 as u128;

        let mut top = acc3 >> 63;
        acc3 &= 0x7fffffffffffffff;

        top *= 19;
        acc0 += top;
        acc1 += acc0 >> 64;
        acc2 += acc1 >> 64;
        acc3 += acc2 >> 64;

        Felem([acc0 as u64, acc1 as u64, acc2 as u64, acc3 as u64])
    }
}

impl Sub for Felem {
    type Output = Felem;
    #[inline(always)]
    fn sub(self, other: Felem) -> Felem {
        static POLY_X4: [u128; 4] = [
            0x1ffffffffffffffb4,
            0x1fffffffffffffffe,
            0x1fffffffffffffffe,
            0x1fffffffffffffffe,
        ];

        let x0 = self.0[0] as u128;
        let x1 = self.0[1] as u128;
        let x2 = self.0[2] as u128;
        let x3 = self.0[3] as u128;

        let y0 = other.0[0] as u128;
        let y1 = other.0[1] as u128;
        let y2 = other.0[2] as u128;
        let y3 = other.0[3] as u128;

        let mut acc0 = POLY_X4[0] + x0 - y0;
        let mut acc1 = POLY_X4[1] + x1 + (acc0 >> 64) - y1;
        acc0 = acc0 as u64 as u128;
        let mut acc2 = POLY_X4[2] + x2 + (acc1 >> 64) - y2;
        acc1 = acc1 as u64 as u128;
        let mut acc3 = POLY_X4[3] + x3 + (acc2 >> 64) - y3;
        acc2 = acc2 as u64 as u128;

        let mut top = acc3 >> 63;
        acc3 &= 0x7fffffffffffffff;

        top *= 19;
        acc0 += top;
        acc1 += acc0 >> 64;
        acc2 += acc1 >> 64;
        acc3 += acc2 >> 64;

        Felem([acc0 as u64, acc1 as u64, acc2 as u64, acc3 as u64])
    }
}

impl Mul for Felem {
    type Output = Felem;
    #[inline(always)]
    fn mul(self, other: Felem) -> Felem {
        let x0 = self.0[0] as u128;
        let x1 = self.0[1] as u128;
        let x2 = self.0[2] as u128;
        let x3 = self.0[3] as u128;

        let mut t: u128;

        // y0
        let y0 = other.0[0] as u128;
        t = x0.wrapping_mul(y0);
        let acc0 = t as u64;
        let mut acc1 = t >> 64;

        t = x1.wrapping_mul(y0);
        acc1 += t;
        let mut acc2 = acc1 >> 64;
        acc1 = (acc1 as u64) as u128;

        t = x2.wrapping_mul(y0);
        acc2 += t;
        let mut acc3 = acc2 >> 64;
        acc2 = (acc2 as u64) as u128;

        t = x3.wrapping_mul(y0);
        acc3 += t;
        let mut acc4 = acc3 >> 64;
        acc3 = (acc3 as u64) as u128;

        // y1
        let y1 = other.0[1] as u128;
        t = x0.wrapping_mul(y1);
        acc1 += t;
        let mut top = acc1 >> 64;
        acc1 = (acc1 as u64) as u128;

        t = x1.wrapping_mul(y1);
        acc2 += top;
        acc2 += t;
        top = acc2 >> 64;
        acc2 = (acc2 as u64) as u128;

        t = x2.wrapping_mul(y1);
        acc3 += top;
        acc3 += t;
        top = acc3 >> 64;
        acc3 = (acc3 as u64) as u128;

        t = x3.wrapping_mul(y1);
        acc4 += top;
        acc4 += t;
        let mut acc5 = acc4 >> 64;
        acc4 = (acc4 as u64) as u128;

        // y2
        let y2 = other.0[2] as u128;
        t = x0.wrapping_mul(y2);
        acc2 += t;
        top = acc2 >> 64;
        acc2 = (acc2 as u64) as u128;

        t = x1.wrapping_mul(y2);
        acc3 += top;
        acc3 += t;
        top = acc3 >> 64;
        acc3 = (acc3 as u64) as u128;

        t = x2.wrapping_mul(y2);
        acc4 += top;
        acc4 += t;
        top = acc4 >> 64;
        acc4 = (acc4 as u64) as u128;

        t = x3.wrapping_mul(y2);
        acc5 += top;
        acc5 += t;
        let mut acc6 = acc5 >> 64;
        acc5 = (acc5 as u64) as u128;

        // y3
        let y3 = other.0[3] as u128;
        t = x0.wrapping_mul(y3);
        acc3 += t;
        top = acc3 >> 64;
        acc3 = (acc3 as u64) as u128;

        t = x1.wrapping_mul(y3);
        acc4 += top;
        acc4 += t;
        top = acc4 >> 64;
        acc4 = (acc4 as u64) as u128;

        t = x2.wrapping_mul(y3);
        acc5 += top;
        acc5 += t;
        top = acc5 >> 64;
        acc5 = (acc5 as u64) as u128;

        t = x3.wrapping_mul(y3);
        acc6 += top;
        acc6 += t;
        let acc7 = acc6 >> 64;
        acc6 = (acc6 as u64) as u128;

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

        // Modulo
    }
}

impl Felem {
    #[inline(always)]
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
fn sqr_256(x: Felem) -> Felem2 {
    let x0 = x.0[0] as u128;
    let x1 = x.0[1] as u128;
    let x2 = x.0[2] as u128;
    let x3 = x.0[3] as u128;

    let mut t: u128;

    // y0
    t = x1 * x0;
    let mut acc1 = t as u64 as u128;
    let mut acc2 = t >> 64;

    t = x2 * x0;
    acc2 += t;
    let mut acc3 = acc2 >> 64;
    acc2 = (acc2 as u64) as u128;

    t = x3 * x0;
    acc3 += t;
    let mut acc4 = acc3 >> 64;
    acc3 = (acc3 as u64) as u128;

    // y1
    t = x2 * x1;
    acc3 += t;
    let top = acc3 >> 64;
    acc3 = (acc3 as u64) as u128;

    t = x3 * x1;
    acc4 += top;
    acc4 += t;
    let mut acc5 = acc4 >> 64;
    acc4 = (acc4 as u64) as u128;

    // y2
    t = x3 * x2;
    acc5 += t;
    let mut acc6 = acc5 >> 64;
    acc5 = (acc5 as u64) as u128;

    acc1 += acc1;
    acc2 += acc2 + (acc1 >> 64);
    acc1 = acc1 as u64 as u128;
    acc3 += acc3 + (acc2 >> 64);
    acc2 = acc2 as u64 as u128;
    acc4 += acc4 + (acc3 >> 64);
    acc3 = acc3 as u64 as u128;
    acc5 += acc5 + (acc4 >> 64);
    acc4 = acc4 as u64 as u128;
    acc6 += acc6 + (acc5 >> 64);
    acc5 = acc5 as u64 as u128;
    let mut acc7 = acc6 >> 64;
    acc6 = acc6 as u64 as u128;

    t = x0 * x0;

    let acc0 = t as u64 as u128;
    acc1 += t >> 64;

    t = x1 * x1;
    acc2 += t + (acc1 >> 64);
    acc3 += acc2 >> 64;

    t = x2 * x2;
    acc4 += t + (acc3 >> 64);
    acc5 += acc4 >> 64;

    t = x3 * x3;
    acc6 += t + (acc5 >> 64);
    acc7 += acc6 >> 64;

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
    let c38 = 38 as u128;

    let mut acc0 = x.0[0] as u128;
    let mut acc1 = x.0[1] as u128;
    let mut acc2 = x.0[2] as u128;
    let mut acc3 = x.0[3] as u128;
    let mut acc4 = x.0[4] as u128;
    let mut acc5 = x.0[5] as u128;
    let mut acc6 = x.0[6] as u128;
    let mut acc7 = x.0[7] as u128;

    acc4 *= c38;
    acc5 *= c38;
    acc6 *= c38;
    acc7 *= c38;

    acc0 += acc4;
    let mut top = acc0 >> 64;
    acc0 = acc0 as u64 as u128;

    acc1 += top;
    acc1 += acc5;

    top = acc1 >> 64;
    acc1 = acc1 as u64 as u128;
    acc2 += top;
    acc2 += acc6;

    top = acc2 >> 64;
    acc2 = acc2 as u64 as u128;
    acc3 += top;
    acc3 += acc7;

    top = acc3 >> 63;
    acc3 &= 0x7fffffffffffffff;

    top *= 19;
    acc0 += top;
    acc1 += acc0 >> 64;
    acc2 += acc1 >> 64;
    acc3 += acc2 >> 64;

    Felem([acc0 as u64, acc1 as u64, acc2 as u64, acc3 as u64])
}

fn mod_final_25519(x: Felem) -> Felem {
    let mut acc0 = x.0[0] as u128;
    let mut acc1 = x.0[1] as u128;
    let mut acc2 = x.0[2] as u128;
    let mut acc3 = x.0[3] as u128;

    let mut top = acc3 >> 63;
    acc3 &= 0x7fffffffffffffff;

    top *= 19;
    acc0 += top;
    acc1 += acc0 >> 64;
    acc2 += acc1 >> 64;
    acc3 += acc2 >> 64;

    Felem([acc0 as u64, acc1 as u64, acc2 as u64, acc3 as u64])
}

fn mod_inv_25519(x: Felem) -> Felem {
    let _1 = x;
    let _10 = x.sqr(1);
    let _1001 = _10.sqr(2) * _1;
    let _1011 = _1001 * _10;

    let x5 = _1011.sqr(1) * _1001;
    let x10 = x5.sqr(5) * x5;
    let x20 = x10.sqr(10) * x10;
    let x40 = x20.sqr(20) * x20;
    let x50 = x40.sqr(10) * x10;
    let x100 = x50.sqr(50) * x50;

    let t = x100.sqr(100) * x100;
    let t2 = t.sqr(50) * x50;
    t2.sqr(5) * _1011
}

#[inline(always)]
fn constant_time_swap(a: Felem, b: Felem, swap: u8) -> (Felem, Felem) {
    let mask = 0_u64.wrapping_sub(swap as u64);

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

#[inline(always)]
fn read_u64(buf: &[u8]) -> u64 {
    if buf.len() < 8 {
        panic!("Illegal");
    }

    return (buf[0] as u64)
        ^ (buf[1] as u64) << 8
        ^ (buf[2] as u64) << 16
        ^ (buf[3] as u64) << 24
        ^ (buf[4] as u64) << 32
        ^ (buf[5] as u64) << 40
        ^ (buf[6] as u64) << 48
        ^ (buf[7] as u64) << 56;
}

#[inline(always)]
fn write_u64(buf: &mut [u8], val: u64) {
    if buf.len() < 8 {
        panic!("Illegal");
    }

    buf[0] = val as u8;
    buf[1] = (val >> 8) as u8;
    buf[2] = (val >> 16) as u8;
    buf[3] = (val >> 24) as u8;
    buf[4] = (val >> 32) as u8;
    buf[5] = (val >> 40) as u8;
    buf[6] = (val >> 48) as u8;
    buf[7] = (val >> 56) as u8;
}

pub fn x25519_gen_secret_key() -> [u8; 32] {
    let rng = SystemRandom::new();
    let mut private_key = [0u8; 32];
    rng.fill(&mut private_key[..]).unwrap();
    return private_key;
}

pub fn x25519_public_key(secret_key: &[u8]) -> [u8; 32] {
    let u = [
        9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    x25519_shared_key(&u, secret_key)
}

pub fn x25519_shared_key(peer_key: &[u8], secret_key: &[u8]) -> [u8; 32] {
    if peer_key.len() != 32 || secret_key.len() != 32 {
        panic!("Illegal values for x25519");
    }

    let mut scalar = [0_u8; 32];
    let mut shared_key = [0_u8; 32];
    scalar[..].copy_from_slice(&secret_key[..]);

    assert!(peer_key.len() == 32);
    let u = Felem([
        read_u64(&peer_key[0..8]),
        read_u64(&peer_key[8..16]),
        read_u64(&peer_key[16..24]),
        read_u64(&peer_key[24..32]),
    ]);

    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    let x_1 = u;
    let mut x_2 = Felem([1, 0, 0, 0]);
    let mut z_2 = Felem([0, 0, 0, 0]);
    let mut x_3 = u;
    let mut z_3 = Felem([1, 0, 0, 0]);
    let a24 = Felem([121665, 0, 0, 0]);
    let mut swap = 0;

    let mut byte_idx: i8 = 31;
    let mut bit_idx = 6;

    while byte_idx >= 0 {
        while bit_idx >= 0 {
            let bit_val = (scalar[byte_idx as usize] >> bit_idx) & 1;

            swap ^= bit_val;
            let (x2, x3) = constant_time_swap(x_2, x_3, swap);
            let (z2, z3) = constant_time_swap(z_2, z_3, swap);
            swap = bit_val;

            let a = x2 + z2;
            let b = x2 - z2;

            let aa = a.sqr(1);
            let bb = b.sqr(1);

            let c = x3 + z3;
            let d = x3 - z3;

            let cb = c * b;
            let da = d * a;

            let e = aa - bb;

            x_3 = (da + cb).sqr(1);
            z_3 = x_1 * (da - cb).sqr(1);
            x_2 = aa * bb;
            z_2 = e * (aa + a24 * e);

            bit_idx -= 1;
        }
        bit_idx = 7;
        byte_idx -= 1;
    }

    let (x2, _) = constant_time_swap(x_2, x_3, swap);
    let (z2, _) = constant_time_swap(z_2, z_3, swap);

    let key = mod_final_25519(x2 * mod_inv_25519(z2));

    write_u64(&mut shared_key[0..8], key.0[0]);
    write_u64(&mut shared_key[8..16], key.0[1]);
    write_u64(&mut shared_key[16..24], key.0[2]);
    write_u64(&mut shared_key[24..32], key.0[3]);

    shared_key
}
