mod tests;

use base64::decode;
use noise::make_array;
use ring::rand::*;
use std::ops::Add;
use std::ops::Mul;
use std::ops::Sub;
use std::str::FromStr;

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
                    key.0[..].copy_from_slice(&decoded_key);
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
        key[..].copy_from_slice(slice);
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

#[cfg_attr(feature = "cargo-clippy", allow(suspicious_arithmetic_impl))]
impl Add for Felem {
    type Output = Felem;
    #[inline(always)]
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

#[cfg_attr(feature = "cargo-clippy", allow(suspicious_arithmetic_impl))]
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

#[cfg_attr(feature = "cargo-clippy", allow(suspicious_arithmetic_impl))]
impl Mul for Felem {
    type Output = Felem;
    #[inline(always)]
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
    let c38 = 38 as u128;

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
    acc3 &= 0x7fff_ffff_ffff_ffff;

    top = top.wrapping_mul(19);
    acc0 = acc0.wrapping_add(top);
    acc1 = acc1.wrapping_add(acc0 >> 64);
    acc2 = acc2.wrapping_add(acc1 >> 64);
    acc3 = acc3.wrapping_add(acc2 >> 64);

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

pub fn x25519_gen_secret_key() -> [u8; 32] {
    let rng = SystemRandom::new();
    let mut private_key = [0u8; 32];
    rng.fill(&mut private_key[..]).unwrap();
    private_key
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
    let a24 = Felem([121666, 0, 0, 0]);
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
