mod tests;
use super::super::noise::errors::*;
use noise::make_array;
use std::ops::Add;
use std::ops::AddAssign;
use std::ops::BitXorAssign;
use std::ops::Index;
use std::ops::Mul;
use std::ops::Rem;
use std::ops::ShlAssign;

struct Felem1305([u64; 3]);
#[derive(Clone, Copy)]
struct Poly1305R([u64; 2]);
struct Poly1305S([u64; 2]);
struct Felem1305NonRed([u64; 4]);
struct Poly1305;

#[cfg_attr(feature = "cargo-clippy", allow(suspicious_arithmetic_impl))]
impl Add for Felem1305 {
    type Output = Felem1305;
    #[inline(always)]
    fn add(self, other: Felem1305) -> Felem1305 {
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

#[cfg_attr(feature = "cargo-clippy", allow(suspicious_arithmetic_impl))]
impl Mul<Poly1305R> for Felem1305 {
    type Output = Felem1305NonRed;
    #[inline(always)]
    fn mul(self, other: Poly1305R) -> Felem1305NonRed {
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

impl Rem<Poly1305> for Felem1305NonRed {
    type Output = Felem1305;
    #[inline(always)]
    fn rem(self, _: Poly1305) -> Felem1305 {
        let acc0 = u128::from(self.0[0]);
        let acc1 = u128::from(self.0[1]);
        let acc2 = u128::from(self.0[2]);

        let t0 = acc2 & 0xfffffffffffffffc;
        let t1 = u128::from(self.0[3]);
        let t2 = u128::from((self.0[2] >> 2) | (self.0[3] << 62));
        let t3 = t1 >> 2;

        let acc2 = acc2 & 0x3;

        let mut acc0 = acc0.wrapping_add(t0);
        let mut acc1 = acc1.wrapping_add(t1).wrapping_add(acc0 >> 64);
        let mut acc2 = acc2.wrapping_add(acc1 >> 64);

        acc0 &= 0xffff_ffff_ffff_ffff;
        acc1 &= 0xffff_ffff_ffff_ffff;
        acc2 &= 0xffff_ffff_ffff_ffff;

        acc0 = acc0.wrapping_add(t2);
        acc1 = acc1.wrapping_add(t3).wrapping_add(acc0 >> 64);
        acc2 = acc2.wrapping_add(acc1 >> 64);

        Felem1305([acc0 as u64, acc1 as u64, acc2 as u64])
    }
}

impl Rem<Poly1305> for Felem1305 {
    type Output = Felem1305;
    #[inline(always)]
    fn rem(self, _: Poly1305) -> Felem1305 {
        Felem1305NonRed([self.0[0], self.0[1], self.0[2], 0]).rem(Poly1305)
    }
}

impl From<[u32; 4]> for Felem1305 {
    fn from(x: [u32; 4]) -> Self {
        Felem1305([
            u64::from(x[0]) | (u64::from(x[1]) << 32),
            u64::from(x[2]) | (u64::from(x[3]) << 32),
            1,
        ])
    }
}

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

#[derive(Debug, Clone)]
pub struct ChaCha20Poly1305 {
    key: [u32; 8],
}

macro_rules! PUTU32LE {
    ($b:ident, $off:expr, $val:expr) => {
        $b[$off] = $val as u8;
        $b[$off + 1] = ($val >> 8) as u8;
        $b[$off + 2] = ($val >> 16) as u8;
        $b[$off + 3] = ($val >> 24) as u8;
    };
}

fn poly_keys(stream: [u32; 16]) -> (Poly1305R, Poly1305S) {
    (
        Poly1305R([
            (u64::from(stream[0]) | (u64::from(stream[1]) << 32)) & 0x0FFFFFFC0FFFFFFF,
            (u64::from(stream[2]) | (u64::from(stream[3]) << 32)) & 0x0FFFFFFC0FFFFFFC,
        ]),
        Poly1305S([
            u64::from(stream[4]) | (u64::from(stream[5]) << 32),
            u64::from(stream[6]) | (u64::from(stream[7]) << 32),
        ]),
    )
}

#[inline(always)]
fn poly_step(acc: Felem1305, x: [u32; 4], k: Poly1305R) -> Felem1305 {
    let acc = acc + Felem1305::from(x);
    let prod = acc * k;
    prod % Poly1305
}

#[inline(always)]
fn poly_step_u8_slice(acc: Felem1305, x: &[u8], k: Poly1305R) -> Felem1305 {
    assert!(x.len() >= 16);
    poly_step(
        acc,
        [
            u32::from_le_bytes(make_array(&x[0..])),
            u32::from_le_bytes(make_array(&x[4..])),
            u32::from_le_bytes(make_array(&x[8..])),
            u32::from_le_bytes(make_array(&x[12..])),
        ],
        k,
    )
}

#[inline(always)]
fn poly_len(acc: Felem1305, aad_len: u64, pt_len: u64, k: Poly1305R) -> Felem1305 {
    let x = [
        aad_len as u32,
        (aad_len >> 32) as u32,
        pt_len as u32,
        (pt_len >> 32) as u32,
    ];
    poly_step(acc, x, k)
}

#[inline(always)]
fn poly_final(acc: Felem1305, aad_len: u64, pt_len: u64, k: Poly1305R, e: Poly1305S) -> (u64, u64) {
    let x = [
        aad_len as u32,
        (aad_len >> 32) as u32,
        pt_len as u32,
        (pt_len >> 32) as u32,
    ];
    let acc = poly_step(acc, x, k);

    let mut t0 = u128::from(acc.0[0]);
    let t1 = u128::from(acc.0[1]);
    let mut t2 = u128::from(acc.0[2]);

    let mut acc0 = t0;
    let mut acc1 = t1;

    t0 = t2 & 0xfffffffffffffffc;
    t2 >>= 2;

    acc0 = acc0.wrapping_add(t0);
    acc1 = acc1.wrapping_add(acc0 >> 64);

    acc0 &= 0xffff_ffff_ffff_ffff;
    acc1 &= 0xffff_ffff_ffff_ffff;

    acc0 = acc0.wrapping_add(t2);
    acc1 = acc1.wrapping_add(acc0 >> 64);

    acc0 &= 0xffff_ffff_ffff_ffff;
    acc1 &= 0xffff_ffff_ffff_ffff;

    acc0 = acc0.wrapping_add(u128::from(e.0[0]));
    acc1 = acc1
        .wrapping_add(u128::from(e.0[1]))
        .wrapping_add(acc0 >> 64);

    (acc0 as u64, acc1 as u64)
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

impl ChaCha20Poly1305 {
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

    #[allow(dead_code)]
    fn seal_slow(&self, mut state: [u32; 16], aad: &[u8], mut pt: &[u8], ct: &mut [u8]) -> usize {
        let blk = chacha20_block(state, false);
        state[12] += 1;

        let (poly_key, poly_enc) = poly_keys(blk);

        let mut acc = Felem1305([0_u64; 3]);
        let mut hashed = 0;
        let mut enced = 0;

        while aad.len() >= hashed + 16 {
            let cur = &aad[hashed..hashed + 16];
            acc = poly_step(
                acc,
                [
                    u32::from_le_bytes(make_array(&cur[0..])),
                    u32::from_le_bytes(make_array(&cur[4..])),
                    u32::from_le_bytes(make_array(&cur[8..])),
                    u32::from_le_bytes(make_array(&cur[12..])),
                ],
                poly_key,
            );
            hashed += 16;
        }

        if aad.len() > hashed {
            let left = aad.len() - hashed;
            let mut arr = [0_u8; 16];
            arr[..left].copy_from_slice(&aad[hashed..aad.len()]);
            acc = poly_step(
                acc,
                [
                    u32::from_le_bytes(make_array(&arr[0..])),
                    u32::from_le_bytes(make_array(&arr[4..])),
                    u32::from_le_bytes(make_array(&arr[8..])),
                    u32::from_le_bytes(make_array(&arr[12..])),
                ],
                poly_key,
            );
            hashed = aad.len();
        }

        loop {
            if pt.is_empty() {
                break;
            }

            let mut blk = chacha20_block(state, false);
            state[12] += 1;

            if pt.len() >= 64 {
                let mut pt_block = [0u8; 64];
                pt_block.copy_from_slice(&pt[0..64]);
                pt = &pt[64..];

                let pt32: [u32; 16] = [
                    u32::from_le_bytes(make_array(&pt_block[0..])),
                    u32::from_le_bytes(make_array(&pt_block[4..])),
                    u32::from_le_bytes(make_array(&pt_block[8..])),
                    u32::from_le_bytes(make_array(&pt_block[12..])),
                    u32::from_le_bytes(make_array(&pt_block[16..])),
                    u32::from_le_bytes(make_array(&pt_block[20..])),
                    u32::from_le_bytes(make_array(&pt_block[24..])),
                    u32::from_le_bytes(make_array(&pt_block[28..])),
                    u32::from_le_bytes(make_array(&pt_block[32..])),
                    u32::from_le_bytes(make_array(&pt_block[36..])),
                    u32::from_le_bytes(make_array(&pt_block[40..])),
                    u32::from_le_bytes(make_array(&pt_block[44..])),
                    u32::from_le_bytes(make_array(&pt_block[48..])),
                    u32::from_le_bytes(make_array(&pt_block[52..])),
                    u32::from_le_bytes(make_array(&pt_block[56..])),
                    u32::from_le_bytes(make_array(&pt_block[60..])),
                ];

                for i in 0..16 {
                    blk[i] ^= pt32[i];
                }

                acc = poly_step(acc, [blk[0], blk[1], blk[2], blk[3]], poly_key);
                acc = poly_step(acc, [blk[4], blk[5], blk[6], blk[7]], poly_key);
                acc = poly_step(acc, [blk[8], blk[9], blk[10], blk[11]], poly_key);
                acc = poly_step(acc, [blk[12], blk[13], blk[14], blk[15]], poly_key);

                PUTU32LE!(pt_block, 0, blk[0]);
                PUTU32LE!(pt_block, 4, blk[1]);
                PUTU32LE!(pt_block, 8, blk[2]);
                PUTU32LE!(pt_block, 12, blk[3]);
                PUTU32LE!(pt_block, 16, blk[4]);
                PUTU32LE!(pt_block, 20, blk[5]);
                PUTU32LE!(pt_block, 24, blk[6]);
                PUTU32LE!(pt_block, 28, blk[7]);
                PUTU32LE!(pt_block, 32, blk[8]);
                PUTU32LE!(pt_block, 36, blk[9]);
                PUTU32LE!(pt_block, 40, blk[10]);
                PUTU32LE!(pt_block, 44, blk[11]);
                PUTU32LE!(pt_block, 48, blk[12]);
                PUTU32LE!(pt_block, 52, blk[13]);
                PUTU32LE!(pt_block, 56, blk[14]);
                PUTU32LE!(pt_block, 60, blk[15]);

                ct[enced..enced + 64].copy_from_slice(&pt_block);
                enced += 64;
            } else {
                let mut pt_block = [0u8; 64];
                pt_block[..pt.len()].copy_from_slice(&pt[..]);

                let pt32: [u32; 16] = [
                    u32::from_le_bytes(make_array(&pt_block[0..])),
                    u32::from_le_bytes(make_array(&pt_block[4..])),
                    u32::from_le_bytes(make_array(&pt_block[8..])),
                    u32::from_le_bytes(make_array(&pt_block[12..])),
                    u32::from_le_bytes(make_array(&pt_block[16..])),
                    u32::from_le_bytes(make_array(&pt_block[20..])),
                    u32::from_le_bytes(make_array(&pt_block[24..])),
                    u32::from_le_bytes(make_array(&pt_block[28..])),
                    u32::from_le_bytes(make_array(&pt_block[32..])),
                    u32::from_le_bytes(make_array(&pt_block[36..])),
                    u32::from_le_bytes(make_array(&pt_block[40..])),
                    u32::from_le_bytes(make_array(&pt_block[44..])),
                    u32::from_le_bytes(make_array(&pt_block[48..])),
                    u32::from_le_bytes(make_array(&pt_block[52..])),
                    u32::from_le_bytes(make_array(&pt_block[56..])),
                    u32::from_le_bytes(make_array(&pt_block[60..])),
                ];

                for i in 0..16 {
                    blk[i] ^= pt32[i];
                }

                blk[pt.len() / 4] &= (0xffffffff_u64 >> (32 - (8 * (pt.len() as u32 % 4)))) as u32;
                for i in (pt.len() / 4 + 1)..16 {
                    blk[i] = 0;
                }

                acc = poly_step(acc, [blk[0], blk[1], blk[2], blk[3]], poly_key);
                PUTU32LE!(pt_block, 0, blk[0]);
                PUTU32LE!(pt_block, 4, blk[1]);
                PUTU32LE!(pt_block, 8, blk[2]);
                PUTU32LE!(pt_block, 12, blk[3]);
                if pt.len() > 16 {
                    acc = poly_step(acc, [blk[4], blk[5], blk[6], blk[7]], poly_key);
                    PUTU32LE!(pt_block, 16, blk[4]);
                    PUTU32LE!(pt_block, 20, blk[5]);
                    PUTU32LE!(pt_block, 24, blk[6]);
                    PUTU32LE!(pt_block, 28, blk[7]);
                }
                if pt.len() > 32 {
                    acc = poly_step(acc, [blk[8], blk[9], blk[10], blk[11]], poly_key);
                    PUTU32LE!(pt_block, 32, blk[8]);
                    PUTU32LE!(pt_block, 36, blk[9]);
                    PUTU32LE!(pt_block, 40, blk[10]);
                    PUTU32LE!(pt_block, 44, blk[11]);
                }
                if pt.len() > 48 {
                    acc = poly_step(acc, [blk[12], blk[13], blk[14], blk[15]], poly_key);
                    PUTU32LE!(pt_block, 48, blk[12]);
                    PUTU32LE!(pt_block, 52, blk[13]);
                    PUTU32LE!(pt_block, 56, blk[14]);
                    PUTU32LE!(pt_block, 60, blk[15]);
                }

                ct[enced..enced + pt.len()].copy_from_slice(&pt_block[..pt.len()]);
                enced += pt.len();
                break;
            }
        }

        acc = poly_step(
            acc,
            [
                hashed as u32,
                ((hashed as u64) >> 32) as u32,
                enced as u32,
                ((enced as u64) >> 32) as u32,
            ],
            poly_key,
        );

        let acc = acc % Poly1305;

        let mut acc0 = u128::from(acc.0[0]);
        let mut acc1 = u128::from(acc.0[1]);

        acc0 = acc0.wrapping_add(u128::from(poly_enc.0[0]));
        acc1 = acc1
            .wrapping_add(acc0 >> 64)
            .wrapping_add(u128::from(poly_enc.0[1]));

        ct[enced] = acc0 as u8;
        ct[enced + 1] = (acc0 >> 8) as u8;
        ct[enced + 2] = (acc0 >> 16) as u8;
        ct[enced + 3] = (acc0 >> 24) as u8;
        ct[enced + 4] = (acc0 >> 32) as u8;
        ct[enced + 5] = (acc0 >> 40) as u8;
        ct[enced + 6] = (acc0 >> 48) as u8;
        ct[enced + 7] = (acc0 >> 56) as u8;

        ct[enced + 8] = acc1 as u8;
        ct[enced + 9] = (acc1 >> 8) as u8;
        ct[enced + 10] = (acc1 >> 16) as u8;
        ct[enced + 11] = (acc1 >> 24) as u8;
        ct[enced + 12] = (acc1 >> 32) as u8;
        ct[enced + 13] = (acc1 >> 40) as u8;
        ct[enced + 14] = (acc1 >> 48) as u8;
        ct[enced + 15] = (acc1 >> 56) as u8;

        enced + 16
    }

    #[allow(dead_code)]
    fn open_slow(
        &self,
        mut state: [u32; 16],
        aad: &[u8],
        mut ct: &[u8],
        pt: &mut [u8],
    ) -> (usize, bool) {
        let blk = chacha20_block(state, false);
        state[12] += 1;

        let poly_key = Poly1305R([
            (u64::from(blk[0]) + (u64::from(blk[1]) << 32)) & 0x0FFFFFFC0FFFFFFF,
            (u64::from(blk[2]) + (u64::from(blk[3]) << 32)) & 0x0FFFFFFC0FFFFFFC,
        ]);

        let poly_enc = Poly1305S([
            u64::from(blk[4]) + (u64::from(blk[5]) << 32),
            u64::from(blk[6]) + (u64::from(blk[7]) << 32),
        ]);

        let mut acc = Felem1305([0_u64; 3]);
        let mut hashed = 0;
        let mut enced = 0;

        while aad.len() >= hashed + 16 {
            let mut arr = [0_u8; 16];
            arr[..].copy_from_slice(&aad[hashed..hashed + 16]);
            acc = poly_step(
                acc,
                [
                    u32::from_le_bytes(make_array(&arr[0..])),
                    u32::from_le_bytes(make_array(&arr[4..])),
                    u32::from_le_bytes(make_array(&arr[8..])),
                    u32::from_le_bytes(make_array(&arr[12..])),
                ],
                poly_key,
            );
            hashed += 16;
        }

        if aad.len() > hashed {
            let left = aad.len() - hashed;
            let mut arr = [0_u8; 16];
            arr[..left].copy_from_slice(&aad[hashed..aad.len()]);
            acc = poly_step(
                acc,
                [
                    u32::from_le_bytes(make_array(&arr[0..])),
                    u32::from_le_bytes(make_array(&arr[4..])),
                    u32::from_le_bytes(make_array(&arr[8..])),
                    u32::from_le_bytes(make_array(&arr[12..])),
                ],
                poly_key,
            );
            hashed = aad.len();
        }

        loop {
            if ct.len() == 16 {
                break;
            }

            let mut blk = chacha20_block(state, false);
            state[12] += 1;

            if ct.len() >= 64 + 16 {
                let mut pt_block = [0u8; 64];
                pt_block.copy_from_slice(&ct[0..64]);
                ct = &ct[64..];

                let pt32: [u32; 16] = [
                    u32::from_le_bytes(make_array(&pt_block[0..])),
                    u32::from_le_bytes(make_array(&pt_block[4..])),
                    u32::from_le_bytes(make_array(&pt_block[8..])),
                    u32::from_le_bytes(make_array(&pt_block[12..])),
                    u32::from_le_bytes(make_array(&pt_block[16..])),
                    u32::from_le_bytes(make_array(&pt_block[20..])),
                    u32::from_le_bytes(make_array(&pt_block[24..])),
                    u32::from_le_bytes(make_array(&pt_block[28..])),
                    u32::from_le_bytes(make_array(&pt_block[32..])),
                    u32::from_le_bytes(make_array(&pt_block[36..])),
                    u32::from_le_bytes(make_array(&pt_block[40..])),
                    u32::from_le_bytes(make_array(&pt_block[44..])),
                    u32::from_le_bytes(make_array(&pt_block[48..])),
                    u32::from_le_bytes(make_array(&pt_block[52..])),
                    u32::from_le_bytes(make_array(&pt_block[56..])),
                    u32::from_le_bytes(make_array(&pt_block[60..])),
                ];

                acc = poly_step(acc, [pt32[0], pt32[1], pt32[2], pt32[3]], poly_key);
                acc = poly_step(acc, [pt32[4], pt32[5], pt32[6], pt32[7]], poly_key);
                acc = poly_step(acc, [pt32[8], pt32[9], pt32[10], pt32[11]], poly_key);
                acc = poly_step(acc, [pt32[12], pt32[13], pt32[14], pt32[15]], poly_key);

                for i in 0..16 {
                    blk[i] ^= pt32[i];
                }

                PUTU32LE!(pt_block, 0, blk[0]);
                PUTU32LE!(pt_block, 4, blk[1]);
                PUTU32LE!(pt_block, 8, blk[2]);
                PUTU32LE!(pt_block, 12, blk[3]);
                PUTU32LE!(pt_block, 16, blk[4]);
                PUTU32LE!(pt_block, 20, blk[5]);
                PUTU32LE!(pt_block, 24, blk[6]);
                PUTU32LE!(pt_block, 28, blk[7]);
                PUTU32LE!(pt_block, 32, blk[8]);
                PUTU32LE!(pt_block, 36, blk[9]);
                PUTU32LE!(pt_block, 40, blk[10]);
                PUTU32LE!(pt_block, 44, blk[11]);
                PUTU32LE!(pt_block, 48, blk[12]);
                PUTU32LE!(pt_block, 52, blk[13]);
                PUTU32LE!(pt_block, 56, blk[14]);
                PUTU32LE!(pt_block, 60, blk[15]);

                pt[enced..enced + 64].copy_from_slice(&pt_block);
                enced += 64;
            } else {
                let left = ct.len() - 16;
                let mut pt_block = [0u8; 64];
                pt_block[..left].copy_from_slice(&ct[..left]);
                ct = &ct[left..];

                let pt32: [u32; 16] = [
                    u32::from_le_bytes(make_array(&pt_block[0..])),
                    u32::from_le_bytes(make_array(&pt_block[4..])),
                    u32::from_le_bytes(make_array(&pt_block[8..])),
                    u32::from_le_bytes(make_array(&pt_block[12..])),
                    u32::from_le_bytes(make_array(&pt_block[16..])),
                    u32::from_le_bytes(make_array(&pt_block[20..])),
                    u32::from_le_bytes(make_array(&pt_block[24..])),
                    u32::from_le_bytes(make_array(&pt_block[28..])),
                    u32::from_le_bytes(make_array(&pt_block[32..])),
                    u32::from_le_bytes(make_array(&pt_block[36..])),
                    u32::from_le_bytes(make_array(&pt_block[40..])),
                    u32::from_le_bytes(make_array(&pt_block[44..])),
                    u32::from_le_bytes(make_array(&pt_block[48..])),
                    u32::from_le_bytes(make_array(&pt_block[52..])),
                    u32::from_le_bytes(make_array(&pt_block[56..])),
                    u32::from_le_bytes(make_array(&pt_block[60..])),
                ];

                acc = poly_step(acc, [pt32[0], pt32[1], pt32[2], pt32[3]], poly_key);

                if left > 16 {
                    acc = poly_step(acc, [pt32[4], pt32[5], pt32[6], pt32[7]], poly_key);
                }
                if left > 32 {
                    acc = poly_step(acc, [pt32[8], pt32[9], pt32[10], pt32[11]], poly_key);
                }
                if left > 48 {
                    acc = poly_step(acc, [pt32[12], pt32[13], pt32[14], pt32[15]], poly_key);
                }

                for i in 0..16 {
                    blk[i] ^= pt32[i];
                }

                PUTU32LE!(pt_block, 0, blk[0]);
                PUTU32LE!(pt_block, 4, blk[1]);
                PUTU32LE!(pt_block, 8, blk[2]);
                PUTU32LE!(pt_block, 12, blk[3]);
                if pt.len() > 16 {
                    PUTU32LE!(pt_block, 16, blk[4]);
                    PUTU32LE!(pt_block, 20, blk[5]);
                    PUTU32LE!(pt_block, 24, blk[6]);
                    PUTU32LE!(pt_block, 28, blk[7]);
                }
                if pt.len() > 32 {
                    PUTU32LE!(pt_block, 32, blk[8]);
                    PUTU32LE!(pt_block, 36, blk[9]);
                    PUTU32LE!(pt_block, 40, blk[10]);
                    PUTU32LE!(pt_block, 44, blk[11]);
                }
                if pt.len() > 48 {
                    PUTU32LE!(pt_block, 48, blk[12]);
                    PUTU32LE!(pt_block, 52, blk[13]);
                    PUTU32LE!(pt_block, 56, blk[14]);
                    PUTU32LE!(pt_block, 60, blk[15]);
                }

                pt[enced..enced + left].copy_from_slice(&pt_block[..left]);
                enced += left;
                break;
            }
        }

        acc = poly_step(
            acc,
            [
                hashed as u32,
                ((hashed as u64) >> 32) as u32,
                enced as u32,
                ((enced as u64) >> 32) as u32,
            ],
            poly_key,
        );

        let mut t0 = u128::from(acc.0[0]);
        let t1 = u128::from(acc.0[1]);
        let mut t2 = u128::from(acc.0[2]);

        let mut acc0 = t0;
        let mut acc1 = t1;

        t0 = t2 & 0xfffffffffffffffc;
        t2 >>= 2;

        acc0 = acc0.wrapping_add(t0);
        acc1 = acc1.wrapping_add(acc0 >> 64);

        acc0 &= 0xffff_ffff_ffff_ffff;
        acc1 &= 0xffff_ffff_ffff_ffff;

        acc0 = acc0.wrapping_add(t2);
        acc1 = acc1.wrapping_add(acc0 >> 64);

        acc0 &= 0xffff_ffff_ffff_ffff;
        acc1 &= 0xffff_ffff_ffff_ffff;

        acc0 = acc0.wrapping_add(u128::from(poly_enc.0[0]));
        acc1 = acc1
            .wrapping_add(u128::from(poly_enc.0[1]))
            .wrapping_add(acc0 >> 64);

        let acc0 = acc0 as u64;
        let acc1 = acc1 as u64;

        let ref_acc0 = u64::from_le_bytes(make_array(&ct[0..]));
        let ref_acc1 = u64::from_le_bytes(make_array(&ct[8..]));

        let ok = ((ref_acc0 ^ acc0) | (ref_acc1 ^ acc1)) == 0;
        (enced, ok)
    }

    fn seal192(&self, state: [u32; 16], aad: &[u8], mut pt: &[u8], ct: &mut [u8]) -> usize {
        let a_init = [state[0], state[1], state[2], state[3]];
        let b_init = [state[4], state[5], state[6], state[7]];
        let c_init = [state[8], state[9], state[10], state[11]];
        let d_init = [state[12], state[13], state[14], state[15]];
        let inc_vec = Vec16([[0, 0, 0, 0], [1, 0, 0, 0], [2, 0, 0, 0], [3, 0, 0, 0]]);

        let a_block = Vec16([a_init, a_init, a_init, a_init]);
        let b_block = Vec16([b_init, b_init, b_init, b_init]);
        let c_block = Vec16([c_init, c_init, c_init, c_init]);
        let mut d_block = Vec16([d_init, d_init, d_init, d_init]);
        d_block += inc_vec;

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

            b = b.rotr1();
            c = c.rotr2();
            d = d.rotr3();

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

            b = b.rotr3();
            c = c.rotr2();
            d = d.rotr1();
        }

        a += a_block;
        b += b_block;
        c += c_block;
        d += d_block;

        let mut acc = Felem1305([0_u64; 3]);

        let poly_key = Poly1305R([
            (u64::from(a[0]) + (u64::from(a[1]) << 32)) & 0x0FFFFFFC0FFFFFFF,
            (u64::from(a[2]) + (u64::from(a[3]) << 32)) & 0x0FFFFFFC0FFFFFFC,
        ]);

        let poly_enc = Poly1305S([
            u64::from(b[0]) + (u64::from(b[1]) << 32),
            u64::from(b[2]) + (u64::from(b[3]) << 32),
        ]);

        let mut hashed = 0;

        while aad.len() >= hashed + 16 {
            let mut arr = [0_u8; 16];
            arr[..].copy_from_slice(&aad[hashed..hashed + 16]);
            acc = poly_step_u8_slice(acc, &arr, poly_key);
            hashed += 16;
        }

        if aad.len() > hashed {
            let left = aad.len() - hashed;
            let mut arr = [0_u8; 16];
            arr[..left].copy_from_slice(&aad[hashed..aad.len()]);
            acc = poly_step_u8_slice(acc, &arr, poly_key);
            hashed = aad.len();
        }

        let mut out = 0;
        let mut stream_block;

        loop {
            if pt.len() >= 64 {
                assert!(pt.len() >= 64);

                let ct_block = [
                    a[4] ^ u32::from_le_bytes(make_array(&pt[0..])),
                    a[5] ^ u32::from_le_bytes(make_array(&pt[4..])),
                    a[6] ^ u32::from_le_bytes(make_array(&pt[8..])),
                    a[7] ^ u32::from_le_bytes(make_array(&pt[12..])),
                    b[4] ^ u32::from_le_bytes(make_array(&pt[16..])),
                    b[5] ^ u32::from_le_bytes(make_array(&pt[20..])),
                    b[6] ^ u32::from_le_bytes(make_array(&pt[24..])),
                    b[7] ^ u32::from_le_bytes(make_array(&pt[28..])),
                    c[4] ^ u32::from_le_bytes(make_array(&pt[32..])),
                    c[5] ^ u32::from_le_bytes(make_array(&pt[36..])),
                    c[6] ^ u32::from_le_bytes(make_array(&pt[40..])),
                    c[7] ^ u32::from_le_bytes(make_array(&pt[44..])),
                    d[4] ^ u32::from_le_bytes(make_array(&pt[48..])),
                    d[5] ^ u32::from_le_bytes(make_array(&pt[52..])),
                    d[6] ^ u32::from_le_bytes(make_array(&pt[56..])),
                    d[7] ^ u32::from_le_bytes(make_array(&pt[60..])),
                ];

                acc = poly_step(
                    acc,
                    [ct_block[0], ct_block[1], ct_block[2], ct_block[3]],
                    poly_key,
                );
                acc = poly_step(
                    acc,
                    [ct_block[4], ct_block[5], ct_block[6], ct_block[7]],
                    poly_key,
                );
                acc = poly_step(
                    acc,
                    [ct_block[8], ct_block[9], ct_block[10], ct_block[11]],
                    poly_key,
                );
                acc = poly_step(
                    acc,
                    [ct_block[12], ct_block[13], ct_block[14], ct_block[15]],
                    poly_key,
                );

                let mut ct_block_8 = [0u8; 64];
                ct_block_8[0..4].copy_from_slice(&(ct_block[0]).to_le_bytes());
                ct_block_8[4..2 * 4].copy_from_slice(&(ct_block[1]).to_le_bytes());
                ct_block_8[2 * 4..3 * 4].copy_from_slice(&(ct_block[2]).to_le_bytes());
                ct_block_8[3 * 4..4 * 4].copy_from_slice(&(ct_block[3]).to_le_bytes());
                ct_block_8[4 * 4..5 * 4].copy_from_slice(&(ct_block[4]).to_le_bytes());
                ct_block_8[5 * 4..6 * 4].copy_from_slice(&(ct_block[5]).to_le_bytes());
                ct_block_8[6 * 4..7 * 4].copy_from_slice(&(ct_block[6]).to_le_bytes());
                ct_block_8[7 * 4..8 * 4].copy_from_slice(&(ct_block[7]).to_le_bytes());
                ct_block_8[8 * 4..9 * 4].copy_from_slice(&(ct_block[8]).to_le_bytes());
                ct_block_8[9 * 4..10 * 4].copy_from_slice(&(ct_block[9]).to_le_bytes());
                ct_block_8[10 * 4..11 * 4].copy_from_slice(&(ct_block[10]).to_le_bytes());
                ct_block_8[11 * 4..12 * 4].copy_from_slice(&(ct_block[11]).to_le_bytes());
                ct_block_8[12 * 4..13 * 4].copy_from_slice(&(ct_block[12]).to_le_bytes());
                ct_block_8[13 * 4..14 * 4].copy_from_slice(&(ct_block[13]).to_le_bytes());
                ct_block_8[14 * 4..15 * 4].copy_from_slice(&(ct_block[14]).to_le_bytes());
                ct_block_8[15 * 4..16 * 4].copy_from_slice(&(ct_block[15]).to_le_bytes());
                ct[out..out + 64].copy_from_slice(&ct_block_8);
                pt = &pt[64..];
                out += 64;
            } else {
                stream_block = [
                    a[4], a[5], a[6], a[7], b[4], b[5], b[6], b[7], c[4], c[5], c[6], c[7], d[4],
                    d[5], d[6], d[7],
                ];
                break;
            }

            if pt.len() >= 64 {
                assert!(pt.len() >= 64);

                let ct_block = [
                    a[8] ^ u32::from_le_bytes(make_array(&pt[0..])),
                    a[9] ^ u32::from_le_bytes(make_array(&pt[4..])),
                    a[10] ^ u32::from_le_bytes(make_array(&pt[8..])),
                    a[11] ^ u32::from_le_bytes(make_array(&pt[12..])),
                    b[8] ^ u32::from_le_bytes(make_array(&pt[16..])),
                    b[9] ^ u32::from_le_bytes(make_array(&pt[20..])),
                    b[10] ^ u32::from_le_bytes(make_array(&pt[24..])),
                    b[11] ^ u32::from_le_bytes(make_array(&pt[28..])),
                    c[8] ^ u32::from_le_bytes(make_array(&pt[32..])),
                    c[9] ^ u32::from_le_bytes(make_array(&pt[36..])),
                    c[10] ^ u32::from_le_bytes(make_array(&pt[40..])),
                    c[11] ^ u32::from_le_bytes(make_array(&pt[44..])),
                    d[8] ^ u32::from_le_bytes(make_array(&pt[48..])),
                    d[9] ^ u32::from_le_bytes(make_array(&pt[52..])),
                    d[10] ^ u32::from_le_bytes(make_array(&pt[56..])),
                    d[11] ^ u32::from_le_bytes(make_array(&pt[60..])),
                ];

                acc = poly_step(
                    acc,
                    [ct_block[0], ct_block[1], ct_block[2], ct_block[3]],
                    poly_key,
                );
                acc = poly_step(
                    acc,
                    [ct_block[4], ct_block[5], ct_block[6], ct_block[7]],
                    poly_key,
                );
                acc = poly_step(
                    acc,
                    [ct_block[8], ct_block[9], ct_block[10], ct_block[11]],
                    poly_key,
                );
                acc = poly_step(
                    acc,
                    [ct_block[12], ct_block[13], ct_block[14], ct_block[15]],
                    poly_key,
                );

                let mut ct_block_8 = [0u8; 64];
                ct_block_8[0..4].copy_from_slice(&(ct_block[0]).to_le_bytes());
                ct_block_8[4..2 * 4].copy_from_slice(&(ct_block[1]).to_le_bytes());
                ct_block_8[2 * 4..3 * 4].copy_from_slice(&(ct_block[2]).to_le_bytes());
                ct_block_8[3 * 4..4 * 4].copy_from_slice(&(ct_block[3]).to_le_bytes());
                ct_block_8[4 * 4..5 * 4].copy_from_slice(&(ct_block[4]).to_le_bytes());
                ct_block_8[5 * 4..6 * 4].copy_from_slice(&(ct_block[5]).to_le_bytes());
                ct_block_8[6 * 4..7 * 4].copy_from_slice(&(ct_block[6]).to_le_bytes());
                ct_block_8[7 * 4..8 * 4].copy_from_slice(&(ct_block[7]).to_le_bytes());
                ct_block_8[8 * 4..9 * 4].copy_from_slice(&(ct_block[8]).to_le_bytes());
                ct_block_8[9 * 4..10 * 4].copy_from_slice(&(ct_block[9]).to_le_bytes());
                ct_block_8[10 * 4..11 * 4].copy_from_slice(&(ct_block[10]).to_le_bytes());
                ct_block_8[11 * 4..12 * 4].copy_from_slice(&(ct_block[11]).to_le_bytes());
                ct_block_8[12 * 4..13 * 4].copy_from_slice(&(ct_block[12]).to_le_bytes());
                ct_block_8[13 * 4..14 * 4].copy_from_slice(&(ct_block[13]).to_le_bytes());
                ct_block_8[14 * 4..15 * 4].copy_from_slice(&(ct_block[14]).to_le_bytes());
                ct_block_8[15 * 4..16 * 4].copy_from_slice(&(ct_block[15]).to_le_bytes());
                ct[out..out + 64].copy_from_slice(&ct_block_8);
                pt = &pt[64..];
                out += 64;
            } else {
                stream_block = [
                    a[8], a[9], a[10], a[11], b[8], b[9], b[10], b[11], c[8], c[9], c[10], c[11],
                    d[8], d[9], d[10], d[11],
                ];
                break;
            }

            if pt.len() >= 64 {
                assert!(pt.len() >= 64);

                let ct_block = [
                    a[12] ^ u32::from_le_bytes(make_array(&pt[0..])),
                    a[13] ^ u32::from_le_bytes(make_array(&pt[4..])),
                    a[14] ^ u32::from_le_bytes(make_array(&pt[8..])),
                    a[15] ^ u32::from_le_bytes(make_array(&pt[12..])),
                    b[12] ^ u32::from_le_bytes(make_array(&pt[16..])),
                    b[13] ^ u32::from_le_bytes(make_array(&pt[20..])),
                    b[14] ^ u32::from_le_bytes(make_array(&pt[24..])),
                    b[15] ^ u32::from_le_bytes(make_array(&pt[28..])),
                    c[12] ^ u32::from_le_bytes(make_array(&pt[32..])),
                    c[13] ^ u32::from_le_bytes(make_array(&pt[36..])),
                    c[14] ^ u32::from_le_bytes(make_array(&pt[40..])),
                    c[15] ^ u32::from_le_bytes(make_array(&pt[44..])),
                    d[12] ^ u32::from_le_bytes(make_array(&pt[48..])),
                    d[13] ^ u32::from_le_bytes(make_array(&pt[52..])),
                    d[14] ^ u32::from_le_bytes(make_array(&pt[56..])),
                    d[15] ^ u32::from_le_bytes(make_array(&pt[60..])),
                ];

                acc = poly_step(
                    acc,
                    [ct_block[0], ct_block[1], ct_block[2], ct_block[3]],
                    poly_key,
                );
                acc = poly_step(
                    acc,
                    [ct_block[4], ct_block[5], ct_block[6], ct_block[7]],
                    poly_key,
                );
                acc = poly_step(
                    acc,
                    [ct_block[8], ct_block[9], ct_block[10], ct_block[11]],
                    poly_key,
                );
                acc = poly_step(
                    acc,
                    [ct_block[12], ct_block[13], ct_block[14], ct_block[15]],
                    poly_key,
                );

                let mut ct_block_8 = [0u8; 64];
                ct_block_8[0..4].copy_from_slice(&(ct_block[0]).to_le_bytes());
                ct_block_8[4..2 * 4].copy_from_slice(&(ct_block[1]).to_le_bytes());
                ct_block_8[2 * 4..3 * 4].copy_from_slice(&(ct_block[2]).to_le_bytes());
                ct_block_8[3 * 4..4 * 4].copy_from_slice(&(ct_block[3]).to_le_bytes());
                ct_block_8[4 * 4..5 * 4].copy_from_slice(&(ct_block[4]).to_le_bytes());
                ct_block_8[5 * 4..6 * 4].copy_from_slice(&(ct_block[5]).to_le_bytes());
                ct_block_8[6 * 4..7 * 4].copy_from_slice(&(ct_block[6]).to_le_bytes());
                ct_block_8[7 * 4..8 * 4].copy_from_slice(&(ct_block[7]).to_le_bytes());
                ct_block_8[8 * 4..9 * 4].copy_from_slice(&(ct_block[8]).to_le_bytes());
                ct_block_8[9 * 4..10 * 4].copy_from_slice(&(ct_block[9]).to_le_bytes());
                ct_block_8[10 * 4..11 * 4].copy_from_slice(&(ct_block[10]).to_le_bytes());
                ct_block_8[11 * 4..12 * 4].copy_from_slice(&(ct_block[11]).to_le_bytes());
                ct_block_8[12 * 4..13 * 4].copy_from_slice(&(ct_block[12]).to_le_bytes());
                ct_block_8[13 * 4..14 * 4].copy_from_slice(&(ct_block[13]).to_le_bytes());
                ct_block_8[14 * 4..15 * 4].copy_from_slice(&(ct_block[14]).to_le_bytes());
                ct_block_8[15 * 4..16 * 4].copy_from_slice(&(ct_block[15]).to_le_bytes());
                ct[out..out + 64].copy_from_slice(&ct_block_8);
                out += 64;
                acc = poly_len(acc, hashed as u64, out as u64, poly_key);

                let mut t0 = u128::from(acc.0[0]);
                let t1 = u128::from(acc.0[1]);
                let mut t2 = u128::from(acc.0[2]);

                let mut acc0 = t0;
                let mut acc1 = t1;

                t0 = t2 & 0xffff_ffff_ffff_fffc;
                t2 >>= 2;

                acc0 = acc0.wrapping_add(t0);
                acc1 = acc1.wrapping_add(acc0 >> 64);

                acc0 &= 0xffff_ffff_ffff_ffff;
                acc1 &= 0xffff_ffff_ffff_ffff;

                acc0 = acc0.wrapping_add(t2);
                acc1 = acc1.wrapping_add(acc0 >> 64);

                acc0 &= 0xffff_ffff_ffff_ffff;
                acc1 &= 0xffff_ffff_ffff_ffff;

                acc0 = acc0.wrapping_add(u128::from(poly_enc.0[0]));
                acc1 = acc1
                    .wrapping_add(u128::from(poly_enc.0[1]))
                    .wrapping_add(acc0 >> 64);

                assert!(ct.len() >= out + 16);
                ct[out..out + 8].copy_from_slice(&(acc0 as u64).to_le_bytes());
                ct[out + 8..out + 16].copy_from_slice(&(acc1 as u64).to_le_bytes());
                return out + 16;
            } else {
                stream_block = [
                    a[12], a[13], a[14], a[15], b[12], b[13], b[14], b[15], c[12], c[13], c[14],
                    c[15], d[12], d[13], d[14], d[15],
                ];
                break;
            }
        }

        if !pt.is_empty() {
            // Partial block
            let mut last_pt = [0u8; 16];
            let mut base = 0;

            while pt.len() >= 16 {
                assert!(pt.len() >= 16);

                stream_block[base] ^= u32::from_le_bytes(make_array(&pt[0..]));
                stream_block[base + 1] ^= u32::from_le_bytes(make_array(&pt[4..]));
                stream_block[base + 2] ^= u32::from_le_bytes(make_array(&pt[8..]));
                stream_block[base + 3] ^= u32::from_le_bytes(make_array(&pt[12..]));
                acc = poly_step(
                    acc,
                    [
                        stream_block[base],
                        stream_block[base + 1],
                        stream_block[base + 2],
                        stream_block[base + 3],
                    ],
                    poly_key,
                );
                let mut ct_block_8 = [0u8; 16];
                ct_block_8[0..4].copy_from_slice(&(stream_block[base]).to_le_bytes());
                ct_block_8[4..2 * 4].copy_from_slice(&(stream_block[base + 1]).to_le_bytes());
                ct_block_8[2 * 4..3 * 4].copy_from_slice(&(stream_block[base + 2]).to_le_bytes());
                ct_block_8[3 * 4..4 * 4].copy_from_slice(&(stream_block[base + 3]).to_le_bytes());
                ct[out..out + 16].copy_from_slice(&ct_block_8);
                pt = &pt[16..];
                out += 16;
                base += 4;
            }

            if !pt.is_empty() {
                last_pt[..pt.len()].copy_from_slice(&pt[..]);
                stream_block[base] ^= u32::from_le_bytes(make_array(&last_pt[0..]));
                stream_block[base + 1] ^= u32::from_le_bytes(make_array(&last_pt[4..]));
                stream_block[base + 2] ^= u32::from_le_bytes(make_array(&last_pt[8..]));
                stream_block[base + 3] ^= u32::from_le_bytes(make_array(&last_pt[12..]));

                let mut ct_block_8 = [0u8; 16];
                ct_block_8[0..4].copy_from_slice(&(stream_block[base]).to_le_bytes());
                ct_block_8[4..2 * 4].copy_from_slice(&(stream_block[base + 1]).to_le_bytes());
                ct_block_8[2 * 4..3 * 4].copy_from_slice(&(stream_block[base + 2]).to_le_bytes());
                ct_block_8[3 * 4..4 * 4].copy_from_slice(&(stream_block[base + 3]).to_le_bytes());
                for i in pt.len()..16 {
                    ct_block_8[i] = 0;
                }
                acc = poly_step(
                    acc,
                    [
                        u32::from_le_bytes(make_array(&ct_block_8[0..])),
                        u32::from_le_bytes(make_array(&ct_block_8[4..])),
                        u32::from_le_bytes(make_array(&ct_block_8[8..])),
                        u32::from_le_bytes(make_array(&ct_block_8[12..])),
                    ],
                    poly_key,
                );
                ct[out..out + pt.len()].copy_from_slice(&ct_block_8[..pt.len()]);
                out += pt.len();
            }
        }

        let (a0, a1) = poly_final(acc, hashed as u64, out as u64, poly_key, poly_enc);
        assert!(ct.len() >= out + 16);
        ct[out..out + 8].copy_from_slice(&a0.to_le_bytes());
        ct[out + 8..out + 16].copy_from_slice(&a1.to_le_bytes());
        return out + 16;
    }

    fn aead_init_wg(&self, nonce_ctr: u64) -> [u32; 16] {
        [
            0x61707865,
            0x3320646e,
            0x79622d32,
            0x6b206574,
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
            0x61707865,
            0x3320646e,
            0x79622d32,
            0x6b206574,
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
            0x61707865,
            0x3320646e,
            0x79622d32,
            0x6b206574,
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
            0x61707865,
            0x3320646e,
            0x79622d32,
            0x6b206574,
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

    pub fn seal_wg(
        &self,
        nonce_ctr: u64,
        aad: &[u8],
        plaintext: &[u8],
        ciphertext: &mut [u8],
    ) -> usize {
        assert!(plaintext.len() <= ciphertext.len() + 16);

        let state = self.aead_init_wg(nonce_ctr);

        if plaintext.len() <= 192 {
            return self.seal192(state, aad, plaintext, ciphertext);
        }
        return self.seal_slow(state, aad, plaintext, ciphertext);
    }

    pub fn open_wg(
        &self,
        nonce_ctr: u64,
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, WireGuardError> {
        assert!(plaintext.len() + 16 >= ciphertext.len());

        let state = self.aead_init_wg(nonce_ctr);

        let (n, ok) = self.open_slow(state, aad, ciphertext, plaintext);
        if ok {
            return Ok(n);
        }

        for p in plaintext {
            *p = 0;
        }

        return Err(WireGuardError::InvalidAeadTag);
    }

    pub fn seal(&self, nonce: &[u8], aad: &[u8], plaintext: &[u8], ciphertext: &mut [u8]) -> usize {
        assert!(plaintext.len() <= ciphertext.len() + 16);

        let state = self.aead_init(nonce);

        if plaintext.len() <= 192 {
            return self.seal192(state, aad, plaintext, ciphertext);
        }
        return self.seal_slow(state, aad, plaintext, ciphertext);
    }

    pub fn open(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, WireGuardError> {
        assert!(plaintext.len() + 16 >= ciphertext.len());
        let state = self.aead_init(nonce);

        let (n, ok) = self.open_slow(state, aad, ciphertext, plaintext);
        if ok {
            return Ok(n);
        }

        for p in plaintext {
            *p = 0;
        }

        Err(WireGuardError::InvalidAeadTag)
    }

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

    pub fn xopen(
        &self,
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8],
    ) -> Result<usize, WireGuardError> {
        assert!(plaintext.len() + 16 >= ciphertext.len());
        let state = self.xaead_init(nonce);
        let (n, ok) = self.open_slow(state, aad, ciphertext, plaintext);
        if ok {
            return Ok(n);
        }

        for p in plaintext {
            *p = 0;
        }

        Err(WireGuardError::InvalidAeadTag)
    }
}

#[derive(Debug, Clone, Copy)]
struct Vec16([[u32; 4]; 4]);
impl AddAssign for Vec16 {
    fn add_assign(&mut self, other: Vec16) {
        for i in 0..4 {
            self.0[0][i] = self.0[0][i].wrapping_add(other.0[0][i]);
            self.0[1][i] = self.0[1][i].wrapping_add(other.0[1][i]);
            self.0[2][i] = self.0[2][i].wrapping_add(other.0[2][i]);
            self.0[3][i] = self.0[3][i].wrapping_add(other.0[3][i]);
        }
    }
}

impl BitXorAssign for Vec16 {
    fn bitxor_assign(&mut self, other: Vec16) {
        for i in 0..4 {
            self.0[0][i] = self.0[0][i] ^ other.0[0][i];
            self.0[1][i] = self.0[1][i] ^ other.0[1][i];
            self.0[2][i] = self.0[2][i] ^ other.0[2][i];
            self.0[3][i] = self.0[3][i] ^ other.0[3][i];
        }
    }
}

impl ShlAssign<u32> for Vec16 {
    fn shl_assign(&mut self, other: u32) {
        for i in 0..4 {
            self.0[0][i] = self.0[0][i].rotate_left(other);
            self.0[1][i] = self.0[1][i].rotate_left(other);
            self.0[2][i] = self.0[2][i].rotate_left(other);
            self.0[3][i] = self.0[3][i].rotate_left(other);
        }
    }
}

impl Vec16 {
    fn rotr1(&mut self) -> Vec16 {
        Vec16([
            [self.0[0][1], self.0[0][2], self.0[0][3], self.0[0][0]],
            [self.0[1][1], self.0[1][2], self.0[1][3], self.0[1][0]],
            [self.0[2][1], self.0[2][2], self.0[2][3], self.0[2][0]],
            [self.0[3][1], self.0[3][2], self.0[3][3], self.0[3][0]],
        ])
    }

    fn rotr2(&mut self) -> Vec16 {
        Vec16([
            [self.0[0][2], self.0[0][3], self.0[0][0], self.0[0][1]],
            [self.0[1][2], self.0[1][3], self.0[1][0], self.0[1][1]],
            [self.0[2][2], self.0[2][3], self.0[2][0], self.0[2][1]],
            [self.0[3][2], self.0[3][3], self.0[3][0], self.0[3][1]],
        ])
    }

    fn rotr3(&mut self) -> Vec16 {
        Vec16([
            [self.0[0][3], self.0[0][0], self.0[0][1], self.0[0][2]],
            [self.0[1][3], self.0[1][0], self.0[1][1], self.0[1][2]],
            [self.0[2][3], self.0[2][0], self.0[2][1], self.0[2][2]],
            [self.0[3][3], self.0[3][0], self.0[3][1], self.0[3][2]],
        ])
    }
}

impl Index<usize> for Vec16 {
    type Output = u32;

    fn index(&self, idx: usize) -> &u32 {
        &self.0[idx / 4][idx % 4]
    }
}
