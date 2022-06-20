// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#![feature(test)]
extern crate test;

#[cfg(test)]
mod tests {
    use boringtun::crypto::Blake2s;
    use boringtun::crypto::ChaCha20Poly1305;
    use rand_core::OsRng;
    use test::{black_box, Bencher};
    use x25519_dalek::{PublicKey, StaticSecret};

    #[bench]
    fn bench_x25519_public_key(b: &mut Bencher) {
        let secret_key = StaticSecret::new(OsRng);

        b.iter(|| {
            black_box(PublicKey::from(&secret_key));
        });
    }

    #[bench]
    fn bench_x25519_shared_key(b: &mut Bencher) {
        let secret_key = StaticSecret::new(OsRng);
        let public_key = PublicKey::from(&StaticSecret::new(OsRng));

        b.iter(|| black_box(secret_key.diffie_hellman(&public_key)));
    }

    #[bench]
    fn bench_blake2s_hash_128b(b: &mut Bencher) {
        let data = [0_u8; 128];
        b.iter(|| black_box(Blake2s::new_hash().hash(&data).finalize()));
    }

    #[bench]
    fn bench_blake2s_hash_1024b(b: &mut Bencher) {
        let data = [0_u8; 1024];
        b.iter(|| black_box(Blake2s::new_hash().hash(&data).finalize()));
    }

    #[bench]
    fn bench_chacha20poly1305_seal_192b(b: &mut Bencher) {
        let pc = ChaCha20Poly1305::new_aead(&[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ]);
        let pt = [0_u8; 192];
        let mut ct = [0_u8; 192 + 16];
        b.iter(|| {
            black_box(pc.seal_wg(0, &[], &pt, &mut ct));
        });
    }

    #[bench]
    fn bench_chacha20poly1305_open_192b(b: &mut Bencher) {
        let pc = ChaCha20Poly1305::new_aead(&[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ]);
        let mut pt = [0_u8; 192];
        let mut ct = [0_u8; 192 + 16];

        pc.seal_wg(0, &[], &pt, &mut ct);

        b.iter(|| {
            black_box(pc.open_wg(0, &[], &ct, &mut pt).unwrap());
        });
    }

    #[bench]
    fn bench_chacha20poly1305_seal_512b(b: &mut Bencher) {
        let pc = ChaCha20Poly1305::new_aead(&[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ]);
        let pt = [0_u8; 512];
        let mut ct = [0_u8; 512 + 16];
        b.iter(|| {
            black_box(pc.seal_wg(0, &[], &pt, &mut ct));
        });
    }

    #[bench]
    fn bench_chacha20poly1305_seal_8192b(b: &mut Bencher) {
        let pc = ChaCha20Poly1305::new_aead(&[
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ]);
        let pt = [0_u8; 8192];
        let mut ct = [0_u8; 8192 + 16];
        b.iter(|| {
            black_box(pc.seal_wg(0, &[], &pt, &mut ct));
        });
    }
}
