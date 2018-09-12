#![feature(test)]
extern crate test;
extern crate wireguard_cf;

#[cfg(test)]
mod tests {
    use test::{black_box, Bencher};
    use wireguard_cf::crypto::blake2s::*;
    use wireguard_cf::crypto::chacha20poly1305::*;
    use wireguard_cf::crypto::x25519::*;

    #[bench]
    fn bench_x25519_public_key(b: &mut Bencher) {
        let x = [
            9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ];

        let scalar = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];

        b.iter(|| {
            black_box(x25519_shared_key(&x, &scalar));
        });
    }

    #[bench]
    fn bench_x25519_shared_key(b: &mut Bencher) {
        let x = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];

        let scalar = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];

        b.iter(|| {
            black_box(x25519_shared_key(&x, &scalar));
        });
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
