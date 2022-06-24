use aead::{AeadInPlace, NewAead};
use criterion::{BenchmarkId, Criterion, Throughput};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};

fn chacha20poly1305_ring(key_bytes: &[u8], buf: &mut [u8]) {
    let len = buf.len();
    let n = len - 16;

    let key = LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &key_bytes).unwrap());

    let tag = key
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key([0u8; 12]),
            Aad::from(&[]),
            &mut buf[..n],
        )
        .unwrap();

    buf[n..].copy_from_slice(tag.as_ref())
}

fn chacha20poly1305_non_ring(key_bytes: &[u8], buf: &mut [u8]) {
    let len = buf.len();
    let n = len - 16;

    let aead = chacha20poly1305::ChaCha20Poly1305::new_from_slice(key_bytes).unwrap();
    let nonce = chacha20poly1305::Nonce::default();

    let tag = aead
        .encrypt_in_place_detached(&nonce, &[], &mut buf[..n])
        .unwrap();

    buf[n..].copy_from_slice(tag.as_ref());
}

pub fn bench_chacha20poly1305(c: &mut Criterion) {
    let mut group = c.benchmark_group("chacha20poly1305");

    for size in [128, 192, 1400, 8192] {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("chacha20poly1305_ring", size),
            &size,
            |b, i| {
                let key = [0; 32];
                let mut buf = vec![0; i + 16];

                b.iter(|| chacha20poly1305_ring(&key, &mut buf));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("chacha20poly1305_non_ring", size),
            &size,
            |b, i| {
                let key = [0; 32];
                let mut buf = vec![0; i + 16];

                b.iter(|| chacha20poly1305_non_ring(&key, &mut buf));
            },
        );

        group.bench_with_input(
            BenchmarkId::new("chacha20poly1305_custom", size),
            &size,
            |b, _| {
                let aead = boringtun::crypto::ChaCha20Poly1305::new_aead(&[0u8; 32]);
                let buf_in = vec![0u8; size];
                let mut buf_out = vec![0u8; size + 16];

                b.iter(|| aead.seal_wg(0, &[], &buf_in, &mut buf_out) - 16)
            },
        );
    }

    group.finish();
}
