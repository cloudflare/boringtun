use criterion::Criterion;
use rand_core::OsRng;

pub fn bench_x25519_shared_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("x25519_shared_key");

    group.bench_function("x25519_shared_key_dalek", |b| {
        let secret_key = x25519_dalek::StaticSecret::new(OsRng);
        let public_key = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::new(OsRng));

        b.iter(|| secret_key.diffie_hellman(&public_key));
    });

    group.bench_function("x25519_shared_key_ring", |b| {
        let rng = ring::rand::SystemRandom::new();

        let peer_public_key = {
            let peer_private_key =
                ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &rng)
                    .unwrap();
            peer_private_key.compute_public_key().unwrap()
        };
        let peer_public_key_alg = &ring::agreement::X25519;

        b.iter(|| {
            let my_private_key =
                ring::agreement::EphemeralPrivateKey::generate(&ring::agreement::X25519, &rng)
                    .unwrap();
            let my_public_key =
                ring::agreement::UnparsedPublicKey::new(peer_public_key_alg, &peer_public_key);

            ring::agreement::agree_ephemeral(
                my_private_key,
                &my_public_key,
                ring::error::Unspecified,
                |_key_material| Ok(()),
            )
            .unwrap()
        });
    });

    group.finish();
}