use boringtun::crypto::Blake2s;
use criterion::{BenchmarkId, Criterion, Throughput};

pub fn bench_blake2s(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake2s");

    group.sample_size(1000);

    for size in [128, 1024] {
        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            let buf_in = vec![0u8; size];

            b.iter(|| {
                Blake2s::new_hash().hash(&buf_in).finalize();
                buf_in.len()
            });
        });
    }

    group.finish();
}
