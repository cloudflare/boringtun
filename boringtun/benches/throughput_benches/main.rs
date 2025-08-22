use boringtun::packet::{IpNextProtocol, Ipv4, Ipv4Header, Packet};
use boringtun::udp::channel::Ipv4Fragments;
use bytes::BytesMut;
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rand::rngs::StdRng;
use rand::{SeedableRng, seq::SliceRandom};
use std::hint::black_box;
use std::net::Ipv4Addr;
use zerocopy::FromBytes;

fn fragment_ipv4_packet(identification: u16, payload: &[u8], mtu: usize) -> Vec<Packet<Ipv4>> {
    let ipv4_header_len = 20;
    let max_payload_per_fragment = ((mtu - ipv4_header_len) / 8) * 8; // must be multiple of 8
    let payload_chunks = payload.chunks_exact(max_payload_per_fragment);
    let last_payload = payload_chunks.remainder();
    assert!(!last_payload.is_empty());
    let last_fragment = make_single_fragment(
        identification,
        ((payload.len() - last_payload.len()) / 8) as u16,
        false,
        last_payload,
    );
    payload_chunks
        .zip(0..)
        .map(|(payload, i)| {
            make_single_fragment(
                identification,
                (i * max_payload_per_fragment / 8) as u16,
                true,
                payload,
            )
        })
        .chain(std::iter::once(last_fragment))
        .collect()
}

fn make_single_fragment(
    identification: u16,
    offset: u16,
    more_fragments: bool,
    payload: &[u8],
) -> Packet<Ipv4> {
    let mut buf = BytesMut::zeroed(Ipv4Header::LEN + payload.len()); // TODO: Use PacketBufPool?
    let ipv4 = Ipv4::<[u8]>::mut_from_bytes(&mut buf).unwrap();
    let source_ip = Ipv4Addr::new(10, 0, 0, 1);
    let destination_ip = Ipv4Addr::new(10, 0, 0, 2);
    ipv4.header = Ipv4Header::new(source_ip, destination_ip, IpNextProtocol::Udp, payload);
    ipv4.header.identification = identification.into();
    let mut flags = boringtun::packet::Ipv4FlagsFragmentOffset::new();
    flags.set_more_fragments(more_fragments);
    flags.set_fragment_offset(offset);
    ipv4.header.flags_and_fragment_offset = flags;
    ipv4.payload.copy_from_slice(payload);

    Packet::from_bytes(buf)
        .try_into_ipvx()
        .unwrap()
        .unwrap_left()
}

fn bench_assemble_ipv4_fragment(c: &mut Criterion) {
    let mut fragments = Ipv4Fragments::default();

    let id = 42;
    let mtu = 1500;
    let mut group = c.benchmark_group("assemble_ipv4_fragment");
    for &payload_len in &[2000, 4000, 10000] {
        let payload = vec![0u8; payload_len];
        let frags = fragment_ipv4_packet(id, &payload, mtu);
        group.throughput(criterion::Throughput::Bytes(payload_len as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(payload_len),
            &frags,
            |b, frags| {
                b.iter(|| {
                    for frag in frags {
                        black_box(
                            fragments.assemble_ipv4_fragment(black_box(Packet::copy_from(frag))),
                        );
                    }
                    assert_eq!(fragments.incomplete_packet_count(), 0);
                })
            },
        );
    }
    group.finish();
}

fn bench_assemble_ipv4_fragment_reverse_order(c: &mut Criterion) {
    let mut fragments = Ipv4Fragments::default();

    let id = 42;
    let mtu = 1500;
    let mut group = c.benchmark_group("assemble_ipv4_fragment_reverse_order");
    for &payload_len in &[2000, 4000, 10000] {
        let payload = vec![0u8; payload_len];
        let mut frags = fragment_ipv4_packet(id, &payload, mtu);
        frags.reverse();
        group.throughput(criterion::Throughput::Bytes(payload_len as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(payload_len),
            &frags,
            |b, frags| {
                b.iter(|| {
                    for frag in frags {
                        black_box(
                            fragments.assemble_ipv4_fragment(black_box(Packet::copy_from(frag))),
                        );
                    }
                    assert_eq!(fragments.incomplete_packet_count(), 0);
                })
            },
        );
    }
    group.finish();
}

fn bench_assemble_ipv4_fragment_interleaved(c: &mut Criterion) {
    let mut fragments = Ipv4Fragments::default();

    let mtu = 1500;
    let mut group = c.benchmark_group("assemble_ipv4_fragment_interleaved");
    for (n_packets, payload_len) in [(4, 10000), (16, 4000), (64, 2000)] {
        group.throughput(criterion::Throughput::Bytes(
            (n_packets * payload_len) as u64,
        ));
        let mut all_frags = Vec::new();
        for i in 0..n_packets {
            let id = 1000 + i as u16;
            let payload = vec![i as u8; payload_len];
            let mut frags = fragment_ipv4_packet(id, &payload, mtu);
            all_frags.append(&mut frags);
        }
        // Shuffle with a fixed seed for reproducibility
        let mut rng = StdRng::seed_from_u64(42);
        all_frags.shuffle(&mut rng);
        group.bench_with_input(
            BenchmarkId::from_parameter(format!("{}x{}", n_packets, payload_len)),
            &all_frags,
            |b, all_frags| {
                b.iter(|| {
                    for frag in all_frags {
                        black_box(
                            fragments.assemble_ipv4_fragment(black_box(Packet::copy_from(frag))),
                        );
                    }
                    assert_eq!(fragments.incomplete_packet_count(), 0);
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_assemble_ipv4_fragment,
    bench_assemble_ipv4_fragment_reverse_order,
    bench_assemble_ipv4_fragment_interleaved
);
criterion_main!(benches);
