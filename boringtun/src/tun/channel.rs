use either::Either;
use std::{io, iter};
use tokio::sync::mpsc;

use crate::{
    packet::{Ip, Ipv4, Ipv6, Packet, PacketBufPool, Udp},
    tun::{IpRecv, IpSend},
};

pub use crate::udp::channel::new_udp_tun_channel;
pub use fragmentation::Ipv4Fragments;

/// An implementation of [`IpRecv`] using tokio channels. Create using
/// [`get_packet_channels`].
pub struct TunChannelRx {
    pub(crate) tun_rx: mpsc::Receiver<Packet<Ip>>,
}

/// An implementation of [`IpSend`] using tokio channels. Create using
/// [`get_packet_channels`].
pub struct TunChannelTx {
    pub(crate) tun_tx_v4: mpsc::Sender<Packet<Ipv4<Udp>>>,
    pub(crate) tun_tx_v6: mpsc::Sender<Packet<Ipv6<Udp>>>,

    /// A map of fragments, keyed by a tuple of (identification, source IP, destination IP).
    /// The value is a BTreeMap of fragment offsets to the corresponding fragments.
    /// The BTreeMap is used to ensure that fragments are kept in order, even if they arrive out of
    /// order. This is used to efficiently check if all fragments have been received.
    pub(crate) fragments_v4: Ipv4Fragments,
    // TODO: Ipv6 fragments?
}

impl IpSend for TunChannelTx {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        let ip_packet = match packet.try_into_ipvx() {
            Ok(p) => p,
            Err(e) => {
                log::trace!("Invalid IP packet: {e:?}");
                return Ok(());
            }
        };

        match ip_packet {
            Either::Left(ipv4) => {
                let ipv4 = if ipv4.header.fragment_offset() == 0 && !ipv4.header.more_fragments() {
                    ipv4
                } else if let Some(ipv4) = self.fragments_v4.assemble_ipv4_fragment(ipv4) {
                    ipv4
                } else {
                    // No complete IPv4 packet was reassembled, nothing to do
                    return Ok(());
                };

                match ipv4.try_into_udp() {
                    Ok(udp_packet) => {
                        self.tun_tx_v4
                            .send(udp_packet)
                            .await
                            .expect("receiver exists");
                    }
                    Err(e) => log::trace!("Invalid UDP packet: {e:?}"),
                }
            }
            Either::Right(ipv6) => match ipv6.try_into_udp() {
                Ok(udp_packet) => {
                    self.tun_tx_v6
                        .send(udp_packet)
                        .await
                        .expect("receiver exists");
                }
                Err(e) => log::trace!("Invalid UDP packet: {e:?}"),
            },
        }

        Ok(())
    }
}

impl IpRecv for TunChannelRx {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let Some(packet) = self.tun_rx.recv().await else {
            log::trace!("tun_rx sender dropped and no more packet can be received");
            let () = std::future::pending().await;
            unreachable!();
        };
        Ok(iter::once(packet))
    }
}

mod fragmentation {
    use zerocopy::{FromBytes, FromZeros};

    use crate::packet::{Ipv4Header, Udp};
    use std::{collections::VecDeque, net::Ipv4Addr};

    use crate::packet::{Ipv4, Packet};

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    struct FragmentId {
        identification: u16,
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
    }

    // TODO: Switch to a total memory limit
    /// The maximum number of unique fragmented IPv4 that can be concurrently assembled.
    /// When this limit is reached, the fragments belonging to the oldest packet is dropped
    /// to make space.
    ///
    /// The sum of all fragments for a given packet cannot exceed the maximum IPv4 length,
    /// which is 65535 bytes. In total, this means that the maximum size that can be
    /// buffered is 64 * 65535 = 4194304 bytes, or 4 MiB.
    const MAX_CONCURRENT_FRAGS: usize = 64;

    #[derive(Debug)]
    pub struct Ipv4Fragments {
        // The `VecDeque` is holds the fragments for each unique packet being assembled.
        // It is also a FIFO queue, so that the oldest fragments are dropped when the maximum
        // number of fragments is reached. The inner `Vec` is used to store the fragments.
        // INVARIANT: The inner `Vec` must always be sorted by fragment_offset
        fragments: VecDeque<(FragmentId, Vec<Packet<Ipv4>>)>,
    }

    impl Default for Ipv4Fragments {
        fn default() -> Self {
            Self {
                fragments: VecDeque::with_capacity(MAX_CONCURRENT_FRAGS),
            }
        }
    }

    impl Ipv4Fragments {
        /// Return the number of unique packets that are currently being assembled.
        pub fn incomplete_packet_count(&self) -> usize {
            self.fragments.len()
        }

        pub fn assemble_ipv4_fragment(
            &mut self,
            ipv4_packet: Packet<Ipv4>,
        ) -> Option<Packet<Ipv4>> {
            let fragment_map = &mut self.fragments;
            let header = ipv4_packet.header;
            let fragment_offset = header.fragment_offset();
            let more_fragments = header.more_fragments();
            debug_assert!(more_fragments || fragment_offset != 0);

            // All fragments except the last must have a length that is a multiple of 8
            // bytes, and the last fragment must not exceed the maximum IPv4 length.
            let fragment_len = ipv4_packet.payload.len();
            if (more_fragments && fragment_len % 8 != 0)
                || fragment_len + fragment_offset as usize * 8 > Ipv4::MAX_LEN
            {
                log::trace!(
                    "Invalid fragment size: {fragment_len} or fragment offset: {fragment_offset}, dropping"
                );
                return None;
            }

            let id = get_frag_id(&ipv4_packet);

            let Some(frag_pos) = fragment_map.iter_mut().position(|(id2, _)| id2 == &id) else {
                if fragment_map.len() >= MAX_CONCURRENT_FRAGS {
                    let (dropped_id, _) =
                        fragment_map.pop_front().expect("Fragment map is not empty");
                    log::trace!(
                        "Fragment map at full capacity {MAX_CONCURRENT_FRAGS}, dropping oldest fragment with ID {dropped_id:?} to make space"
                    );
                    // TODO: send "Fragment Reassembly Timeout" ICMP message, per RFC792
                }
                // Since this was the first fragment, we don't check if the packet
                // can be reassembled yet.
                fragment_map.push_back((id, vec![ipv4_packet]));
                return None;
            };
            let (_, fragments) = fragment_map
                .get_mut(frag_pos)
                .expect("Fragment exists because of the above check");

            // Check if the fragment with the same offset already exists.
            let Err(i) =
                fragments.binary_search_by_key(&fragment_offset, |f| f.header.fragment_offset())
            else {
                log::trace!(
                    "Fragment with offset {fragment_offset} already existed for for ID {id:?} and was dropped"
                );
                return None;
            };

            // Check if the new fragment overlaps with existing fragments.
            // Note that the fragments are sorted by fragment_offset, so we only need to check
            // the previous and next fragments.
            if let Some(prev_i) = i.checked_sub(1)
                && let prev_frag_offset = &fragments[prev_i].header.fragment_offset()
                && let prev_frag_len = &fragments[prev_i].payload.len()
                && prev_frag_offset + (prev_frag_len / 8) as u16 > fragment_offset
            {
                log::trace!(
                    "Fragment with offset {fragment_offset} overlaps with existing fragment with offset {prev_frag_offset} and length {prev_frag_len} for ID {id:?}, dropping",
                );
                return None;
            }
            if let Some(next_frag) = fragments.get(i)
                && let next_frag_offset = next_frag.header.fragment_offset()
                && fragment_offset + (fragment_len / 8) as u16 > next_frag_offset
            {
                log::trace!(
                    "Fragment with offset {fragment_offset} and length {fragment_len} overlaps with existing fragment with offset {next_frag_offset} for ID {id:?}, dropping",
                );
                return None;
            }

            fragments.insert(i, ipv4_packet);

            let [first, .., last] = &fragments[..] else {
                unreachable!("There are at least 2 fragments.");
            };
            // Check that we have the first and last fragment
            if last.header.more_fragments() || first.header.fragment_offset() != 0 {
                return None;
            }

            // Check if the IP packet can be reassembled.
            // The fragments must be consecutive, i.e. each fragment must begin where the previous one ended.
            // Note that fragment offset is given in units of 8 bytes.
            let fragment_offsets = fragments.iter().map(|f| f.header.fragment_offset());
            let fragment_ends = fragments
                .iter()
                .map(|f| f.header.fragment_offset() + (f.payload.len() / 8) as u16);
            if !fragment_offsets
                .skip(1)
                .eq(fragment_ends.take(fragments.len() - 1))
            {
                return None;
            }

            let len =
                last.header.fragment_offset() as usize * 8 + last.payload.len() + Ipv4Header::LEN;
            let (_, packet_fragments) = fragment_map
                .remove(frag_pos)
                .expect("The same fragment as we accessed above must exist");
            // To potentially avoid allocating a new packet, we will use the first fragment
            // and extend it with the payloads of the other fragments.
            let mut remaining_fragments = packet_fragments.into_iter();
            let first_packet = remaining_fragments
                .next()
                .expect("At least one fragment exists");

            let mut bytes = first_packet.into_bytes();
            let additional_bytes_needed = len.saturating_sub(bytes.buf_mut().len());
            bytes.buf_mut().reserve(additional_bytes_needed);
            for frag in remaining_fragments {
                bytes.buf_mut().extend_from_slice(&frag.payload);
            }

            // The header of the first packet is updated to reflect that the packet is no
            // longer fragmented.
            {
                let ip = Ipv4::<Udp>::mut_from_bytes(&mut bytes).expect("valid IP packet buffer");
                ip.header.total_len = (len as u16).into();

                // This set `more_fragments`, `dont_fragment`, and `fragment_offset` to zero.
                ip.header.flags_and_fragment_offset.zero();

                // We do not need to recompute the checksum, because the checksum is
                // only read by the `ExitDevice` and discarded
                ip.header.header_checksum.zero();
            }

            // NOTE: We could change the `tun_tx_vx` channels to take a tuple of source ip,
            // destination ip, and `Packet<Udp>`, instead of `Packet<Ipv4<Udp>>`, to avoid
            // having to reconstruct the IP head and validate the IP packet with
            // `try_into_ipvx`
            Some(
                bytes
                    .try_into_ipvx()
                    .expect("Previously valid Ipv4 packet should still be valid")
                    .unwrap_left(),
            )
        }
    }

    fn get_frag_id(ipv4_packet: &Packet<Ipv4>) -> FragmentId {
        FragmentId {
            identification: ipv4_packet.header.identification.get(),
            source_ip: ipv4_packet.header.source(),
            destination_ip: ipv4_packet.header.destination(),
        }
    }

    #[cfg(test)]
    mod test {
        use super::*;
        use crate::packet::{IpNextProtocol, Ipv4FlagsFragmentOffset, Ipv4Header, UdpHeader};
        use bytes::BytesMut;
        use rand::rng;
        use rand::seq::SliceRandom;
        use std::collections::HashMap;
        use std::net::Ipv4Addr;
        use zerocopy::IntoBytes;

        fn make_ip_fragment(
            identification: u16,
            source_ip: Ipv4Addr,
            destination_ip: Ipv4Addr,
            offset: u16,
            more_fragments: bool,
            payload: &[u8],
        ) -> Packet<Ipv4> {
            // Build a minimal UDP payload
            let total_len = Ipv4Header::LEN + payload.len();
            let mut buf = BytesMut::zeroed(total_len);
            let ipv4 = Ipv4::<[u8]>::mut_from_bytes(&mut buf).unwrap();
            ipv4.header = Ipv4Header::new_for_length(
                source_ip,
                destination_ip,
                IpNextProtocol::Udp,
                payload.len() as u16,
            );
            ipv4.header.identification = identification.into();
            let mut flags = Ipv4FlagsFragmentOffset::new();
            flags.set_more_fragments(more_fragments);
            flags.set_fragment_offset(offset);
            ipv4.header.flags_and_fragment_offset = flags;
            ipv4.payload.copy_from_slice(payload);

            Packet::from_bytes(buf)
                .try_into_ipvx()
                .unwrap()
                .unwrap_left()
        }

        fn make_udp_bytes(payload: &[u8]) -> BytesMut {
            let len = UdpHeader::LEN + payload.len();
            let mut buf = BytesMut::zeroed(len);
            let udp = Udp::<[u8]>::mut_from_bytes(&mut buf).unwrap();
            udp.header.source_port = 1234u16.into();
            udp.header.destination_port = 5678u16.into();
            udp.header.length = (len as u16).into();
            udp.header.checksum = 0.into();
            assert_eq!(udp.payload.len(), payload.len());
            udp.payload.copy_from_slice(payload);
            buf
        }

        #[test]
        fn test_ipv4_defragmentation() {
            let mut fragments = Ipv4Fragments::default();
            let src1 = Ipv4Addr::new(10, 0, 0, 1);
            let dst1 = Ipv4Addr::new(10, 0, 0, 2);
            let src2 = Ipv4Addr::new(10, 0, 0, 3);
            let dst2 = Ipv4Addr::new(10, 0, 0, 4);
            let id1 = 100;
            let id2 = 200;
            // Two packets
            let payload1 = make_udp_bytes(b"ABCDEFGHIJKLMN");
            let payload2 = make_udp_bytes(b"MY SLIGHTLY LONGER PACKET");

            // Split each into 3 fragments
            let mut all_frags = vec![
                (
                    id1,
                    make_ip_fragment(id1, src1, dst1, 0, true, &payload1[0..8]),
                ),
                (
                    id1,
                    make_ip_fragment(id1, src1, dst1, 1, true, &payload1[8..16]),
                ),
                (
                    id1,
                    make_ip_fragment(id1, src1, dst1, 2, false, &payload1[16..]),
                ),
                (
                    id2,
                    make_ip_fragment(id2, src2, dst2, 0, true, &payload2[0..16]),
                ),
                (
                    id2,
                    make_ip_fragment(id2, src2, dst2, 2, true, &payload2[16..24]),
                ),
                (
                    id2,
                    make_ip_fragment(id2, src2, dst2, 3, true, &payload2[24..32]),
                ),
                (
                    id2,
                    make_ip_fragment(id2, src2, dst2, 4, false, &payload2[32..]),
                ),
            ];
            all_frags.shuffle(&mut rng());
            let mut seen = HashMap::new();
            for (id, frag) in all_frags {
                let res = fragments.assemble_ipv4_fragment(frag.clone());
                let count = seen.entry(id).or_insert(0);
                *count += 1;
                if let Some(ip_packet) = res {
                    let udp_packet = ip_packet.try_into_udp().unwrap();
                    log::debug!(
                        "Reassembled UDP payload (ascii): {:?}",
                        String::from_utf8_lossy(&udp_packet.payload.payload)
                    );

                    if id == id1 {
                        assert_eq!(*count, 3, "Should reassemble on last fragment");
                        assert_eq!(udp_packet.payload.as_bytes(), &payload1[..]);
                    } else {
                        assert_eq!(*count, 4, "Should reassemble on last fragment");
                        assert_eq!(udp_packet.payload.as_bytes(), &payload2[..]);
                    };
                    assert_eq!(udp_packet.header.fragment_offset(), 0);
                    assert!(!udp_packet.header.more_fragments());
                    assert_eq!(
                        udp_packet.header.source(),
                        if id == id1 { src1 } else { src2 }
                    );
                    assert_eq!(
                        udp_packet.header.destination(),
                        if id == id1 { dst1 } else { dst2 }
                    );
                }

                // Last fragment for this id
            }

            assert_eq!(
                fragments.incomplete_packet_count(),
                0,
                "All fragments should be processed"
            );
        }

        #[test]
        fn test_ipv4_defragmentation_single_packet() {
            let mut fragments = Ipv4Fragments::default();
            let src = Ipv4Addr::new(192, 168, 1, 1);
            let dst = Ipv4Addr::new(192, 168, 1, 2);
            let id = 42;
            let payload = make_udp_bytes(b"HELLOFRAGMENTS");
            // Split into 3 fragments
            let mut frags = vec![
                make_ip_fragment(id, src, dst, 0, true, &payload[0..8]),
                make_ip_fragment(id, src, dst, 1, true, &payload[8..16]),
                make_ip_fragment(id, src, dst, 2, false, &payload[16..]),
            ];
            frags.shuffle(&mut rng());
            let mut count = 0;
            for frag in frags {
                let res = fragments.assemble_ipv4_fragment(frag.clone());
                count += 1;
                if let Some(ip_packet) = res {
                    let udp_packet = ip_packet.try_into_udp().unwrap();
                    log::debug!(
                        "Reassembled UDP payload (ascii): {:?}",
                        String::from_utf8_lossy(&udp_packet.payload.payload)
                    );
                    assert_eq!(count, 3, "Should reassemble on last fragment");
                    assert_eq!(udp_packet.payload.as_bytes(), &payload[..]);
                    assert_eq!(udp_packet.header.fragment_offset(), 0);
                    assert!(!udp_packet.header.more_fragments());
                    assert_eq!(udp_packet.header.source(), src);
                    assert_eq!(udp_packet.header.destination(), dst);
                } else {
                    assert!(count < 3, "Should not reassemble until last fragment");
                }
            }
            assert_eq!(
                fragments.incomplete_packet_count(),
                0,
                "All fragments should be processed"
            );
        }

        #[test]
        fn test_fragment_eviction_max_concurrent_frags() {
            let mut fragments = Ipv4Fragments::default();
            let src = Ipv4Addr::new(1, 2, 3, 4);
            let dst = Ipv4Addr::new(5, 6, 7, 8);
            let payload = make_udp_bytes(b"0123456789");

            let id = 1000;
            // Each packet will be split into 2 fragments
            let old_frag_first_half = make_ip_fragment(id, src, dst, 0, true, &payload[0..8]);
            let old_frag_second_half = make_ip_fragment(id, src, dst, 1, false, &payload[8..]);
            // Only insert the first fragment for now
            assert!(
                fragments
                    .assemble_ipv4_fragment(old_frag_first_half)
                    .is_none()
            );

            let mut second_halves = Vec::new();
            for i in 0..super::MAX_CONCURRENT_FRAGS {
                let id = 1000 + i as u16;
                // Each packet will be split into 2 fragments
                let frag1 = make_ip_fragment(id, src, dst, 0, true, &payload[0..8]);
                let frag2 = make_ip_fragment(id, src, dst, 1, false, &payload[8..]);
                // Only insert the first fragment for now
                assert!(fragments.assemble_ipv4_fragment(frag1).is_none());
                second_halves.push(frag2);
            }
            for second_half in second_halves {
                // Insert the second fragment for all but the oldest
                let res = fragments.assemble_ipv4_fragment(second_half);
                assert!(res.is_some(), "Should reassemble remaining fragments");
            }
            assert!(
                fragments
                    .assemble_ipv4_fragment(old_frag_second_half)
                    .is_none(),
                "Should not reassemble oldest fragment, as first half should have been discarded"
            );

            assert_eq!(
                fragments.incomplete_packet_count(),
                1,
                "Only second half of the first packet should be left"
            );
        }

        #[test]
        /// Test that overlapping fragments are detected and dropped.
        fn test_fragmentation_overlap() {
            let src = Ipv4Addr::new(192, 168, 1, 1);
            let dst = Ipv4Addr::new(192, 168, 1, 2);
            let id = 42;
            let payload = make_udp_bytes(b"HELLOFRAGMENTS");
            // Create two overlapping fragments
            // Note that the `fragmentation_offset` is in units of 8 bytes and should be `2`
            // for the second fragment to not overlap with the first.
            let frag1 = make_ip_fragment(id, src, dst, 0, true, &payload[0..16]);
            let frag2 = make_ip_fragment(id, src, dst, 1, false, &payload[16..]);
            let id = get_frag_id(&frag1);
            let frag_is_buffered = |fragments: &Ipv4Fragments, frag: &Packet<Ipv4>| {
                fragments
                    .fragments
                    .iter()
                    .find(|(id2, _)| id2 == &id)
                    .expect("Fragment ID should exist")
                    .1
                    .iter()
                    .any(|f| f.as_bytes() == frag.as_bytes())
            };

            // Assert that after insert both fragments, no packet is reassembled
            {
                let mut fragments = Ipv4Fragments::default();
                fragments.assemble_ipv4_fragment(frag1.clone());
                assert!(frag_is_buffered(&fragments, &frag1));
                fragments.assemble_ipv4_fragment(frag2.clone());
                assert!(
                    !frag_is_buffered(&fragments, &frag2),
                    "Second fragment should be dropped because it overlaps with the first"
                );
            }

            // Repeat in reverse order
            {
                let mut fragments = Ipv4Fragments::default();
                fragments.assemble_ipv4_fragment(frag2.clone());
                assert!(frag_is_buffered(&fragments, &frag2));
                fragments.assemble_ipv4_fragment(frag1.clone());
                assert!(
                    !frag_is_buffered(&fragments, &frag1),
                    "First fragment should be dropped because it overlaps with the second"
                );
            }
        }
    }
}
