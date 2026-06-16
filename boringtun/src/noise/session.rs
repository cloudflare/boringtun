// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use super::PacketData;
use crate::noise::errors::WireGuardError;
use portable_atomic::{AtomicU64, Ordering};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use std::hint;

pub struct Session {
    pub(crate) receiving_index: u32,
    sending_index: u32,
    receiver: LessSafeKey,
    sender: LessSafeKey,
    sending_key_counter: AtomicU64,
    receiving_key_counter: ReceivingKeyCounterValidator,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Session: {}<- ->{}",
            self.receiving_index, self.sending_index
        )
    }
}

/// Where encrypted data resides in a data packet
const DATA_OFFSET: usize = 16;
/// The overhead of the AEAD
const AEAD_SIZE: usize = 16;

#[cfg(target_has_atomic = "64")]
type CounterBitmap = AtomicU64;
#[cfg(not(target_has_atomic = "64"))]
use portable_atomic::AtomicU32 as CounterBitmap;

// Receiving buffer constants
const WORD_SIZE: u64 = if cfg!(target_has_atomic = "64") {
    64
} else {
    32
};
const N_BITS: u64 = 1024;
const N_WORDS: usize = (N_BITS / WORD_SIZE) as usize;

// The most significant bit used as a flag to indicate that the bitmap is being updated,
// and acts effectively as a spinlock.
const COUNTER_LOCK: u64 = 1u64 << 63;
const COUNTER_MASK: u64 = !COUNTER_LOCK;

#[derive(Debug, Default)]
struct ReceivingKeyCounterValidator {
    /// In order to avoid replays while allowing for some reordering of the packets, we keep a
    /// bitmap of received packets, and the value of the highest counter
    next: AtomicU64,
    /// Used to estimate packet loss
    receive_cnt: AtomicU64,
    bitmap: [CounterBitmap; N_WORDS],
}

impl ReceivingKeyCounterValidator {
    pub const fn new() -> ReceivingKeyCounterValidator {
        ReceivingKeyCounterValidator {
            next: AtomicU64::new(0),
            receive_cnt: AtomicU64::new(0),
            bitmap: [const { CounterBitmap::new(0) }; N_WORDS],
        }
    }

    #[inline(always)]
    fn get_next(&self) -> u64 {
        self.next.load(Ordering::SeqCst) & COUNTER_MASK
    }

    /// Returns true if bit is set, false otherwise
    #[inline(always)]
    fn check_bit(&self, idx: u64) -> bool {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = bit_idx % WORD_SIZE;
        ((self.bitmap[word].load(Ordering::SeqCst) >> bit) & 1) == 1
    }

    /// Mark the packet as received, release the spinlock and return the verdict.
    #[inline(always)]
    fn mark_and_unlock(&self, idx: u64) -> Result<(), WireGuardError> {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = bit_idx % WORD_SIZE;
        let previous = self.bitmap[word].fetch_or(1 << bit, Ordering::SeqCst);
        self.next.fetch_and(COUNTER_MASK, Ordering::SeqCst);
        if (previous >> bit) & 1 == 1 {
            Err(WireGuardError::DuplicateCounter)
        } else {
            Ok(())
        }
    }

    /// Clear all the packets between prev and next.
    #[inline(always)]
    fn clear_range(&self, prev: u64, next: u64) {
        if next < prev {
            return;
        }

        if next - prev >= N_BITS {
            // Too far ahead, clear all the bits
            for i in 0..N_WORDS {
                self.bitmap[i].store(0, Ordering::SeqCst);
            }
            return;
        }

        #[cfg(target_has_atomic = "64")]
        const ONE: u64 = 1;
        #[cfg(not(target_has_atomic = "64"))]
        const ONE: u32 = 1;

        let prev_idx = (prev / WORD_SIZE) as usize;
        let prev_mask = (ONE << (prev % WORD_SIZE)) - 1;
        let next_idx = (next / WORD_SIZE) as usize;
        let next_mask = (!ONE) << (next % WORD_SIZE);

        if next_idx == prev_idx {
            // The bits to clear all fit within a single word.
            self.bitmap[prev_idx % N_WORDS].fetch_and(next_mask | prev_mask, Ordering::SeqCst);
        } else {
            // The bits to clear span multiple words.
            self.bitmap[prev_idx % N_WORDS].fetch_and(prev_mask, Ordering::SeqCst);
            for i in prev_idx + 1..next_idx {
                self.bitmap[i % N_WORDS].store(0, Ordering::SeqCst);
            }
            self.bitmap[next_idx % N_WORDS].fetch_and(next_mask, Ordering::SeqCst);
        }
    }

    /// Returns true if the counter was not yet received, and is not too far back.
    #[inline(always)]
    fn will_accept(&self, counter: u64) -> Result<(), WireGuardError> {
        if counter >= COUNTER_MASK {
            // Too many packets, counter would overflow.
            return Err(WireGuardError::InvalidCounter);
        }

        // Spin while checking the counter until the bitmap is updated, as
        // indicated by the COUNTER_LOCK bit being cleared.
        let mut next = self.next.load(Ordering::SeqCst);
        loop {
            if counter >= (next & COUNTER_MASK) {
                // As long as the counter is growing no replay took place for sure
                return Ok(());
            }
            if counter + N_BITS < (next & COUNTER_MASK) {
                // Drop if too far back
                return Err(WireGuardError::InvalidCounter);
            }
            if (next & COUNTER_LOCK) == 0 {
                break;
            }
            next = self.next.load(Ordering::SeqCst);
            hint::spin_loop();
        }

        // Check the bitmap for duplicates, then re-check the counter
        // one last time in case a race conditioned occurred.
        let duplicate = self.check_bit(counter);
        let next = self.next.load(Ordering::SeqCst) & COUNTER_MASK;
        return if counter + N_BITS < next {
            Err(WireGuardError::InvalidCounter)
        } else if duplicate {
            Err(WireGuardError::DuplicateCounter)
        } else {
            Ok(())
        };
    }

    /// Marks the counter as received, and returns true if it is still good (in case during
    /// decryption something changed)
    #[inline(always)]
    fn mark_did_receive(&self, counter: u64) -> Result<(), WireGuardError> {
        if counter >= COUNTER_MASK {
            // Too many packets, counter would overflow.
            return Err(WireGuardError::InvalidCounter);
        }

        let mut prev = self.next.load(Ordering::Acquire);
        loop {
            if (counter + N_BITS) < (prev & COUNTER_MASK) {
                // Drop if too far back that the packet would fall outside the bitmap.
                return Err(WireGuardError::InvalidCounter);
            }
            if prev & COUNTER_LOCK == COUNTER_LOCK {
                // Someone else has the spinlock. Try again.
                prev = self.next.load(Ordering::SeqCst);
            } else if counter < prev {
                // This packet arrived out of order, acquire the spinlock to mark the packet.
                match self.next.compare_exchange_weak(
                    prev,
                    prev | COUNTER_LOCK,
                    Ordering::SeqCst,
                    Ordering::Acquire,
                ) {
                    Ok(_) => break,
                    Err(x) => prev = x,
                }
            } else {
                // This packet arrived in-order.
                // Acquire the spinlock, update the next packet counter, and clear bits that will wrap over.
                match self.next.compare_exchange_weak(
                    prev,
                    (counter + 1) | COUNTER_LOCK,
                    Ordering::SeqCst,
                    Ordering::Acquire,
                ) {
                    Ok(_) => {
                        self.clear_range(prev, counter);
                        break;
                    }
                    Err(x) => prev = x,
                }
            }
            hint::spin_loop();
        }

        // And finally try to mark the packet, release the spinlock, and return the verdict.
        self.mark_and_unlock(counter)?;
        self.receive_cnt.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

impl Session {
    pub(super) fn new(
        local_index: u32,
        peer_index: u32,
        receiving_key: [u8; 32],
        sending_key: [u8; 32],
    ) -> Session {
        Session {
            receiving_index: local_index,
            sending_index: peer_index,
            receiver: LessSafeKey::new(
                UnboundKey::new(&CHACHA20_POLY1305, &receiving_key).unwrap(),
            ),
            sender: LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &sending_key).unwrap()),
            sending_key_counter: AtomicU64::new(0),
            receiving_key_counter: ReceivingKeyCounterValidator::new(),
        }
    }

    pub(super) fn local_index(&self) -> usize {
        self.receiving_index as usize
    }

    /// src - an IP packet from the interface
    /// dst - pre-allocated space to hold the encapsulating UDP packet to send over the network
    /// returns the size of the formatted packet
    pub(super) fn format_packet_data<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> &'a mut [u8] {
        if dst.len() < src.len() + super::DATA_OVERHEAD_SZ {
            panic!("The destination buffer is too small");
        }

        let sending_key_counter = self.sending_key_counter.fetch_add(1, Ordering::Relaxed) as u64;

        let (message_type, rest) = dst.split_at_mut(4);
        let (receiver_index, rest) = rest.split_at_mut(4);
        let (counter, data) = rest.split_at_mut(8);

        message_type.copy_from_slice(&super::DATA.to_le_bytes());
        receiver_index.copy_from_slice(&self.sending_index.to_le_bytes());
        counter.copy_from_slice(&sending_key_counter.to_le_bytes());

        // TODO: spec requires padding to 16 bytes, but actually works fine without it
        let n = {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&sending_key_counter.to_le_bytes());
            data[..src.len()].copy_from_slice(src);
            self.sender
                .seal_in_place_separate_tag(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&[]),
                    &mut data[..src.len()],
                )
                .map(|tag| {
                    data[src.len()..src.len() + AEAD_SIZE].copy_from_slice(tag.as_ref());
                    src.len() + AEAD_SIZE
                })
                .unwrap()
        };

        &mut dst[..DATA_OFFSET + n]
    }

    /// packet - a data packet we received from the network
    /// dst - pre-allocated space to hold the encapsulated IP packet, to send to the interface
    ///       dst will always take less space than src
    /// return the size of the encapsulated packet on success
    pub(super) fn receive_packet_data<'a>(
        &self,
        packet: PacketData,
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        let ct_len = packet.encrypted_encapsulated_packet.len();
        if dst.len() < ct_len {
            // This is a very incorrect use of the library, therefore panic and not error
            panic!("The destination buffer is too small");
        }
        if packet.receiver_idx != self.receiving_index {
            return Err(WireGuardError::WrongIndex);
        }
        // Don't reuse counters, in case this is a replay attack we want to quickly check the counter without running expensive decryption
        self.receiving_key_counter.will_accept(packet.counter)?;

        let ret = {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&packet.counter.to_le_bytes());
            dst[..ct_len].copy_from_slice(packet.encrypted_encapsulated_packet);
            self.receiver
                .open_in_place(
                    Nonce::assume_unique_for_key(nonce),
                    Aad::from(&[]),
                    &mut dst[..ct_len],
                )
                .map_err(|_| WireGuardError::InvalidAeadTag)?
        };

        // After decryption is done, check counter again, and mark as received
        self.receiving_key_counter
            .mark_did_receive(packet.counter)?;
        Ok(ret)
    }

    /// Returns the estimated downstream packet loss for this session
    pub(super) fn current_packet_cnt(&self) -> (u64, u64) {
        let rx = self
            .receiving_key_counter
            .receive_cnt
            .load(Ordering::Relaxed);
        (self.receiving_key_counter.get_next(), rx)
    }
}

#[cfg(test)]
use std::thread;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(test)]
    fn check_replay_clear_range(start: u64, end: u64) {
        // Setup the replay bitmap with all bits set.
        let c: ReceivingKeyCounterValidator = Default::default();
        for i in 0..N_WORDS {
            c.bitmap[i].store(!0, Ordering::Release);
        }
        c.next.store(N_BITS, Ordering::Release);
        for i in 0..N_BITS {
            assert!(c.check_bit(i));
        }

        // Clear a range, and recheck the bitmap.
        c.clear_range(start, end);
        let check_start = (start / WORD_SIZE) * WORD_SIZE;
        for i in check_start..check_start + N_BITS {
            if i < start || i > end {
                assert!(c.check_bit(i), "expected bit {} to be set", i);
            } else {
                assert!(!c.check_bit(i), "expected bit {} to be clear", i);
            }
        }
    }

    #[test]
    fn test_replay_clear_range() {
        // Clear a single bit and check edge cases.
        check_replay_clear_range(0, 0);
        check_replay_clear_range(42, 42);
        check_replay_clear_range(WORD_SIZE - 1, WORD_SIZE - 1);
        check_replay_clear_range(WORD_SIZE, WORD_SIZE);
        check_replay_clear_range(N_BITS - 1, N_BITS - 1);
        check_replay_clear_range(N_BITS, N_BITS);

        // Clear some bits in the middle of a single word.
        check_replay_clear_range(13, 19);

        // Clear precisely one word.
        check_replay_clear_range(WORD_SIZE, WORD_SIZE * 2 - 1);

        // Clear some bits spanning two words.
        check_replay_clear_range(WORD_SIZE + 7, WORD_SIZE * 2 + 13);

        // Clear some bits that span many words.
        check_replay_clear_range(WORD_SIZE + 7, N_BITS - 7);

        // Clear some bits that wrap around to the start of the index.
        check_replay_clear_range(N_BITS - 7, N_BITS + 7);
    }

    #[test]
    fn test_replay_counter() {
        let c: ReceivingKeyCounterValidator = Default::default();

        assert!(c.mark_did_receive(0).is_ok());
        assert!(c.mark_did_receive(0).is_err());
        assert!(c.mark_did_receive(1).is_ok());
        assert!(c.mark_did_receive(1).is_err());
        assert!(c.mark_did_receive(63).is_ok());
        assert!(c.mark_did_receive(63).is_err());
        assert!(c.mark_did_receive(15).is_ok());
        assert!(c.mark_did_receive(15).is_err());

        for i in 64..N_BITS + 128 {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3).is_ok());
        for i in 0..=N_BITS * 2 {
            assert!(matches!(
                c.will_accept(i),
                Err(WireGuardError::InvalidCounter)
            ));
            assert!(c.mark_did_receive(i).is_err());
        }
        for i in N_BITS * 2 + 1..N_BITS * 3 {
            assert!(c.will_accept(i).is_ok());
        }
        assert!(matches!(
            c.will_accept(N_BITS * 3),
            Err(WireGuardError::DuplicateCounter)
        ));

        for i in (N_BITS * 2 + 1..N_BITS * 3).rev() {
            assert!(c.mark_did_receive(i).is_ok());
            assert!(c.mark_did_receive(i).is_err());
        }

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 72 + 125).is_ok());
        assert!(c.mark_did_receive(N_BITS * 3 + 63).is_ok());

        assert!(c.mark_did_receive(N_BITS * 3 + 70).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 71).is_err());
        assert!(c.mark_did_receive(N_BITS * 3 + 72).is_err());
    }

    const RACE_MAX_PACKETS: u64 = 1024 * 1024;

    // Race check worker to try and send valid packets, they should be accepted.
    #[cfg(test)]
    fn racecheck_counter_worker(counter: &AtomicU64, validator: &ReceivingKeyCounterValidator) {
        loop {
            let mut value = counter.fetch_add(1, Ordering::Relaxed);
            if value > RACE_MAX_PACKETS {
                break;
            }

            // To drive the out-of-order packet handling a little harder, simulate some packet
            // reordering. If the packet is a multiple of 29, increment the value being sent by
            // 29. This should still never generate a duplicate but forces the validator to
            // interact with the bitmap to figure it out.
            if value % 29 == 0 {
                value += 29;
            }

            match validator.will_accept(value) {
                Ok(_) => {}
                Err(WireGuardError::InvalidCounter) => {
                    // This error is allowed if, and only if, the thread hit an
                    // unlucky interrupt and the counter is too old now.
                    assert!(validator.get_next() >= value + N_BITS);
                    continue;
                }
                Err(WireGuardError::DuplicateCounter) => {
                    panic!("duplicate while checking {}", value)
                }
                _ => panic!("error while checking packet {}", value),
            };

            match validator.mark_did_receive(value) {
                Ok(_) => {}
                Err(WireGuardError::InvalidCounter) => {
                    // This error is allowed if, and only if, the thread hit an
                    // unlucky interrupt and the counter is too old now.
                    assert!(validator.get_next() >= value + N_BITS);
                    continue;
                }
                Err(WireGuardError::DuplicateCounter) => {
                    panic!("duplicate while marking {}", value)
                }
                _ => panic!("error while marking {}", value),
            };

            // Resend it as a duplicate, it must be rejected.
            assert!(
                validator.mark_did_receive(value).is_err(),
                "race encountered while checking duplicate {}",
                value
            );

            thread::yield_now();
        }
    }

    // Race check worker to try and send duplicate packets, they must all be rejected.
    #[cfg(test)]
    fn racecheck_dup_worker(counter: &AtomicU64, validator: &ReceivingKeyCounterValidator) {
        while counter.load(Ordering::Relaxed) < RACE_MAX_PACKETS {
            let value = validator.get_next();
            if value > 0 {
                assert!(validator.mark_did_receive(value - 1).is_err());
            }
        }
    }

    #[test]
    fn test_replay_racecheck() {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        static VALIDATOR: ReceivingKeyCounterValidator = ReceivingKeyCounterValidator::new();
        let mut threads = Vec::new();
        let num_threads = thread::available_parallelism().map_or(8, |x| x.get());

        for _ in 0..num_threads - 1 {
            threads.push(thread::spawn(|| {
                racecheck_counter_worker(&COUNTER, &VALIDATOR)
            }));
        }
        threads.push(thread::spawn(|| racecheck_dup_worker(&COUNTER, &VALIDATOR)));

        for handle in threads {
            handle.join().unwrap();
        }
    }
}
