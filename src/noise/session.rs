// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#[cfg(target_arch = "arm")]
use crypto::chacha20poly1305::*;
use crate::noise::errors::WireGuardError;
use crate::noise::make_array;
#[cfg(not(target_arch = "arm"))]
use ring::aead::*;
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(not(target_arch = "arm"))]
pub struct Session {
    receiving_index: u32,
    sending_index: u32,
    receiver: OpeningKey,
    sender: SealingKey,
    sending_key_counter: AtomicUsize,
    receiving_key_counter: spin::Mutex<ReceivingKeyCounterValidator>,
}

#[cfg(target_arch = "arm")]
pub struct Session {
    receiving_index: u32,
    sending_index: u32,
    receiver: ChaCha20Poly1305,
    sender: ChaCha20Poly1305,
    sending_key_counter: AtomicUsize,
    receiving_key_counter: spin::Mutex<ReceivingKeyCounterValidator>,
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

// WireGuard constants
const PACKET_DATA_TYPE: u32 = 4;

const MSG_TYPE_OFF: usize = 0;
const MSG_TYPE_SZ: usize = 4;
pub const IDX_OFF: usize = MSG_TYPE_OFF + MSG_TYPE_SZ;
pub const IDX_SZ: usize = 4;
const CTR_OFF: usize = IDX_OFF + IDX_SZ;
const CTR_SZ: usize = 8;
const DATA_OFF: usize = CTR_OFF + CTR_SZ;
const AEAD_SIZE: usize = 16;

// Receiving buffer constants
const WORD_SIZE: u64 = 64;
const N_WORDS: u64 = 16; // Suffice to reorder 64*16 = 1024 packets; can be increased at will
const N_BITS: u64 = WORD_SIZE * N_WORDS;

#[derive(Debug, Clone, Default)]
struct ReceivingKeyCounterValidator {
    // In order to avoid replays while allowing for some reordering of the packets, we keep a
    // bitmask of received packets, and the value of the highest counter
    next: u64,
    bitmap: [u64; N_WORDS as usize],
}

impl ReceivingKeyCounterValidator {
    #[inline(always)]
    fn set_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] |= 1 << bit;
    }

    #[inline(always)]
    fn clear_bit(&mut self, idx: u64) {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        self.bitmap[word] &= !(1u64 << bit);
    }

    // Returns true if bit is set, false otherwise
    #[inline(always)]
    fn check_bit(&self, idx: u64) -> bool {
        let bit_idx = idx % N_BITS;
        let word = (bit_idx / WORD_SIZE) as usize;
        let bit = (bit_idx % WORD_SIZE) as usize;
        ((self.bitmap[word] >> bit) & 1) == 1
    }

    // Returns true if the counter was not yet recieved, and is not too far back
    #[inline(always)]
    fn will_accept(&self, counter: u64) -> bool {
        if counter >= self.next {
            // As long as the counter is growing no replay took place for sure
            return true;
        }
        if counter + N_BITS < self.next {
            // Drop if too far back
            return false;
        }
        !self.check_bit(counter)
    }

    // Marks the counter as received, and returns true if it is still good (in case during
    // decryption something changed)
    #[inline(always)]
    fn mark_did_receive(&mut self, counter: u64) -> Result<(), WireGuardError> {
        if counter + N_BITS < self.next {
            // Drop if too far back
            return Err(WireGuardError::InvalidCounter);
        }
        if counter == self.next {
            // Usually the packets arrive in order, in that case we simply mark the bit and
            // increment the counter
            self.set_bit(counter);
            self.next += 1;
            return Ok(());
        }
        if counter < self.next {
            // A packet arrived out of order, check if it is valid, and mark
            if self.check_bit(counter) {
                return Err(WireGuardError::InvalidCounter);
            }
            self.set_bit(counter);
            return Ok(());
        }
        // Packets where dropped, or maybe reordered, skip them and mark unused
        let mut i = self.next;
        while i < counter {
            self.clear_bit(i);
            i += 1;
        }
        self.set_bit(counter);
        self.next = counter + 1;
        Ok(())
    }
}

impl Session {
    pub fn new(
        local_index: u32,
        peer_index: u32,
        receiving_key: [u8; 32],
        sending_key: [u8; 32],
    ) -> Session {
        #[cfg(not(target_arch = "arm"))]
        return Session {
            receiving_index: local_index,
            sending_index: peer_index,
            receiver: OpeningKey::new(&CHACHA20_POLY1305, &receiving_key).unwrap(),
            sender: SealingKey::new(&CHACHA20_POLY1305, &sending_key).unwrap(),
            sending_key_counter: AtomicUsize::new(0),
            receiving_key_counter: spin::Mutex::new(Default::default()),
        };

        #[cfg(target_arch = "arm")]
        return Session {
            receiving_index: local_index,
            sending_index: peer_index,
            receiver: ChaCha20Poly1305::new_aead(&receiving_key[..]),
            sender: ChaCha20Poly1305::new_aead(&sending_key[..]),
            sending_key_counter: AtomicUsize::new(0),
            receiving_key_counter: spin::Mutex::new(Default::default()),
        };
    }

    pub fn local_index(&self) -> usize {
        self.receiving_index as usize
    }

    // Returns true if receiving counter is good to use
    fn receiving_counter_quick_check(&self, counter: u64) -> Result<(), WireGuardError> {
        let counter_validator = self.receiving_key_counter.lock();
        if counter_validator.will_accept(counter) {
            Ok(())
        } else {
            Err(WireGuardError::InvalidCounter)
        }
    }

    // Returns true if receiving counter is good to use, and marks it as used {
    fn receiving_counter_mark(&self, counter: u64) -> Result<(), WireGuardError> {
        let mut counter_validator = self.receiving_key_counter.lock();
        counter_validator.mark_did_receive(counter)
    }

    // src - an IP packet from the interface
    // dst - preallocated space to hold the encapsulating UDP packet to send over the network
    // returns the size of the formatted packet
    pub fn format_packet_data<'a>(&self, src: &[u8], dst: &'a mut [u8]) -> &'a mut [u8] {
        if DATA_OFF + src.len() + AEAD_SIZE > dst.len() {
            // This is a very incorrect use of the library, therefore panic and not error
            panic!("The destination buffer is too small");
        }

        let sending_key_counter = self.sending_key_counter.fetch_add(1, Ordering::Relaxed) as u64;
        dst[MSG_TYPE_OFF..MSG_TYPE_OFF + MSG_TYPE_SZ]
            .copy_from_slice(&PACKET_DATA_TYPE.to_le_bytes());
        dst[IDX_OFF..IDX_OFF + IDX_SZ].copy_from_slice(&self.sending_index.to_le_bytes());
        dst[CTR_OFF..CTR_OFF + CTR_SZ].copy_from_slice(&sending_key_counter.to_le_bytes());
        // TODO: spec requires padding to 16 bytes, but actually works fine without it

        #[cfg(not(target_arch = "arm"))]
        {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&sending_key_counter.to_le_bytes());
            dst[DATA_OFF..DATA_OFF + src.len()].copy_from_slice(src);
            let n = seal_in_place(
                &self.sender,
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&[]),
                &mut dst[DATA_OFF..DATA_OFF + src.len() + AEAD_SIZE],
                AEAD_SIZE,
            )
            .unwrap();
            &mut dst[..DATA_OFF + n]
        }

        #[cfg(target_arch = "arm")]
        {
            let n = self.sender.seal_wg(
                sending_key_counter,
                &[],
                src,
                &mut dst[DATA_OFF..DATA_OFF + src.len() + AEAD_SIZE],
            );
            &mut dst[..DATA_OFF + n]
        }
    }

    // src - a packet we received from the network
    // dst - preallocated space to hold the encapsulated IP packet, to send to the interface
    //       dst will always take less space than src
    // return the size of the encapsulated packet on success
    pub fn receive_packet_data<'a>(
        &self,
        src: &[u8],
        dst: &'a mut [u8],
    ) -> Result<&'a mut [u8], WireGuardError> {
        if DATA_OFF + dst.len() + AEAD_SIZE < src.len() {
            // This is a very incorrect use of the library, therefore panic and not error
            panic!("The destination buffer is too small");
        }
        let message_type = u32::from_le_bytes(make_array(&src[MSG_TYPE_OFF..]));
        if message_type != PACKET_DATA_TYPE {
            return Err(WireGuardError::WrongPacketType);
        }
        let receiver_index = u32::from_le_bytes(make_array(&src[IDX_OFF..]));
        let receiving_key_counter = u64::from_le_bytes(make_array(&src[CTR_OFF..]));
        if receiver_index != self.receiving_index {
            return Err(WireGuardError::WrongIndex);
        }
        // Don't reuse counters, in case this is a replay attack we want to quickly check the counter without running expensive decryption
        self.receiving_counter_quick_check(receiving_key_counter)?;

        #[cfg(not(target_arch = "arm"))]
        {
            let mut nonce = [0u8; 12];
            nonce[4..12].copy_from_slice(&receiving_key_counter.to_le_bytes());
            dst[..src.len() - DATA_OFF].copy_from_slice(&src[DATA_OFF..]);
            let packet = open_in_place(
                &self.receiver,
                Nonce::assume_unique_for_key(nonce),
                Aad::from(&[]),
                0,
                &mut dst[..src.len() - DATA_OFF],
            )
            .map_err(|_| WireGuardError::InvalidAeadTag)?;
            // After decryption is done, check counter again, and mark as recieved
            self.receiving_counter_mark(receiving_key_counter)?;
            Ok(packet)
        }

        #[cfg(target_arch = "arm")]
        {
            let packet =
                self.receiver
                    .open_wg(receiving_key_counter, &[], &src[DATA_OFF..], dst)?;

            self.receiving_counter_mark(receiving_key_counter)?;
            Ok(packet)
        }
    }
}
