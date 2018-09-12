use crypto::chacha20poly1305::*;
use noise::errors::WireGuardError;
use noise::h2n::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::RwLock;

pub struct Session {
    receiving_index: u32,
    sending_index: u32,
    receiver: ChaCha20Poly1305,
    sender: ChaCha20Poly1305,
    sending_key_counter: AtomicUsize,
    receiving_key_counter: RwLock<ReceivingKeyCounterValidator>,
}

impl Clone for Session {
    fn clone(&self) -> Session {
        Session {
            receiving_index: self.receiving_index,
            sending_index: self.sending_index,
            receiver: self.receiver.clone(),
            sender: self.sender.clone(),
            sending_key_counter: AtomicUsize::new(self.sending_key_counter.load(Ordering::Relaxed)),
            receiving_key_counter: RwLock::new(self.receiving_key_counter.read().unwrap().clone()),
        }
    }
}

// WireGuard constants
const PACKET_DATA_TYPE: u32 = 4;

const MSG_TYPE_OFF: usize = 0;
const MSG_TYPE_SZ: usize = 4;
const IDX_OFF: usize = MSG_TYPE_OFF + MSG_TYPE_SZ;
const IDX_SZ: usize = 4;
const CTR_OFF: usize = IDX_OFF + IDX_SZ;
const CTR_SZ: usize = 8;
const DATA_OFF: usize = CTR_OFF + CTR_SZ;
const AEAD_SIZE: usize = 16;

// Receiving buffer constants
const WORD_SIZE: u64 = 64;
const N_WORDS: u64 = 8; // Suffice to reorder 512 packets, can be increased at will
const N_BITS: u64 = WORD_SIZE * N_WORDS;

#[derive(Clone, Default)]
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
    fn mark_did_receive(&mut self, counter: u64) -> bool {
        if counter + N_BITS < self.next {
            // Drop if too far back
            return false;
        }
        if counter == self.next {
            // Usually the packets arrive in order, in that case we simply mark the bit and
            // increment the counter
            self.set_bit(counter);
            self.next += 1;
            return true;
        }
        if counter < self.next {
            // A packet arrived out of order, check if it is valid, and mark
            if self.check_bit(counter) {
                return false;
            }
            self.set_bit(counter);
            return true;
        }
        // Packets where dropped, or maybe reordered, skip them an mark unused
        let mut i = self.next;
        while i < counter {
            self.clear_bit(i);
            i += 1;
        }
        self.set_bit(counter);
        self.next = counter + 1;
        return true;
    }
}

impl Session {
    pub fn new(
        local_index: u32,
        peer_index: u32,
        receiving_key: [u8; 32],
        sending_key: [u8; 32],
    ) -> Session {
        Session {
            receiving_index: local_index,
            sending_index: peer_index,
            receiver: ChaCha20Poly1305::new_aead(&receiving_key),
            sender: ChaCha20Poly1305::new_aead(&sending_key),
            sending_key_counter: AtomicUsize::new(0),
            receiving_key_counter: RwLock::new(Default::default()),
        }
    }

    // Returns true if receiving counter is good to use
    fn receiving_counter_quick_check(&self, counter: u64) -> bool {
        let counter_validator = self.receiving_key_counter.read().unwrap();
        counter_validator.will_accept(counter)
    }

    // Returns true if receiving counter is good to use, and marks it as used {
    fn receiving_counter_mark(&self, counter: u64) -> bool {
        let mut counter_validator = self.receiving_key_counter.write().unwrap();
        counter_validator.mark_did_receive(counter)
    }

    // src - an IP packet from the interface
    // dst - preallocated space to hold the encapsulating UDP packet to send over the network
    // returns the size of the formatted packet
    pub fn format_packet_data(&self, src: &[u8], dst: &mut [u8]) -> usize {
        if DATA_OFF + src.len() + AEAD_SIZE > dst.len() {
            // This is a very incorrect use of the library, therefore panic and not error
            panic!("The destination buffer is too small");
        }

        let sending_key_counter = self.sending_key_counter.fetch_add(1, Ordering::Relaxed) as u64;
        write_u32(
            PACKET_DATA_TYPE,
            &mut dst[MSG_TYPE_OFF..MSG_TYPE_OFF + MSG_TYPE_SZ],
        );
        write_u32(self.sending_index, &mut dst[IDX_OFF..IDX_OFF + IDX_SZ]);
        write_u64(sending_key_counter, &mut dst[CTR_OFF..CTR_OFF + CTR_SZ]);
        // TODO: spec requires padding to 16 bytes, but actually works fine without it
        let n = self.sender.seal_wg(
            sending_key_counter,
            &[],
            src,
            &mut dst[DATA_OFF..DATA_OFF + src.len() + AEAD_SIZE],
        );
        DATA_OFF + n
    }

    // src - a packet we received from the network
    // dst - preallocated space to hold the encapsulated IP packet, to send to the interface
    //       dst will always take less space than src
    // return the size of the encapsulated packet on success
    pub fn receive_packet_data(&self, src: &[u8], dst: &mut [u8]) -> Result<usize, WireGuardError> {
        if DATA_OFF + dst.len() + AEAD_SIZE < src.len() {
            // This is a very incorrect use of the library, therefore panic and not error
            panic!("The destination buffer is too small");
        }
        let message_type = read_u32(&src[MSG_TYPE_OFF..MSG_TYPE_OFF + MSG_TYPE_SZ]);
        if message_type != PACKET_DATA_TYPE {
            return Err(WireGuardError::WrongPacketType);
        }
        let receiver_index = read_u32(&src[IDX_OFF..IDX_OFF + IDX_SZ]);
        let receiving_key_counter = read_u64(&src[CTR_OFF..CTR_OFF + CTR_SZ]);
        if receiver_index != self.receiving_index {
            return Err(WireGuardError::WrongIndex);
        }
        // Don't reuse counters
        if !self.receiving_counter_quick_check(receiving_key_counter) {
            return Err(WireGuardError::InvalidCounter);
        }

        self.receiver
            .open_wg(receiving_key_counter, &[], &src[DATA_OFF..], dst)
            .and_then(|n| {
                // After decryption is done, check counter again, and mark
                if self.receiving_counter_mark(receiving_key_counter) {
                    Ok(n)
                } else {
                    Err(WireGuardError::InvalidCounter)
                }
            })
    }
}
