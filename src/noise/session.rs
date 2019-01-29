use crypto::chacha20poly1305::*;
use noise::errors::WireGuardError;
use noise::h2n::*;
use std::sync::atomic::{AtomicUsize, Ordering};

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
const N_WORDS: u64 = 16; // Suffice to reorder 8*16 = 512 packets; can be increased at will
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
        return Ok(());
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
            receiving_key_counter: spin::Mutex::new(Default::default()),
        }
    }

    pub fn local_index(&self) -> usize {
        self.receiving_index as usize
    }

    // Returns true if receiving counter is good to use
    fn receiving_counter_quick_check(&self, counter: u64) -> Result<(), WireGuardError> {
        let counter_validator = self.receiving_key_counter.lock();
        match counter_validator.will_accept(counter) {
            true => Ok(()),
            false => Err(WireGuardError::InvalidCounter),
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

        &mut dst[..DATA_OFF + n]
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
        let message_type = read_u32(&src[MSG_TYPE_OFF..MSG_TYPE_OFF + MSG_TYPE_SZ]);
        if message_type != PACKET_DATA_TYPE {
            return Err(WireGuardError::WrongPacketType);
        }
        let receiver_index = read_u32(&src[IDX_OFF..IDX_OFF + IDX_SZ]);
        let receiving_key_counter = read_u64(&src[CTR_OFF..CTR_OFF + CTR_SZ]);
        if receiver_index != self.receiving_index {
            return Err(WireGuardError::WrongIndex);
        }
        // Don't reuse counters, in case this is a replay attack we want to quickly check the counter without running expensive decryption
        self.receiving_counter_quick_check(receiving_key_counter)?;

        self.receiver
            .open_wg(receiving_key_counter, &[], &src[DATA_OFF..], dst)
            .and_then(move |n| {
                // After decryption is done, check counter again, and mark
                self.receiving_counter_mark(receiving_key_counter)?;
                Ok(&mut dst[..n])
            })
    }
}
