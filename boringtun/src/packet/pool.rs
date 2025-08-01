use bytes::BytesMut;
use std::mem;
use tokio::sync::mpsc;

use crate::packet::Packet;

/// A pool of packet buffers.
pub struct PacketBufPool<const N: usize = 4096> {
    // FIXME: Allocate contiguous memory
    packet_tx: mpsc::Sender<BytesMut>,
    packet_rx: mpsc::Receiver<BytesMut>,
}

impl<const N: usize> PacketBufPool<N> {
    /// Create `num_packets` packets, each `N` bytes.
    pub fn new(capacity: usize) -> Self {
        let (packet_tx, packet_rx) = mpsc::channel(capacity);

        /*for _ in 0..capacity {
            let _ = packet_tx.try_send(BytesMut::zeroed(N));
        }*/

        PacketBufPool {
            packet_tx,
            packet_rx,
        }
    }

    pub fn capacity(&self) -> usize {
        self.packet_tx.capacity()
    }

    /// Get a new [Packet] from the pool.
    ///
    /// This will try to re-use an already allocated packet if possible, or allocate one otherwise.
    pub fn get(&mut self) -> Packet<[u8]> {
        while let Ok(mut pointer_to_start_of_allocation) = self.packet_rx.try_recv() {
            debug_assert_eq!(pointer_to_start_of_allocation.len(), 0);
            if pointer_to_start_of_allocation.try_reclaim(N) {
                let mut buf = pointer_to_start_of_allocation.split_off(0);

                debug_assert!(buf.capacity() >= N);

                // SAFETY:
                // - buf was split from the BytesMut allocated below.
                // - buf has not been mutated, and still points to the original allocation.
                // - try_reclaim succeeded, so the capacity is at least `N`.
                // - the allocation was created using `BytesMut::zeroed`, so the bytes are initialized.
                unsafe { buf.set_len(N) };

                let return_to_pool = ReturnToPool {
                    pointer_to_start_of_allocation,
                    drop_tx: self.packet_tx.clone(),
                };

                return Packet::new_from_pool(return_to_pool, buf);
            } else {
                // Backing buffer is still in use. Someone probably called split_* on it.
                continue;
            }
        }

        let mut buf = BytesMut::zeroed(N);
        let pointer_to_start_of_allocation = buf.split_to(0);

        debug_assert_eq!(pointer_to_start_of_allocation.len(), 0);
        debug_assert_eq!(buf.len(), N);

        let return_to_pool = ReturnToPool {
            pointer_to_start_of_allocation,
            drop_tx: self.packet_tx.clone(),
        };

        Packet::new_from_pool(return_to_pool, buf)
    }
}

/// This sends a previously allocated [BytesMut] back to [PacketBufPool] when its dropped.
pub struct ReturnToPool {
    /// This is a pointer to the allocation allocated by [PacketBufPool::get].
    /// By making sure we never modify this (by calling reserve, etc), we can efficiently re-use this allocation later.
    ///
    /// INVARIANT:
    /// - Points to the start of an `N`-sized allocation.
    pointer_to_start_of_allocation: BytesMut,
    drop_tx: mpsc::Sender<BytesMut>,
}

impl Drop for ReturnToPool {
    fn drop(&mut self) {
        let p = mem::take(&mut self.pointer_to_start_of_allocation);
        if self.drop_tx.try_send(p).is_err() {
            log::debug!("capacity :(");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{hint::black_box, thread};

    use super::PacketBufPool;

    /// Test buffer recycle semantics of [PacketBufPool].
    #[test]
    fn pool_buffer_recycle() {
        let mut pool = PacketBufPool::<4096>::new(1);

        for i in 0..10 {
            // Get a packet and record its address.
            let mut packet1 = black_box(pool.get());
            let packet1_addr = packet1.buf().as_ptr();

            // Mutate the packet for good measure
            let data = format!("Hello there. x{i}\nGeneral Kenobi! You are a bold one.");
            let data = data.as_bytes();
            packet1.truncate(data.len());
            packet1.copy_from_slice(data);

            // Drop the packet, allowing it to be re-used.
            // Do it on another thread for good measure.
            thread::spawn(move || drop(packet1)).join().unwrap();

            // Get another packet. This should be the same as packet1.
            let packet2 = black_box(pool.get());
            let packet2_addr = packet2.buf().as_ptr();

            // Get a third packet.
            // Since we're still holding packet2, this will result in an allocation.
            let packet3 = black_box(pool.get());
            let packet3_addr = packet3.buf().as_ptr();

            assert!(
                packet2.starts_with(data),
                "old data should remain in the recycled buffer",
            );

            assert!(
                !packet3.starts_with(data),
                "old data should not exist in the new buffer",
            );

            assert_eq!(packet1_addr, packet2_addr);
            assert_ne!(packet1_addr, packet3_addr);

            drop((packet2, packet3));
        }
    }
}
