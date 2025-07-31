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
            if pointer_to_start_of_allocation.try_reclaim(N) {
                let mut buf = pointer_to_start_of_allocation.split_off(0);

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
