use bytes::BytesMut;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

use crate::packet::Packet;

/// A pool of packet buffers
#[derive(Debug, Clone)]
pub struct PacketBufPool<const N: usize = 4096> {
    // FIXME: Allocate contiguous memory
    packet_tx: mpsc::Sender<BytesMut>,
    packet_rx: Arc<Mutex<mpsc::Receiver<BytesMut>>>,
}

impl<const N: usize> PacketBufPool<N> {
    /// Create `num_packets` packets, each `N` bytes.
    pub fn new(capacity: usize) -> Self {
        let (packet_tx, packet_rx) = mpsc::channel(capacity);

        for _ in 0..capacity {
            let _ = packet_tx.try_send(BytesMut::zeroed(N));
        }

        PacketBufPool {
            packet_tx,
            packet_rx: Arc::new(Mutex::new(packet_rx)),
        }
    }

    /// Retrieve an unused packet from the pool
    pub fn get(&self) -> Packet<[u8]> {
        self.packet_rx
            .lock()
            .unwrap()
            .try_recv()
            .map(|mut bytes| {
                // grow BytesMut to `N`
                // this is cheap since we should be the only ones holding a Bytes(Mut) that references the backing buffer
                bytes.resize(N, 0u8);
                Packet::new_from_pool(self.packet_tx.clone(), bytes)
            })
            .unwrap_or_else(|_err| {
                log::debug!("Allocating new packet buffer");
                Packet::new_from_pool(self.packet_tx.clone(), BytesMut::zeroed(N))
            })
    }
}
