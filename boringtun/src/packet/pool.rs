use std::sync::{Arc, Mutex};
use bytes::BytesMut;
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
    pub fn new(capacity: usize) -> Arc<Self> {
        let (packet_tx, packet_rx) = mpsc::channel(capacity);

        for _ in 0..capacity {
            let _ = packet_tx.try_send(BytesMut::zeroed(N));
        }

        let pool = PacketBufPool {
            packet_tx,
            packet_rx: Arc::new(Mutex::new(packet_rx)),
        };
        Arc::new(pool)
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

/*
/// A borrowed buffer pointing into one packet of the pool.
/// When dropped, it atomically returns its packet.
pub struct PacketBuf<const N: usize = 4096> {
    packet_tx: mpsc::Sender<Box<[u8; N]>>,
    data: Option<Box<[u8; N]>>,
    pub len: usize,
}

impl<const N: usize> PacketBuf<N> {
    /// Allocate a new buffer that will be returned to `pool`
    fn alloc(packet_tx: mpsc::Sender<Box<[u8; N]>>) -> Self {
        PacketBuf {
            packet_tx,
            data: Some(Box::new([0u8; N])), // TODO: avoid stack allocation
            len: 0,
        }
    }

    /// Reuse existing buffer
    fn reuse(packet_tx: mpsc::Sender<Box<[u8; N]>>, data: Box<[u8; N]>) -> Self {
        PacketBuf {
            packet_tx,
            data: Some(data),
            len: 0,
        }
    }

    /// Immutable view of the current packet.
    pub fn packet(&self) -> &[u8] {
        let data = self.data.as_ref().unwrap();
        &data[..self.len]
    }

    /// Mutable access to the entire packet.
    pub fn packet_mut(&mut self) -> &mut [u8] {
        let data = self.data.as_mut().unwrap();
        &mut data[..]
    }

    /// Mutable access to the entire packet and length.
    pub fn packet_and_len_mut(&mut self) -> (&mut [u8], &mut usize) {
        let data = self.data.as_mut().unwrap();
        (&mut data[..], &mut self.len)
    }

    /// Copy data into the packet.
    pub fn copy_from(&mut self, data: &[u8]) {
        assert!(data.len() <= N, "packet too large");
        let dst = self.packet_mut();
        dst[..data.len()].copy_from_slice(data);
        self.len = data.len();
    }

    pub fn packet_len(&self) -> usize {
        self.len
    }

    pub fn set_packet_len(&mut self, len: usize) {
        self.len = len;
    }
}

impl<const N: usize> Drop for PacketBuf<N> {
    fn drop(&mut self) {
        // Return packet to the pool
        let data = self.data.take().unwrap();
        let _ = self.packet_tx.try_send(data);
    }
}
*/