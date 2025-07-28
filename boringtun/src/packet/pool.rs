use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// A pool of packet buffers
#[derive(Debug, Clone)]
pub struct PacketBufPool<const N: usize = 4096> {
    // FIXME: Allocate contiguous memory
    packet_tx: mpsc::Sender<Box<[u8; N]>>,
    packet_rx: Arc<Mutex<mpsc::Receiver<Box<[u8; N]>>>>,
}

impl<const N: usize> PacketBufPool<N> {
    /// Create `num_packets` packets, each `N` bytes.
    pub fn new(capacity: usize) -> Arc<Self> {
        let (packet_tx, packet_rx) = mpsc::channel(capacity);

        for _ in 0..capacity {
            let _ = packet_tx.try_send(Box::new([0u8; N]));
        }

        let pool = PacketBufPool {
            packet_tx,
            packet_rx: Arc::new(Mutex::new(packet_rx)),
        };
        Arc::new(pool)
    }

    /// Retrieve an unused packet from the pool
    pub fn get(self: &Arc<Self>) -> PacketBuf<N> {
        self.packet_rx
            .lock()
            .unwrap()
            .try_recv()
            .map(|data| PacketBuf::reuse(Arc::clone(self), data))
            .unwrap_or_else(|_err| {
                log::debug!("Allocating new packet buffer");
                PacketBuf::alloc(Arc::clone(self))
            })
    }
}

/// A borrowed buffer pointing into one packet of the pool.
/// When dropped, it atomically returns its packet.
pub struct PacketBuf<const N: usize = 4096> {
    pool: Arc<PacketBufPool<N>>,
    data: Option<Box<[u8; N]>>,
    pub len: usize,
}

impl<const N: usize> PacketBuf<N> {
    /// Allocate a new buffer that will be returned to `pool`
    fn alloc(pool: Arc<PacketBufPool<N>>) -> Self {
        PacketBuf {
            pool,
            data: Some(Box::new([0u8; N])),
            len: 0,
        }
    }

    /// Reuse existing buffer
    fn reuse(pool: Arc<PacketBufPool<N>>, data: Box<[u8; N]>) -> Self {
        PacketBuf {
            pool,
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
        let _ = self.pool.packet_tx.try_send(data).inspect_err(|err| {
            log::error!("Failed to return packet to pool: {err}");
        });
    }
}
