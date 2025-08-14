//! Generic buffered IP send and receive implementations.

use std::sync::Arc;

use crate::{
    packet::{Ip, Packet, PacketBufPool},
    task::Task,
    tun::{IpRecv, IpSend},
};
use tokio::{
    io,
    sync::{Mutex, mpsc},
};

#[derive(Clone)]
pub struct BufferedIpSend {
    tx: mpsc::Sender<Packet<Ip>>,
    _task: Arc<Task>,
}

impl BufferedIpSend {
    pub fn new<I: IpSend>(capacity: usize, inner: I) -> Self {
        let (tx, mut rx) = mpsc::channel::<Packet<Ip>>(capacity);

        let task = Task::spawn("buffered IP send", async move {
            while let Some(packet) = rx.recv().await {
                if let Err(e) = inner.send(packet).await {
                    log::error!("Error sending IP packet: {e}");
                }
            }
        });

        Self {
            tx,
            _task: Arc::new(task),
        }
    }
}

impl IpSend for BufferedIpSend {
    async fn send(&self, packet: Packet<Ip>) -> io::Result<()> {
        self.tx
            .send(packet)
            .await
            .expect("receiver dropped after senders");
        Ok(())
    }
}

pub struct BufferedIpRecv<I> {
    rx: mpsc::Receiver<Packet<Ip>>,
    rx_packet_buf: Vec<Packet<Ip>>,
    _task: Arc<Task>,
    _phantom: std::marker::PhantomData<I>,
}

impl<I: IpRecv> BufferedIpRecv<I> {
    /// Create a new [BufferedIpRecv].
    ///
    /// This takes an `Arc<Mutex<I>>` because the inner `I` will be re-used after [Self] is
    /// dropped. We will take the mutex lock when this function is called, and hold onto it for the
    /// lifetime of [Self]. Will panic if the lock is already taken.
    pub fn new(capacity: usize, mut pool: PacketBufPool, inner: Arc<Mutex<I>>) -> Self {
        let (tx, rx) = mpsc::channel::<Packet<Ip>>(capacity);

        let task = Task::spawn("buffered IP recv", async move {
            let mut inner = inner.try_lock().expect("Lock must not be taken");

            loop {
                match inner.recv(&mut pool).await {
                    Ok(packets) => {
                        for packet in packets {
                            if tx.send(packet).await.is_err() {
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        log::error!("Error receiving IP packet: {e}");
                        // exit?
                        continue;
                    }
                }
            }
        });

        Self {
            rx,
            rx_packet_buf: vec![],
            _task: Arc::new(task),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<I: IpRecv> IpRecv for BufferedIpRecv<I> {
    async fn recv<'a>(
        &'a mut self,
        _pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        let max_n = self.rx.capacity();
        let n = self.rx.recv_many(&mut self.rx_packet_buf, max_n).await;
        if n == 0 {
            // Channel is closed
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "channel closed",
            ));
        }
        Ok(self.rx_packet_buf.drain(..n))
    }
}
