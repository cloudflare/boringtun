//! Generic buffered IP send and receive implementations.

use std::sync::Arc;

use crate::{
    packet::{PacketBuf, PacketBufPool},
    task::Task,
    tun::{IpRecv, IpSend},
};
use tokio::{io, sync::mpsc};

#[derive(Clone)]
pub struct BufferedIpSend<I> {
    tx: mpsc::Sender<PacketBuf>,
    pool: Arc<PacketBufPool>,
    _task: Arc<Task>,
    _phantom: std::marker::PhantomData<I>,
}

impl<I: IpSend> BufferedIpSend<I> {
    pub fn new(capacity: usize, pool: Arc<PacketBufPool>, inner: I) -> Self {
        let (tx, mut rx) = mpsc::channel::<PacketBuf>(capacity);

        let task = Task::spawn("buffered IP send", async move {
            while let Some(packet) = rx.recv().await {
                if let Err(e) = inner.send(packet.packet()).await {
                    log::error!("Error sending IP packet: {}", e);
                }
            }
        });

        Self {
            tx,
            pool,
            _task: Arc::new(task),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<I: IpSend> IpSend for BufferedIpSend<I> {
    async fn send(&self, packet: &[u8]) -> io::Result<()> {
        let mut packet_buf = self.pool.get();
        packet_buf.copy_from(packet);

        self.tx
            .send(packet_buf)
            .await
            .expect("receiver dropped after senders");
        Ok(())
    }
}

#[derive(Clone)]
pub struct BufferedIpRecv<I> {
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<PacketBuf>>>,
    _task: Arc<Task>,
    _phantom: std::marker::PhantomData<I>,
}

impl<I: IpRecv> BufferedIpRecv<I> {
    pub fn new(capacity: usize, pool: Arc<PacketBufPool>, mut inner: I) -> Self {
        let (tx, rx) = mpsc::channel::<PacketBuf>(capacity);

        let task = Task::spawn("buffered IP recv", async move {
            loop {
                let mut packet_buf = pool.get();
                match inner.recv(packet_buf.packet_mut()).await {
                    Ok(n) => {
                        packet_buf.set_packet_len(n);
                        if tx.send(packet_buf).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        log::error!("Error receiving IP packet: {}", e);
                        // exit?
                        continue;
                    }
                }
            }
        });

        Self {
            rx: Arc::new(tokio::sync::Mutex::new(rx)),
            _task: Arc::new(task),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<I: IpRecv> IpRecv for BufferedIpRecv<I> {
    async fn recv(&mut self, packet: &mut [u8]) -> io::Result<usize> {
        let Some(rx_packet) = self.rx.lock().await.recv().await else {
            return Err(io::Error::new(io::ErrorKind::Other, "No packet available"));
        };
        packet[..rx_packet.len].copy_from_slice(rx_packet.packet());
        Ok(rx_packet.packet_len())
    }
}
