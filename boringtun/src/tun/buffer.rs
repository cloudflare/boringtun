//! Generic buffered IP send and receive implementations.

use std::sync::Arc;

use crate::{
    packet::{Ip, Packet, PacketBufPool},
    task::Task,
    tun::{IpRecv, IpSend},
};
use tokio::{io, sync::mpsc};

#[derive(Clone)]
pub struct BufferedIpSend<I> {
    tx: mpsc::Sender<Packet<Ip>>,
    pool: Arc<PacketBufPool>,
    _task: Arc<Task>,
    _phantom: std::marker::PhantomData<I>,
}

impl<I: IpSend> BufferedIpSend<I> {
    pub fn new(capacity: usize, pool: Arc<PacketBufPool>, inner: I) -> Self {
        let (tx, mut rx) = mpsc::channel::<Packet<Ip>>(capacity);

        let task = Task::spawn("buffered IP send", async move {
            while let Some(packet) = rx.recv().await {
                if let Err(e) = inner.send(&packet.into_bytes()[..]).await {
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
    async fn send(&self, data: &[u8]) -> io::Result<()> {
        let mut packet = self.pool.get();
        packet.truncate(data.len());
        packet.copy_from_slice(data);
        let ip_packet = packet.try_into_ipvx().unwrap(/* TODO */);

        self.tx
            .send(ip_packet)
            .await
            .expect("receiver dropped after senders");
        Ok(())
    }
}

#[derive(Clone)]
pub struct BufferedIpRecv<I> {
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Packet<Ip>>>>,
    _task: Arc<Task>,
    _phantom: std::marker::PhantomData<I>,
}

impl<I: IpRecv> BufferedIpRecv<I> {
    pub fn new(capacity: usize, pool: Arc<PacketBufPool>, mut inner: I) -> Self {
        let (tx, rx) = mpsc::channel::<Packet<Ip>>(capacity);

        let task = Task::spawn("buffered IP recv", async move {
            loop {
                let mut packet = pool.get();
                match inner.recv(&mut packet[..]).await {
                    Ok(n) => {
                        packet.truncate(n);
                        let ip_packet = packet.try_into_ipvx().unwrap(/* TODO */);
                        if tx.send(ip_packet).await.is_err() {
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
            return Err(io::Error::other("No packet available"));
        };
        let rx_packet = rx_packet.into_bytes();
        let len = rx_packet.len();
        packet[..len].copy_from_slice(&rx_packet);
        Ok(len)
    }
}
