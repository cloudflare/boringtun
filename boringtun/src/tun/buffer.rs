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
    _task: Arc<Task>,
    _phantom: std::marker::PhantomData<I>,
}

impl<I: IpSend> BufferedIpSend<I> {
    pub fn new(capacity: usize, inner: I) -> Self {
        let (tx, mut rx) = mpsc::channel::<Packet<Ip>>(capacity);

        let task = Task::spawn("buffered IP send", async move {
            while let Some(packet) = rx.recv().await {
                if let Err(e) = inner.send(packet).await {
                    log::error!("Error sending IP packet: {}", e);
                }
            }
        });

        Self {
            tx,
            _task: Arc::new(task),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<I: IpSend> IpSend for BufferedIpSend<I> {
    async fn send(&self, packet: Packet<Ip>) -> io::Result<()> {
        self.tx
            .send(packet)
            .await
            .expect("receiver dropped after senders");
        Ok(())
    }
}

pub struct BufferedIpRecv<I> {
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Packet<Ip>>>>,
    rx_packet_buf: Vec<Packet<Ip>>,
    _task: Arc<Task>,
    _phantom: std::marker::PhantomData<I>,
}

impl<I> Clone for BufferedIpRecv<I> {
    fn clone(&self) -> Self {
        BufferedIpRecv {
            rx: self.rx.clone(),
            rx_packet_buf: vec![],
            _task: self._task.clone(),
            _phantom: self._phantom,
        }
    }
}

impl<I: IpRecv> BufferedIpRecv<I> {
    pub fn new(capacity: usize, pool: PacketBufPool, mut inner: I) -> Self {
        let (tx, rx) = mpsc::channel::<Packet<Ip>>(capacity);

        let task = Task::spawn("buffered IP recv", async move {
            loop {
                match inner.recv(&pool).await {
                    Ok(packets) => {
                        for packet in packets {
                            if tx.send(packet).await.is_err() {
                                return;
                            }
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
            rx_packet_buf: vec![],
            _task: Arc::new(task),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<I: IpRecv> IpRecv for BufferedIpRecv<I> {
    async fn recv(
        &mut self,
        _pool: &PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>>> {
        let mut rx = self.rx.try_lock().expect("simultaneous recv calls");
        let max_n = rx.capacity();
        let n = rx.recv_many(&mut self.rx_packet_buf, max_n).await;
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
