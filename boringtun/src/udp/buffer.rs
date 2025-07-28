//! Generic buffered UdpTransport implementation.

use std::iter;
use std::{net::SocketAddr, sync::Arc};

use tokio::{
    io,
    sync::{Mutex, mpsc},
};

use crate::task::Task;
use crate::{
    packet::{PacketBuf, PacketBufPool},
    udp::UdpTransport,
};

pub struct BufferedUdpTransport<U: UdpTransport> {
    inner: Arc<U>,
    pool: Arc<PacketBufPool>,
    _send_task: Arc<Task>,
    _recv_task: Arc<Task>,
    send_tx: mpsc::Sender<(PacketBuf, SocketAddr)>,
    recv_rx: Arc<Mutex<mpsc::Receiver<(PacketBuf, SocketAddr)>>>,
}

impl<U: UdpTransport> Clone for BufferedUdpTransport<U> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            pool: self.pool.clone(),
            _send_task: self._send_task.clone(),
            _recv_task: self._recv_task.clone(),
            send_tx: self.send_tx.clone(),
            recv_rx: self.recv_rx.clone(),
        }
    }
}

impl<U: UdpTransport + 'static> BufferedUdpTransport<U> {
    pub fn new(capacity: usize, inner: Arc<U>, pool: Arc<PacketBufPool>) -> Self {
        let (send_tx, mut send_rx) = mpsc::channel::<(PacketBuf, SocketAddr)>(capacity);

        let udp_tx = inner.clone();
        let udp_rx = inner.clone();

        let send_task = Task::spawn("buffered UDP send", async move {
            let mut buf = vec![];
            let max_number_of_packets_to_send = udp_tx.max_number_of_packets_to_send();
            let mut send_many_buf = Default::default();

            while let Some((packet_buf, addr)) = send_rx.recv().await {
                buf.clear();

                if send_rx.is_empty() {
                    let _ = udp_tx.send_to(packet_buf.packet(), addr).await;
                } else {
                    // collect as many packets as possible into a buffer, and use send_many_to
                    [(packet_buf, addr)]
                        .into_iter()
                        .chain(iter::from_fn(|| send_rx.try_recv().ok()))
                        .take(max_number_of_packets_to_send)
                        .for_each(|(packet_buf, target)| buf.push((packet_buf, target)));

                    // send all packets at once
                    let _ = udp_tx
                        .send_many_to(&mut send_many_buf, &buf)
                        .await
                        .inspect_err(|e| log::trace!("send_to_many_err: {e:#}"));

                    // Release borrowed buffers
                    buf.clear();
                }
            }
        });

        let (recv_tx, recv_rx) = mpsc::channel::<(PacketBuf, SocketAddr)>(capacity);

        let recv_pool = pool.clone();

        let recv_task = Task::spawn("buffered UDP receive", async move {
            let max_number_of_packets = udp_rx.max_number_of_packets_to_recv();
            let mut packet_bufs = Vec::with_capacity(max_number_of_packets);
            let mut source_addrs = vec![None; max_number_of_packets];

            loop {
                while packet_bufs.len() < max_number_of_packets {
                    packet_bufs.push(recv_pool.get());
                }
                let n_available_bufs = packet_bufs.len();

                // Read packets from the socket.
                // TODO: src in PacketBuf?
                let Ok(num_packets) = udp_rx
                    .recv_many_from(
                        &mut packet_bufs[..n_available_bufs],
                        &mut source_addrs[..n_available_bufs],
                    )
                    .await
                else {
                    // TODO
                    return;
                };

                for (i, packet_buf) in packet_bufs.drain(..num_packets).enumerate() {
                    let src = source_addrs[i];

                    let Some(src) = src else {
                        log::trace!("recv_many_from returned packet with no src; ignoring");
                        continue;
                    };

                    match recv_tx.try_send((packet_buf, src)) {
                        Ok(_) => (),
                        Err(mpsc::error::TrySendError::Full((packet_buf, addr))) => {
                            if recv_tx.send((packet_buf, addr)).await.is_err() {
                                // Buffer dropped
                                return;
                            }
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => return,
                    }
                }
            }
        });

        Self {
            inner,
            pool,
            _send_task: Arc::new(send_task),
            _recv_task: Arc::new(recv_task),
            send_tx,
            recv_rx: Arc::new(Mutex::new(recv_rx)),
        }
    }
}

impl<U: UdpTransport> UdpTransport for BufferedUdpTransport<U> {
    type SendManyBuf = U::SendManyBuf;

    async fn send_to(&self, packet: &[u8], destination: SocketAddr) -> io::Result<()> {
        let mut packet_buf = self.pool.get();
        packet_buf.copy_from(packet);
        self.send_tx.send((packet_buf, destination)).await.unwrap();
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let Some((rx_packet, src)) = self
            .recv_rx
            .try_lock()
            .expect("simultaneous recv")
            .recv()
            .await
        else {
            return Err(io::Error::other("No packet available"));
        };
        buf[..rx_packet.len].copy_from_slice(rx_packet.packet());
        Ok((rx_packet.packet_len(), src))
    }

    // TODO: implement recv_from many with mpsc::Receiver::recv_many?

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr()
    }

    #[cfg(target_os = "linux")]
    fn set_fwmark(&self, mark: u32) -> io::Result<()> {
        self.inner.set_fwmark(mark)
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        self.inner.max_number_of_packets_to_send()
    }

    fn max_number_of_packets_to_recv(&self) -> usize {
        self.inner.max_number_of_packets_to_recv()
    }
}
