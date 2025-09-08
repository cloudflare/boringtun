use crate::tun::IpRecv;
use crate::udp::UdpSend;

use super::peer::Peer;
use maybenot::Framework;
use maybenot::MachineId;
use maybenot::TriggerAction;
use maybenot::TriggerEvent;
use tokio::sync::mpsc;

use std::sync::Arc;
use tokio::sync::Mutex;

struct Daita<M, R, T = std::time::Instant>
where
    T: maybenot::time::Instant,
{
    maybenot: Framework<M, R, T>,
    peer: Arc<Mutex<Peer>>,
    event_rx: mpsc::Receiver<TriggerEvent>,
}

impl<M, R, T> Daita<M, R, T>
where
    T: maybenot::time::Instant,
{
    fn new(maybenot: Framework<M, R, T>, peer: Arc<Mutex<Peer>>) -> Self {
        Self { maybenot, peer }
    }
}
struct DaitaIpRecv<I: IpRecv> {
    inner: I,
    event_tx: mpsc::Sender<TriggerEvent>,
}

impl<I: IpRecv> IpRecv for DaitaIpRecv<I> {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut crate::packet::PacketBufPool,
    ) -> std::io::Result<impl Iterator<Item = crate::packet::Packet<crate::packet::Ip>> + Send + 'a>
    {
        todo!()
    }
}

struct DaitaUdpSend<I: UdpSend> {
    inner: I,
    event_tx: mpsc::Sender<TriggerEvent>,
    // blocking_queue: VecDeque<>
}

impl<I: UdpSend> UdpSend for DaitaUdpSend<I> {
    type SendManyBuf;

    async fn send_to(
        &self,
        packet: crate::packet::Packet,
        destination: std::net::SocketAddr,
    ) -> std::io::Result<()> {
        todo!()
    }
}
