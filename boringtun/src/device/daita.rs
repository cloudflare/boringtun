use std::{
    collections::HashMap,
    sync::{
        Arc, Weak,
        atomic::{self, AtomicBool, AtomicU32},
    },
};

use crate::{noise::TunnResult, packet::Packet, tun::IpRecv, udp::UdpSend};

use super::peer::Peer;
use futures::FutureExt;
use maybenot::{Framework, Machine, MachineId, TriggerAction, TriggerEvent};
use rand::RngCore;
use tokio::sync::mpsc;
use tokio::time::Instant;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned, big_endian};

use tokio::sync::Mutex;

enum ErrorAction {
    Close,
    Ignore,
}

type Result<T> = std::result::Result<T, ErrorAction>;

pub fn new_daita<M, R, IR, US>(
    maybenot: Framework<M, R>,
    peer: Weak<Mutex<Peer>>,
    ip_recv: IR,
    udp_send: US,
    packet_pool: crate::packet::PacketBufPool,
) -> (DaitaIpRecv<IR>, DaitaUdpSend<US>)
where
    Framework<M, R>: Send + 'static,
    IR: IpRecv,
    US: UdpSend + 'static,
    M: AsRef<[Machine]>,
    R: RngCore,
{
    let (event_tx, event_rx) = mpsc::unbounded_channel();
    let outbound_packet_count = Arc::new(AtomicU32::new(0));
    let replaced_packet_count = Arc::new(AtomicU32::new(0));
    let blocking_ongoing = Arc::new(AtomicBool::new(false));
    let (blocking_queue_tx, blocking_queue_rx) = mpsc::unbounded_channel();
    tokio::spawn(handle_events(
        maybenot,
        peer,
        event_rx,
        event_tx.clone(),
        packet_pool,
        udp_send.clone(),
        outbound_packet_count.clone(),
        replaced_packet_count.clone(),
        blocking_queue_rx,
        blocking_ongoing.clone(),
    ));
    (
        DaitaIpRecv {
            inner: ip_recv,
            event_tx: event_tx.clone(),
            outbound_packet_count: outbound_packet_count.clone(),
        },
        DaitaUdpSend {
            inner: udp_send,
            event_tx,
            outbound_packet_count,
            replaced_packet_count,
            blocking_queue_tx,
            blocking_ongoing,
        },
    )
}

#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq)]
#[repr(C)]
struct PaddingPacket<Payload: ?Sized = [u8]> {
    header: PaddingHeader,
    payload: Payload,
}

#[derive(FromBytes, IntoBytes, KnownLayout, Unaligned, Immutable, PartialEq, Eq, Clone, Copy)]
#[repr(C, packed)]
struct PaddingHeader {
    pub _daita_marker: u8,
    pub _reserved: u8,
    pub length: big_endian::U16,
}

#[derive(Clone, Copy)]
enum ActionTimerType {
    Padding {
        replace: bool,
        bypass: bool,
    },
    Block {
        replace: bool,
        bypass: bool,
        duration: std::time::Duration,
    },
}

async fn handle_events<M, R>(
    mut maybenot: Framework<M, R>,
    peer: Weak<Mutex<Peer>>,
    mut event_rx: mpsc::UnboundedReceiver<TriggerEvent>,
    event_tx: mpsc::UnboundedSender<TriggerEvent>,
    mut packet_pool: crate::packet::PacketBufPool,
    udp_send: impl UdpSend,
    outbound_packet_count: Arc<AtomicU32>,
    replaced_packet_count: Arc<AtomicU32>,
    mut blocking_queue_rx: mpsc::UnboundedReceiver<Packet>,
    blocking_ongoing: Arc<AtomicBool>,
) where
    M: AsRef<[Machine]>,
    R: RngCore,
{
    let mut padding_packet = packet_pool.get();
    let mtu: u16 = 1300;
    make_padding_packet(&mut padding_packet, mtu);

    let mut internal_timers = HashMap::<MachineId, Instant>::new();

    let mut action_timers = HashMap::<MachineId, (Instant, ActionTimerType)>::new();

    let mut event_buf = Vec::new();
    loop {
        let (internal_timer_fut, action_timer_fut) =
            create_time_futs(&internal_timers, &action_timers);

        futures::select! {
            count = event_rx.recv_many(&mut event_buf, usize::MAX).fuse()  => {
                if count == 0 {
                    return; // channel closed
                }
            },
            machine = internal_timer_fut.fuse() => {
                event_buf.push(TriggerEvent::TimerEnd { machine });
            }
            (machine, action_type) = action_timer_fut.fuse() => {
                match action_type {
                    ActionTimerType::Padding { replace, bypass } => {

                        let packet = if blocking_ongoing.load(atomic::Ordering::SeqCst)  {
                            if bypass {
                                if replace {
                                    &blocking_queue_rx.try_recv().unwrap() // TODO: error case?
                                } else {
                                    &padding_packet
                                }
                            } else {
                                // TODO: Or do we block the padding too?
                                continue;
                            }
                        } else {
                            let should_replace =replace &&  replaced_packet_count.load(atomic::Ordering::SeqCst) < outbound_packet_count.load(atomic::Ordering::SeqCst);
                            if should_replace {
                                replaced_packet_count.fetch_add(1, atomic::Ordering::SeqCst);
                                action_timers.remove(&machine);
                                continue;
                            } else {
                                &padding_packet
                            }
                        };

                        outbound_packet_count.fetch_add(1, atomic::Ordering::SeqCst); // TODO: Ordering?
                        if let Err(ErrorAction::Close) = send_padding_packet(
                            &udp_send,
                            &mut packet_pool,
                            &peer,
                            packet,
                            event_tx.clone(),
                            machine,
                        ).await {
                            return;
                        }
                    },
                    ActionTimerType::Block { replace, bypass, duration } => todo!(),
                };
                continue;
            },
        }
        let actions = maybenot.trigger_events(event_buf.as_slice(), std::time::Instant::now()); // TODO: support mocked time?
        for action in actions {
            match action {
                TriggerAction::Cancel { machine, timer } => match timer {
                    maybenot::Timer::Action => {
                        action_timers.remove(machine);
                    }
                    maybenot::Timer::Internal => {
                        internal_timers.remove(machine);
                    }
                    maybenot::Timer::All => {
                        action_timers.remove(machine);
                        internal_timers.remove(machine);
                    }
                },
                TriggerAction::SendPadding {
                    timeout,
                    bypass,
                    replace,
                    machine,
                } => {
                    action_timers.insert(
                        *machine,
                        (
                            Instant::now() + *timeout,
                            ActionTimerType::Padding {
                                replace: *replace,
                                bypass: *bypass,
                            },
                        ),
                    );
                }
                TriggerAction::BlockOutgoing {
                    timeout,
                    duration,
                    bypass,
                    replace,
                    machine,
                } => {
                    if action_timers
                        .get(machine)
                        .is_none_or(|(time, _)| *replace || time < &(Instant::now() + *duration))
                    {
                        action_timers.insert(
                            *machine,
                            (
                                Instant::now() + *timeout,
                                ActionTimerType::Block {
                                    replace: *replace,
                                    bypass: *bypass,
                                    duration: *duration,
                                },
                            ),
                        );
                    }
                }
                TriggerAction::UpdateTimer {
                    duration,
                    replace,
                    machine,
                } => {
                    if internal_timers
                        .get(machine)
                        .is_none_or(|time| *replace || time < &(Instant::now() + *duration))
                    {
                        internal_timers.insert(*machine, Instant::now() + *duration);
                    }
                }
            }
        }
        event_buf.clear();
    }
}

fn create_time_futs(
    internal_timers: &HashMap<MachineId, Instant>,
    action_timers: &HashMap<MachineId, (Instant, ActionTimerType)>,
) -> (
    impl Future<Output = MachineId>,
    impl Future<Output = (MachineId, ActionTimerType)>,
) {
    let internal_timer_fut = async {
        if let Some((machine, time)) = internal_timers.iter().min_by_key(|&(_, time)| time) {
            tokio::time::sleep_until(*time).await;
            *machine
        } else {
            futures::future::pending().await
        }
    };

    let action_timer_fut = async {
        if let Some((machine, (time, action_type))) =
            action_timers.iter().min_by_key(|&(_, (time, _))| time)
        {
            tokio::time::sleep_until(*time).await;
            (*machine, *action_type)
        } else {
            futures::future::pending().await
        }
    };
    (internal_timer_fut, action_timer_fut)
}

async fn send_padding_packet(
    udp_send: &impl UdpSend,
    packet_pool: &mut crate::packet::PacketBufPool,
    peer: &Weak<Mutex<Peer>>,
    padding_packet: &Packet,
    event_tx: mpsc::UnboundedSender<TriggerEvent>,
    machine: MachineId,
) -> Result<()> {
    let mut dst_buf = packet_pool.get();
    let Some(peer) = peer.upgrade() else {
        return Err(ErrorAction::Close);
    };
    let mut peer = peer.lock().await;
    match peer
        .tunnel
        .encapsulate(padding_packet.as_bytes(), &mut dst_buf[..])
    {
        TunnResult::Done => {}
        TunnResult::Err(e) => {
            log::error!("Encapsulate error={e:?}: {e:?}");
        }
        TunnResult::WriteToNetwork(packet) => {
            // TODO: DAITA tunnel_sent here?
            let len = packet.len();
            dst_buf.truncate(len);
            let endpoint_addr = peer.endpoint().addr;
            let Some(addr) = endpoint_addr else {
                log::error!("No endpoint");
                return Err(ErrorAction::Ignore);
            };
            if udp_send.send_to(dst_buf, addr).await.is_err() {
                return Err(ErrorAction::Close); // TODO: what action?
            }
            event_tx
                .send(TriggerEvent::PaddingSent { machine })
                .unwrap_or(());
        }
        _ => panic!("Unexpected result from encapsulate"),
    };
    Ok(())
}

fn make_padding_packet(padding_packet: &mut Packet, mtu: u16) {
    let padding_packet_header = PaddingHeader {
        _daita_marker: 0xFF,
        _reserved: 0,
        length: mtu.into(),
    };
    padding_packet.buf_mut().clear();
    padding_packet
        .buf_mut()
        .extend_from_slice(padding_packet_header.as_bytes());
    padding_packet.buf_mut().resize(mtu.into(), 0);
}

pub struct DaitaIpRecv<I: IpRecv> {
    inner: I,
    event_tx: mpsc::UnboundedSender<TriggerEvent>,
    outbound_packet_count: Arc<AtomicU32>,
}

impl<I: IpRecv> IpRecv for DaitaIpRecv<I> {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut crate::packet::PacketBufPool,
    ) -> std::io::Result<impl Iterator<Item = crate::packet::Packet<crate::packet::Ip>> + Send + 'a>
    {
        let res = self.inner.recv(pool).await;
        res.map(|packet_iter| {
            packet_iter.inspect(|_| {
                let _ = self.event_tx.send(TriggerEvent::NormalRecv);
                // TODO:Close on error?
                self.outbound_packet_count
                    .fetch_add(1, atomic::Ordering::SeqCst); // TODO: Ordering?
            })
        })
    }
}

#[derive(Clone)]
pub struct DaitaUdpSend<I: UdpSend> {
    inner: I,
    event_tx: mpsc::UnboundedSender<TriggerEvent>,
    outbound_packet_count: Arc<AtomicU32>,
    replaced_packet_count: Arc<AtomicU32>,
    blocking_queue_tx: mpsc::UnboundedSender<Packet>,
    blocking_ongoing: Arc<AtomicBool>,
}

impl<I: UdpSend> UdpSend for DaitaUdpSend<I> {
    type SendManyBuf = ();

    async fn send_to(
        &self,
        packet: crate::packet::Packet,
        destination: std::net::SocketAddr,
    ) -> std::io::Result<()> {
        if self.blocking_ongoing.load(atomic::Ordering::SeqCst) {
            let _ = self.blocking_queue_tx.send(packet);
            return Ok(());
        }

        let res = self.inner.send_to(packet, destination).await;
        if res.is_ok() {
            let _ = self.event_tx.send(TriggerEvent::TunnelSent);
        }
        self.replaced_packet_count
            .fetch_update(atomic::Ordering::SeqCst, atomic::Ordering::SeqCst, |x| {
                if x > 0 { Some(x - 1) } else { None }
            })
            .ok();
        self.outbound_packet_count
            .fetch_sub(1, atomic::Ordering::SeqCst); // TODO: Ordering?
        res
    }
}
