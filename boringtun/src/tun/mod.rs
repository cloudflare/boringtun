use crate::packet::{Ip, Packet, PacketBufPool};
use std::future::Future;
use std::io;

pub mod buffer;
pub mod channel;

#[cfg(feature = "pcap")]
pub mod pcap;

#[cfg(feature = "tun")]
pub mod tun_async_device;

/// A type that let's you send an IP packet.
///
/// This is used as an abstraction of the TUN device used by wireguard,
/// and enables us to, for example, swap it out with a channel.
pub trait IpSend: Send + Sync + 'static {
    /// Send a complete IP packet.
    // TODO: consider refactoring trait with methods that take `Packet<Ipv4>` and `Packet<Ipv6>`
    fn send(&mut self, packet: Packet<Ip>) -> impl Future<Output = io::Result<()>> + Send;
}

/// A type that let's you receive an IP packet.
///
/// This is used as an abstraction of the TUN device used by wireguard,
/// and enables us to, for example, swap it out with a channel.
pub trait IpRecv: Send + Sync + 'static {
    /// Receive a complete IP packet.
    // TODO: consider refactoring trait with methods that return `Packet<Ipv4>` and `Packet<Ipv6>`
    fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> impl Future<Output = io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a>> + Send;
}
