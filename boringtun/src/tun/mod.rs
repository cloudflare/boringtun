use crate::packet::{Ip, Packet, PacketBufPool};
use std::future::Future;
use std::io;

pub mod buffer;

#[cfg(feature = "pcap")]
pub mod pcap;

/// A type that let's you send an IP packet.
///
/// This is used as an abstraction of the TUN device used by wireguard,
/// and enables us to, for example, swap it out with a channel.
pub trait IpSend: Send + Sync + Clone + 'static {
    /// Send a complete IP packet.
    // TODO: consider refactoring trait with methods that take `Packet<Ipv4>` and `Packet<Ipv6>`
    fn send(&self, packet: Packet<Ip>) -> impl Future<Output = io::Result<()>> + Send;
}

/// A type that let's you receive an IP packet.
///
/// This is used as an abstraction of the TUN device used by wireguard,
/// and enables us to, for example, swap it out with a channel.
// TODO: Refactor Device to remove Clone requirement
pub trait IpRecv: Send + Sync + Clone + 'static {
    /// Receive a complete IP packet.
    // TODO: consider refactoring trait with methods that return `Packet<Ipv4>` and `Packet<Ipv6>`
    fn recv(
        &mut self,
        pool: &PacketBufPool,
    ) -> impl Future<Output = io::Result<impl Iterator<Item = Packet<Ip>> + Send>> + Send;
}

/// Implementations of [IpSend] and [IpRecv] for the [::tun] crate.
#[cfg(feature = "tun")]
mod tun_async_device {
    use super::*;
    use std::{iter, sync::Arc};

    impl IpSend for Arc<::tun::AsyncDevice> {
        async fn send(&self, packet: Packet<Ip>) -> io::Result<()> {
            ::tun::AsyncDevice::send(self, &packet.into_bytes()).await?;
            Ok(())
        }
    }

    impl IpRecv for Arc<::tun::AsyncDevice> {
        async fn recv(
            &mut self,
            pool: &PacketBufPool,
        ) -> io::Result<impl Iterator<Item = Packet<Ip>>> {
            let mut packet = pool.get();
            let n = ::tun::AsyncDevice::recv(self.as_ref(), &mut packet).await?;
            packet.truncate(n);
            match packet.try_into_ip() {
                Ok(packet) => Ok(iter::once(packet)),
                Err(e) => Err(io::Error::other(e.to_string())),
            }
        }
    }
}
