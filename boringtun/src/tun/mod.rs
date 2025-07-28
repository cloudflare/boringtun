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
    fn send(&self, packet: &[u8]) -> impl Future<Output = io::Result<()>> + Send;
}

/// A type that let's you receive an IP packet.
///
/// This is used as an abstraction of the TUN device used by wireguard,
/// and enables us to, for example, swap it out with a channel.
// TODO: Refactor Device to remove Clone requirement
pub trait IpRecv: Send + Sync + Clone + 'static {
    /// Receive a complete IP packet.
    // TODO: consider refactoring trait with methods that return `Packet<Ipv4>` and `Packet<Ipv6>`
    fn recv(&mut self, buf: &mut [u8]) -> impl Future<Output = io::Result<usize>> + Send;
}

#[cfg(feature = "tun")]
mod tun {
    use super::*;
    use std::sync::Arc;

    impl IpSend for Arc<::tun::AsyncDevice> {
        async fn send(&self, packet: &[u8]) -> io::Result<()> {
            ::tun::AsyncDevice::send(self, packet).await?;
            Ok(())
        }
    }

    impl IpRecv for Arc<::tun::AsyncDevice> {
        async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            ::tun::AsyncDevice::recv(self.as_ref(), buf).await
        }
    }
}
