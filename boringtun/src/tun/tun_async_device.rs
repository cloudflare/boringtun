//! Implementations of [IpSend] and [IpRecv] for the [::tun] crate.

use super::*;
use std::{iter, sync::Arc};

impl IpSend for Arc<::tun::AsyncDevice> {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        ::tun::AsyncDevice::send(self, &packet.into_bytes()).await?;
        Ok(())
    }
}

impl IpRecv for Arc<::tun::AsyncDevice> {
    async fn recv<'a>(
        &'a mut self,
        pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + 'a> {
        let mut packet = pool.get();
        let n = ::tun::AsyncDevice::recv(self.as_ref(), &mut packet).await?;
        packet.truncate(n);
        match packet.try_into_ip() {
            Ok(packet) => Ok(iter::once(packet)),
            Err(e) => Err(io::Error::other(e.to_string())),
        }
    }
}
