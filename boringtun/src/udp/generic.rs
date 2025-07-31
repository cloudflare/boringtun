use std::{
    io::{self},
    net::SocketAddr,
};

use crate::{
    packet::Packet,
    udp::{UdpRecv, UdpSend},
};

use super::UdpTransport;

impl UdpTransport for super::UdpSocket {
    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        super::UdpSocket::local_addr(self).map(Some)
    }
}

impl UdpSend for super::UdpSocket {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, target: SocketAddr) -> io::Result<()> {
        self.inner.send_to(&packet, target).await?;
        Ok(())
    }
}

impl UdpRecv for super::UdpSocket {
    async fn recv_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.inner.recv_from(buf).await
    }
}
