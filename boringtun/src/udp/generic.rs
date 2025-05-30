use std::{
    io::{self},
    net::SocketAddr,
};

use super::UdpTransport;

impl UdpTransport for tokio::net::UdpSocket {
    type SendManyBuf = ();

    async fn send_to(&self, packet: &[u8], target: SocketAddr) -> io::Result<()> {
        self.send_to(packet, target).await?;
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from(buf).await
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.local_addr().map(Some)
    }
}
