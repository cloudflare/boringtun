use nix::sys::socket::{MsgFlags, MultiHeaders, SockaddrIn, SockaddrStorage};
#[cfg(target_os = "linux")]
use nix::sys::socket::{setsockopt, sockopt};
use std::{
    io::{self, IoSlice, IoSliceMut},
    net::SocketAddr,
    os::fd::AsRawFd,
};
use tokio::io::Interest;

use crate::packet::PacketBuf;

use super::UdpTransport;

const MAX_PACKET_COUNT: usize = 100;

#[derive(Default)]
pub struct SendmmsgBuf {
    targets: Vec<Option<SockaddrStorage>>,
}

impl UdpTransport for tokio::net::UdpSocket {
    type SendManyBuf = SendmmsgBuf;

    async fn send_many_to(
        &self,
        buf: &mut SendmmsgBuf,
        packets: &[(PacketBuf, SocketAddr)],
    ) -> io::Result<()> {
        let n = packets.len();
        debug_assert!(n <= MAX_PACKET_COUNT);

        let fd = self.as_raw_fd();

        buf.targets.clear();
        packets
            .iter()
            .map(|(_packet, target)| Some(SockaddrStorage::from(*target)))
            .for_each(|target| buf.targets.push(target));

        // This allocation can't be put in the struct because of lifetimes.
        // So we allocate it on the stack instead.
        let mut packets_buf = [[IoSlice::new(&[])]; MAX_PACKET_COUNT];
        packets
            .iter()
            .map(|(packet_buf, _target)| [IoSlice::new(packet_buf.packet())])
            .enumerate()
            // packets.len() is no greater than MAX_PACKET_COUNT
            .for_each(|(i, packet)| packets_buf[i] = packet);
        let packets = &packets_buf[..n];

        self.async_io(Interest::WRITABLE, || {
            let mut multiheaders = MultiHeaders::preallocate(packets.len(), None);
            nix::sys::socket::sendmmsg(
                fd,
                &mut multiheaders,
                packets,
                &buf.targets[..],
                [],
                MsgFlags::MSG_DONTWAIT,
            )?;

            Ok(())
        })
        .await?;

        Ok(())
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        MAX_PACKET_COUNT
    }

    fn max_number_of_packets_to_recv(&self) -> usize {
        MAX_PACKET_COUNT
    }

    async fn send_to(&self, packet: &[u8], target: SocketAddr) -> io::Result<()> {
        self.send_to(packet, target).await?;
        Ok(())
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        self.recv_from(buf).await
    }

    async fn recv_many_from(
        &self,
        bufs: &mut [PacketBuf],
        source_addrs: &mut [Option<SocketAddr>],
    ) -> io::Result<usize> {
        debug_assert_eq!(bufs.len(), source_addrs.len());

        let fd = self.as_raw_fd();

        let num_bufs = self
            .async_io(Interest::READABLE, || {
                let mut headers = MultiHeaders::<SockaddrIn>::preallocate(bufs.len(), None);

                let (mut msgs, mut packet_lens): (Vec<_>, Vec<_>) = bufs
                    .iter_mut()
                    .map(|buf| {
                        let (buf, packet_len) = buf.packet_and_len_mut();
                        ([IoSliceMut::new(buf)], packet_len)
                    })
                    .unzip();

                let results = nix::sys::socket::recvmmsg(
                    fd,
                    &mut headers,
                    &mut msgs,
                    MsgFlags::MSG_DONTWAIT,
                    None,
                )?;

                let mut num_bufs = 0;

                results.zip(source_addrs.iter_mut()).enumerate().for_each(
                    |(i, (result, out_addr))| {
                        *packet_lens[i] = result.bytes;
                        *out_addr = result.address.map(|addr| addr.into());
                        num_bufs += 1;
                    },
                );

                Ok(num_bufs)
            })
            .await?;

        Ok(num_bufs)
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.local_addr().map(Some)
    }

    #[cfg(target_os = "linux")]
    fn set_fwmark(&self, mark: u32) -> io::Result<()> {
        setsockopt(self, sockopt::Mark, &mark)?;
        Ok(())
    }
}
