use nix::sys::socket::{MsgFlags, MultiHeaders, SockaddrStorage};
use std::{
    io::{self, IoSlice},
    net::SocketAddr,
    os::fd::AsRawFd,
};
use tokio::io::Interest;

use crate::{packet::Packet, udp::UdpSend};

/// Max number of packets/messages for sendmmsg/recvmmsg
const MAX_PACKET_COUNT: usize = 100;

#[derive(Default)]
pub struct SendmmsgBuf {
    targets: Vec<Option<SockaddrStorage>>,
}

impl UdpSend for super::UdpSocket {
    type SendManyBuf = SendmmsgBuf;

    async fn send_to(&self, packet: Packet, target: SocketAddr) -> io::Result<()> {
        tokio::net::UdpSocket::send_to(&self.inner, &packet, target).await?;
        Ok(())
    }

    async fn send_many_to(
        &self,
        buf: &mut SendmmsgBuf,
        packets: &mut Vec<(Packet, SocketAddr)>,
    ) -> io::Result<()> {
        let n = packets.len();
        debug_assert!(n <= MAX_PACKET_COUNT);

        let fd = self.inner.as_raw_fd();

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
            .map(|(packet, _target)| [IoSlice::new(&packet[..])])
            .enumerate()
            // packets.len() is no greater than MAX_PACKET_COUNT
            .for_each(|(i, packet)| packets_buf[i] = packet);
        let pkts = &packets_buf[..n];

        self.inner
            .async_io(Interest::WRITABLE, || {
                let mut multiheaders = MultiHeaders::preallocate(pkts.len(), None);
                nix::sys::socket::sendmmsg(
                    fd,
                    &mut multiheaders,
                    pkts,
                    &buf.targets[..],
                    [],
                    MsgFlags::MSG_DONTWAIT,
                )?;

                Ok(())
            })
            .await?;

        packets.clear();

        Ok(())
    }

    fn max_number_of_packets_to_send(&self) -> usize {
        MAX_PACKET_COUNT
    }
}

#[cfg(target_os = "linux")]
mod gro {
    /// Number of segments per message received
    const MAX_SEGMENTS: usize = 64;
    /// Size of a single UDP packet with multiple segments
    // TODO: Fix constant
    const MAX_GRO_SIZE: usize = MAX_SEGMENTS * 4096;

    use super::MAX_PACKET_COUNT;
    use crate::packet::{Packet, PacketBufPool};
    use crate::udp::{UdpRecv, UdpSocket, UdpTransport};
    use bytes::BytesMut;
    use nix::cmsg_space;
    use nix::sys::socket::{
        ControlMessageOwned, MsgFlags, MultiHeaders, SockaddrIn, setsockopt, sockopt,
    };
    use std::io::{self, IoSliceMut};
    use std::net::SocketAddr;
    use std::os::fd::AsRawFd;
    use tokio::io::Interest;

    pub struct RecvManyBuf {
        pub(crate) gro_bufs: Box<[BytesMut; MAX_PACKET_COUNT]>,
    }

    // SAFETY: MultiHeaders contains pointers, but we only ever mutate data in [Self::recv_many_from].
    // This should be fine.
    unsafe impl Send for RecvManyBuf {}

    impl Default for RecvManyBuf {
        fn default() -> Self {
            let mut gro_buf = BytesMut::zeroed(MAX_PACKET_COUNT * MAX_GRO_SIZE);
            let gro_bufs = [(); MAX_PACKET_COUNT];
            let gro_bufs = gro_bufs.map(|_| gro_buf.split_to(MAX_GRO_SIZE));
            let gro_bufs = Box::new(gro_bufs);

            Self { gro_bufs }
        }
    }

    impl UdpRecv for UdpSocket {
        type RecvManyBuf = RecvManyBuf;

        fn max_number_of_packets_to_recv(&self) -> usize {
            MAX_SEGMENTS * MAX_PACKET_COUNT
        }

        async fn recv_from(
            &mut self,
            pool: &mut PacketBufPool,
        ) -> io::Result<(Packet, SocketAddr)> {
            let mut buf = pool.get();
            let (n, src) = self.inner.recv_from(&mut buf).await?;
            buf.truncate(n);
            Ok((buf, src))
        }

        async fn recv_many_from(
            &mut self,
            recv_many_bufs: &mut Self::RecvManyBuf,
            pool: &mut PacketBufPool,
            bufs: &mut Vec<Packet>,
            source_addrs: &mut [Option<SocketAddr>],
        ) -> io::Result<()> {
            let fd = self.inner.as_raw_fd();

            self.inner
                .async_io(Interest::READABLE, move || {
                    // TODO: the CMSG space cannot be reused, so we must allocate new headers each time
                    // [ControlMessageOwned::UdpGroSegments(i32)] contains the size of all smaller packets/segments
                    let headers = &mut MultiHeaders::<SockaddrIn>::preallocate(
                        MAX_PACKET_COUNT,
                        Some(cmsg_space!(i32)),
                    );

                    let mut io_slices: [[IoSliceMut; 1]; MAX_PACKET_COUNT] =
                        std::array::from_fn(|_| [IoSliceMut::new(&mut [])]);

                    for (i, buf) in recv_many_bufs.gro_bufs.iter_mut().enumerate() {
                        io_slices[i] = [IoSliceMut::new(&mut buf[..])];
                    }

                    let results = nix::sys::socket::recvmmsg(
                        fd,
                        headers,
                        &mut io_slices[..MAX_PACKET_COUNT],
                        MsgFlags::MSG_DONTWAIT,
                        None,
                    )?;

                    let mut bufs_index = 0;

                    for result in results {
                        let iov = result.iovs().next().expect("we create exactly one IoSlice");

                        // TODO: is this true? Under what circumstance can the cmsg buffer overflow?
                        let mut cmsgs = result.cmsgs().expect("we have allocated enough memory");

                        let gro_size = cmsgs
                            .find_map(|cmsg| match cmsg {
                                ControlMessageOwned::UdpGroSegments(gro_size) => Some(gro_size),
                                _ => None,
                            })
                            .and_then(|gro_size| usize::try_from(gro_size).ok())
                            .filter(|&gro_size| gro_size > 0);

                        // Generic Receive Offload
                        if let Some(gro_size) = gro_size {
                            // Divide packet into GRO-sized segments and copy them into Packet bufs
                            for gro_segment in iov.chunks(gro_size) {
                                let mut buf = pool.get();
                                // TODO: consider splitting the iov backing buffer into multiple
                                // BytesMut to avoid copying the data here.
                                buf[..gro_segment.len()].copy_from_slice(gro_segment);
                                buf.truncate(gro_segment.len());
                                bufs.push(buf);

                                source_addrs[bufs_index] = result.address.map(|addr| addr.into());
                                bufs_index += 1;
                            }
                        } else {
                            // Single packet
                            source_addrs[bufs_index] = result.address.map(|addr| addr.into());

                            let size = result.bytes;
                            let mut buf = pool.get();
                            buf[..size].copy_from_slice(&iov[..size]);
                            buf.truncate(size);
                            bufs.push(buf);

                            bufs_index += 1;
                        }
                    }

                    Ok(())
                })
                .await?;

            Ok(())
        }
    }

    impl UdpTransport for UdpSocket {
        fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
            UdpSocket::local_addr(self).map(Some)
        }

        fn set_fwmark(&self, mark: u32) -> io::Result<()> {
            setsockopt(&self.inner, sockopt::Mark, &mark)?;
            Ok(())
        }

        fn enable_udp_gro(&self) -> io::Result<()> {
            // TODO: missing constants on Android
            use std::os::fd::AsFd;
            nix::sys::socket::setsockopt(
                &self.inner.as_fd(),
                nix::sys::socket::sockopt::UdpGroSegment,
                &true,
            )?;
            Ok(())
        }
    }
}

#[cfg(target_os = "android")]
mod android {
    use crate::packet::{Packet, PacketBufPool};
    use crate::udp::{UdpRecv, UdpSocket, UdpTransport};
    use std::io;
    use std::net::SocketAddr;

    impl UdpRecv for UdpSocket {
        type RecvManyBuf = ();

        async fn recv_from(
            &mut self,
            pool: &mut PacketBufPool,
        ) -> io::Result<(Packet, SocketAddr)> {
            let mut buf = pool.get();
            let (n, src) = self.inner.recv_from(&mut buf).await?;
            buf.truncate(n);
            Ok((buf, src))
        }
    }

    impl UdpTransport for UdpSocket {
        fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
            UdpSocket::local_addr(self).map(Some)
        }
    }
}
