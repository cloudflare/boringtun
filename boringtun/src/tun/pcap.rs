//! See [PcapSniffer].

use std::{
    io::{self, Write},
    sync::{Arc, Mutex},
    time::Instant,
};

use pcap_file::pcap::{PcapHeader, PcapPacket};
use zerocopy::IntoBytes;

use crate::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend},
};

#[derive(Clone)]
pub struct PcapStream {
    writer: Arc<Mutex<pcap_file::pcap::PcapWriter<Box<dyn Write + Send>>>>,
}

/// An implementor of [IpSend] and [IpRecv] which also dumps all packets in the pcap file format to a [Write] (See [PcapStream]).
#[derive(Clone)]
pub struct PcapSniffer<I> {
    inner: I,
    epoch: Instant,
    writer: PcapStream,
}

impl PcapStream {
    pub fn new(write: Box<dyn Write + Send>) -> Self {
        let writer = pcap_file::pcap::PcapWriter::with_header(
            write,
            PcapHeader {
                endianness: pcap_file::Endianness::native(),
                datalink: pcap_file::DataLink::IPV4,
                ..Default::default()
            },
        )
        .unwrap();

        Self {
            writer: Arc::new(Mutex::new(writer)),
        }
    }
}

impl<R> PcapSniffer<R> {
    pub fn new(inner: R, writer: PcapStream, epoch: Instant) -> Self {
        Self {
            inner,
            epoch,
            writer,
        }
    }
}

impl<R: IpRecv> IpRecv for PcapSniffer<R> {
    async fn recv<'a>(
        &'a mut self,
        buf: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        let packets = self.inner.recv(buf).await?;

        let packets = packets.inspect(|packet| {
            let packet = packet.as_bytes();
            let timestamp = Instant::now().duration_since(self.epoch);
            if let Ok(mut write) = self.writer.writer.lock() {
                let pcap_packet = PcapPacket::new(timestamp, packet.len() as u32, packet);
                let _ = write.write_packet(&pcap_packet);
            }
        });

        Ok(packets)
    }
}

impl<S: IpSend> IpSend for PcapSniffer<S> {
    async fn send(&self, packet: Packet<Ip>) -> io::Result<()> {
        if let Ok(mut write) = self.writer.writer.lock() {
            let packet = packet.as_bytes();
            let timestamp = Instant::now().duration_since(self.epoch);
            let pcap_packet = PcapPacket::new(timestamp, packet.len() as u32, packet);
            let _ = write.write_packet(&pcap_packet);
        }
        self.inner.send(packet).await?;
        Ok(())
    }
}
