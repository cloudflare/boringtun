//! See [PcapSniffer].

use std::{
    io::{self, Write},
    sync::Arc,
    time::Instant,
};

use pcap_file::pcap::{PcapHeader, PcapPacket};
use tokio::sync::Mutex;

use crate::tun::{IpRecv, IpSend};

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
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.recv(buf).await?;

        let packet = &buf[..n];

        let timestamp = Instant::now().duration_since(self.epoch);
        let pcap_packet = PcapPacket::new(timestamp, packet.len() as u32, packet);
        let mut write = self.writer.writer.lock().await;
        let _ = write.write_packet(&pcap_packet);

        Ok(n)
    }
}

impl<S: IpSend> IpSend for PcapSniffer<S> {
    async fn send(&self, packet: &[u8]) -> io::Result<()> {
        self.inner.send(packet).await?;

        let timestamp = Instant::now().duration_since(self.epoch);
        let pcap_packet = PcapPacket::new(timestamp, packet.len() as u32, packet);
        let mut write = self.writer.writer.lock().await;
        let _ = write.write_packet(&pcap_packet);

        Ok(())
    }
}
