use std::{
    io::{self, Write},
    sync::Arc,
    time::Instant,
};

use pcap_file::pcap::{PcapHeader, PcapPacket, PcapWriter};
use tokio::sync::Mutex;

use crate::tun::{IpRecv, IpSend};

/// An implementor of [IpSend] and [IpRecv] which also dumps all packets in the pcap file format to a [Write].
#[derive(Clone)]
pub struct PcapSniff<I> {
    inner: I,
    epoch: Instant,
    write: Arc<Mutex<PcapWriter<Box<dyn Write + Send>>>>,
}

impl<R> PcapSniff<R> {
    pub fn new(inner: R, write: Box<dyn Write + Send>, epoch: Instant) -> Self {
        let writer = PcapWriter::with_header(
            write,
            PcapHeader {
                endianness: pcap_file::Endianness::native(),
                datalink: pcap_file::DataLink::IPV4,
                ..Default::default()
            },
        )
        .unwrap();
        Self {
            inner,
            epoch,
            write: Arc::new(Mutex::new(writer)),
        }
    }
}

impl<R: IpRecv> IpRecv for PcapSniff<R> {
    async fn recv(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.recv(buf).await?;

        let packet = &buf[..n];

        let timestamp = Instant::now().duration_since(self.epoch);
        let pcap_packet = PcapPacket::new(timestamp, packet.len() as u32, packet);
        let mut write = self.write.lock().await;
        let _ = write.write_packet(&pcap_packet);

        Ok(n)
    }
}

impl<S: IpSend> IpSend for PcapSniff<S> {
    async fn send(&self, packet: &[u8]) -> io::Result<()> {
        self.inner.send(packet).await?;

        let timestamp = Instant::now().duration_since(self.epoch);
        let pcap_packet = PcapPacket::new(timestamp, packet.len() as u32, packet);
        let mut write = self.write.lock().await;
        let _ = write.write_packet(&pcap_packet);

        Ok(())
    }
}
