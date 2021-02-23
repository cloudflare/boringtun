// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

#[cfg(test)]
mod tests {
    use super::super::*;
    use crate::crypto::x25519::*;
    use base64::encode;
    use slog::*;
    use std::fs;
    use std::fs::File;
    use std::io::prelude::Write;
    use std::net::UdpSocket;
    use std::process::Command;
    use std::str;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    // Simple counter, atomically increasing by one each call
    struct AtomicCounter {
        ctr: AtomicUsize,
    }

    impl AtomicCounter {
        pub fn next(&self) -> usize {
            self.ctr.fetch_add(1, Ordering::Relaxed)
        }
    }

    // Very dumb spin lock
    struct SpinLock {
        lock: AtomicBool,
    }

    impl SpinLock {
        pub fn lock(&self) {
            loop {
                if let Ok(true) =
                    self.lock
                        .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                {
                    break;
                }
            }
        }

        pub fn unlock(&self) {
            self.lock.store(true, Ordering::Relaxed);
        }
    }

    const MAX_PACKET: usize = 65536;
    // Next unused port
    static NEXT_PORT: AtomicCounter = AtomicCounter {
        ctr: AtomicUsize::new(30000),
    };
    // Next WG conf file name to use
    static NEXT_CONF: AtomicCounter = AtomicCounter {
        ctr: AtomicUsize::new(1),
    };
    // Next ip address to use for WG interface, of the form 192.168.2.NEXT_IP
    static NEXT_IP: AtomicCounter = AtomicCounter {
        ctr: AtomicUsize::new(3),
    };
    // Locks the use of wg-quick to a single thread
    static WG_LOCK: SpinLock = SpinLock {
        lock: AtomicBool::new(true),
    };

    // Reads a decapsulated packet and strips its IPv4 header
    fn read_ipv4_packet(socket: &UdpSocket) -> Vec<u8> {
        let mut data = [0u8; MAX_PACKET];
        let mut packet = Vec::new();
        let len = socket.recv(&mut data).unwrap();
        packet.extend_from_slice(&data[IPV4_MIN_HEADER_SIZE..len]);
        packet
    }

    // Appends an IPv4 header to a buffer and writes the resulting "packet"
    fn write_ipv4_packet(socket: &UdpSocket, data: &[u8]) {
        let mut header = [0u8; IPV4_MIN_HEADER_SIZE];
        let mut packet = Vec::new();
        let packet_len = data.len() + header.len();
        header[0] = 4 << 4;
        header[IPV4_LEN_OFF] = (packet_len >> 8) as u8;
        header[IPV4_LEN_OFF + 1] = packet_len as u8;
        packet.extend_from_slice(&header);
        packet.extend_from_slice(&data);
        socket.send(&packet).unwrap();
    }

    fn write_u16_be(val: u16, buf: &mut [u8]) {
        assert!(buf.len() >= 2);
        buf[0] = (val >> 8) as u8;
        buf[1] = val as u8;
    }

    // Compute the internet checksum of a buffer
    fn ipv4_checksum(buf: &[u8]) -> u16 {
        let mut sum = 0u32;
        for i in 0..buf.len() / 2 {
            sum += u16::from_be_bytes([buf[i * 2], buf[i * 2 + 1]]) as u32;
        }
        if buf.len() % 2 == 1 {
            sum += (buf[buf.len() - 1] as u32) << 8;
        }
        while sum > 0xffff {
            sum = (sum >> 16) + sum & 0xffff;
        }
        !(sum as u16)
    }

    // Generate a simple ping request packet from 192.168.2.2 to 192.168.2.ip
    fn write_ipv4_ping(socket: &UdpSocket, data: &[u8], seq: u16, ip: u8) {
        let mut ipv4_header = [0u8; IPV4_MIN_HEADER_SIZE];
        let mut icmp_header = [0u8; 8];

        let packet_len = ipv4_header.len() + icmp_header.len() + data.len();

        ipv4_header[0] = (4 << 4) + 5; // version = 4, header length = 5 * 4
        write_u16_be(packet_len as u16, &mut ipv4_header[2..]); // packet length
        ipv4_header[8] = 64; // TTL
        ipv4_header[9] = 1; // ICMP

        ipv4_header[12..16].copy_from_slice(&0xC0A80202u32.to_be_bytes()); // src ip = 192.168.2.2
        ipv4_header[16..20].copy_from_slice(&(0xC0A80200u32 + ip as u32).to_be_bytes()); // dst ip = 192.168.2.ip

        let checksum = ipv4_checksum(&ipv4_header);
        write_u16_be(checksum, &mut ipv4_header[10..]);

        icmp_header[0] = 8; // PING
        write_u16_be(654, &mut icmp_header[4..]); // identifier
        write_u16_be(seq, &mut icmp_header[6..]); // sequence number

        let mut packet = Vec::new();
        packet.extend_from_slice(&ipv4_header);
        packet.extend_from_slice(&icmp_header);
        packet.extend_from_slice(&data);
        // Compute the checksum of the icmp header + payload
        let icmp_checksum = ipv4_checksum(&packet[20..]);
        write_u16_be(icmp_checksum, &mut packet[20 + 2..]);
        socket.send(&packet).unwrap();
    }

    // Validate a ping reply packet
    fn read_ipv4_ping(socket: &UdpSocket, want_seq: u16) -> Vec<u8> {
        let mut data = [0u8; MAX_PACKET];
        let mut packet = Vec::new();
        if let Ok(len) = socket.recv(&mut data) {
            assert!(len >= IPV4_MIN_HEADER_SIZE);
            assert_eq!(data[0] >> 4, 4);

            let hdr_len = ((data[0] & 15) * 4) as usize;
            assert!(len >= hdr_len + 8);
            let ipv4_header = &data[..hdr_len];
            assert_eq!(ipv4_header[9], 1); // ICMP
            let icmp_header = &data[hdr_len..hdr_len + 8];
            let seq = u16::from_be_bytes([icmp_header[6], icmp_header[7]]);
            assert_eq!(seq, want_seq);

            packet.extend_from_slice(&data[hdr_len + 8..len]);
        } else {
            println!("skip {}", want_seq);
        }
        packet
    }

    // Start a WireGuard peer
    fn wireguard_test_peer(
        network_socket: UdpSocket,
        static_private: &str,
        peer_static_public: &str,
        logger: Logger,
        close: Arc<AtomicBool>,
    ) -> UdpSocket {
        let static_private = static_private.parse().unwrap();
        let peer_static_public = peer_static_public.parse().unwrap();

        let mut peer = Tunn::new(
            Arc::new(static_private),
            Arc::new(peer_static_public),
            None,
            None,
            100,
            None,
        )
        .unwrap();

        peer.set_logger(logger);

        let peer: Arc<Box<Tunn>> = Arc::from(peer);

        let (iface_socket_ret, iface_socket) = connected_sock_pair();

        network_socket
            .set_read_timeout(Some(Duration::from_millis(1000)))
            .unwrap();
        iface_socket
            .set_read_timeout(Some(Duration::from_millis(1000)))
            .unwrap();

        // The peer has three threads:
        // 1) listens on the network for encapsulated packets and decapsulates them
        // 2) listens on the iface for raw packets and encapsulates them
        // 3) times maintenance function responsible for state expiration
        {
            let network_socket = network_socket.try_clone().unwrap();
            let iface_socket = iface_socket.try_clone().unwrap();
            let peer = peer.clone();
            let close = close.clone();

            thread::spawn(move || loop {
                // Listen on the network
                let mut recv_buf = [0u8; MAX_PACKET];
                let mut send_buf = [0u8; MAX_PACKET];

                let n = match network_socket.recv(&mut recv_buf) {
                    Ok(n) => n,
                    Err(_) => {
                        if close.load(Ordering::Relaxed) {
                            return;
                        }
                        continue;
                    }
                };

                match peer.decapsulate(None, &recv_buf[..n], &mut send_buf) {
                    TunnResult::WriteToNetwork(packet) => {
                        network_socket.send(packet).unwrap();
                        // Send form queue?
                        loop {
                            let mut send_buf = [0u8; MAX_PACKET];
                            match peer.decapsulate(None, &[], &mut send_buf) {
                                TunnResult::WriteToNetwork(packet) => {
                                    network_socket.send(packet).unwrap();
                                }
                                _ => {
                                    break;
                                }
                            }
                        }
                    }
                    TunnResult::WriteToTunnelV4(packet, _) => {
                        iface_socket.send(packet).unwrap();
                    }
                    TunnResult::WriteToTunnelV6(packet, _) => {
                        iface_socket.send(packet).unwrap();
                    }
                    _ => {}
                }
            });
        }

        {
            let network_socket = network_socket.try_clone().unwrap();
            let iface_socket = iface_socket.try_clone().unwrap();
            let peer = peer.clone();
            let close = close.clone();

            thread::spawn(move || loop {
                let mut recv_buf = [0u8; MAX_PACKET];
                let mut send_buf = [0u8; MAX_PACKET];

                let n = match iface_socket.recv(&mut recv_buf) {
                    Ok(n) => n,
                    Err(_) => {
                        if close.load(Ordering::Relaxed) {
                            return;
                        }
                        continue;
                    }
                };

                match peer.encapsulate(&recv_buf[..n], &mut send_buf) {
                    TunnResult::WriteToNetwork(packet) => {
                        network_socket.send(packet).unwrap();
                    }
                    _ => {}
                }
            });
        }

        thread::spawn(move || loop {
            if close.load(Ordering::Relaxed) {
                return;
            }

            let mut send_buf = [0u8; MAX_PACKET];
            match peer.update_timers(&mut send_buf) {
                TunnResult::WriteToNetwork(packet) => {
                    network_socket.send(packet).unwrap();
                }
                _ => {}
            }

            thread::sleep(Duration::from_millis(200));
        });

        iface_socket_ret
    }

    fn connected_sock_pair() -> (UdpSocket, UdpSocket) {
        let addr_a = format!("localhost:{}", NEXT_PORT.next());
        let addr_b = format!("localhost:{}", NEXT_PORT.next());
        let sock_a = UdpSocket::bind(&addr_a).unwrap();
        let sock_b = UdpSocket::bind(&addr_b).unwrap();
        sock_a.connect(&addr_b).unwrap();
        sock_b.connect(&addr_a).unwrap();
        (sock_a, sock_b)
    }

    fn key_pair() -> (String, String) {
        let secret_key = X25519SecretKey::new();
        let public_key = secret_key.public_key();
        (encode(secret_key.as_bytes()), encode(public_key.as_bytes()))
    }

    fn wireguard_test_pair() -> (UdpSocket, UdpSocket, Arc<AtomicBool>) {
        let (s_sock, c_sock) = connected_sock_pair();
        let close = Arc::new(AtomicBool::new(false));
        let server_pair = key_pair();
        let client_pair = key_pair();

        let logger = Logger::root(
            slog_term::FullFormat::new(slog_term::PlainSyncDecorator::new(std::io::stdout()))
                .build()
                .fuse(),
            slog::o!(),
        );

        let s_iface = wireguard_test_peer(
            s_sock,
            &server_pair.0,
            &client_pair.1,
            logger.new(o!("server" => "")),
            close.clone(),
        );

        let c_iface = wireguard_test_peer(
            c_sock,
            &client_pair.0,
            &server_pair.1,
            logger.new(o!("client" => "")),
            close.clone(),
        );

        (s_iface, c_iface, close)
    }

    #[test]
    fn wireguard_handshake() {
        // Test the connection is successfully established and some packets are passed around
        {
            let (peer_iface_socket_sender, client_iface_socket_sender, close) =
                wireguard_test_pair();

            client_iface_socket_sender
                .set_read_timeout(Some(Duration::from_millis(1000)))
                .unwrap();
            client_iface_socket_sender
                .set_write_timeout(Some(Duration::from_millis(1000)))
                .unwrap();

            thread::spawn(move || loop {
                let data = read_ipv4_packet(&peer_iface_socket_sender);
                let data_string = str::from_utf8(&data).unwrap().to_uppercase().into_bytes();
                write_ipv4_packet(&peer_iface_socket_sender, &data_string);
            });

            for _i in 0..64 {
                write_ipv4_packet(&client_iface_socket_sender, b"test");
                let response = read_ipv4_packet(&client_iface_socket_sender);
                assert_eq!(&response, b"TEST");
            }

            for _i in 0..64 {
                write_ipv4_packet(&client_iface_socket_sender, b"check");
                let response = read_ipv4_packet(&client_iface_socket_sender);
                assert_eq!(&response, b"CHECK");
            }

            close.store(true, Ordering::Relaxed);
        }
    }

    struct WireGuardExt {
        conf_file_name: String,
        port: u16,
        public_key: String,
        ip: u8, // Last byte of ip
    }

    impl WireGuardExt {
        // Start an instance of wireguard using wg-quick
        pub fn start(endpoint: u16, public_key: &str) -> WireGuardExt {
            WG_LOCK.lock();
            let conf_file_name = format!("./wg{}.conf", NEXT_CONF.next());
            let mut file = File::create(&conf_file_name).unwrap();
            let port = NEXT_PORT.next() as u16;
            let ip = NEXT_IP.next() as u8;

            let key_pair = key_pair();

            file.write_all(
                format!(
                    r#"[Interface]
                        Address = 192.168.2.{}
                        ListenPort = {}
                        PrivateKey = {}
                        [Peer]
                        PublicKey = {}
                        AllowedIPs = 192.168.2.2/32
                        Endpoint = localhost:{}"#,
                    ip, port, key_pair.0, public_key, endpoint,
                )
                .as_bytes(),
            )
            .unwrap();

            // Start wireguard
            Command::new("wg-quick")
                .env("WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD", "1")
                .args(&["up", &conf_file_name])
                .status()
                .expect("Failed to run wg-quick");

            WireGuardExt {
                conf_file_name,
                port,
                public_key: key_pair.1,
                ip,
            }
        }
    }

    impl Drop for WireGuardExt {
        fn drop(&mut self) {
            // Stop wireguard
            Command::new("wg-quick")
                .args(&["down", &self.conf_file_name])
                .status()
                .expect("Failed to run wg-quick");
            fs::remove_file(&self.conf_file_name).unwrap();
            WG_LOCK.unlock();
        }
    }

    #[test]
    #[ignore]
    fn wireguard_interop() {
        // Test the connection with wireguard-go is successfully established
        // and we are getting ping from server
        let c_key_pair = key_pair();
        let itr = 1000;
        let endpoint = NEXT_PORT.next() as u16;
        let wg = WireGuardExt::start(endpoint, &c_key_pair.1);
        let c_addr = format!("localhost:{}", endpoint);
        let w_addr = format!("localhost:{}", wg.port);
        let client_socket =
            UdpSocket::bind(&c_addr).unwrap_or_else(|e| panic!("UdpSocket {}: {}", c_addr, e));
        client_socket
            .connect(&w_addr)
            .unwrap_or_else(|e| panic!("connect {}: {}", w_addr, e));

        let close = Arc::new(AtomicBool::new(false));

        let logger = Logger::root(
            slog_term::FullFormat::new(slog_term::PlainSyncDecorator::new(std::io::stdout()))
                .build()
                .fuse(),
            slog::o!(),
        );

        let c_iface = wireguard_test_peer(
            client_socket,
            &c_key_pair.0,
            &wg.public_key,
            logger.new(o!()),
            close.clone(),
        );

        c_iface
            .set_read_timeout(Some(Duration::from_millis(1000)))
            .unwrap();

        for i in 0..itr {
            write_ipv4_ping(&c_iface, b"test_ping", i as u16, wg.ip);
            assert_eq!(read_ipv4_ping(&c_iface, i as u16), b"test_ping",);
            thread::sleep(Duration::from_millis(30));
        }

        close.store(true, Ordering::Relaxed);
    }

    #[test]
    #[ignore]
    fn wireguard_receiver() {
        // Test the connection with wireguard-go is successfully established
        // when go is the initiator
        let c_key_pair = key_pair();
        let itr = 1000;

        let endpoint = NEXT_PORT.next() as u16;
        let wg = WireGuardExt::start(endpoint, &c_key_pair.1);
        let c_addr = format!("localhost:{}", endpoint);
        let w_addr = format!("localhost:{}", wg.port);
        let client_socket = UdpSocket::bind(c_addr).unwrap();
        client_socket.connect(w_addr).unwrap();

        let close = Arc::new(AtomicBool::new(false));

        let logger = Logger::root(
            slog_term::FullFormat::new(slog_term::PlainSyncDecorator::new(std::io::stdout()))
                .build()
                .fuse(),
            slog::o!(),
        );

        let c_iface = wireguard_test_peer(
            client_socket,
            &c_key_pair.0,
            &wg.public_key,
            logger,
            close.clone(),
        );

        c_iface
            .set_read_timeout(Some(Duration::from_millis(1000)))
            .unwrap();

        let t_addr = format!("192.168.2.{}:{}", wg.ip, NEXT_PORT.next());
        let test_socket = UdpSocket::bind(t_addr).unwrap();
        test_socket.connect("192.168.2.2:30000").unwrap();

        thread::spawn(move || {
            for i in 0..itr {
                test_socket
                    .send(format!("This is a test message {}", i).as_bytes())
                    .unwrap();
                thread::sleep(Duration::from_millis(10));
            }
        });

        let mut src = [0u8; MAX_PACKET];

        for i in 0..itr {
            let m = c_iface.recv(&mut src).unwrap();
            assert_eq!(
                &src[28..m], // Strip ip and udp headers
                format!("This is a test message {}", i).as_bytes()
            );
        }
    }
}
