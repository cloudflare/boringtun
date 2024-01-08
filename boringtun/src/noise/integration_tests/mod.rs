mod tests {
    use parking_lot::Mutex;
    use rand::prelude::*;
    use std::{net::SocketAddr, str::FromStr, sync::Arc};
    use tokio::net::UdpSocket;
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::noise::{Tunn, TunnResult, HANDSHAKE_INIT_SZ, HANDSHAKE_RESP_SZ};

    const MAX_PACKET: usize = 2048;

    struct WGClient {
        pub client_socket: UdpSocket,
        pub client_address: SocketAddr,
        pub tunnel: Arc<Mutex<Tunn>>,
    }

    impl WGClient {
        async fn new(client_private_key: StaticSecret, peer_public_key: PublicKey) -> Self {
            let client_socket = UdpSocket::bind(SocketAddr::from_str("127.0.0.1:0").unwrap())
                .await
                .expect("Failed to bind client socket");
            let client_port = client_socket
                .local_addr()
                .expect("Failed to get client local address")
                .port();
            let client_address = ([127, 0, 0, 1], client_port).into();

            WGClient {
                client_socket,
                client_address,
                tunnel: Arc::new(Mutex::new(
                    Tunn::new(
                        client_private_key,
                        peer_public_key.clone(),
                        None,
                        None,
                        0,
                        None,
                    )
                    .expect("Failed to create client tunnel"),
                )),
            }
        }

        fn assert_tx_rx(&self, tx_bytes: usize, rx_bytes: usize) {
            let (_, tx, rx, _, _) = self.tunnel.lock().stats();
            assert_eq!(tx, tx_bytes);
            assert_eq!(rx, rx_bytes);
        }
    }

    async fn setup() -> (WGClient, WGClient) {
        let a_secret_key = StaticSecret::new(&mut rand::rngs::StdRng::from_entropy());
        let a_public_key = PublicKey::from(&a_secret_key);

        let b_secret_key = StaticSecret::new(&mut rand::rngs::StdRng::from_entropy());
        let b_public_key = PublicKey::from(&b_secret_key);

        let a = WGClient::new(a_secret_key, b_public_key).await;
        let b = WGClient::new(b_secret_key, a_public_key).await;

        (a, b)
    }

    #[tokio::test]
    async fn test_tx_rx_bytes_counters() {
        let (a, b) = setup().await;

        let mut sending_buffer = vec![0u8; MAX_PACKET];
        let mut receiving_buffer = vec![0u8; MAX_PACKET];

        // Initiate handshake from a side
        match a.tunnel.lock().encapsulate(&[], &mut sending_buffer) {
            TunnResult::WriteToNetwork(msg) => {
                a.client_socket
                    .send_to(msg, b.client_address)
                    .await
                    .expect("Failed to send handshake message");
            }
            TunnResult::Err(e) => panic!("Encapsulate error: {:?}", e),
            _ => panic!("Unexpected TunnResult during handshake phase"),
        }
        a.assert_tx_rx(HANDSHAKE_INIT_SZ, 0);

        // Handle handshake from b side
        let bytes_read = b
            .client_socket
            .recv(&mut receiving_buffer)
            .await
            .expect("Failed to recv");

        match b.tunnel.lock().decapsulate(
            None,
            &receiving_buffer[..bytes_read],
            &mut sending_buffer,
        ) {
            TunnResult::WriteToNetwork(msg) => {
                b.client_socket
                    .send_to(msg, a.client_address)
                    .await
                    .expect("Failed to send");
            }
            TunnResult::Err(e) => panic!("Decapsulate error: {:?}", e),
            _ => panic!("Unexpected TunnResult during handshake phase"),
        }
        b.assert_tx_rx(HANDSHAKE_RESP_SZ, HANDSHAKE_INIT_SZ);

        // Handle handshake response on a side
        let bytes_read = a
            .client_socket
            .recv(&mut receiving_buffer)
            .await
            .expect("Failed to recv");

        match a.tunnel.lock().decapsulate(
            None,
            &receiving_buffer[..bytes_read],
            &mut sending_buffer,
        ) {
            TunnResult::WriteToNetwork(msg) => {
                // This will send a keepalive
                a.client_socket
                    .send_to(msg, b.client_address)
                    .await
                    .expect("Failed to send");
            }
            TunnResult::Err(e) => panic!("Decapsulate error: {:?}", e),
            _ => panic!("Unexpected TunnResult during handshake phase"),
        }
        a.assert_tx_rx(HANDSHAKE_INIT_SZ + 32, HANDSHAKE_RESP_SZ);

        // Ensure handshake is done on b side
        let bytes_read = b
            .client_socket
            .recv(&mut receiving_buffer)
            .await
            .expect("Failed to recv");

        match b.tunnel.lock().decapsulate(
            None,
            &receiving_buffer[..bytes_read],
            &mut sending_buffer,
        ) {
            TunnResult::Done => (),
            TunnResult::Err(e) => panic!("Decapsulate error: {:?}", e),
            _ => panic!("Unexpected TunnResult during handshake phase"),
        }
        b.assert_tx_rx(HANDSHAKE_RESP_SZ, HANDSHAKE_INIT_SZ + 32);
    }
}
