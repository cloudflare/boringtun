// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod command;

use super::peer::AllowedIP;
use super::{Connection, Device, Error, Reconfigure};
use crate::serialization::KeyBytes;
use command::{Get, GetPeer, GetResponse, Peer, Request, Response, Set, SetPeer, SetResponse};
use eyre::{bail, eyre, Context};
use libc::EINVAL;
use std::fmt::Debug;
use std::io::{BufRead, BufReader, Read, Write};
use std::str::FromStr;
use std::sync::Weak;
use tokio::sync::{mpsc, oneshot, RwLock};

const SOCK_DIR: &str = "/var/run/wireguard/";

/// A server that receives [Request]s. Should be passed a [Device] when created.
pub struct ApiServer {
    rx: mpsc::Receiver<(Request, oneshot::Sender<Response>)>,
}

/// An api client to a boringtun [Device].
///
/// Use [ApiClient::send] or [ApiClient::send_sync] to configure the [Device] by adding peers, etc.
#[derive(Clone)]
pub struct ApiClient {
    tx: mpsc::Sender<(Request, oneshot::Sender<Response>)>,
}

impl ApiClient {
    pub async fn send(&self, request: impl Into<Request>) -> eyre::Result<Response> {
        let request = request.into();
        log::trace!("Handling API request: {request:?}");
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send((request, response_tx))
            .await
            .map_err(|_| eyre!("Channel closed"))?;
        response_rx
            .await
            .inspect(|response| log::trace!("Sending API response: {response:?}"))
            .map_err(|_| eyre!("Channel closed"))
    }

    pub fn send_sync(&self, request: impl Into<Request>) -> eyre::Result<Response> {
        let request = request.into();
        log::trace!("Handling API request: {request:?}");
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .blocking_send((request, response_tx))
            .map_err(|_| eyre!("Channel closed"))?;
        response_rx
            .blocking_recv()
            .inspect(|response| log::trace!("Sending API response: {response:?}"))
            .map_err(|_| eyre!("Channel closed"))
    }
}

impl ApiClient {
    /// Wrap a [Read] + [Write] and spawn a thread to convert between the textual configuration
    /// protocol and [Request]/[Response].
    ///
    /// <https://www.wireguard.com/xplatform/#configuration-protocol>
    pub fn wrap_read_write<RW>(self, rw: RW)
    where
        for<'a> &'a RW: Read + Write,
        RW: Send + Sync + 'static,
    {
        std::thread::spawn(move || {
            let r = BufReader::new(&rw);

            let make_request = |s: &str| {
                let request = Request::from_str(s).wrap_err("Failed to parse command")?;

                let Some(response) = self.send_sync(request).ok() else {
                    bail!("Server hung up");
                };

                log::info!("{:?}", response.to_string());
                if let Err(e) = writeln!(&rw, "{response}") {
                    log::error!("Failed to write API response: {e}");
                };

                Ok(())
            };

            let mut lines = String::new();

            for line in r.lines() {
                let Ok(line) = line else {
                    if !lines.is_empty() {
                        if let Err(e) = make_request(&lines) {
                            log::error!("Failed to handle UAPI request: {e:#}");
                            return;
                        };
                    }
                    return;
                };

                // Final line of a command is empty, so if this one is not, we add it to the
                // `lines` buffer and wait for more.
                if !line.is_empty() {
                    lines.push_str(&line);
                    lines.push('\n');
                    continue;
                }

                if lines.is_empty() {
                    continue;
                }

                if let Err(e) = make_request(&lines) {
                    log::error!("Failed to handle UAPI request: {e:#}");
                    return;
                };

                lines.clear();
            }
        });
    }
}

impl ApiServer {
    pub fn new() -> (ApiClient, ApiServer) {
        let (tx, rx) = mpsc::channel(100);

        (ApiClient { tx }, ApiServer { rx })
    }

    /// Spawn a unix socket in [`SOCK_DIR`] called `<name>.sock`. This socket speaks the official
    /// [configuration protocol](https://www.wireguard.com/xplatform/#configuration-protocol).
    #[cfg(unix)]
    pub fn default_unix_socket(name: &str) -> eyre::Result<Self> {
        use std::os::unix::net::UnixListener;

        let path = format!("{SOCK_DIR}/{name}.sock");

        create_sock_dir();

        let _ = std::fs::remove_file(&path); // Attempt to remove the socket if already exists

        // Bind a new socket to the path
        let api_listener =
            UnixListener::bind(&path).map_err(|e| eyre!("Failed to bidd unix socket: {e}"))?;

        let (tx, rx) = ApiServer::new();

        std::thread::spawn(move || loop {
            let Ok((stream, _)) = api_listener.accept() else {
                break;
            };

            log::info!("New UAPI connection on unix socket");

            tx.clone().wrap_read_write(stream);
        });

        Ok(rx)

        //self.cleanup_paths.push(path.clone());
    }

    /// Create an [ApiServer] from a reader+writer that speaks the official
    /// [configuration protocol](https://www.wireguard.com/xplatform/#configuration-protocol).
    pub fn from_read_write<RW>(rw: RW) -> Self
    where
        RW: Send + Sync + 'static,
        for<'a> &'a RW: Read + Write,
    {
        let (tx, rx) = Self::new();
        tx.wrap_read_write(rw);
        rx
    }

    /// Wait for a [Request]. The response should be sent on the provided [`oneshot`].
    pub(crate) async fn recv(&mut self) -> Option<(Request, oneshot::Sender<Response>)> {
        let (request, response_tx) = self.rx.recv().await?;

        Some((request, response_tx))
    }
}

impl Debug for ApiServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ApiServer").finish()
    }
}

#[cfg(unix)]
fn create_sock_dir() {
    use super::drop_privileges::get_saved_ids;

    let _ = std::fs::create_dir(SOCK_DIR); // Create the directory if it does not exist

    if let Ok((saved_uid, saved_gid)) = get_saved_ids() {
        unsafe {
            let c_path = std::ffi::CString::new(SOCK_DIR).unwrap();
            // The directory is under the root user, but we want to be able to
            // delete the files there when we exit, so we need to change the owner
            libc::chown(
                c_path.as_bytes_with_nul().as_ptr() as _,
                saved_uid,
                saved_gid,
            );
        }
    }
}

impl Device {
    pub(super) async fn handle_api(device: Weak<RwLock<Self>>, mut api: ApiServer) {
        loop {
            let Some((request, respond)) = api.recv().await else {
                // The remote side is closed
                return;
            };

            let Some(device) = device.upgrade() else {
                return;
            };
            let response = match request {
                Request::Get(get) => {
                    let device_guard = device.read().await;
                    Response::Get(on_api_get(get, &device_guard).await)
                }
                Request::Set(set) => {
                    let mut device_guard = device.write().await;
                    let (response, reconfigure) = on_api_set(set, &mut device_guard).await;
                    drop(device_guard);

                    if reconfigure == Reconfigure::Yes {
                        match Connection::set_up(device.clone()).await {
                            Ok(con) => {
                                let mut device_guard = device.write().await;
                                device_guard.connection = Some(con);
                                Response::Set(response)
                            }
                            Err(err) => {
                                // TODO: error message
                                log::error!("Failed to set up stuff: {err}");
                                // TODO: response code
                                Response::Set(SetResponse { errno: EINVAL })
                            }
                        }
                    } else {
                        Response::Set(response)
                    }
                } //_ => EIO,
            };

            let _ = respond.send(response);

            // The protocol requires to return an error code as the response, or zero on success
            //channel.tx.send(format!("errno={}\n", status)).ok();
        }
    }

    fn register_monitor(&self, _path: String) -> Result<(), Error> {
        // TODO: fix this

        /*
        self.queue.new_periodic_event(
            Box::new(move |d, _| {
                // This is not a very nice hack to detect if the control socket was removed
                // and exiting nicely as a result. We check every 3 seconds in a loop if the
                // file was deleted by stating it.
                // The problem is that on linux inotify can be used quite beautifully to detect
                // deletion, and kqueue EVFILT_VNODE can be used for the same purpose, but that
                // will require introducing new events, for no measurable benefit.
                // TODO: Could this be an issue if we restart the service too quickly?
                let path = std::path::Path::new(&path);
                if !path.exists() {
                    d.trigger_exit();
                    return Action::Exit;
                }

                // Periodically read the mtu of the interface in case it changes
                if let Ok(mtu) = d.iface.mtu() {
                    d.mtu.store(mtu, Ordering::Relaxed);
                }

                Action::Continue
            }),
            std::time::Duration::from_millis(1000),
        )?;
        */

        Ok(())
    }
}

/// Handle a [Get] request.
async fn on_api_get(_: Get, d: &Device) -> GetResponse {
    let mut peers = vec![];
    for (public_key, peer) in d.peers.iter() {
        let peer = peer.lock().await;
        let (_, tx_bytes, rx_bytes, ..) = peer.tunnel.stats();
        let endpoint = peer.endpoint().addr;

        peers.push(GetPeer {
            peer: Peer {
                public_key: KeyBytes(*public_key.as_bytes()),
                preshared_key: None, // TODO
                endpoint,
                persistent_keepalive_interval: peer.persistent_keepalive(),
                allowed_ip: peer
                    .allowed_ips()
                    .map(|(addr, cidr)| AllowedIP { addr, cidr })
                    .collect(),
            },
            last_handshake_time_sec: peer.time_since_last_handshake().map(|d| d.as_secs()),
            last_handshake_time_nsec: peer.time_since_last_handshake().map(|d| d.subsec_nanos()),
            rx_bytes: Some(rx_bytes as u64),
            tx_bytes: Some(tx_bytes as u64),
        });
    }

    GetResponse {
        private_key: d.key_pair.as_ref().map(|k| KeyBytes(k.0.to_bytes())),
        listen_port: Some(
            d.connection
                .as_ref()
                .map(|con| con.listen_port)
                .unwrap_or(0),
        ),
        fwmark: d.fwmark,
        peers,
        errno: 0,
    }
}

/// Handle a [Set] request.
async fn on_api_set(set: Set, device: &mut Device) -> (SetResponse, Reconfigure) {
    let Set {
        private_key,
        listen_port,
        fwmark,
        replace_peers,
        protocol_version,
        peers,
    } = set;

    if let Some(protocol_version) = protocol_version {
        if protocol_version != "1" {
            log::warn!("Invalid API protocol version: {protocol_version}");
            return (SetResponse { errno: EINVAL }, Reconfigure::No);
        }
    }

    let mut reconfigure: Reconfigure = Reconfigure::No;

    if replace_peers {
        device.clear_peers();
    }

    if let Some(private_key) = private_key {
        reconfigure |= device
            .set_key(x25519_dalek::StaticSecret::from(private_key.0))
            .await;
    }

    if let Some(listen_port) = listen_port {
        reconfigure |= device.set_port(listen_port).await;
    }

    if let Some(fwmark) = fwmark {
        #[cfg(target_os = "linux")]
        if device.set_fwmark(fwmark).is_err() {
            // TODO: roll back changes and don't reconfigure
            return (
                SetResponse {
                    errno: libc::EADDRINUSE,
                },
                reconfigure,
            );
        }
        // fwmark only applies on Linux
        // TODO: return error?
        #[cfg(not(target_os = "linux"))]
        let _ = fwmark;
    }

    for peer in peers {
        let SetPeer {
            peer:
                Peer {
                    public_key,
                    preshared_key,
                    endpoint,
                    persistent_keepalive_interval,
                    allowed_ip,
                },
            remove,
            update_only,
        } = peer;

        let public_key = x25519_dalek::PublicKey::from(public_key.0);

        if update_only && !device.peers.contains_key(&public_key) {
            continue;
        }

        let preshared_key = preshared_key.map(|psk| match psk {
            command::SetUnset::Set(psk) => psk.0,
            command::SetUnset::Unset => todo!("not sure how to handle this"),
        });

        device.update_peer(
            public_key,
            remove,
            //replace_allowed_ips,
            false,
            endpoint,
            allowed_ip.as_slice(),
            persistent_keepalive_interval,
            preshared_key,
        );
    }

    (SetResponse { errno: 0 }, reconfigure)
}
