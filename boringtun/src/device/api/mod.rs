// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod command;

use super::drop_privileges::get_saved_ids;
use super::peer::AllowedIP;
use super::{Device, Error};
use crate::serialization::KeyBytes;
use command::{Get, GetPeer, GetResponse, Peer, Request, Response, Set, SetPeer, SetResponse};
use eyre::{bail, eyre, Context};
use libc::*;
use std::fmt::Debug;
use std::fs::create_dir;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::str::FromStr;
use std::sync::{mpsc, Arc};
use tokio::sync::RwLock;

const SOCK_DIR: &str = "/var/run/wireguard/";

pub struct ConfigRx {
    // TODO: oneshot
    rx: mpsc::Receiver<(Request, mpsc::Sender<Response>)>,
}

#[derive(Clone)]
pub struct ConfigTx {
    tx: mpsc::Sender<(Request, mpsc::Sender<Response>)>,
}

impl ConfigTx {
    pub fn send(&self, request: impl Into<Request>) -> eyre::Result<Response> {
        let (response_tx, response_rx) = mpsc::channel();
        self.tx
            .send((request.into(), response_tx))
            .map_err(|_| eyre!("Channel closed"))?;
        response_rx.recv().map_err(|_| eyre!("Channel closed"))
    }
}

impl ConfigTx {
    /// Wrap a [Read] + [Write] and spawn a thread to convert between the textual config format and
    /// [Request]/[Response].
    pub fn wrap_read_write<RW>(self, rw: RW)
    where
        for<'a> &'a RW: Read + Write,
        RW: Send + Sync + 'static,
    {
        std::thread::spawn(move || {
            let r = BufReader::new(&rw);

            let make_request = |s: &str| {
                let request = Request::from_str(s).wrap_err("Failed to parse command")?;

                let Some(response) = self.send(request).ok() else {
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
                dbg!(&line);
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

impl ConfigRx {
    pub fn new() -> (ConfigTx, ConfigRx) {
        let (tx, rx) = mpsc::channel();

        (ConfigTx { tx }, ConfigRx { rx })
    }

    pub fn default_unix_socket(interface_name: &str) -> eyre::Result<Self> {
        let path = format!("{SOCK_DIR}/{interface_name}.sock");

        create_sock_dir();

        let _ = std::fs::remove_file(&path); // Attempt to remove the socket if already exists

        // Bind a new socket to the path
        let api_listener =
            UnixListener::bind(&path).map_err(|e| eyre!("Failed to bidd unix socket: {e}"))?;

        let (tx, rx) = ConfigRx::new();

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

    pub fn from_read_write<RW>(rw: RW) -> Self
    where
        RW: Send + Sync + 'static,
        for<'a> &'a RW: Read + Write,
    {
        let (tx, rx) = Self::new();
        tx.wrap_read_write(rw);
        rx
    }

    pub fn recv(&mut self) -> Option<(Request, impl FnOnce(Response))> {
        let (request, response_tx) = self.rx.recv().ok()?;

        let respond = move |response| {
            let _ = response_tx.send(response);
        };

        Some((request, respond))
    }
}

impl Debug for ConfigRx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ApiChannel").finish()
    }
}

fn create_sock_dir() {
    let _ = create_dir(SOCK_DIR); // Create the directory if it does not exist

    if let Ok((saved_uid, saved_gid)) = get_saved_ids() {
        unsafe {
            let c_path = std::ffi::CString::new(SOCK_DIR).unwrap();
            // The directory is under the root user, but we want to be able to
            // delete the files there when we exit, so we need to change the owner
            chown(
                c_path.as_bytes_with_nul().as_ptr() as _,
                saved_uid,
                saved_gid,
            );
        }
    }
}

impl Device {
    pub fn register_api_handler(device: &Arc<RwLock<Self>>, mut channel: ConfigRx) {
        let device = device.clone();
        tokio::spawn(async move {
            loop {
                let Some((request, respond)) = channel.recv() else {
                    // The remote side is closed
                    return;
                };

                let response = match request {
                    Request::Get(get) => {
                        let device_guard = device.read().await;
                        Response::Get(api_get(get, &device_guard))
                    }
                    Request::Set(set) => {
                        let mut device_guard = device.write().await;
                        Response::Set(api_set(set, &mut device_guard))
                    } //_ => EIO,
                };

                respond(response);

                // The protocol requires to return an error code as the response, or zero on success
                //channel.tx.send(format!("errno={}\n", status)).ok();
            }
        });
    }

    fn register_monitor(&self, path: String) -> Result<(), Error> {
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

fn api_get(_: Get, d: &Device) -> GetResponse {
    let peers = d
        .peers
        .iter()
        .map(|(public_key, peer)| {
            let peer = peer.lock(); // TODO: is this ok?
            let (_, tx_bytes, rx_bytes, ..) = peer.tunnel.stats();
            let endpoint = peer.endpoint().addr;

            GetPeer {
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
                last_handshake_time_nsec: peer
                    .time_since_last_handshake()
                    .map(|d| d.subsec_nanos()),
                rx_bytes: Some(rx_bytes as u64),
                tx_bytes: Some(tx_bytes as u64),
            }
        })
        .collect();

    GetResponse {
        private_key: d.key_pair.as_ref().map(|k| KeyBytes(k.0.to_bytes())),
        listen_port: Some(d.listen_port),
        fwmark: d.fwmark,
        peers,
        errno: 0,
    }
}

fn api_set(set: Set, device: &mut Device) -> SetResponse {
    let Set {
        private_key,
        listen_port,
        fwmark,
        replace_peers,
        protocol_version,
        peers,
    } = set;

    if replace_peers {
        device.clear_peers();
    }

    if let Some(private_key) = private_key {
        device.set_key(x25519_dalek::StaticSecret::from(private_key.0));
    }
    if let Some(listen_port) = listen_port {
        unimplemented!("change port");
        //Device::open_listen_socket(;, port)
        //f device.open_listen_socket(listen_port).is_err() {
        //    return SetResponse { errno: EADDRINUSE };
        //}
    }
    if let Some(fwmark) = fwmark {
        if device.set_fwmark(fwmark).is_err() {
            return SetResponse { errno: EADDRINUSE };
        }
    }

    if let Some(protocol_version) = protocol_version {
        if protocol_version != "1" {
            todo!("handle invalid protocol version");
        }
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

    SetResponse { errno: 0 }
}
