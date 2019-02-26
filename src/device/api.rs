use super::{make_array, AllowedIP, Device, Error, SocketAddr, X25519PublicKey, X25519SecretKey};
use dev_lock::LockReadGuard;
use device::Action;
use hex::encode as encode_hex;
use libc::{EADDRINUSE, EINVAL, EIO, EPROTO};
use std::fs::{create_dir, remove_file};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::os::unix::io::AsRawFd;
use std::os::unix::net::{UnixListener, UnixStream};

impl Device {
    /// Register the api handler for this Device. The api handler recieves stream connections on a Unix socket
    /// with a known path: /var/run/wireguard/{tun_name}.sock.
    pub fn register_api_handler(&self) -> Result<(), Error> {
        let path = format!("/var/run/wireguard/{}.sock", self.iface.name()?);
        create_dir("/var/run/wireguard/").is_ok(); // Create the directory if not existant
        remove_file(&path).is_ok(); // Attempt to remove the socket if already exists
        let api_listener = UnixListener::bind(&path).map_err(|e| Error::ApiSocket(e))?; // Bind a new socket to the path

        let api_sock_ev = self.factory.new_event(
            api_listener.as_raw_fd(),
            Box::new(move |d: &mut LockReadGuard<Device>| {
                // This is the closure that listens on the api unix socket
                let (api_conn, _) = match api_listener.accept() {
                    Ok(conn) => conn,
                    _ => return Action::Continue,
                };

                let mut reader = BufReader::new(&api_conn);
                let mut writer = BufWriter::new(&api_conn);
                let mut cmd = String::new();
                if reader.read_line(&mut cmd).is_ok() {
                    cmd.pop(); // pop the new line character
                    let status = match cmd.as_ref() {
                        // Only two commands are legal according to the protocol, get=1 and set=1.
                        "get=1" => api_get(&mut writer, d),
                        "set=1" => api_set(&mut reader, d),
                        _ => EIO,
                    };
                    // The protocol requires to return an error code as the response, or zero on success
                    write!(writer, "errno={}\n\n", status).ok();
                }
                Action::Continue // Inidicates the worker thread should continue as normal
            }),
            false,
        );
        self.factory.register_event(&self.queue, &api_sock_ev)?;

        // This is not a very nice hack to detect if the control socket was removed
        // and exiting nicely as a result. We check every 3 seconds in a loop if the
        // file was deleted by stating it.
        // The problem is that on linux inotify can be used quite beautifully to detect
        // deletion, and kqueue EVFILT_VNODE can be used for the same purpose, but that
        // will require introducing new events, for no measureable benefit.
        // TODO: Could this be an issue if we restart the service too quickly?
        let timer_ev = self.factory.new_periodic_event(
            Box::new(move |d: &mut LockReadGuard<Device>| {
                let path = std::path::Path::new(&path);
                if path.exists() {
                    Action::Continue
                } else {
                    d.trigger_exit();
                    Action::Exit
                }
            }),
            std::time::Duration::from_millis(3000),
        )?;
        self.factory.register_event(&self.queue, &timer_ev)
    }
}

#[allow(unused_must_use)]
fn api_get(writer: &mut BufWriter<&UnixStream>, d: &Device) -> i32 {
    // get command requires an empty line, but there is no reason to be religious about it
    if let Some(ref k) = d.key_pair {
        write!(writer, "private_key={}\n", encode_hex(k.0.as_bytes()));
    }

    if d.listen_port != 0 {
        write!(writer, "listen_port={}\n", d.listen_port);
    }

    for (k, p) in d.peers.iter() {
        write!(writer, "public_key={}\n", encode_hex(k.as_bytes()));

        if let Some(ref key) = p.preshared_key() {
            write!(writer, "preshared_key={}\n", encode_hex(key));
        }

        if let Some(fwmark) = d.fwmark {
            write!(writer, "fwmark={}\n", fwmark);
        }

        if let Some(ref addr) = p.endpoint().addr {
            write!(writer, "endpoint={}\n", addr);
        }

        for (_, ip, cidr) in p.allowed_ips() {
            write!(writer, "allowed_ip={}/{}\n", ip, cidr);
        }

        if let Some(time) = p.time_since_last_handshake() {
            write!(writer, "last_handshake_time_sec={}\n", time.as_secs());
            write!(writer, "last_handshake_time_nsec={}\n", time.subsec_nanos());
        }

        write!(writer, "rx_bytes={}\n", p.get_rx_bytes());
        write!(writer, "tx_bytes={}\n", p.get_tx_bytes());
    }
    0
}

fn api_set(reader: &mut BufReader<&UnixStream>, d: &mut LockReadGuard<Device>) -> i32 {
    // We need to get a write lock on the device first
    let mut write_mark = match d.mark_want_write() {
        None => return EIO,
        Some(lock) => lock,
    };

    write_mark.trigger_yield();
    let mut device = write_mark.write();
    device.cancel_yield();

    let mut cmd = String::new();

    while let Ok(_) = reader.read_line(&mut cmd) {
        cmd.pop(); // remove newline if any
        if cmd.is_empty() {
            return 0; // Done
        }
        {
            let parsed_cmd: Vec<&str> = cmd.split('=').collect();
            if parsed_cmd.len() != 2 {
                return EPROTO;
            }

            let (key, val) = (parsed_cmd[0], parsed_cmd[1]);

            match key {
                "private_key" => match val.parse::<X25519SecretKey>() {
                    Ok(key) => device.set_key(key),
                    Err(_) => return EINVAL,
                },
                "listen_port" => match val.parse::<u16>() {
                    Ok(port) => match device.open_listen_socket(port) {
                        Ok(()) => {}
                        Err(_) => return EADDRINUSE,
                    },
                    Err(_) => return EINVAL,
                },
                "fwmark" => match val.parse::<u32>() {
                    Ok(mark) => match device.set_fwmark(mark) {
                        Ok(()) => {}
                        Err(_) => return EADDRINUSE,
                    },
                    Err(_) => return EINVAL,
                },
                "replace_peers" => match val.parse::<bool>() {
                    Ok(true) => device.clear_peers(),
                    Ok(false) => {}
                    Err(_) => return EINVAL,
                },
                "public_key" => match val.parse::<X25519PublicKey>() {
                    // Indicates a new peer section
                    Ok(key) => return api_set_peer(reader, &mut device, key),
                    Err(_) => return EINVAL,
                },
                _ => return EINVAL,
            }
        }
        cmd.clear();
    }
    0
}

fn api_set_peer(
    reader: &mut BufReader<&UnixStream>,
    d: &mut Device,
    pub_key: X25519PublicKey,
) -> i32 {
    let mut cmd = String::new();

    let mut remove = false;
    let mut replace_ips = false;
    let mut endpoint = None;
    let mut keepalive = None;
    let mut preshared_key = None;
    let mut allowed_ips: Vec<AllowedIP> = vec![];

    while let Ok(_) = reader.read_line(&mut cmd) {
        cmd.pop(); // remove newline if any
        if cmd.is_empty() {
            d.update_peer(
                pub_key,
                remove,
                replace_ips,
                endpoint,
                allowed_ips,
                keepalive,
                preshared_key,
            );
            return 0; // Done
        }
        {
            let parsed_cmd: Vec<&str> = cmd.split('=').collect();
            if parsed_cmd.len() != 2 {
                return EPROTO;
            }

            let (key, val) = (parsed_cmd[0], parsed_cmd[1]);

            match key {
                "remove" => match val.parse::<bool>() {
                    Ok(true) => remove = true,
                    Ok(false) => remove = false,
                    Err(_) => return EINVAL,
                },
                "preshared_key" => match val.parse::<X25519PublicKey>() {
                    Ok(key) => preshared_key = Some(make_array(key.as_bytes())),
                    Err(_) => return EINVAL,
                },
                "endpoint" => match val.parse::<SocketAddr>() {
                    Ok(addr) => endpoint = Some(addr),
                    Err(_) => return EINVAL,
                },
                "persistent_keepalive_interval" => match val.parse::<u16>() {
                    Ok(interval) => keepalive = Some(interval),
                    Err(_) => return EINVAL,
                },
                "replace_allowed_ips" => match val.parse::<bool>() {
                    Ok(true) => replace_ips = true,
                    Ok(false) => replace_ips = false,
                    Err(_) => return EINVAL,
                },
                "allowed_ip" => match val.parse::<AllowedIP>() {
                    Ok(ip) => allowed_ips.push(ip),
                    Err(_) => return EINVAL,
                },
                "public_key" => {
                    // Indicates a new peer section. Commit changes for current peer, and continue to next peer
                    d.update_peer(
                        pub_key,
                        remove,
                        replace_ips,
                        endpoint,
                        allowed_ips,
                        keepalive,
                        preshared_key,
                    );
                    match val.parse::<X25519PublicKey>() {
                        Ok(key) => return api_set_peer(reader, d, key),
                        Err(_) => return EINVAL,
                    }
                }
                "protocol_version" => match val.parse::<u32>() {
                    Ok(1) => {} // Only version 1 is legal
                    _ => return EINVAL,
                },
                _ => return EINVAL,
            }
        }
        cmd.clear();
    }
    0
}
