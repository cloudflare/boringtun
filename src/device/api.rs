use super::*;
use dev_lock::*;
use hex::encode as encode_hex;
use libc::*;
use std::fs::{create_dir, File};
use std::io::{BufRead, BufReader, BufWriter, Write};

impl Device {
    pub fn register_api_handler(&self) -> Result<(), Error> {
        if let Err(_) = create_dir("/var/run/wireguard/") {};
        let path = format!("/var/run/wireguard/{}.sock", self.iface.name()?);

        let api_sock = UNIXSocket::new()
            .and_then(|s| s.bind(&path))
            .and_then(|s| s.listen())?;

        let api_sock_ev = self.factory.new_event(
            api_sock.descriptor(),
            Box::new(move |d: &mut LockReadGuard<Device>| {
                // This is the closure that listens on the api unix socket
                let api_conn = match api_sock.accept() {
                    Ok(conn) => conn,
                    _ => return None,
                };

                let api_conn = api_conn.as_file();
                let mut reader = BufReader::new(&api_conn);
                let mut writer = BufWriter::new(&api_conn);
                let mut cmd = String::new();
                if let Ok(_) = reader.read_line(&mut cmd) {
                    cmd.pop(); // pop the new line character
                    let status = match cmd.as_ref() {
                        "get=1" => api_get(&mut writer, d),
                        "set=1" => api_set(&mut reader, d),
                        _ => Some(EIO),
                    };

                    writer
                        .write(format!("errno={}\n\n", status.unwrap_or(0)).as_ref())
                        .ok();
                }
                None // Return None to indicate no further action is expected from the caller
            }),
            false,
        );
        self.factory.register_event(&self.queue, &api_sock_ev)?;
        Ok(())
    }
}

#[allow(unused_must_use)]
fn api_get(writer: &mut BufWriter<&File>, d: &Device) -> Option<i32> {
    // get command requires an empty line, but there is no reason to be religious about it
    if let Some(ref k) = d.key_pair {
        writer.write(format!("private_key={}\n", encode_hex(k.0.as_bytes())).as_ref());
    }

    if d.listen_port != 0 {
        writer.write(format!("listen_port={}\n", d.listen_port).as_ref());
    }

    for (k, p) in d.peers.iter() {
        writer.write(format!("public_key={}\n", encode_hex(k.as_bytes())).as_ref());

        if let Some(ref key) = p.preshared_key() {
            writer.write(format!("preshared_key={}\n", encode_hex(key)).as_ref());
        }

        if let Some(ref addr) = p.endpoint().addr {
            writer.write(format!("endpoint={}\n", addr).as_ref());
        }

        for (_, ip, cidr) in p.allowed_ips() {
            writer.write(format!("allowed_ip={}/{}\n", ip, cidr).as_ref());
        }

        if let Some(time) = p.time_since_last_handshake() {
            writer.write(format!("last_handshake_time_sec={}\n", time.as_secs()).as_ref());
            writer.write(format!("last_handshake_time_nsec={}\n", time.subsec_nanos()).as_ref());
        }

        writer.write(format!("rx_bytes={}\n", p.get_rx_bytes()).as_ref());
        writer.write(format!("tx_bytes={}\n", p.get_tx_bytes()).as_ref());
    }
    None
}

fn api_set(reader: &mut BufReader<&File>, d: &mut LockReadGuard<Device>) -> Option<i32> {
    // We need to get a write lock on the device first
    let want_write = d.mark_want_write();
    if want_write.is_none() {
        return Some(EIO);
    }
    let mut write_mark = want_write.unwrap();
    write_mark.trigger_notifier();
    let mut device = write_mark.write();
    device.cancel_notifier();

    let mut cmd = String::new();

    while let Ok(_) = reader.read_line(&mut cmd) {
        cmd.pop(); // remove newline if any
        if cmd.len() == 0 {
            return None; // Done
        }
        {
            let parsed_cmd: Vec<&str> = cmd.split('=').collect();
            if parsed_cmd.len() != 2 {
                return Some(EPROTO);
            }

            let (key, val) = (parsed_cmd[0], parsed_cmd[1]);

            match key {
                "private_key" => match val.parse::<X25519Key>() {
                    Ok(key) => device.set_key(key),
                    Err(_) => return Some(EINVAL),
                },
                "listen_port" => match val.parse::<u16>() {
                    Ok(port) => device.open_listen_socket(port).unwrap(),
                    Err(_) => return Some(EINVAL),
                },
                "fwmark" => match val.parse::<u32>() {
                    Ok(mark) => device.set_fwmark(mark),
                    Err(_) => return Some(EINVAL),
                },
                "replace_peers" => match val.parse::<bool>() {
                    Ok(true) => device.clear_peers(),
                    Ok(false) => {}
                    Err(_) => return Some(EINVAL),
                },
                "public_key" => match val.parse::<X25519Key>() {
                    Ok(key) => return api_set_peer(reader, &mut device, key),
                    Err(_) => return Some(EINVAL),
                },
                _ => return Some(EINVAL),
            }
        }
        cmd.clear();
    }
    None
}

fn api_set_peer(reader: &mut BufReader<&File>, d: &mut Device, pub_key: X25519Key) -> Option<i32> {
    let mut cmd = String::new();

    let mut remove = false;
    let mut replace_ips = false;
    let mut endpoint = None;
    let mut keepalive = None;
    let mut preshared_key = None;
    let mut allowed_ips: Vec<AllowedIP> = vec![];

    while let Ok(_) = reader.read_line(&mut cmd) {
        cmd.pop(); // remove newline if any
        if cmd.len() == 0 {
            d.update_peer(
                pub_key,
                remove,
                replace_ips,
                endpoint,
                allowed_ips,
                keepalive,
                preshared_key,
            );
            return None; // Done
        }
        {
            let parsed_cmd: Vec<&str> = cmd.split('=').collect();
            if parsed_cmd.len() != 2 {
                return Some(EPROTO);
            }

            let (key, val) = (parsed_cmd[0], parsed_cmd[1]);

            match key {
                "remove" => match val.parse::<bool>() {
                    Ok(true) => remove = true,
                    Ok(false) => remove = false,
                    Err(_) => return Some(EINVAL),
                },
                "preshared_key" => match val.parse::<X25519Key>() {
                    Ok(key) => preshared_key = Some(key.inner()),
                    Err(_) => return Some(EINVAL),
                },
                "endpoint" => match val.parse::<SocketAddr>() {
                    Ok(addr) => endpoint = Some(addr),
                    Err(_) => return Some(EINVAL),
                },
                "persistent_keepalive_interval" => match val.parse::<u16>() {
                    Ok(interval) => keepalive = Some(interval),
                    Err(_) => return Some(EINVAL),
                },
                "replace_allowed_ips" => match val.parse::<bool>() {
                    Ok(true) => replace_ips = true,
                    Ok(false) => replace_ips = false,
                    Err(_) => return Some(EINVAL),
                },
                "allowed_ip" => match val.parse::<AllowedIP>() {
                    Ok(ip) => allowed_ips.push(ip),
                    Err(_) => return Some(EINVAL),
                },
                "public_key" => {
                    d.update_peer(
                        pub_key,
                        remove,
                        replace_ips,
                        endpoint,
                        allowed_ips,
                        keepalive,
                        preshared_key,
                    );
                    match val.parse::<X25519Key>() {
                        Ok(key) => return api_set_peer(reader, d, key),
                        Err(_) => return Some(EINVAL),
                    }
                }
                "protocol_version" => match val.parse::<u32>() {
                    Ok(1) => {}
                    _ => return Some(EINVAL),
                },
                _ => return Some(EINVAL),
            }
        }
        cmd.clear();
    }
    None
}
