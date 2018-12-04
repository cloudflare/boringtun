use super::events::*;
use super::*;
use dev_lock::*;
use hex::encode as encode_hex;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::mem::forget;
use std::os::unix::io::{FromRawFd, RawFd};

// This handler accepts connections from the wg app.
pub const UNIX_SOCKET_HANDLER: HandlerFunction =
    |_: RawFd, d: &mut LockReadGuard<Device>, e: Event| -> Option<()> {
        if let Ok(conn) = d.api.accept() {
            d.event_queue
                .register_event(Event::new_event(
                    conn.descriptor(),
                    &API_HANDLER,
                    EventType::None,
                ))
                .unwrap();
            forget(conn); // Don't close the fd yet
        }
        d.event_queue.enable_event(e).unwrap();
        None
    };

// This handler handles the actual API connection
pub const API_HANDLER: HandlerFunction =
    |fd: RawFd, d: &mut LockReadGuard<Device>, e: Event| -> Option<()> {
        let file_conn = unsafe { File::from_raw_fd(fd) };
        let mut reader = BufReader::new(&file_conn);
        let mut writer = BufWriter::new(&file_conn);
        let mut cmd = String::new();
        // TODO: tidy
        match reader.read_line(&mut cmd) {
            Ok(_) => {
                cmd.pop(); // pop the new line character
                match cmd.as_ref() {
                    "get=1" => api_get(&mut writer, d),
                    "set=1" => {
                        // We require a mutable reference for set
                        if let Some(mut mark) = d.mark_want_write() {
                            mark.event_queue.trigger_notification(); // Notify threads to release their read locks
                            let mut write_device = mark.write(); // Upgrade to a write lock
                            write_device.event_queue.stop_notification(); // Let the threads to try and aquire the read locks back
                            api_set(&mut reader, &mut writer, &mut *write_device)
                        } else {
                            {}
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }

        d.event_queue.remove_event(e).unwrap();
        None
        // Connection will be closed by File here
    };

#[allow(unused_must_use)]
fn api_get(writer: &mut BufWriter<&File>, d: &Device) {
    // get command requires an empty line, but there is no reason to be religious about it
    if let Some(ref k) = d.key_pair {
        writer.write(format!("private_key={}\n", encode_hex(k.0.as_bytes())).as_ref());
    }

    if d.listen_port != 0 {
        writer.write(format!("listen_port={}\n", d.listen_port).as_ref());
    }

    for (k, p) in d.peers.iter() {
        writer.write(format!("public_key={}\n", encode_hex(k.as_bytes())).as_ref());

        if let Some(ref addr) = p.endpoint().addr {
            writer.write(format!("endpoint={}\n", addr).as_ref());
        }

        writer.write(format!("rx_bytes={}\n", p.get_rx_bytes()).as_ref());
        writer.write(format!("tx_bytes={}\n", p.get_tx_bytes()).as_ref());
    }

    writer.write(b"errno=0\n\n");
}

fn api_set(reader: &mut BufReader<&File>, writer: &mut BufWriter<&File>, device: &mut Device) {
    let mut cmd = String::new();

    let reply = loop {
        match reader.read_line(&mut cmd) {
            Ok(_) => {
                cmd.pop();
                if cmd.len() == 0 {
                    break b"errno=0\n\n";
                }

                let cmd: Vec<&str> = cmd.split('=').collect();
                if cmd.len() != 2 {
                    break b"errno=2\n\n";
                }

                match cmd[0] {
                    "private_key" => match cmd[1].parse::<X25519Key>() {
                        Ok(key) => device.set_key(key),
                        Err(_) => break b"errno=3\n\n",
                    },
                    "listen_port" => match cmd[1].parse::<u16>() {
                        Ok(port) => device.open_listen_socket(port).unwrap(),
                        Err(_) => break b"errno=3\n\n",
                    },
                    "fwmark" => println!("set new fwmark"),
                    "replace_peers" => match cmd[1].parse::<bool>() {
                        Ok(true) => device.clear_peers(),
                        Ok(false) => {}
                        Err(_) => break b"errno=3\n\n",
                    },
                    "public_key" => match cmd[1].parse::<X25519Key>() {
                        Ok(key) => break api_set_peer(reader, device, key),
                        Err(_) => break b"errno=3\n\n",
                    },
                    _ => println!("unhandled {:?}", cmd),
                }
            }
            Err(_) => break b"errno=1\n\n",
        }
        cmd.clear();
    };

    writer.write(reply).unwrap();
}

fn api_set_peer(
    conn_reader: &mut BufReader<&File>,
    d: &mut Device,
    pub_key: X25519Key,
) -> &'static [u8; 9] {
    println!("Set peer");
    let mut cmd = String::new();

    let mut remove = false;
    let mut replace_ips = false;
    let mut endpoint = None;
    let mut keepalive = None;
    let mut allowed_ips: Vec<AllowedIP> = vec![];

    loop {
        cmd.clear();
        match conn_reader.read_line(&mut cmd) {
            Ok(_) => {
                cmd.pop();
                if cmd.len() == 0 {
                    d.update_peer(
                        pub_key,
                        remove,
                        replace_ips,
                        endpoint,
                        allowed_ips,
                        keepalive,
                    );
                    break b"errno=0\n\n";
                }

                let cmd: Vec<&str> = cmd.split('=').collect();
                if cmd.len() != 2 {
                    break b"errno=2\n\n";
                }

                match cmd[0] {
                    "remove" => match cmd[1].parse::<bool>() {
                        Ok(true) => remove = true,
                        Ok(false) => remove = false,
                        Err(_) => break b"errno=3\n\n",
                    },
                    "preshared_key" => panic!("preshared key not yet supported"),
                    "endpoint" => match cmd[1].parse::<SocketAddr>() {
                        Ok(addr) => endpoint = Some(addr),
                        Err(_) => break b"errno=4\n\n",
                    },
                    "persistent_keepalive_interval" => match cmd[1].parse::<u16>() {
                        Ok(interval) => keepalive = Some(interval),
                        Err(_) => break b"errno=5\n\n",
                    },
                    "replace_allowed_ips" => match cmd[1].parse::<bool>() {
                        Ok(true) => replace_ips = true,
                        Ok(false) => replace_ips = false,
                        Err(_) => break b"errno=6\n\n",
                    },
                    "allowed_ip" => match cmd[1].parse::<AllowedIP>() {
                        Ok(ip) => allowed_ips.push(ip),
                        Err(_) => break b"errno=9\n\n",
                    },
                    "public_key" => {
                        d.update_peer(
                            pub_key,
                            remove,
                            replace_ips,
                            endpoint,
                            allowed_ips,
                            keepalive,
                        );
                        match cmd[1].parse::<X25519Key>() {
                            Ok(key) => return api_set_peer(conn_reader, d, key),
                            Err(_) => break b"errno=3\n\n",
                        }
                    }
                    "protocol_version" => match cmd[1].parse::<u32>() {
                        Ok(1) => {}
                        _ => break b"errno=7\n\n",
                    },
                    _ => break b"errno=8\n\n",
                }
            }
            Err(_) => break b"errno=1\n\n",
        }
    }
}
