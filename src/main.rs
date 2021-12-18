// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod crypto;

#[cfg(not(target_os = "windows"))]
pub mod device;

pub mod ffi;
pub mod noise;

use crypto::x25519::X25519SecretKey;
use crate::device::drop_privileges::drop_privileges;
use crate::device::{DeviceConfig, DeviceHandle};
use clap::{value_t, App, Arg};
use daemonize::Daemonize;
use std::fs::File;
use std::fs;
use std::os::unix::net::UnixDatagram;
use std::process::exit;
use std::process::Command;

fn check_tun_name(_v: String) -> Result<(), String> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        if device::tun::parse_utun_name(&_v).is_ok() {
            Ok(())
        } else {
            Err("Tunnel name must have the format 'utun[0-9]+', use 'utun' for automatic assignment".to_owned())
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(())
    }
}

fn main() {
    let matches = App::new("boringtun")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Vlad Krasnov <vlad@cloudflare.com>")
        .args(&[
            Arg::with_name("INTERFACE_NAME")
                .required(true)
                .takes_value(true)
                .validator(check_tun_name)
                .help("The name of the created interface"),
            Arg::with_name("foreground")
                .long("foreground")
                .short("f")
                .help("Run and log in the foreground"),
            Arg::with_name("threads")
                .takes_value(true)
                .long("threads")
                .short("-t")
                .env("WG_THREADS")
                .help("Number of OS threads to use")
                .default_value("4"),
            Arg::with_name("verbosity")
                .takes_value(true)
                .long("verbosity")
                .short("-v")
                .env("WG_LOG_LEVEL")
                .possible_values(&["error", "info", "debug", "trace"])
                .help("Log verbosity")
                .default_value("error"),
            Arg::with_name("uapi-fd")
                .long("uapi-fd")
                .env("WG_UAPI_FD")
                .help("File descriptor for the user API")
                .default_value("-1"),
            Arg::with_name("tun-fd")
                .long("tun-fd")
                .env("WG_TUN_FD")
                .help("File descriptor for an already-existing TUN device")
                .default_value("-1"),
            Arg::with_name("log")
                .takes_value(true)
                .long("log")
                .short("-l")
                .env("WG_LOG_FILE")
                .help("Log file")
                .default_value("/tmp/boringtun.out"),
            Arg::with_name("disable-drop-privileges")
                .long("disable-drop-privileges")
                .env("WG_SUDO")
                .help("Do not drop sudo privileges"),
            Arg::with_name("disable-connected-udp")
                .long("disable-connected-udp")
                .help("Disable connected UDP sockets to each peer"),
            #[cfg(target_os = "linux")]
            Arg::with_name("disable-multi-queue")
                .long("disable-multi-queue")
                .help("Disable using multiple queues for the tunnel interface"),
            Arg::with_name("listen-port")
                .takes_value(true)
                .long("listen-port")
                .short("-p")
                .env("WG_LISTEN_PORT")
                .help("The port to listen on at start"),
            Arg::with_name("peer-auth")
                .takes_value(true)
                .long("peer-auth")
                .short("-a")
                .env("WG_PEER_AUTH")
                .help("External auth script to call for unknown peers"),
            Arg::with_name("address")
                .takes_value(true)
                .long("address")
                .short("-i")
                .env("WG_IFACE_ADDR")
                .help("Interface address"),
            Arg::with_name("mtu")
                .takes_value(true)
                .long("mtu")
                .short("-m")
                .env("WG_MTU")
                .default_value("1420")
                .help("Set MTU for the interface"),
            Arg::with_name("private-key")
                .takes_value(true)
                .long("private-key")
                .short("-k")
                .env("WG_PRIVATE_KEY")
                .help("Path to the private key"),
        ])
        .get_matches();

    let background = !matches.is_present("foreground");
    #[cfg(target_os = "linux")]
    let uapi_fd = value_t!(matches.value_of("uapi-fd"), i32).unwrap_or_else(|e| e.exit());
    let tun_fd = value_t!(matches.value_of("tun-fd"), isize).unwrap_or_else(|e| e.exit());
    let mut tun_name = matches.value_of("INTERFACE_NAME").unwrap();
    if tun_fd >= 0 {
        tun_name = matches.value_of("tun-fd").unwrap();
    }
    let n_threads = value_t!(matches.value_of("threads"), usize).unwrap_or_else(|e| e.exit());
    let log_level =
        value_t!(matches.value_of("verbosity"), tracing::Level).unwrap_or_else(|e| e.exit());

    let init_pkey = matches.value_of("private-key").unwrap_or_default();
    let peer_auth = matches.value_of("peer-auth").unwrap_or_default();
    let listen_port: u16 = matches.value_of("listen-port").unwrap_or_default().parse().unwrap_or_default();
    let init_address = matches.value_of("address").unwrap_or_default();
    let init_mtu = matches.value_of("mtu").unwrap_or_default();

    let mut private_key = None;
    //if init_pkey is set, read it and parse it
    if init_pkey.len() > 0 {
        let contents = fs::read_to_string(init_pkey).expect("could not read private key file");
        private_key = match contents.trim().parse::<X25519SecretKey>() {
            Ok(key) => Some(key),
            Err(e) => {
                eprintln!("Failed to parse private key: {:?}", e);
                exit(1);
            },
        };
    }

    // Create a socketpair to communicate between forked processes
    let (sock1, sock2) = UnixDatagram::pair().unwrap();
    let _ = sock1.set_nonblocking(true);

    let _guard;

    if background {
        let log = matches.value_of("log").unwrap();

        let log_file =
            File::create(&log).unwrap_or_else(|_| panic!("Could not create log file {}", log));

        let (non_blocking, guard) = tracing_appender::non_blocking(log_file);

        _guard = guard;

        tracing_subscriber::fmt()
            .with_max_level(log_level)
            .with_writer(non_blocking)
            .with_ansi(false)
            .init();

        let daemonize = Daemonize::new()
            .working_directory("/tmp")
            .exit_action(move || {
                let mut b = [0u8; 1];
                if sock2.recv(&mut b).is_ok() && b[0] == 1 {
                    println!("BoringTun started successfully");
                } else {
                    eprintln!("BoringTun failed to start");
                    exit(1);
                };
            });

        match daemonize.start() {
            Ok(_) => tracing::info!("BoringTun started successfully"),
            Err(e) => {
                tracing::error!(error = ?e);
                exit(1);
            }
        }
    } else {
        tracing_subscriber::fmt()
            .pretty()
            .with_max_level(log_level)
            .init();
    }

    let config = DeviceConfig {
        n_threads,
        #[cfg(target_os = "linux")]
        uapi_fd,
        use_connected_socket: !matches.is_present("disable-connected-udp"),
        #[cfg(target_os = "linux")]
        use_multi_queue: !matches.is_present("disable-multi-queue"),
        peer_auth_script: Some(peer_auth.to_string()),
        listen_port: listen_port,
    };

    let mut device_handle: DeviceHandle = match DeviceHandle::new(&tun_name, config, private_key) {
        Ok(d) => d,
        Err(e) => {
            // Notify parent that tunnel initialization failed
            tracing::error!(message = "Failed to initialize tunnel", error=?e);
            sock1.send(&[0]).unwrap();
            exit(1);
        }
    };

    if !matches.is_present("disable-drop-privileges") {
        if let Err(e) = drop_privileges() {
            tracing::error!(message = "Failed to drop privileges", error = ?e);
            sock1.send(&[0]).unwrap();
            exit(1);
        }
    }

    //set the interface address if provided, and bring up the interface
    if init_address.len() > 0 {
        if let Err(e) = Command::new("/sbin/ip")
                        .arg("addr")
                        .arg("add")
                        .arg(init_address)
                        .arg("dev")
                        .arg(tun_name)
                        .status() {
                            eprintln!("Failed to add interface address: {:?}", e);
                            sock1.send(&[0]).unwrap();
                            exit(1);
                        }
        if let Err(e) = Command::new("/sbin/ip")
                        .arg("link")
                        .arg("set")
                        .arg(tun_name)
                        .arg("up")
                        .status() {
                            eprintln!("Failed to bring up interface: {:?}", e);
                            sock1.send(&[0]).unwrap();
                            exit(1);
                        }
    }

    //set the interface mtu
    if init_mtu.len() > 0 {
        if let Err(e) = Command::new("/sbin/ip")
                        .arg("link")
                        .arg("set")
                        .arg(tun_name)
                        .arg("mtu")
                        .arg(init_mtu)
                        .status() {
                            eprintln!("Failed to interface MTU: {:?}", e);
                            sock1.send(&[0]).unwrap();
                            exit(1);
                        }
    }

    // Notify parent that tunnel initialization succeeded
    sock1.send(&[1]).unwrap();
    drop(sock1);

    tracing::info!("BoringTun started successfully");

    device_handle.wait();
}
