// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use boringtun::device::drop_privileges::drop_privileges;
use boringtun::device::{DeviceConfig, DeviceHandle};
use clap::{value_parser, Arg, Command};
use daemonize::{Daemonize, Outcome, Parent};
use std::fs::File;
use std::os::unix::net::UnixDatagram;
use std::path::PathBuf;
use std::process::exit;
use std::sync::Arc;
use tracing::Level;

fn check_tun_name(name: &str) -> Result<String, String> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        if boringtun::device::tun::parse_utun_name(name).is_ok() {
            Ok(name.to_owned())
        } else {
            Err("Tunnel name must have the format 'utun[0-9]+', use 'utun' for automatic assignment".to_owned())
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(name.to_owned())
    }
}

fn main() {
    let matches = Command::new("boringtun")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Vlad Krasnov <vlad@cloudflare.com>")
        .args(&[
            Arg::new("INTERFACE_NAME")
                .required(true)
                .num_args(1)
                .value_parser(check_tun_name)
                .help("The name of the created interface"),
            Arg::new("foreground")
                .long("foreground")
                .short('f')
                .action(clap::ArgAction::SetTrue)
                .help("Run and log in the foreground"),
            Arg::new("threads")
                .num_args(1)
                .long("threads")
                .short('t')
                .env("WG_THREADS")
                .value_parser(value_parser!(usize))
                .help("Number of OS threads to use")
                .default_value("4"),
            Arg::new("verbosity")
                .num_args(1)
                .long("verbosity")
                .short('v')
                .env("WG_LOG_LEVEL")
                .value_parser(value_parser!(Level))
                .help("Log verbosity [possible values: error, warn, info, debug, trace]")
                .default_value("error"),
            Arg::new("uapi-fd")
                .long("uapi-fd")
                .env("WG_UAPI_FD")
                .value_parser(value_parser!(i32))
                .help("File descriptor for the user API")
                .default_value("-1"),
            Arg::new("tun-fd")
                .long("tun-fd")
                .value_parser(value_parser!(isize))
                .env("WG_TUN_FD")
                .help("File descriptor for an already-existing TUN device")
                .default_value("-1"),
            Arg::new("log")
                .num_args(1)
                .long("log")
                .short('l')
                .env("WG_LOG_FILE")
                .value_parser(value_parser!(PathBuf))
                .help("Log file")
                .default_value("/tmp/boringtun.out"),
            Arg::new("disable-drop-privileges")
                .long("disable-drop-privileges")
                .env("WG_SUDO")
                .action(clap::ArgAction::SetTrue)
                .help("Do not drop sudo privileges"),
            Arg::new("disable-connected-udp")
                .long("disable-connected-udp")
                .action(clap::ArgAction::SetTrue)
                .help("Disable connected UDP sockets to each peer"),
            #[cfg(target_os = "linux")]
            Arg::new("disable-multi-queue")
                .long("disable-multi-queue")
                .action(clap::ArgAction::SetTrue)
                .help("Disable using multiple queues for the tunnel interface"),
        ])
        .get_matches();

    let background = !matches.get_flag("foreground");
    #[cfg(target_os = "linux")]
    let uapi_fd: i32 = *matches.get_one("uapi-fd").unwrap();
    let tun_fd: isize = *matches.get_one("tun-fd").unwrap();
    let mut tun_name: String = matches.get_one::<String>("INTERFACE_NAME").unwrap().clone();
    if tun_fd >= 0 {
        tun_name = matches.get_one::<String>("tun-fd").unwrap().clone();
    }
    let n_threads: usize = *matches.get_one("threads").unwrap();
    let log_level: Level = *matches.get_one("verbosity").unwrap();

    // Create a socketpair to communicate between forked processes
    let (sock1, sock2) = UnixDatagram::pair().unwrap();
    let _ = sock1.set_nonblocking(true);

    let _guard;

    if background {
        let log: PathBuf = matches.get_one::<PathBuf>("log").unwrap().clone();
        let log_file = File::create(log.clone())
            .unwrap_or_else(|_| panic!("Could not create log file {:?}", log));

        let (non_blocking, guard) = tracing_appender::non_blocking(log_file);

        _guard = guard;

        tracing_subscriber::fmt()
            .with_max_level(log_level)
            .with_writer(non_blocking)
            .with_ansi(false)
            .init();

        let daemonize = Daemonize::new().working_directory("/tmp");

        match daemonize.execute() {
            Outcome::Parent(Ok(Parent {
                first_child_exit_code,
                ..
            })) => {
                let mut b = [0u8; 1];
                if sock2.recv(&mut b).is_ok() && b[0] == 1 {
                    println!("BoringTun started successfully");
                    exit(first_child_exit_code)
                } else {
                    eprintln!("BoringTun failed to start");
                    exit(1);
                };
            }
            Outcome::Parent(Err(err)) => {
                eprintln!("Failed to fork process: {err}");
                exit(1);
            }
            Outcome::Child(Ok(_)) => tracing::info!("BoringTun started successfully"),
            Outcome::Child(Err(err)) => {
                tracing::error!(error = ?err);
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
        use_connected_socket: !matches.get_flag("disable-connected-udp"),
        #[cfg(target_os = "linux")]
        use_multi_queue: !matches.get_flag("disable-multi-queue"),
        open_uapi_socket: false,
        protect: Arc::new(boringtun::device::MakeExternalBoringtunNoop),
        firewall_process_inbound_callback: None,
        firewall_process_outbound_callback: None,
    };

    let mut device_handle: DeviceHandle = match DeviceHandle::new(&tun_name, config) {
        Ok(d) => d,
        Err(e) => {
            // Notify parent that tunnel initialization failed
            tracing::error!(message = "Failed to initialize tunnel", error=?e);
            sock1.send(&[0]).unwrap();
            exit(1);
        }
    };

    if !matches.get_flag("disable-drop-privileges") {
        if let Err(e) = drop_privileges() {
            tracing::error!(message = "Failed to drop privileges", error = ?e);
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
