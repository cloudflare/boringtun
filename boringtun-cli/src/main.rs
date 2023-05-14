// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

extern crate daemonize;
use boringtun::device::drop_privileges::drop_privileges;
use boringtun::device::{DeviceConfig, DeviceHandle};
use clap::{Arg, ArgAction, Command};
use daemonize::Daemonize;
use std::fs::File;
use std::os::unix::net::UnixDatagram;
use std::process::exit;
use tracing::Level;

fn check_tun_name(_v: &str) -> Result<String, String> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        if boringtun::device::tun::parse_utun_name(_v).is_ok() {
            Ok(_v.to_string())
        } else {
            Err("Tunnel name must have the format 'utun[0-9]+', use 'utun' for automatic assignment".to_owned())
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(_v.to_string())
    }
}

fn main() {
    let matches = Command::new("boringtun")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Vlad Krasnov <vlad@cloudflare.com>")
        .args(&[
            Arg::new("INTERFACE_NAME")
                .required(true)
                .value_name("INTERFACE")
                .value_parser(check_tun_name)
                .help("The name of the created interface"),
            Arg::new("foreground")
                .long("foreground")
                .short('f')
                .action(ArgAction::SetTrue)
                .help("Run and log in the foreground"),
            Arg::new("threads")
                .long("threads")
                .short('t')
                .env("WG_THREADS")
                .value_parser(clap::value_parser!(usize))
                .help("Number of OS threads to use")
                .default_value("4"),
            Arg::new("verbosity")
                .long("verbosity")
                .short('v')
                .env("WG_LOG_LEVEL")
                .value_parser(clap::value_parser!(Level))
                .help("Log verbosity")
                .default_value("error"),
            Arg::new("uapi-fd")
                .long("uapi-fd")
                .env("WG_UAPI_FD")
                .value_parser(clap::value_parser!(i32))
                .help("File descriptor for the user API")
                .default_value("-1"),
            Arg::new("tun-fd")
                .long("tun-fd")
                .env("WG_TUN_FD")
                .help("File descriptor for an already-existing TUN device"),
            Arg::new("log")
                .long("log")
                .short('l')
                .env("WG_LOG_FILE")
                .help("Log file")
                .default_value("/tmp/boringtun.out"),
            Arg::new("disable-drop-privileges")
                .long("disable-drop-privileges")
                .env("WG_SUDO")
                .value_parser(|v: &str| -> Result<bool, String> {
                    if v == "true" || v == "1" {
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                })
                .action(ArgAction::SetTrue)
                .help("Do not drop sudo privileges"),
            Arg::new("disable-connected-udp")
                .long("disable-connected-udp")
                .action(ArgAction::SetTrue)
                .help("Disable connected UDP sockets to each peer"),
            #[cfg(target_os = "linux")]
            Arg::new("disable-multi-queue")
                .long("disable-multi-queue")
                .action(ArgAction::SetTrue)
                .help("Disable using multiple queues for the tunnel interface"),
        ])
        .get_matches();

    let background = !matches.get_flag("foreground");
    #[cfg(target_os = "linux")]
    let uapi_fd: i32 = matches.get_one::<i32>("uapi-fd").unwrap();
    let tun_name = if let Some(tun_name) = matches.get_one::<String>("tun-fd") {
        tun_name
    } else {
        matches
            .get_one::<String>("INTERFACE_NAME")
            .expect("provide interface name")
    };
    let n_threads: usize = matches.get_one::<usize>("threads").unwrap().to_owned();
    let log_level: Level = matches.get_one::<Level>("verbosity").unwrap().to_owned();

    let (sock1, sock2) = UnixDatagram::pair().unwrap();
    let _ = sock1.set_nonblocking(true);

    if background {
        let log = matches.get_one::<String>("log").unwrap();

        let log_file =
            File::create(log).unwrap_or_else(|_| panic!("Could not create log file {}", log));

        tracing_subscriber::fmt()
            .with_max_level(log_level)
            .with_writer(log_file)
            .with_ansi(false)
            .init();

        let daemonize = Daemonize::new().working_directory("/tmp");
        match daemonize.execute() {
            daemonize::Outcome::Parent(Ok(parent)) => {
                let mut b = [0u8; 1];
                if sock2.recv(&mut b).is_ok() && b[0] == 1 {
                    tracing::info!("BoringTun daemonized successfully!");
                    exit(parent.first_child_exit_code);
                } else {
                    tracing::error!("BoringTun failed to start");
                    exit(1);
                };
            }
            daemonize::Outcome::Child(Ok(_)) => {}
            daemonize::Outcome::Parent(Err(e)) | daemonize::Outcome::Child(Err(e)) => {
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
        use_connected_socket: !matches.get_flag("disable-connected-udp"),
        #[cfg(target_os = "linux")]
        use_multi_queue: !matches.get_flag("disable-multi-queue"),
    };

    let mut device_handle: DeviceHandle = match DeviceHandle::new(tun_name, config) {
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

    tracing::info!("BoringTun started successfully");

    // Notify parent that tunnel initialization succeeded
    sock1.send(&[1]).unwrap();
    drop(sock1);

    device_handle.wait();
}
