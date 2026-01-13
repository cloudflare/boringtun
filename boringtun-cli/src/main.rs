// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

use boringtun::device::drop_privileges::drop_privileges;
use boringtun::device::{DeviceConfig, DeviceHandle};
use clap::{Arg, Command};
use nix::unistd::{fork, ForkResult, chdir};
use std::env;
use std::process;
use std::fs::File;
use std::os::unix::net::UnixDatagram;
use std::process::exit;
use tracing::Level;

fn check_tun_name(_v: &str) -> Result<String, String> {
    #[cfg(any(target_os = "macos", target_os = "ios", target_os = "tvos"))]
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
                .help("The name of the created interface"),
            Arg::new("foreground")
                .long("foreground")
                .short('f')
                .help("Run and log in the foreground"),
            Arg::new("threads")
                .value_parser(clap::value_parser!(usize))
                .long("threads")
                .short('t')
                .env("WG_THREADS")
                .help("Number of OS threads to use")
                .default_value("4"),
            Arg::new("verbosity")
                .value_parser(["error", "info", "debug", "trace"])
                .long("verbosity")
                .short('v')
                .env("WG_LOG_LEVEL")
                .help("Log verbosity")
                .default_value("error"),
            Arg::new("uapi-fd")
                .long("uapi-fd")
                .env("WG_UAPI_FD")
                .help("File descriptor for the user API")
                .default_value("-1")
                .value_parser(clap::value_parser!(i32)),
            Arg::new("tun-fd")
                .long("tun-fd")
                .env("WG_TUN_FD")
                .help("File descriptor for an already-existing TUN device")
                .default_value("-1"),
            Arg::new("log")
                .long("log")
                .short('l')
                .env("WG_LOG_FILE")
                .help("Log file")
                .default_value("/tmp/boringtun.out"),
            Arg::new("disable-drop-privileges")
                .long("disable-drop-privileges")
                .env("WG_SUDO")
                .help("Do not drop sudo privileges"),
            Arg::new("disable-connected-udp")
                .long("disable-connected-udp")
                .help("Disable connected UDP sockets to each peer"),
            #[cfg(target_os = "linux")]
            Arg::new("disable-multi-queue")
                .long("disable-multi-queue")
                .help("Disable using multiple queues for the tunnel interface"),
        ])
        .get_matches();

    let background = !matches.get_flag("foreground");
    #[cfg(target_os = "linux")]
    let uapi_fd: i32 = *matches.get_one::<i32>("uapi-fd").unwrap();
    let tun_fd: isize = matches.get_one::<String>("tun-fd").unwrap().parse().unwrap();
    let mut tun_name = matches.get_one::<String>("INTERFACE_NAME").unwrap();
    if tun_fd >= 0 {
        tun_name = matches.get_one::<String>("tun-fd").unwrap();
    }
    let n_threads: usize = *matches.get_one::<usize>("threads").unwrap();
    let log_level: Level = matches.get_one::<String>("verbosity").unwrap().parse().unwrap();

    // Create a socketpair to communicate between forked processes
    let (sock1, sock2) = UnixDatagram::pair().unwrap();
    let _ = sock1.set_nonblocking(true);

    let _guard;

    if background {
        let log = matches.get_one::<String>("log").unwrap();

        let log_file =
            File::create(log).unwrap_or_else(|_| panic!("Could not create log file {}", log));

        let (non_blocking, guard) = tracing_appender::non_blocking(log_file);

        _guard = guard;

        tracing_subscriber::fmt()
            .with_max_level(log_level)
            .with_writer(non_blocking)
            .with_ansi(false)
            .init();

        // Manual daemonization using nix
        match unsafe { fork() } {
            Ok(ForkResult::Parent { .. }) => {
                // Parent process - wait for child to signal success
                let mut b = [0u8; 1];
                if sock2.recv(&mut b).is_ok() && b[0] == 1 {
                    println!("BoringTun started successfully");
                    process::exit(0);
                } else {
                    eprintln!("BoringTun failed to start");
                    process::exit(1);
                }
            }
            Ok(ForkResult::Child) => {
                // Child process - continue execution
                if let Err(e) = chdir("/tmp") {
                    tracing::error!("Failed to change directory: {:?}", e);
                    process::exit(1);
                }
                tracing::info!("BoringTun started successfully");
            }
            Err(e) => {
                tracing::error!("Fork failed: {:?}", e);
                process::exit(1);
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

    // Notify parent that tunnel initialization succeeded
    sock1.send(&[1]).unwrap();
    drop(sock1);

    tracing::info!("BoringTun started successfully");

    device_handle.wait();
}
