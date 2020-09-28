// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod crypto;

#[cfg(not(target_os = "windows"))]
pub mod device;

pub mod ffi;
pub mod noise;

use crate::device::drop_privileges::*;
use crate::device::*;
use clap::{value_t, App, Arg};
use daemonize::Daemonize;
use slog::{error, info, o, Drain, Logger};
use std::fs::File;
use std::os::unix::net::UnixDatagram;
use std::process::exit;

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
        ])
        .get_matches();

    let background = !matches.is_present("foreground");
    let tun_name = matches.value_of("INTERFACE_NAME").unwrap();
    let n_threads = value_t!(matches.value_of("threads"), usize).unwrap_or_else(|e| e.exit());
    let log_level =
        value_t!(matches.value_of("verbosity"), slog::Level).unwrap_or_else(|e| e.exit());

    // Create a socketpair to communicate between forked processes
    let (sock1, sock2) = UnixDatagram::pair().unwrap();
    let _ = sock1.set_nonblocking(true);

    let logger;

    if background {
        let log = matches.value_of("log").unwrap();

        let log_file =
            File::create(&log).unwrap_or_else(|_| panic!("Could not create log file {}", log));

        let plain = slog_term::PlainSyncDecorator::new(log_file);
        let drain = slog_term::CompactFormat::new(plain)
            .build()
            .filter_level(log_level);
        let drain = std::sync::Mutex::new(drain).fuse();
        logger = Logger::root(drain, o!());

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
            Ok(_) => info!(logger, "BoringTun started successfully"),
            Err(e) => {
                error!(logger, "Error, {}", e);
                exit(1);
            }
        }
    } else {
        let plain = slog_term::TermDecorator::new().stdout().build();
        let drain = slog_term::FullFormat::new(plain)
            .build()
            .filter_level(log_level);
        let drain = std::sync::Mutex::new(drain).fuse();
        logger = Logger::root(drain, o!());
    }

    let config = DeviceConfig {
        n_threads,
        logger: logger.clone(),
        use_connected_socket: !matches.is_present("disable-connected-udp"),
        #[cfg(target_os = "linux")]
        use_multi_queue: !matches.is_present("disable-multi-queue"),
    };

    let mut device_handle: DeviceHandle = match DeviceHandle::new(&tun_name, config) {
        Ok(d) => d,
        Err(e) => {
            // Notify parent that tunnel initialization failed
            error!(logger, "Failed to initialize tunnel: {:?}", e);
            sock1.send(&[0]).unwrap();
            exit(1);
        }
    };

    if !matches.is_present("disable-drop-privileges") {
        if let Err(e) = drop_privileges() {
            error!(logger, "Failed to drop privileges: {:?}", e);
            sock1.send(&[0]).unwrap();
            exit(1);
        }
    }

    // Notify parent that tunnel initialization succeeded
    sock1.send(&[1]).unwrap();
    drop(sock1);

    info!(logger, "BoringTun started successfully");

    device_handle.wait();
}
