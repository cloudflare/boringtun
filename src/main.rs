// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause

pub mod crypto;
mod device;
pub mod ffi;
pub mod noise;

use crate::device::drop_privileges::*;
use crate::device::*;
use crate::noise::Verbosity;
use clap::{value_t, App, Arg};
use daemonize::Daemonize;
use std::fs::File;
use std::os::unix::net::UnixDatagram;

fn check_tun_name(_v: String) -> Result<(), String> {
    #[cfg(target_os = "macos")]
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
                .possible_values(&["silent", "info", "debug"])
                .help("Log verbosity")
                .default_value("silent"),
            Arg::with_name("log")
                .takes_value(true)
                .long("log")
                .short("-l")
                .env("WG_LOG_FILE")
                .help("Log file")
                .default_value("/tmp/boringtun.out"),
            Arg::with_name("err")
                .takes_value(true)
                .long("err")
                .short("-e")
                .env("WG_ERR_LOG_FILE")
                .help("Critical errors log file")
                .default_value("/tmp/boringtun.err"),
            Arg::with_name("disable-drop-privileges")
                .long("disable-drop-privileges")
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
    let log_level = value_t!(matches.value_of("verbosity"), Verbosity).unwrap_or_else(|e| e.exit());

    // Create a socketpair to communicate between forked processes
    let (sock1, sock2) = UnixDatagram::pair().unwrap();
    sock1.set_nonblocking(true).ok();

    if background {
        let log = matches.value_of("log").unwrap();
        let err_log = matches.value_of("err").unwrap();

        let stdout =
            File::create(&log).unwrap_or_else(|_| panic!("Could not create log file {}", log));
        let stderr = File::create(&err_log)
            .unwrap_or_else(|_| panic!("Could not create error log file {}", err_log));

        let daemonize = Daemonize::new()
            .working_directory("/tmp")
            .stdout(stdout)
            .stderr(stderr)
            .exit_action(move || {
                let mut b = [0u8; 1];
                sock2.recv(&mut b).ok();

                println!(
                    "{}",
                    match b[0] {
                        0 => "boringtun failed to start",
                        _ => "boringtun started successfully",
                    }
                );
            });

        match daemonize.start() {
            Ok(_) => println!("Success, daemonized"),
            Err(e) => eprintln!("Error, {}", e),
        }
    }

    let config = DeviceConfig {
        n_threads,
        log_level,
        use_connected_socket: !matches.is_present("disable-connected-udp"),
        #[cfg(target_os = "linux")]
        use_multi_queue: !matches.is_present("disable-multi-queue"),
    };

    let mut device_handle = match DeviceHandle::new(&tun_name, config) {
        Ok(d) => d,
        Err(e) => {
            // Notify parent that tunnel initialization failed
            println!("{:?}", e);
            sock1.send(&[0]).ok();
            return;
        }
    };

    if !matches.is_present("disable-drop-priviliges") {
        drop_privileges().ok();
    }

    // Notify parent that tunnel initialization succeeded
    sock1.send(&[1]).ok();
    drop(sock1);

    device_handle.wait();
}
