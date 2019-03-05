/// Simple implementation of the client side of the WireGuard protocol
extern crate base64;
extern crate chrono;
extern crate daemonize;
extern crate hex;
extern crate libc;
extern crate ring;
extern crate spin;

pub mod crypto;
mod device;
pub mod ffi;
pub mod noise;

use daemonize::Daemonize;
use device::drop_privileges::*;
use device::*;
use noise::Verbosity;
use std::env;
use std::env::var;
use std::fs::File;
use std::os::unix::net::UnixDatagram;

fn print_usage(bin: &str) {
    println!("usage:");
    println!("{} [-f/--foreground] INTERFACE-NAME", bin);
}

fn main() {
    let mut args: Vec<_> = env::args().collect();

    let (background, tun_name) = match args.len() {
        2 => {
            // A single argument means we have only the tunnel name as parameter
            (true, args.pop().unwrap())
        }
        3 => {
            // When two arguments are given, the first must be -f/--foreground
            if args[1] == "-f" || args[1] == "--foreground" {
                (false, args.pop().unwrap())
            } else {
                return print_usage(&args[0]);
            }
        }
        _ => return print_usage(&args[0]),
    };

    let n_threads = match var("WG_THREADS") {
        Ok(val) => usize::from_str_radix(&val, 10).expect("WG_THREADS expected an integer"),
        Err(_) => 4,
    };

    let log_level = match var("WG_LOG_LEVEL") {
        Ok(val) => match val.as_ref() {
            "silent" => Verbosity::None,
            "info" => Verbosity::Info,
            "debug" => Verbosity::Debug,
            _ => panic!("WG_LOG_LEVEL expected 'silent', 'info', or 'debug'"),
        },
        Err(_) => Verbosity::None,
    };

    // Create a socketpair to communicate between forked processes
    let (sock1, sock2) = UnixDatagram::pair().unwrap();

    if background {
        let log = match var("WG_LOG") {
            Ok(path) => path,
            Err(_) => "/tmp/wireguard_cf.out".to_owned(),
        };

        let err_log = match var("WG_ERR_LOG") {
            Ok(path) => path,
            Err(_) => "/tmp/wireguard_cf.err".to_owned(),
        };

        let stdout = File::create(&log).expect(&format!("Could not create log file {}", log));
        let stderr =
            File::create(&err_log).expect(&format!("Could not create error log file {}", err_log));

        let daemonize = Daemonize::new()
            .working_directory("/tmp")
            .stdout(stdout)
            .stderr(stderr)
            .exit_action(move || {
                let mut b = [0u8; 1];
                sock2.recv(&mut b).ok();
            });

        match daemonize.start() {
            Ok(_) => println!("Success, daemonized"),
            Err(e) => eprintln!("Error, {}", e),
        }
    }

    let config = DeviceConfig {
        n_threads,
        log_level,
        use_connected_socket: true,
    };

    let device_handle = DeviceHandle::new(&tun_name, config);

    drop_privileges().unwrap();

    // Signal to parent process that it can now exit
    sock1.set_nonblocking(true).ok();
    sock1.send(&[1]).ok();
    drop(sock1);

    device_handle.unwrap().wait();
}
