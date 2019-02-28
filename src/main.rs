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
use std::env;
use std::env::var;
use std::fs::File;

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

    if background {
        let stdout = File::create("/tmp/wireguard_cf.out").unwrap();
        let stderr = File::create("/tmp/wireguard_cf.err").unwrap();

        let daemonize = Daemonize::new()
            .working_directory("/tmp")
            .stdout(stdout) // Redirect stdout
            .stderr(stderr) // Redirect stderr
            .privileged_action(|| {});

        match daemonize.start() {
            Ok(_) => println!("Success, daemonized"),
            Err(e) => eprintln!("Error, {}", e),
        }
    }

    let n_threads = match var("WG_THREADS") {
        Ok(val) => usize::from_str_radix(&val, 10).unwrap(),
        Err(_) => 4,
    };

    let config = DeviceConfig {
        n_threads,
        use_connected_socket: true,
    };

    let mut device_handle = DeviceHandle::new(&tun_name, config).unwrap();

    drop_privileges().unwrap();

    device_handle.wait();
}
