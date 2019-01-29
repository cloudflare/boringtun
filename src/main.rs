/// Simple implementation of the client side of the WireGuard protocol
extern crate base64;
extern crate hex;
extern crate libc;
extern crate rand;
extern crate spin;

pub mod crypto;
mod device;
pub mod ffi;
pub mod noise;

//use device::event::*;
use device::*;
use std::env;
use std::sync::Arc;
use std::thread;

fn print_usage(bin: &str) {
    println!("usage:");
    println!("{} [-f/--foreground] INTERFACE-NAME", bin);
}

struct WireGuard {}

impl WireGuard {
    pub fn new() -> WireGuard {
        WireGuard {}
    }

    pub fn register_device(&mut self, name: &str) -> bool {
        match Device::new(name) {
            Ok(new_device) => {
                let dev = Arc::new(DeviceHandle::new(new_device));
                let mut threads = vec![];

                let nthreads = match std::env::var("WG_THREADS") {
                    Ok(val) => usize::from_str_radix(&val, 10).unwrap(),
                    Err(_) => 4,
                };

                for _ in 0..nthreads {
                    threads.push({
                        let dev = Arc::clone(&dev);
                        thread::spawn(move || dev.event_loop())
                    });
                }

                for t in threads {
                    t.join().unwrap();
                }

                true
            }
            Err(e) => {
                println!("{:?}", e);
                false
            }
        }
    }
}

fn main() {
    let mut args: Vec<_> = env::args().collect();

    let (_background, tun_name) = match args.len() {
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

    let mut wg = WireGuard::new();
    if !wg.register_device(&tun_name) {
        return;
    }
}
