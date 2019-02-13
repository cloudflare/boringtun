#![allow(warnings)]

extern crate base64;
extern crate hex;
extern crate libc;
extern crate ring;
extern crate spin;

mod crypto;
mod ffi;
mod noise;

use ffi::benchmark::do_benchmark;
use std::io::prelude::Write;

fn main() {
    let mut i = 0;
    while let Some(benchmark_name) = do_benchmark(true, i) {
        print!("{}", benchmark_name);
        std::io::stdout().flush().unwrap();
        let benchmark_result = do_benchmark(false, i).unwrap();
        println!("{}", benchmark_result);
        i += 1;
    }
    println!("Done");
}
