// Copyright (c) 2019 Cloudflare, Inc. All rights reserved.
// SPDX-License-Identifier: BSD-3-Clause
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
