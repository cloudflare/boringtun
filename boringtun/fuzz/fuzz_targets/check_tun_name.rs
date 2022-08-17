#![no_main]
#[macro_use] extern crate libfuzzer_sys;
extern crate boringtun;
use std::os::raw::c_int;
use std::convert::TryInto;

fuzz_target!(|data: &[u8]| {
    if data.len() >= 4 {
        let d = i32::from_ne_bytes((&data[0..4]).try_into().unwrap());
        let _ = boringtun::device::poll::block_signal(d);
    }
});
