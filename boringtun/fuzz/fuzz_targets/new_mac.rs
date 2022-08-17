#![no_main]
use libfuzzer_sys::fuzz_target;
use boringtun::noise::Tunn;

fuzz_target!(|data: &[u8]| {
    Tunn::dst_address(data);
});
