#![cfg(target_os = "ios")]
#![allow(non_camel_case_types)]

// This is a partial copy of std::time::Instant (ios)
// * mach_absolute_time replaced with mach_continuous_time
// * removed code not used by ./timers.rs

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const NSEC_PER_SEC: u64 = 1_000_000_000;

//////////////////////////////////////////////////////////
// Instant

#[derive(Copy, Clone, Debug)]
pub struct Instant {
    t: u64,
}

impl Instant {
    pub fn now() -> Instant {
        extern "C" {
            fn mach_continuous_time() -> u64;
        }
        Instant {
            t: unsafe { mach_continuous_time() },
        }
    }

    fn checked_sub_instant(&self, other: &Instant) -> Option<Duration> {
        let diff = self.t.checked_sub(other.t)?;
        let info = info();
        let nanos = mul_div_u64(diff, info.numer as u64, info.denom as u64);
        Some(Duration::new(
            nanos / NSEC_PER_SEC,
            (nanos % NSEC_PER_SEC) as u32,
        ))
    }

    pub fn duration_since(&self, earlier: Instant) -> Duration {
        self.checked_sub_instant(&earlier)
            .expect("supplied instant is later than self")
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct mach_timebase_info {
    numer: u32,
    denom: u32,
}

type mach_timebase_info_t = *mut mach_timebase_info;
type kern_return_t = libc::c_int;

fn mul_div_u64(value: u64, numer: u64, denom: u64) -> u64 {
    let q = value / denom;
    let r = value % denom;
    // Decompose value as (value/denom*denom + value%denom),
    // substitute into (value*numer)/denom and simplify.
    // r < denom, so (denom*numer) is the upper bound of (r*numer)
    q * numer + r * numer / denom
}

fn info() -> mach_timebase_info {
    // INFO_BITS conceptually is an `Option<mach_timebase_info>`. We can do
    // this in 64 bits because we know 0 is never a valid value for the
    // `denom` field.
    //
    // Encoding this as a single `AtomicU64` allows us to use `Relaxed`
    // operations, as we are only interested in the effects on a single
    // memory location.
    static INFO_BITS: AtomicU64 = AtomicU64::new(0);

    // If a previous thread has initialized `INFO_BITS`, use it.
    let info_bits = INFO_BITS.load(Ordering::Relaxed);
    if info_bits != 0 {
        return info_from_bits(info_bits);
    }

    // ... otherwise learn for ourselves ...
    extern "C" {
        fn mach_timebase_info(info: mach_timebase_info_t) -> kern_return_t;
    }

    let mut info = info_from_bits(0);
    unsafe {
        mach_timebase_info(&mut info);
    }
    INFO_BITS.store(info_to_bits(info), Ordering::Relaxed);
    info
}

#[inline]
fn info_to_bits(info: mach_timebase_info) -> u64 {
    ((info.denom as u64) << 32) | (info.numer as u64)
}

#[inline]
fn info_from_bits(bits: u64) -> mach_timebase_info {
    mach_timebase_info {
        numer: bits as u32,
        denom: (bits >> 32) as u32,
    }
}
