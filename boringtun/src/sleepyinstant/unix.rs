use crate::sleepyinstant::{ClockDuration, ClockInstant};
use nix::time::{clock_gettime, ClockId};

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "freebsd",
    target_os = "netbsd"
))]
const CLOCK_ID: ClockId = ClockId::CLOCK_MONOTONIC;
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "freebsd",
    target_os = "netbsd"
)))]
const CLOCK_ID: ClockId = ClockId::CLOCK_BOOTTIME;

pub(super) fn now() -> ClockInstant {
    // std::time::Instant unwraps as well, so feel safe doing so here
    let t = clock_gettime(CLOCK_ID).unwrap();
    let elapsed =
        ClockDuration::from_secs(t.tv_sec() as u64) + ClockDuration::from_ticks(t.tv_nsec() as u64);
    ClockInstant::from_ticks(elapsed.as_ticks())
}
