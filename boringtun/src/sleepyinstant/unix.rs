use core::ops::Add;
use embedded_time::duration::Seconds;
use embedded_time::rate::Fraction;
use embedded_time::{Clock, Instant};
use nix::time::{ClockId, clock_gettime};

#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "freebsd"
))]
const CLOCK_ID: ClockId = ClockId::CLOCK_MONOTONIC;
#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "tvos",
    target_os = "freebsd"
)))]
const CLOCK_ID: ClockId = ClockId::CLOCK_BOOTTIME;

#[derive(Copy, Clone, Debug, Default)]
pub struct UnixClock;

impl Clock for UnixClock {
    type T = u64;

    const SCALING_FACTOR: Fraction = Fraction::new(1, 1_000_000_000);

    fn try_now(&self) -> Result<Instant<UnixClock>, embedded_time::clock::Error> {
        let t = clock_gettime(CLOCK_ID).unwrap();
        let mut i = Instant::new(t.tv_nsec() as u64);
        i = i.add(Seconds(t.tv_sec() as u64));
        Ok(i)
    }
}
