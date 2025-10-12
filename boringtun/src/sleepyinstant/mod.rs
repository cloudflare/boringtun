#![forbid(unsafe_code)]
//! Attempts to provide the same functionality as std::time::Instant, except it
//! uses a timer which accounts for time when the system is asleep

use embedded_time::duration::Generic;
use embedded_time::Clock;
#[cfg(windows)]
pub use std_embedded_time::StandardClock as ClockImpl;

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use inner::UnixClock as ClockImpl;
#[cfg(unix)]
use unix as inner;

#[cfg(feature = "ariel-os")]
pub use embassy_embedded_time::EmbassyClock as ClockImpl;

/// A measurement of a monotonically nondecreasing clock.
/// Opaque and useful only with [`Duration`].
///
/// Instants are always guaranteed, barring [platform bugs], to be no less than any previously
/// measured instant when created, and are often useful for tasks such as measuring
/// benchmarks or timing how long an operation takes.
///
/// Note, however, that instants are **not** guaranteed to be **steady**. In other
/// words, each tick of the underlying clock might not be the same length (e.g.
/// some seconds may be longer than others). An instant may jump forwards or
/// experience time dilation (slow down or speed up), but it will never go
/// backwards.
///
/// Instants are opaque types that can only be compared to one another. There is
/// no method to get "the number of seconds" from an instant. Instead, it only
/// allows measuring the duration between two instants (or comparing two
/// instants).
///
/// The size of an `Instant` struct may vary depending on the target operating
/// system.
///
#[derive(Clone, Copy, Debug)]
pub struct Instant {
    t: embedded_time::Instant<ClockImpl>,
}

/// The underlying unit of time for the clock.
pub type ClockUnit = <ClockImpl as Clock>::T;

/// A span of time between two instants of the clock.
pub type ClockDuration = Generic<ClockUnit>;

impl Instant {
    /// Returns an instant corresponding to "now".
    pub fn now() -> Self {
        Self {
            t: ClockImpl::default().try_now().unwrap(),
        }
    }

    /// Returns the amount of time elapsed from another instant to this one,
    /// or zero duration if that instant is later than this one.
    ///
    /// # Panics
    ///
    /// panics when `earlier` was later than `self`.
    pub fn duration_since(&self, earlier: Instant) -> ClockDuration {
        self.t.checked_duration_since(&earlier.t).unwrap()
    }

    /// Returns the amount of time elapsed since this instant was created.
    pub fn elapsed(&self) -> ClockDuration {
        Self::now().duration_since(*self)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use core::convert::TryInto;
    use embedded_time::duration::Milliseconds;

    #[test]
    fn time_increments_after_sleep() {
        let sleep_time = Milliseconds(10u32);
        let start = Instant::now();
        std::thread::sleep(sleep_time.try_into().unwrap());
        assert!(start.elapsed() >= sleep_time);
    }
}
