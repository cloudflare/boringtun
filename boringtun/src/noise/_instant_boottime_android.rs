#![cfg(target_os = "android")]

// This is a partial copy of std::time::Instant (android)
// * libc::CLOCK_MONOTONIC replaced with libc::CLOCK_BOOTTIME
// * removed code not used by ./timers.rs

use std::time::Duration;

//////////////////////////////////////////////////////////
// Instant

#[derive(Copy, Clone)]
pub struct Instant {
    t: Timespec,
}

impl Instant {
    pub fn now() -> Instant {
        Instant {
            t: {
                let mut t = Timespec {
                    t: libc::timespec {
                        tv_sec: 0,
                        tv_nsec: 0,
                    },
                };
                unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut t.t) };
                t
            },
        }
    }

    fn checked_sub_instant(&self, other: &Instant) -> Option<Duration> {
        self.t.sub_timespec(&other.t).ok()
    }

    pub fn duration_since(&self, earlier: Instant) -> Duration {
        self.checked_sub_instant(&earlier)
            .expect("supplied instant is later than self")
    }
}

impl std::fmt::Debug for Instant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Instant")
            .field("tv_sec", &self.t.t.tv_sec)
            .field("tv_nsec", &self.t.t.tv_nsec)
            .finish()
    }
}

//////////////////////////////////////////////////////////
// Timespec

const NSEC_PER_SEC: u64 = 1_000_000_000;

#[derive(Copy, Clone)]
struct Timespec {
    t: libc::timespec,
}

impl Timespec {
    fn sub_timespec(&self, other: &Timespec) -> Result<Duration, Duration> {
        if self >= other {
            let (secs, nsec) = if self.t.tv_nsec >= other.t.tv_nsec {
                (
                    (self.t.tv_sec - other.t.tv_sec) as u64,
                    (self.t.tv_nsec - other.t.tv_nsec) as u32,
                )
            } else {
                (
                    (self.t.tv_sec - other.t.tv_sec - 1) as u64,
                    self.t.tv_nsec as u32 + (NSEC_PER_SEC as u32) - other.t.tv_nsec as u32,
                )
            };

            Ok(Duration::new(secs, nsec))
        } else {
            match other.sub_timespec(self) {
                Ok(d) => Err(d),
                Err(d) => Ok(d),
            }
        }
    }
}

impl PartialOrd for Timespec {
    fn partial_cmp(&self, other: &Timespec) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Timespec {
    fn cmp(&self, other: &Timespec) -> std::cmp::Ordering {
        let me = (self.t.tv_sec, self.t.tv_nsec);
        let other = (other.t.tv_sec, other.t.tv_nsec);
        me.cmp(&other)
    }
}

impl PartialEq for Timespec {
    fn eq(&self, other: &Self) -> bool {
        (self.t.tv_sec, self.t.tv_nsec) == (other.t.tv_sec, other.t.tv_nsec)
    }
}

impl Eq for Timespec {}
