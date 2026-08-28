use crate::sleepyinstant::{ClockDuration, ClockInstant};

/// `winsafe::GetTickCount64` is a safe wrapper around the Win32 API of the same name: the
/// number of milliseconds since system startup, which (like Linux's `CLOCK_BOOTTIME`) keeps
/// advancing across system sleep.
pub(super) fn now() -> ClockInstant {
    let elapsed = ClockDuration::from_millis(winsafe::GetTickCount64());
    ClockInstant::from_ticks(elapsed.as_ticks())
}
