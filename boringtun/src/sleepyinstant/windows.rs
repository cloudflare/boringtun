pub(crate) use std::time::Instant;

#[derive(Debug)]
pub struct WindowsClock;

impl Clock for WindowsClock {
    fn now() -> Instant {
        Instant::now()
    }

    fn duration_since(start: Instant, end: Instant) -> Duration {
        end.duration_since(start)
    }
}
