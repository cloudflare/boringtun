//! Example to show difference between std and sleepyinstant
//!
//! To test, run the `timers` on your machine, put it to sleep, and wake it back
//! up. You'll see the times are no longer the same
//!
//! Note: This does not work on Windows since the underlying implementation of
//! std::time::Instant does count sleep
use std::io::Write;

fn main() {
    let sleepy_start = sleepyinstant::Instant::now();
    let std_start = std::time::Instant::now();

    loop {
        print!(
            "\rSleepy Elapsed Time: {} secs Std Elapsed Time: {} secs",
            sleepy_start.elapsed().as_secs(),
            std_start.elapsed().as_secs()
        );
        let _ = std::io::stdout().flush();
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
