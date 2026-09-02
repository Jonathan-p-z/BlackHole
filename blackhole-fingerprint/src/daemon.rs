//! Periodic scan mode: run a scan on a configurable interval instead of
//! only on demand, so degradation between scans (e.g. a Windows update
//! silently re-enabling telemetry) gets caught without the operator
//! remembering to run the tool.
//!
//! Ticks are scheduled at `start + n * interval` for each `n`, computed
//! fresh from a fixed `start` instant every time — never by sleeping for
//! `interval` and then measuring elapsed time again from *that* point.
//! The latter drifts: each tick's own work (however small) pushes every
//! subsequent tick later by a compounding amount. Anchoring every tick to
//! the same `start` means a slow tick delays only that one tick, not the
//! whole schedule going forward.

use std::time::{Duration, Instant};

use crate::error::FingerprintError;

/// The absolute instant of the `n`th tick after `start`, `interval` apart.
/// Pure and synchronous — no sleeping — so the scheduling arithmetic
/// itself is directly testable without waiting on a real clock.
pub fn nth_tick(start: Instant, interval: Duration, n: u32) -> Instant {
    start + interval * n
}

/// Run `on_tick` once immediately, then again every `interval`, until
/// `should_stop` returns `true` (checked right before each tick, including
/// the first). Blocking/synchronous — this crate has no async runtime —
/// so it's meant to be the entire body of a `daemon` CLI subcommand, not
/// called from inside other work.
pub fn run<F, S>(interval: Duration, mut on_tick: F, mut should_stop: S) -> Result<(), FingerprintError>
where
    F: FnMut() -> Result<(), FingerprintError>,
    S: FnMut() -> bool,
{
    let start = Instant::now();
    let mut n = 0u32;

    loop {
        if should_stop() {
            return Ok(());
        }

        on_tick()?;
        n += 1;

        let target = nth_tick(start, interval, n);
        let now = Instant::now();
        if target > now {
            std::thread::sleep(target - now);
        }
        // If `on_tick` alone took longer than `interval`, `target` is
        // already in the past: proceed immediately to the next tick
        // rather than sleeping (and rather than trying to "catch up" by
        // firing several ticks back-to-back) — the schedule baseline
        // (`start`) is untouched either way, so it self-corrects on the
        // next tick that *does* fit within its interval.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::Mutex;

    #[test]
    fn nth_tick_is_evenly_spaced_from_start_not_cumulative() {
        let start = Instant::now();
        let interval = Duration::from_secs(60);

        assert_eq!(nth_tick(start, interval, 0), start);
        assert_eq!(nth_tick(start, interval, 1), start + Duration::from_secs(60));
        assert_eq!(nth_tick(start, interval, 5), start + Duration::from_secs(300));
        // Directly encodes "no drift": the 5th tick is exactly 5x the
        // interval after start, not "whatever accumulated sleep(60s) x5
        // plus each tick's own work happened to add up to".
    }

    #[test]
    fn stops_promptly_when_should_stop_returns_true() {
        let ticks = AtomicU32::new(0);
        run(
            Duration::from_millis(1),
            || {
                ticks.fetch_add(1, Ordering::SeqCst);
                Ok(())
            },
            || ticks.load(Ordering::SeqCst) >= 3,
        )
        .unwrap();

        assert_eq!(ticks.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn respects_the_configured_interval_across_several_ticks() {
        // Real (short) sleeps, asserting the *pattern* the drift-free
        // design produces: each recorded tick lands close to its
        // `start + n*interval` target, and the gap between consecutive
        // ticks stays close to `interval` throughout — it doesn't grow
        // tick over tick the way a naive "sleep(interval) after work"
        // loop would once `on_tick`'s own cost is non-negligible.
        let interval = Duration::from_millis(20);
        let times = Mutex::new(Vec::<Instant>::new());

        run(
            interval,
            || {
                // Simulate `on_tick` work taking a non-trivial slice of
                // the interval, on purpose — this is exactly the
                // condition under which a naive loop would drift.
                std::thread::sleep(Duration::from_millis(5));
                times.lock().unwrap().push(Instant::now());
                Ok(())
            },
            {
                let times = &times;
                move || times.lock().unwrap().len() >= 5
            },
        )
        .unwrap();

        let times = times.into_inner().unwrap();
        assert_eq!(times.len(), 5);

        let gaps: Vec<Duration> = times.windows(2).map(|w| w[1] - w[0]).collect();
        for gap in &gaps {
            // Generous bound (interval +/- 15ms) to absorb OS scheduling
            // jitter in a test environment — the property under test is
            // "does not grow", not "is exactly on time".
            assert!(
                gap.as_millis() <= interval.as_millis() + 15,
                "gap {gap:?} grew well beyond the configured interval {interval:?} — schedule is drifting"
            );
        }
    }
}
