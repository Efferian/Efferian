use std::io;
use std::mem::MaybeUninit;
use std::time::Duration;

use crate::PlatformError;

#[cfg(target_os = "linux")]
const CLOCK_ID: libc::clockid_t = libc::CLOCK_BOOTTIME;

#[cfg(target_os = "macos")]
const CLOCK_ID: libc::clockid_t = libc::CLOCK_MONOTONIC_RAW;

const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// Monotonic system time that advances during suspend.
pub struct MonotonicClock;

/// A reading from the system's monotonic clock, in nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MonoInstant(u64);

impl MonotonicClock {
    pub fn now() -> Result<MonoInstant, PlatformError> {
        let mut reading = MaybeUninit::<libc::timespec>::uninit();
        // SAFETY: reading provides aligned writable storage for a timespec.
        // clock_gettime initializes it on success, the only case where we read it.
        let reading = unsafe {
            if libc::clock_gettime(CLOCK_ID, reading.as_mut_ptr()) != 0 {
                return Err(PlatformError::ClockUnavailable {
                    source: io::Error::last_os_error(),
                });
            }
            reading.assume_init()
        };

        let seconds = u64::try_from(reading.tv_sec).map_err(|_| PlatformError::ClockOverflow)?;
        let nanos = u64::try_from(reading.tv_nsec)
            .ok()
            .filter(|&nanos| nanos < NANOS_PER_SECOND)
            .ok_or(PlatformError::ClockOverflow)?;
        seconds
            .checked_mul(NANOS_PER_SECOND)
            .and_then(|seconds| seconds.checked_add(nanos))
            .map(MonoInstant)
            .ok_or(PlatformError::ClockOverflow)
    }
}

impl MonoInstant {
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    pub const fn as_millis(self) -> u64 {
        self.0 / 1_000_000
    }

    pub fn checked_duration_since(self, earlier: Self) -> Option<Duration> {
        self.0.checked_sub(earlier.0).map(Duration::from_nanos)
    }

    pub fn saturating_duration_since(self, earlier: Self) -> Duration {
        Duration::from_nanos(self.0.saturating_sub(earlier.0))
    }

    pub fn checked_add(self, duration: Duration) -> Option<Self> {
        self.0
            .checked_add(u64::try_from(duration.as_nanos()).ok()?)
            .map(Self)
    }

    pub fn checked_sub(self, duration: Duration) -> Option<Self> {
        self.0
            .checked_sub(u64::try_from(duration.as_nanos()).ok()?)
            .map(Self)
    }

    pub fn elapsed(self) -> Result<Duration, PlatformError> {
        Ok(MonotonicClock::now()?.saturating_duration_since(self))
    }
}
