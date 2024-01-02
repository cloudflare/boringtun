use std::{
    ops::{Add, Mul, Sub},
    time::Duration,
};

#[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct SafeDuration(Duration);

impl SafeDuration {
    pub const fn from_secs(secs: u64) -> Self {
        Self(Duration::from_secs(secs))
    }

    pub const fn is_zero(&self) -> bool {
        self.0.is_zero()
    }

    pub const fn checked_sub(&self, rhs: SafeDuration) -> Option<Duration> {
        self.0.checked_sub(rhs.0)
    }

    pub const fn from_millis(millis: u64) -> SafeDuration {
        Self(Duration::from_millis(millis))
    }
}

impl Add for SafeDuration {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.saturating_add(rhs.0))
    }
}

impl Sub for SafeDuration {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.saturating_sub(rhs.0))
    }
}

impl Mul<u32> for SafeDuration {
    type Output = Self;

    fn mul(self, rhs: u32) -> Self::Output {
        Self(self.0.saturating_mul(rhs))
    }
}

impl PartialEq<Duration> for SafeDuration {
    fn eq(&self, other: &Duration) -> bool {
        self.0.eq(other)
    }
}

impl PartialOrd<Duration> for SafeDuration {
    fn partial_cmp(&self, other: &Duration) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(other)
    }
}

impl PartialEq<SafeDuration> for Duration {
    fn eq(&self, other: &SafeDuration) -> bool {
        self.eq(&other.0)
    }
}

impl PartialOrd<SafeDuration> for Duration {
    fn partial_cmp(&self, other: &SafeDuration) -> Option<std::cmp::Ordering> {
        self.partial_cmp(&other.0)
    }
}

impl From<Duration> for SafeDuration {
    fn from(value: Duration) -> Self {
        Self(value)
    }
}

impl From<SafeDuration> for Duration {
    fn from(value: SafeDuration) -> Self {
        value.0
    }
}
