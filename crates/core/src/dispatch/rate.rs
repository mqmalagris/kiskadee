//! Per-token rate limits: a rolling window of call times per token, kept in
//! memory, so a restart starts every window fresh.

use std::collections::{HashMap, VecDeque};

use super::{RATE_LIMIT, RATE_WINDOW_MS};

/// Calls a bucket let through in the last window, oldest first.
#[derive(Default)]
struct Bucket {
    calls: VecDeque<i64>,
    /// When a rate-limited call from this bucket was last written to the
    /// Ledger.
    logged_ms: Option<i64>,
}

pub(super) enum Verdict {
    Allowed,
    Limited {
        retry_after_s: u64,
        /// Whether to write this call to the Ledger: only the first
        /// rate-limited call of each window is, so a flood can't grow it.
        log: bool,
    },
}

/// Buckets by token id; `None` is the one bucket shared by every caller
/// whose token can't be identified.
#[derive(Default)]
pub(super) struct RateLimiter {
    buckets: HashMap<Option<String>, Bucket>,
    unlogged: u64,
}

impl RateLimiter {
    /// Counts a call from `token` at `now_ms`, unless the window is full.
    /// Rate-limited calls aren't counted, so a caller that backs off for
    /// the retry-after gets through.
    pub fn check(&mut self, token: Option<&str>, now_ms: i64) -> Verdict {
        let bucket = self.buckets.entry(token.map(str::to_string)).or_default();
        let window_start = now_ms.saturating_sub(RATE_WINDOW_MS);
        while bucket.calls.front().is_some_and(|&at| at <= window_start) {
            bucket.calls.pop_front();
        }
        let Some(&oldest) = bucket
            .calls
            .front()
            .filter(|_| bucket.calls.len() >= RATE_LIMIT)
        else {
            bucket.calls.push_back(now_ms);
            return Verdict::Allowed;
        };
        let wait_ms = oldest.saturating_add(RATE_WINDOW_MS).saturating_sub(now_ms);
        let retry_after_s = u64::try_from(wait_ms).unwrap_or(0).div_ceil(1000).max(1);
        let log = bucket
            .logged_ms
            .is_none_or(|at| now_ms.saturating_sub(at) >= RATE_WINDOW_MS);
        if log {
            bucket.logged_ms = Some(now_ms);
        } else {
            self.unlogged += 1;
        }
        Verdict::Limited { retry_after_s, log }
    }

    /// Rate-limited calls left out of the Ledger since the Broker started.
    pub fn unlogged(&self) -> u64 {
        self.unlogged
    }
}
