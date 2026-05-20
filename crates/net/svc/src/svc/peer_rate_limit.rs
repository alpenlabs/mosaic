//! Per-peer protocol-stream rate limiting.
//!
//! Bounds how fast an authenticated peer can drive new protocol streams into
//! the service. This is the upstream admission control that lets internal
//! job-system channels stay unbounded (see #221) while still bounding
//! peer-driven fan-in.
//!
//! Each peer has its own token bucket of capacity [`PeerStreamRateLimit::burst`]
//! that refills at [`PeerStreamRateLimit::per_second`] tokens per second. A
//! protocol-stream router consumes one token before routing the stream into
//! the protocol stream channel; if the bucket is empty the stream is reset
//! with an explicit error and the event is logged.
//!
//! Bulk-transfer streams are deliberately *not* rate-limited here: bulk
//! transfers are application-driven (one per garbling-table transfer) and
//! already gated by the protocol-state-machine layer.

use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};

use mosaic_net_svc_api::{PeerId, PeerStreamRateLimit};

/// Per-peer token-bucket rate limiter.
///
/// Cheap to clone (the bucket map is shared via interior mutability behind
/// a `Mutex`). Threadsafe; called from short critical sections only.
#[derive(Debug, Clone)]
pub(crate) struct PeerStreamRateLimiter {
    inner: std::sync::Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    config: PeerStreamRateLimit,
    buckets: Mutex<HashMap<PeerId, Bucket>>,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    /// Tokens currently available, in tokens. Float for fractional refill.
    tokens: f64,
    /// Last instant the bucket was refilled.
    last_refill: Instant,
    /// Last instant a `Reject { warn: true }` was emitted for this peer.
    /// `None` means we have not yet warned for this peer.
    last_warn: Option<Instant>,
}

/// Result of an admission attempt. The `Reject` arm carries a hint about
/// whether the caller should emit a `warn`-level log: under sustained
/// flooding the limiter wants to be loud once per peer per window but quiet
/// in between, so consumers don't pay log-amplification cost on every
/// rejected stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AdmissionDecision {
    Admit,
    Reject { warn: bool },
}

/// Minimum gap between consecutive `warn`-level rate-limit logs for a
/// single peer. All other rejects are returned with `warn: false` so the
/// caller logs at debug or skips entirely.
const WARN_THROTTLE: Duration = Duration::from_secs(5);

impl PeerStreamRateLimiter {
    pub(crate) fn new(config: PeerStreamRateLimit) -> Self {
        Self {
            inner: std::sync::Arc::new(Inner {
                config,
                buckets: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Try to consume one token for `peer`. Returns [`AdmissionDecision`]
    /// indicating whether the stream is admitted, and on rejection whether
    /// the caller should emit a warn-level log (rate-limited per peer to
    /// avoid log amplification under sustained flooding).
    ///
    /// `now` is taken explicitly so tests can drive the clock deterministically.
    pub(crate) fn try_admit_at(&self, peer: PeerId, now: Instant) -> AdmissionDecision {
        let cap = self.inner.config.burst as f64;
        let rate = self.inner.config.per_second as f64;

        // Fast path: unlimited (sentinel). Avoid per-call locking when the
        // operator has explicitly disabled the limit upstream.
        if self.inner.config.burst == u32::MAX && self.inner.config.per_second == u32::MAX {
            return AdmissionDecision::Admit;
        }

        let mut buckets = self.inner.buckets.lock().unwrap_or_else(|e| e.into_inner());
        let bucket = buckets.entry(peer).or_insert(Bucket {
            tokens: cap,
            last_refill: now,
            last_warn: None,
        });

        // Refill since last touch.
        let elapsed = now.saturating_duration_since(bucket.last_refill);
        if elapsed > Duration::ZERO {
            let refill = rate * elapsed.as_secs_f64();
            bucket.tokens = (bucket.tokens + refill).min(cap);
            bucket.last_refill = now;
        }

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            AdmissionDecision::Admit
        } else {
            // Throttle the warn-level log to once per `WARN_THROTTLE` per
            // peer. Subsequent rejects in the throttle window still
            // happen — they reset the stream — but don't amplify the
            // log volume that the abuse path would otherwise drive.
            let warn = match bucket.last_warn {
                None => true,
                Some(last) => now.saturating_duration_since(last) >= WARN_THROTTLE,
            };
            if warn {
                bucket.last_warn = Some(now);
            }
            AdmissionDecision::Reject { warn }
        }
    }

    /// Convenience for production callers — uses `Instant::now()`.
    pub(crate) fn try_admit(&self, peer: PeerId) -> AdmissionDecision {
        self.try_admit_at(peer, Instant::now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(seed: u8) -> PeerId {
        PeerId::from_bytes([seed; 32])
    }

    fn admit(d: AdmissionDecision) -> bool {
        matches!(d, AdmissionDecision::Admit)
    }

    #[test]
    fn admits_up_to_burst_then_refuses() {
        let limiter = PeerStreamRateLimiter::new(PeerStreamRateLimit {
            burst: 3,
            per_second: 1,
        });
        let now = Instant::now();
        assert!(admit(limiter.try_admit_at(peer(1), now)));
        assert!(admit(limiter.try_admit_at(peer(1), now)));
        assert!(admit(limiter.try_admit_at(peer(1), now)));
        assert!(
            !admit(limiter.try_admit_at(peer(1), now)),
            "fourth admit at the same instant should be refused"
        );
    }

    #[test]
    fn refills_at_configured_rate() {
        let limiter = PeerStreamRateLimiter::new(PeerStreamRateLimit {
            burst: 2,
            per_second: 4,
        });
        let t0 = Instant::now();
        assert!(admit(limiter.try_admit_at(peer(2), t0)));
        assert!(admit(limiter.try_admit_at(peer(2), t0)));
        assert!(!admit(limiter.try_admit_at(peer(2), t0)));

        // 4 tokens/sec → 0.5s gives 2 tokens, but cap is 2.
        assert!(admit(
            limiter.try_admit_at(peer(2), t0 + Duration::from_millis(500))
        ));
        assert!(admit(
            limiter.try_admit_at(peer(2), t0 + Duration::from_millis(500))
        ));
        assert!(!admit(
            limiter.try_admit_at(peer(2), t0 + Duration::from_millis(500))
        ));
    }

    #[test]
    fn buckets_are_independent_per_peer() {
        let limiter = PeerStreamRateLimiter::new(PeerStreamRateLimit {
            burst: 1,
            per_second: 1,
        });
        let now = Instant::now();
        assert!(admit(limiter.try_admit_at(peer(1), now)));
        assert!(admit(limiter.try_admit_at(peer(2), now)));
        // peer 1 is now empty
        assert!(!admit(limiter.try_admit_at(peer(1), now)));
        // peer 2 is also empty
        assert!(!admit(limiter.try_admit_at(peer(2), now)));
    }

    #[test]
    fn unlimited_sentinel_skips_locking() {
        let limiter = PeerStreamRateLimiter::new(PeerStreamRateLimit::UNLIMITED);
        let now = Instant::now();
        for _ in 0..10_000 {
            assert!(admit(limiter.try_admit_at(peer(1), now)));
        }
    }

    #[test]
    fn warn_log_throttled_per_peer() {
        // First reject for a peer warns; subsequent rejects within the
        // throttle window are quiet so an abusive peer can't drive log
        // amplification at the stream-open rate.
        let limiter = PeerStreamRateLimiter::new(PeerStreamRateLimit {
            burst: 1,
            per_second: 1,
        });
        let t0 = Instant::now();
        assert!(admit(limiter.try_admit_at(peer(7), t0))); // consume the one token
        assert_eq!(
            limiter.try_admit_at(peer(7), t0),
            AdmissionDecision::Reject { warn: true },
            "first reject after burst exhaustion should warn"
        );
        assert_eq!(
            limiter.try_admit_at(peer(7), t0 + Duration::from_millis(50)),
            AdmissionDecision::Reject { warn: false },
            "subsequent reject within the throttle window should be quiet"
        );
        assert_eq!(
            limiter.try_admit_at(peer(7), t0 + Duration::from_millis(100)),
            AdmissionDecision::Reject { warn: false },
            "still inside throttle window"
        );
        // After the throttle window elapses, refills also kick in for this
        // toy config (1 token/sec), so we admit again — exercise that the
        // throttle is wall-clock based by issuing many rejects elsewhere.
        let t1 = t0 + WARN_THROTTLE + Duration::from_millis(100);
        // Different peer — independent throttle.
        assert_eq!(
            limiter.try_admit_at(peer(8), t1),
            AdmissionDecision::Admit,
            "peer 8's first attempt at t1 admits"
        );
        assert_eq!(
            limiter.try_admit_at(peer(8), t1),
            AdmissionDecision::Reject { warn: true },
            "peer 8's first reject warns independently of peer 7"
        );
    }
}
