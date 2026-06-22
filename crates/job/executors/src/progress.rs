//! Heartbeat progress logging for long-running garbling phases.
//!
//! Long phases like table upload (G8) and table evaluation (E8) can each
//! take minutes. Without periodic logs, operators can't tell whether a node
//! is making progress or wedged.
//!
//! [`HeartbeatTracker`] emits one `INFO` line per [`HEARTBEAT_PERIOD`]
//! interval at the call site's choosing — no spawned timer, no shared
//! state. Call sites tick `maybe_log` per chunk/block; the tracker prints
//! only when enough time has elapsed since the last print.
//!
//! Logs are emitted on the `mosaic_progress` tracing target — operators can
//! grep that string to surface only progress lines, or filter via
//! `RUST_LOG=mosaic_progress=info`.

use std::time::{Duration, Instant};

/// Default interval between heartbeat log emissions.
pub const HEARTBEAT_PERIOD: Duration = Duration::from_secs(30);

/// The thing being counted on the wire — bytes get rate + eta formatting;
/// blocks get percent + elapsed only.
#[derive(Copy, Clone, Debug)]
pub enum ProgressUnit {
    /// Counter is bytes — output includes throughput (`inst`, `avg`) and ETA.
    Bytes,
    /// Counter is opaque units (typically blocks) — output is percent + elapsed only.
    Blocks,
}

/// Tracks progress through a long-running phase and emits periodic INFO
/// heartbeat logs.
///
/// Created at the start of a phase; `maybe_log` is called per chunk with
/// the cumulative-progress count. `done` emits a final summary line.
#[derive(Debug)]
pub struct HeartbeatTracker {
    label: &'static str,
    short_id: String,
    total: Option<u64>,
    unit: ProgressUnit,
    started_at: Instant,
    last_log_at: Instant,
    last_log_progress: u64,
    period: Duration,
}

impl HeartbeatTracker {
    /// Create a new tracker.
    ///
    /// `label` is the phase name printed in the log (e.g. `"table.upload"`).
    /// `short_id` is a stable identifier the caller chose for this work item
    /// (e.g. a commitment short-hash, or a circuit index).
    /// `total` is the expected final count if known; `None` suppresses
    /// percent/ETA in the output. `period` is the minimum interval between
    /// emissions; pass [`HEARTBEAT_PERIOD`] for the default.
    pub fn new(
        label: &'static str,
        short_id: String,
        total: Option<u64>,
        unit: ProgressUnit,
        period: Duration,
    ) -> Self {
        let now = Instant::now();
        Self {
            label,
            short_id,
            total,
            unit,
            started_at: now,
            last_log_at: now,
            last_log_progress: 0,
            period,
        }
    }

    /// If [`HEARTBEAT_PERIOD`] has elapsed since the last log (or since
    /// construction), emit an INFO heartbeat. Cheap on the not-yet-time path.
    pub fn maybe_log(&mut self, current: u64) {
        let now = Instant::now();
        if now.duration_since(self.last_log_at) < self.period {
            return;
        }
        self.emit(current, now, /* final = */ false);
        self.last_log_at = now;
        self.last_log_progress = current;
    }

    /// Emit a final summary line. Always logs regardless of last_log_at.
    pub fn done(&mut self, current: u64) {
        let now = Instant::now();
        self.emit(current, now, /* final = */ true);
    }

    fn emit(&mut self, current: u64, now: Instant, is_final: bool) {
        let elapsed = now.duration_since(self.started_at);
        let interval = now.duration_since(self.last_log_at);
        let delta = current.saturating_sub(self.last_log_progress);

        let avg_rate = (current as f64) / elapsed.as_secs_f64().max(1e-3);
        let inst_rate = (delta as f64) / interval.as_secs_f64().max(1e-3);

        let pct = self
            .total
            .filter(|t| *t > 0)
            .map(|t| (current as f64) * 100.0 / (t as f64));

        let event_label = if is_final { "summary" } else { "progress" };

        match self.unit {
            ProgressUnit::Bytes => {
                let done_str = match self.total {
                    Some(t) => format!("{}/{}", fmt_bytes(current), fmt_bytes(t)),
                    None => fmt_bytes(current),
                };
                let pct_str = pct.map(|p| format!(" pct={p:.1}%")).unwrap_or_default();
                let eta_str = match (self.total, inst_rate) {
                    (Some(t), r) if r > 0.0 && t > current => {
                        let remaining = (t - current) as f64 / r;
                        format!(" eta={}", fmt_duration(Duration::from_secs_f64(remaining)))
                    }
                    _ => String::new(),
                };
                tracing::info!(
                    target: "mosaic_progress",
                    phase = self.label,
                    id = %self.short_id,
                    "{} {} id={} done={}{} inst={}/s avg={}/s elapsed={}{}",
                    self.label,
                    event_label,
                    self.short_id,
                    done_str,
                    pct_str,
                    fmt_rate(inst_rate),
                    fmt_rate(avg_rate),
                    fmt_duration(elapsed),
                    eta_str,
                );
            }
            ProgressUnit::Blocks => {
                let pct_str = match pct {
                    Some(p) => format!(" pct=~{p:.0}%"),
                    None => String::new(),
                };
                tracing::info!(
                    target: "mosaic_progress",
                    phase = self.label,
                    id = %self.short_id,
                    "{} {} id={}{} elapsed={}",
                    self.label,
                    event_label,
                    self.short_id,
                    pct_str,
                    fmt_duration(elapsed),
                );
            }
        }
    }
}

fn fmt_bytes(n: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * KIB;
    const GIB: f64 = 1024.0 * MIB;
    const TIB: f64 = 1024.0 * GIB;
    let v = n as f64;
    if v >= TIB {
        format!("{:.1}TiB", v / TIB)
    } else if v >= GIB {
        format!("{:.1}GiB", v / GIB)
    } else if v >= MIB {
        format!("{:.1}MiB", v / MIB)
    } else if v >= KIB {
        format!("{:.1}KiB", v / KIB)
    } else {
        format!("{n}B")
    }
}

fn fmt_rate(bytes_per_sec: f64) -> String {
    const KB: f64 = 1_000.0;
    const MB: f64 = 1_000_000.0;
    const GB: f64 = 1_000_000_000.0;
    if bytes_per_sec >= GB {
        format!("{:.1}GB", bytes_per_sec / GB)
    } else if bytes_per_sec >= MB {
        format!("{:.0}MB", bytes_per_sec / MB)
    } else if bytes_per_sec >= KB {
        format!("{:.0}KB", bytes_per_sec / KB)
    } else {
        format!("{:.0}B", bytes_per_sec)
    }
}

fn fmt_duration(d: Duration) -> String {
    let total = d.as_secs();
    let h = total / 3600;
    let m = (total % 3600) / 60;
    let s = total % 60;
    if h > 0 {
        format!("{h}h{m:02}m")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_bytes_units() {
        assert_eq!(fmt_bytes(500), "500B");
        assert_eq!(fmt_bytes(2048), "2.0KiB");
        assert_eq!(fmt_bytes(2 * 1024 * 1024), "2.0MiB");
        assert_eq!(
            fmt_bytes(3 * 1024 * 1024 * 1024 + 500 * 1024 * 1024),
            "3.5GiB"
        );
    }

    #[test]
    fn fmt_rate_units() {
        assert_eq!(fmt_rate(500.0), "500B");
        assert_eq!(fmt_rate(50_000.0), "50KB");
        assert_eq!(fmt_rate(51_000_000.0), "51MB");
    }

    #[test]
    fn fmt_duration_units() {
        assert_eq!(fmt_duration(Duration::from_secs(5)), "5s");
        assert_eq!(fmt_duration(Duration::from_secs(125)), "2m05s");
        assert_eq!(fmt_duration(Duration::from_secs(3_600 + 600 + 45)), "1h10m");
    }

    #[test]
    fn maybe_log_respects_period() {
        // Tracker with a 60s period; immediate maybe_log shouldn't emit
        // (period not elapsed), so last_log_at stays unchanged.
        let mut t = HeartbeatTracker::new(
            "test",
            "0x01".to_string(),
            Some(1_000),
            ProgressUnit::Bytes,
            Duration::from_secs(60),
        );
        let last_before = t.last_log_at;
        t.maybe_log(100);
        assert_eq!(t.last_log_at, last_before);
        assert_eq!(t.last_log_progress, 0);
    }

    #[test]
    fn maybe_log_emits_after_period_elapsed() {
        // Sub-millisecond period + a short sleep guarantees we cross it.
        let mut t = HeartbeatTracker::new(
            "test",
            "0x01".to_string(),
            Some(1_000),
            ProgressUnit::Bytes,
            Duration::from_micros(100),
        );
        let last_before = t.last_log_at;
        std::thread::sleep(Duration::from_millis(2));
        t.maybe_log(250);
        assert!(
            t.last_log_at > last_before,
            "last_log_at should advance after the period elapses"
        );
        assert_eq!(t.last_log_progress, 250);
    }
}
