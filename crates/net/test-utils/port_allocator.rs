//! Cross-process localhost UDP port allocator for integration tests.
//!
//! Why this exists:
//! - `cargo test` usually runs many tests in one process.
//! - `nextest` can run tests in multiple processes.
//! - A process-local `AtomicU16` counter isn't safe across processes.
//!
//! This allocator uses a lock file + state file in the system temp dir so all
//! test processes draw ports from one sequence per namespace/range.

use std::{
    fs,
    io::{self, ErrorKind},
    net::{Ipv4Addr, SocketAddrV4, UdpSocket},
    path::{Path, PathBuf},
    thread,
    time::{Duration, SystemTime},
};

const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(2);
const STALE_LOCK_AFTER: Duration = Duration::from_secs(30);

/// Allocate the next UDP port in `[range_start, range_end]` for `namespace`.
///
/// The namespace should be stable per test suite (for example: `"net-client"`).
pub(crate) fn next_port(namespace: &str, range_start: u16, range_end: u16) -> io::Result<u16> {
    if range_start > range_end {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!(
                "invalid port range: start {} > end {}",
                range_start, range_end
            ),
        ));
    }

    let span = usize::from(range_end - range_start) + 1;
    if span == 0 {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "invalid empty port range",
        ));
    }

    let root = allocator_root_dir()?;
    let state_path = root.join(format!(
        "{}-{}-{}.state",
        sanitize(namespace),
        range_start,
        range_end
    ));
    let lock_path = root.join(format!(
        "{}-{}-{}.lock",
        sanitize(namespace),
        range_start,
        range_end
    ));

    with_file_lock(&lock_path, || {
        let mut candidate = read_next_candidate(&state_path, range_start, range_end)?;
        for _ in 0..span {
            if udp_port_available(candidate) {
                let next = increment(candidate, range_start, range_end);
                write_next_candidate(&state_path, next)?;
                return Ok(candidate);
            }
            candidate = increment(candidate, range_start, range_end);
        }

        Err(io::Error::new(
            ErrorKind::AddrNotAvailable,
            format!(
                "no free UDP ports in range {}..={} for namespace {}",
                range_start, range_end, namespace
            ),
        ))
    })
}

fn allocator_root_dir() -> io::Result<PathBuf> {
    let dir = std::env::temp_dir().join("mosaic-test-port-allocator-v1");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn sanitize(namespace: &str) -> String {
    namespace
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn with_file_lock<T>(lock_path: &Path, f: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    let lock_file = loop {
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(lock_path)
        {
            Ok(file) => break file,
            Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                maybe_remove_stale_lock(lock_path);
                thread::sleep(LOCK_POLL_INTERVAL);
            }
            Err(err) => return Err(err),
        }
    };

    let result = f();
    drop(lock_file);
    let _ = fs::remove_file(lock_path);
    result
}

fn maybe_remove_stale_lock(lock_path: &Path) {
    let modified = fs::metadata(lock_path).and_then(|m| m.modified());
    let is_stale = match modified {
        Ok(t) => SystemTime::now()
            .duration_since(t)
            .map(|age| age >= STALE_LOCK_AFTER)
            .unwrap_or(false),
        Err(_) => false,
    };

    if is_stale {
        let _ = fs::remove_file(lock_path);
    }
}

fn read_next_candidate(path: &Path, range_start: u16, range_end: u16) -> io::Result<u16> {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(range_start),
        Err(err) => return Err(err),
    };

    let parsed = match content.trim().parse::<u16>() {
        Ok(port) => port,
        Err(_) => return Ok(range_start),
    };

    if (range_start..=range_end).contains(&parsed) {
        Ok(parsed)
    } else {
        Ok(range_start)
    }
}

fn write_next_candidate(path: &Path, next: u16) -> io::Result<()> {
    let tmp_path = path.with_extension("state.tmp");
    fs::write(&tmp_path, format!("{next}\n"))?;
    fs::rename(tmp_path, path)?;
    Ok(())
}

fn increment(port: u16, range_start: u16, range_end: u16) -> u16 {
    if port >= range_end {
        range_start
    } else {
        port + 1
    }
}

fn udp_port_available(port: u16) -> bool {
    let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    UdpSocket::bind(addr).is_ok()
}
