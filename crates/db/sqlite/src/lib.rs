//! SQLite database implementation for Mosaic.
//!
//! This crate provides a SQLite-backed implementation of the database traits
//! defined in `mosaic-db-types`. It uses a single connection protected by a
//! mutex for thread-safe access.
//!
//! # Example
//!
//! ```no_run
//! use mosaic_db_sqlite::SqliteDatabase;
//! use mosaic_db_types::{JobStore, JobFilter};
//!
//! let db = SqliteDatabase::open("mosaic.db").unwrap();
//!
//! // Create a job
//! let job_id = db.create_job("table_generation", b"config").unwrap();
//!
//! // Query jobs
//! let pending = db.list_pending_jobs().unwrap();
//! ```

mod error;
mod jobs;
mod schema;
mod snapshots;
mod state_machines;

use std::path::Path;
use std::sync::Mutex;

use rusqlite::Connection;

pub use error::{SqliteError, SqliteResult};

/// SQLite database implementation.
///
/// This struct provides thread-safe access to a SQLite database through
/// a mutex-protected connection. All trait implementations acquire the
/// lock before performing operations.
#[derive(Debug)]
pub struct SqliteDatabase {
    conn: Mutex<Connection>,
}

impl SqliteDatabase {
    /// Open a database at the given path.
    ///
    /// Creates the database file and initializes the schema if it doesn't exist.
    pub fn open<P: AsRef<Path>>(path: P) -> SqliteResult<Self> {
        let conn = Connection::open(path)?;
        Self::init_connection(conn)
    }

    /// Open an in-memory database.
    ///
    /// Useful for testing. The database is lost when the connection is closed.
    pub fn open_in_memory() -> SqliteResult<Self> {
        let conn = Connection::open_in_memory()?;
        Self::init_connection(conn)
    }

    /// Initialize a connection with the schema.
    fn init_connection(conn: Connection) -> SqliteResult<Self> {
        // Enable foreign keys and WAL mode for better concurrency
        conn.execute_batch(
            "PRAGMA foreign_keys = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;",
        )?;

        // Initialize schema
        schema::init_schema(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Execute a closure with the database connection.
    ///
    /// This is useful for operations that need direct access to the connection,
    /// such as custom queries or batch operations.
    pub fn with_connection<F, T>(&self, f: F) -> SqliteResult<T>
    where
        F: FnOnce(&Connection) -> SqliteResult<T>,
    {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;
        f(&conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mosaic_db_types::{JobStore, SnapshotStore, StateMachineStore};

    #[test]
    fn test_open_in_memory() {
        let db = SqliteDatabase::open_in_memory().unwrap();

        // Verify we can use all the stores
        let _job_id = db.create_job("test", b"config").unwrap();
        db.save_snapshot("test", 0, b"data").unwrap();
        db.save_state("machine", &42u32).unwrap();
    }

    #[test]
    fn test_open_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.db");

        {
            let db = SqliteDatabase::open(&path).unwrap();
            db.create_job("test", b"config").unwrap();
        }

        // Re-open and verify data persists
        {
            let db = SqliteDatabase::open(&path).unwrap();
            let jobs = db.list_pending_jobs().unwrap();
            assert_eq!(jobs.len(), 1);
        }
    }

    #[test]
    fn test_with_connection() {
        let db = SqliteDatabase::open_in_memory().unwrap();

        let count: i64 = db
            .with_connection(|conn| {
                conn.query_row("SELECT COUNT(*) FROM jobs", [], |row| row.get(0))
                    .map_err(SqliteError::from)
            })
            .unwrap();

        assert_eq!(count, 0);
    }
}
