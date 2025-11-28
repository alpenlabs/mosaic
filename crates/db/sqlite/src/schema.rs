//! Database schema and migrations.

use rusqlite::Connection;

use crate::error::SqliteResult;

/// Current schema version.
pub(crate) const SCHEMA_VERSION: u32 = 1;

/// Initialize the database schema.
///
/// Creates all tables if they don't exist and runs any pending migrations.
pub(crate) fn init_schema(conn: &Connection) -> SqliteResult<()> {
    // Check current schema version
    let current_version = get_schema_version(conn)?;

    if current_version == 0 {
        // Fresh database, create all tables
        create_tables(conn)?;
        set_schema_version(conn, SCHEMA_VERSION)?;
    } else if current_version < SCHEMA_VERSION {
        // Run migrations
        migrate(conn, current_version)?;
    }

    Ok(())
}

/// Get the current schema version.
fn get_schema_version(conn: &Connection) -> SqliteResult<u32> {
    // Create schema_version table if it doesn't exist
    conn.execute(
        "CREATE TABLE IF NOT EXISTS schema_version (
            version INTEGER NOT NULL
        )",
        [],
    )?;

    let version: Option<u32> = conn
        .query_row("SELECT version FROM schema_version LIMIT 1", [], |row| {
            row.get(0)
        })
        .ok();

    Ok(version.unwrap_or(0))
}

/// Set the schema version.
fn set_schema_version(conn: &Connection, version: u32) -> SqliteResult<()> {
    conn.execute("DELETE FROM schema_version", [])?;
    conn.execute("INSERT INTO schema_version (version) VALUES (?1)", [version])?;
    Ok(())
}

/// Create all database tables.
fn create_tables(conn: &Connection) -> SqliteResult<()> {
    // Jobs table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS jobs (
            id INTEGER PRIMARY KEY,
            job_type TEXT NOT NULL,
            state TEXT NOT NULL,
            config BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            completed_units INTEGER NOT NULL DEFAULT 0,
            total_units INTEGER NOT NULL DEFAULT 0,
            error_message TEXT
        )",
        [],
    )?;

    // State machines table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS state_machines (
            machine_id TEXT PRIMARY KEY,
            state_data BLOB NOT NULL,
            pending_actions BLOB,
            updated_at INTEGER NOT NULL
        )",
        [],
    )?;

    // Snapshots table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS snapshots (
            key TEXT NOT NULL,
            step INTEGER NOT NULL,
            data BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (key, step)
        )",
        [],
    )?;

    // Create indexes
    conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(state)", [])?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_jobs_type ON jobs(job_type)",
        [],
    )?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_snapshots_key ON snapshots(key)",
        [],
    )?;

    Ok(())
}

/// Run migrations from the given version to the current version.
fn migrate(conn: &Connection, _from_version: u32) -> SqliteResult<()> {
    // No migrations yet - this is version 1
    // Future migrations would be handled here:
    //
    // if from_version < 2 {
    //     migrate_to_v2(conn)?;
    // }
    // if from_version < 3 {
    //     migrate_to_v3(conn)?;
    // }

    set_schema_version(conn, SCHEMA_VERSION)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_schema() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();

        // Verify tables exist
        let tables: Vec<String> = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
            .unwrap()
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert!(tables.contains(&"jobs".to_string()));
        assert!(tables.contains(&"state_machines".to_string()));
        assert!(tables.contains(&"snapshots".to_string()));
        assert!(tables.contains(&"schema_version".to_string()));
    }

    #[test]
    fn test_schema_version() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();

        let version = get_schema_version(&conn).unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }

    #[test]
    fn test_idempotent_init() {
        let conn = Connection::open_in_memory().unwrap();
        init_schema(&conn).unwrap();
        init_schema(&conn).unwrap(); // Should not fail

        let version = get_schema_version(&conn).unwrap();
        assert_eq!(version, SCHEMA_VERSION);
    }
}
