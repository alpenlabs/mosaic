//! Snapshot store implementation for SQLite.

use std::time::{SystemTime, UNIX_EPOCH};

use mosaic_db_types::{DbResult, SnapshotStore};
use rusqlite::params;

use crate::error::SqliteError;
use crate::SqliteDatabase;

impl SnapshotStore for SqliteDatabase {
    fn save_snapshot(&self, key: &str, step: u64, data: &[u8]) -> DbResult<()> {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;
        let now = current_timestamp();

        conn.execute(
            "INSERT INTO snapshots (key, step, data, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(key, step) DO UPDATE SET
                data = excluded.data,
                created_at = excluded.created_at",
            params![key, step as i64, data, now],
        )
        .map_err(SqliteError::from)?;

        Ok(())
    }

    fn load_latest_snapshot(&self, key: &str) -> DbResult<Option<(u64, Vec<u8>)>> {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;

        let result: Result<(i64, Vec<u8>), _> = conn.query_row(
            "SELECT step, data FROM snapshots WHERE key = ?1 ORDER BY step DESC LIMIT 1",
            params![key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        );

        match result {
            Ok((step, data)) => Ok(Some((step as u64, data))),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(SqliteError::from(e).into()),
        }
    }

    fn load_snapshot(&self, key: &str, step: u64) -> DbResult<Option<Vec<u8>>> {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;

        let result: Result<Vec<u8>, _> = conn.query_row(
            "SELECT data FROM snapshots WHERE key = ?1 AND step = ?2",
            params![key, step as i64],
            |row| row.get(0),
        );

        match result {
            Ok(data) => Ok(Some(data)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(SqliteError::from(e).into()),
        }
    }

    fn delete_snapshots(&self, key: &str) -> DbResult<()> {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;

        conn.execute("DELETE FROM snapshots WHERE key = ?1", params![key])
            .map_err(SqliteError::from)?;

        Ok(())
    }

    fn delete_snapshots_before(&self, key: &str, step: u64) -> DbResult<()> {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;

        conn.execute(
            "DELETE FROM snapshots WHERE key = ?1 AND step < ?2",
            params![key, step as i64],
        )
        .map_err(SqliteError::from)?;

        Ok(())
    }
}

fn current_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SqliteDatabase;

    fn test_db() -> SqliteDatabase {
        SqliteDatabase::open_in_memory().unwrap()
    }

    #[test]
    fn test_save_and_load_snapshot() {
        let db = test_db();
        let data = b"snapshot data".to_vec();

        db.save_snapshot("job1", 5, &data).unwrap();
        let loaded = db.load_snapshot("job1", 5).unwrap();

        assert_eq!(loaded, Some(data));
    }

    #[test]
    fn test_load_nonexistent_snapshot() {
        let db = test_db();
        let loaded = db.load_snapshot("nonexistent", 0).unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_load_latest_snapshot() {
        let db = test_db();

        db.save_snapshot("job1", 1, b"data1").unwrap();
        db.save_snapshot("job1", 5, b"data5").unwrap();
        db.save_snapshot("job1", 3, b"data3").unwrap();

        let (step, data) = db.load_latest_snapshot("job1").unwrap().unwrap();
        assert_eq!(step, 5);
        assert_eq!(data, b"data5".to_vec());
    }

    #[test]
    fn test_load_latest_snapshot_empty() {
        let db = test_db();
        let result = db.load_latest_snapshot("nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_overwrite_snapshot() {
        let db = test_db();

        db.save_snapshot("job1", 5, b"old data").unwrap();
        db.save_snapshot("job1", 5, b"new data").unwrap();

        let loaded = db.load_snapshot("job1", 5).unwrap();
        assert_eq!(loaded, Some(b"new data".to_vec()));
    }

    #[test]
    fn test_delete_snapshots() {
        let db = test_db();

        db.save_snapshot("job1", 1, b"data1").unwrap();
        db.save_snapshot("job1", 2, b"data2").unwrap();
        db.save_snapshot("job2", 1, b"other").unwrap();

        db.delete_snapshots("job1").unwrap();

        assert!(db.load_snapshot("job1", 1).unwrap().is_none());
        assert!(db.load_snapshot("job1", 2).unwrap().is_none());
        assert!(db.load_snapshot("job2", 1).unwrap().is_some());
    }

    #[test]
    fn test_delete_snapshots_before() {
        let db = test_db();

        db.save_snapshot("job1", 1, b"data1").unwrap();
        db.save_snapshot("job1", 5, b"data5").unwrap();
        db.save_snapshot("job1", 10, b"data10").unwrap();

        db.delete_snapshots_before("job1", 6).unwrap();

        assert!(db.load_snapshot("job1", 1).unwrap().is_none());
        assert!(db.load_snapshot("job1", 5).unwrap().is_none());
        assert!(db.load_snapshot("job1", 10).unwrap().is_some());
    }

    #[test]
    fn test_multiple_keys() {
        let db = test_db();

        db.save_snapshot("job1", 1, b"job1-data").unwrap();
        db.save_snapshot("job2", 1, b"job2-data").unwrap();

        let job1_data = db.load_snapshot("job1", 1).unwrap();
        let job2_data = db.load_snapshot("job2", 1).unwrap();

        assert_eq!(job1_data, Some(b"job1-data".to_vec()));
        assert_eq!(job2_data, Some(b"job2-data".to_vec()));
    }
}
