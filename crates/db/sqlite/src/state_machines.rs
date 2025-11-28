//! State machine store implementation for SQLite.

use std::time::{SystemTime, UNIX_EPOCH};

use mosaic_db_types::{DbResult, StateMachineStore};
use rusqlite::params;
use serde::{de::DeserializeOwned, Serialize};

use crate::error::SqliteError;
use crate::SqliteDatabase;

impl StateMachineStore for SqliteDatabase {
    fn save_state<S: Serialize>(&self, machine_id: &str, state: &S) -> DbResult<()> {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;
        let now = current_timestamp();
        let state_data = serde_json::to_vec(state).map_err(SqliteError::from)?;

        conn.execute(
            "INSERT INTO state_machines (machine_id, state_data, updated_at)
             VALUES (?1, ?2, ?3)
             ON CONFLICT(machine_id) DO UPDATE SET
                state_data = excluded.state_data,
                updated_at = excluded.updated_at",
            params![machine_id, state_data, now],
        )
        .map_err(SqliteError::from)?;

        Ok(())
    }

    fn load_state<S: DeserializeOwned>(&self, machine_id: &str) -> DbResult<Option<S>> {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;

        let result: Result<Vec<u8>, _> = conn.query_row(
            "SELECT state_data FROM state_machines WHERE machine_id = ?1",
            params![machine_id],
            |row| row.get(0),
        );

        match result {
            Ok(data) => {
                let state = serde_json::from_slice(&data).map_err(SqliteError::from)?;
                Ok(Some(state))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(SqliteError::from(e).into()),
        }
    }

    fn save_pending_actions(&self, machine_id: &str, actions: &[u8]) -> DbResult<()> {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;
        let now = current_timestamp();

        // First ensure the machine exists
        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM state_machines WHERE machine_id = ?1",
                params![machine_id],
                |_| Ok(true),
            )
            .unwrap_or(false);

        if exists {
            conn.execute(
                "UPDATE state_machines SET pending_actions = ?1, updated_at = ?2 WHERE machine_id = ?3",
                params![actions, now, machine_id],
            )
            .map_err(SqliteError::from)?;
        } else {
            // Create a placeholder state machine entry
            conn.execute(
                "INSERT INTO state_machines (machine_id, state_data, pending_actions, updated_at)
                 VALUES (?1, ?2, ?3, ?4)",
                params![machine_id, b"null", actions, now],
            )
            .map_err(SqliteError::from)?;
        }

        Ok(())
    }

    fn load_pending_actions(&self, machine_id: &str) -> DbResult<Option<Vec<u8>>> {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;

        let result: Result<Option<Vec<u8>>, _> = conn.query_row(
            "SELECT pending_actions FROM state_machines WHERE machine_id = ?1",
            params![machine_id],
            |row| row.get(0),
        );

        match result {
            Ok(data) => Ok(data),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(SqliteError::from(e).into()),
        }
    }

    fn clear_pending_actions(&self, machine_id: &str) -> DbResult<()> {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;
        let now = current_timestamp();

        conn.execute(
            "UPDATE state_machines SET pending_actions = NULL, updated_at = ?1 WHERE machine_id = ?2",
            params![now, machine_id],
        )
        .map_err(SqliteError::from)?;

        Ok(())
    }

    fn delete_machine(&self, machine_id: &str) -> DbResult<()> {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;

        conn.execute(
            "DELETE FROM state_machines WHERE machine_id = ?1",
            params![machine_id],
        )
        .map_err(SqliteError::from)?;

        Ok(())
    }

    fn machine_exists(&self, machine_id: &str) -> DbResult<bool> {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;

        let exists: bool = conn
            .query_row(
                "SELECT 1 FROM state_machines WHERE machine_id = ?1",
                params![machine_id],
                |_| Ok(true),
            )
            .unwrap_or(false);

        Ok(exists)
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
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    struct TestState {
        counter: u32,
        name: String,
    }

    fn test_db() -> SqliteDatabase {
        SqliteDatabase::open_in_memory().unwrap()
    }

    #[test]
    fn test_save_and_load_state() {
        let db = test_db();
        let state = TestState {
            counter: 42,
            name: "test".to_string(),
        };

        db.save_state("machine1", &state).unwrap();
        let loaded: Option<TestState> = db.load_state("machine1").unwrap();

        assert_eq!(loaded, Some(state));
    }

    #[test]
    fn test_load_nonexistent_state() {
        let db = test_db();
        let loaded: Option<TestState> = db.load_state("nonexistent").unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_overwrite_state() {
        let db = test_db();

        let state1 = TestState {
            counter: 1,
            name: "first".to_string(),
        };
        let state2 = TestState {
            counter: 2,
            name: "second".to_string(),
        };

        db.save_state("machine1", &state1).unwrap();
        db.save_state("machine1", &state2).unwrap();

        let loaded: Option<TestState> = db.load_state("machine1").unwrap();
        assert_eq!(loaded, Some(state2));
    }

    #[test]
    fn test_pending_actions() {
        let db = test_db();
        let state = TestState {
            counter: 1,
            name: "test".to_string(),
        };
        let actions = b"pending action data".to_vec();

        // First save state
        db.save_state("machine1", &state).unwrap();

        // Save pending actions
        db.save_pending_actions("machine1", &actions).unwrap();

        // Load pending actions
        let loaded = db.load_pending_actions("machine1").unwrap();
        assert_eq!(loaded, Some(actions));

        // Clear pending actions
        db.clear_pending_actions("machine1").unwrap();
        let loaded = db.load_pending_actions("machine1").unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_pending_actions_without_state() {
        let db = test_db();
        let actions = b"pending action data".to_vec();

        // Save pending actions without saving state first
        db.save_pending_actions("machine1", &actions).unwrap();

        // Should still be loadable
        let loaded = db.load_pending_actions("machine1").unwrap();
        assert_eq!(loaded, Some(actions));
    }

    #[test]
    fn test_delete_machine() {
        let db = test_db();
        let state = TestState {
            counter: 1,
            name: "test".to_string(),
        };

        db.save_state("machine1", &state).unwrap();
        assert!(db.machine_exists("machine1").unwrap());

        db.delete_machine("machine1").unwrap();
        assert!(!db.machine_exists("machine1").unwrap());

        let loaded: Option<TestState> = db.load_state("machine1").unwrap();
        assert!(loaded.is_none());
    }

    #[test]
    fn test_machine_exists() {
        let db = test_db();

        assert!(!db.machine_exists("machine1").unwrap());

        let state = TestState {
            counter: 1,
            name: "test".to_string(),
        };
        db.save_state("machine1", &state).unwrap();

        assert!(db.machine_exists("machine1").unwrap());
    }
}
