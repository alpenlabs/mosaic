//! Job store implementation for SQLite.

use std::time::{SystemTime, UNIX_EPOCH};

use mosaic_db_types::{DbResult, JobExecState, JobFilter, JobId, JobRecord, JobStore};
use rusqlite::{params, Connection};

use crate::error::SqliteError;
use crate::SqliteDatabase;

impl JobStore for SqliteDatabase {
    fn create_job(&self, job_type: &str, config: &[u8]) -> DbResult<JobId> {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;
        let now = current_timestamp();

        conn.execute(
            "INSERT INTO jobs (job_type, state, config, created_at, updated_at, completed_units, total_units)
             VALUES (?1, ?2, ?3, ?4, ?5, 0, 0)",
            params![job_type, state_to_str(JobExecState::Created), config, now, now],
        )
        .map_err(SqliteError::from)?;

        let id = conn.last_insert_rowid() as u64;
        Ok(JobId(id))
    }

    fn get_job(&self, id: JobId) -> DbResult<Option<JobRecord>> {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;
        get_job_impl(&conn, id).map_err(Into::into)
    }

    fn update_job_state(&self, id: JobId, state: JobExecState) -> DbResult<()> {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;
        let now = current_timestamp();

        conn.execute(
            "UPDATE jobs SET state = ?1, updated_at = ?2 WHERE id = ?3",
            params![state_to_str(state), now, id.0],
        )
        .map_err(SqliteError::from)?;

        Ok(())
    }

    fn update_job_progress(&self, id: JobId, completed: u64, total: u64) -> DbResult<()> {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;
        let now = current_timestamp();

        conn.execute(
            "UPDATE jobs SET completed_units = ?1, total_units = ?2, updated_at = ?3 WHERE id = ?4",
            params![completed, total, now, id.0],
        )
        .map_err(SqliteError::from)?;

        Ok(())
    }

    fn set_job_error(&self, id: JobId, error: &str) -> DbResult<()> {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;
        let now = current_timestamp();

        conn.execute(
            "UPDATE jobs SET error_message = ?1, updated_at = ?2 WHERE id = ?3",
            params![error, now, id.0],
        )
        .map_err(SqliteError::from)?;

        Ok(())
    }

    fn list_jobs(&self, filter: &JobFilter) -> DbResult<Vec<JobRecord>> {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;
        list_jobs_impl(&conn, filter).map_err(Into::into)
    }

    fn list_pending_jobs(&self) -> DbResult<Vec<JobRecord>> {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;

        let mut stmt = conn
            .prepare(
                "SELECT id, job_type, state, config, created_at, updated_at,
                        completed_units, total_units, error_message
                 FROM jobs
                 WHERE state IN (?1, ?2)
                 ORDER BY created_at ASC",
            )
            .map_err(SqliteError::from)?;

        let rows = stmt
            .query_map(
                params![
                    state_to_str(JobExecState::Created),
                    state_to_str(JobExecState::Running)
                ],
                row_to_job_record,
            )
            .map_err(SqliteError::from)?;

        let mut jobs = Vec::new();
        for row in rows {
            jobs.push(row.map_err(SqliteError::from)?);
        }

        Ok(jobs)
    }

    fn delete_job(&self, id: JobId) -> DbResult<()> {
        let conn = self.conn.lock().map_err(|_| SqliteError::Poisoned)?;

        conn.execute("DELETE FROM jobs WHERE id = ?1", params![id.0])
            .map_err(SqliteError::from)?;

        Ok(())
    }
}

fn get_job_impl(conn: &Connection, id: JobId) -> Result<Option<JobRecord>, SqliteError> {
    let mut stmt = conn.prepare(
        "SELECT id, job_type, state, config, created_at, updated_at,
                completed_units, total_units, error_message
         FROM jobs WHERE id = ?1",
    )?;

    let result = stmt.query_row(params![id.0], row_to_job_record);

    match result {
        Ok(record) => Ok(Some(record)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

fn list_jobs_impl(conn: &Connection, filter: &JobFilter) -> Result<Vec<JobRecord>, SqliteError> {
    let mut sql = String::from(
        "SELECT id, job_type, state, config, created_at, updated_at,
                completed_units, total_units, error_message
         FROM jobs WHERE 1=1",
    );

    let mut params_vec: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if let Some(state) = &filter.state {
        sql.push_str(" AND state = ?");
        params_vec.push(Box::new(state_to_str(*state).to_string()));
    }

    if let Some(job_type) = &filter.job_type {
        sql.push_str(" AND job_type = ?");
        params_vec.push(Box::new(job_type.clone()));
    }

    sql.push_str(" ORDER BY created_at DESC");

    if let Some(limit) = filter.limit {
        sql.push_str(&format!(" LIMIT {}", limit));
    }

    let mut stmt = conn.prepare(&sql)?;
    let params_refs: Vec<&dyn rusqlite::ToSql> = params_vec.iter().map(|p| p.as_ref()).collect();

    let rows = stmt.query_map(params_refs.as_slice(), row_to_job_record)?;

    let mut jobs = Vec::new();
    for row in rows {
        jobs.push(row?);
    }

    Ok(jobs)
}

fn row_to_job_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<JobRecord> {
    Ok(JobRecord {
        id: JobId(row.get::<_, i64>(0)? as u64),
        job_type: row.get(1)?,
        state: str_to_state(&row.get::<_, String>(2)?),
        config: row.get(3)?,
        created_at: row.get(4)?,
        updated_at: row.get(5)?,
        completed_units: row.get::<_, i64>(6)? as u64,
        total_units: row.get::<_, i64>(7)? as u64,
        error_message: row.get(8)?,
    })
}

fn state_to_str(state: JobExecState) -> &'static str {
    match state {
        JobExecState::Created => "created",
        JobExecState::Running => "running",
        JobExecState::Finished => "finished",
        JobExecState::Failed => "failed",
    }
}

fn str_to_state(s: &str) -> JobExecState {
    match s {
        "created" => JobExecState::Created,
        "running" => JobExecState::Running,
        "finished" => JobExecState::Finished,
        "failed" => JobExecState::Failed,
        _ => JobExecState::Failed, // Default to failed for unknown states
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
    fn test_create_and_get_job() {
        let db = test_db();
        let config = b"test config".to_vec();

        let id = db.create_job("test_job", &config).unwrap();
        let job = db.get_job(id).unwrap().unwrap();

        assert_eq!(job.id, id);
        assert_eq!(job.job_type, "test_job");
        assert_eq!(job.state, JobExecState::Created);
        assert_eq!(job.config, config);
        assert_eq!(job.completed_units, 0);
        assert_eq!(job.total_units, 0);
        assert!(job.error_message.is_none());
    }

    #[test]
    fn test_update_job_state() {
        let db = test_db();
        let id = db.create_job("test_job", b"config").unwrap();

        db.update_job_state(id, JobExecState::Running).unwrap();
        let job = db.get_job(id).unwrap().unwrap();
        assert_eq!(job.state, JobExecState::Running);

        db.update_job_state(id, JobExecState::Finished).unwrap();
        let job = db.get_job(id).unwrap().unwrap();
        assert_eq!(job.state, JobExecState::Finished);
    }

    #[test]
    fn test_update_job_progress() {
        let db = test_db();
        let id = db.create_job("test_job", b"config").unwrap();

        db.update_job_progress(id, 50, 100).unwrap();
        let job = db.get_job(id).unwrap().unwrap();
        assert_eq!(job.completed_units, 50);
        assert_eq!(job.total_units, 100);
    }

    #[test]
    fn test_set_job_error() {
        let db = test_db();
        let id = db.create_job("test_job", b"config").unwrap();

        db.set_job_error(id, "something went wrong").unwrap();
        let job = db.get_job(id).unwrap().unwrap();
        assert_eq!(job.error_message, Some("something went wrong".to_string()));
    }

    #[test]
    fn test_list_pending_jobs() {
        let db = test_db();

        let id1 = db.create_job("job1", b"config1").unwrap();
        let id2 = db.create_job("job2", b"config2").unwrap();
        let id3 = db.create_job("job3", b"config3").unwrap();

        db.update_job_state(id2, JobExecState::Running).unwrap();
        db.update_job_state(id3, JobExecState::Finished).unwrap();

        let pending = db.list_pending_jobs().unwrap();
        assert_eq!(pending.len(), 2);

        let pending_ids: Vec<JobId> = pending.iter().map(|j| j.id).collect();
        assert!(pending_ids.contains(&id1));
        assert!(pending_ids.contains(&id2));
        assert!(!pending_ids.contains(&id3));
    }

    #[test]
    fn test_list_jobs_with_filter() {
        let db = test_db();

        db.create_job("type_a", b"config1").unwrap();
        db.create_job("type_b", b"config2").unwrap();
        db.create_job("type_a", b"config3").unwrap();

        let filter = JobFilter::new().with_job_type("type_a");
        let jobs = db.list_jobs(&filter).unwrap();
        assert_eq!(jobs.len(), 2);
        assert!(jobs.iter().all(|j| j.job_type == "type_a"));
    }

    #[test]
    fn test_delete_job() {
        let db = test_db();
        let id = db.create_job("test_job", b"config").unwrap();

        assert!(db.get_job(id).unwrap().is_some());
        db.delete_job(id).unwrap();
        assert!(db.get_job(id).unwrap().is_none());
    }

    #[test]
    fn test_get_nonexistent_job() {
        let db = test_db();
        let result = db.get_job(JobId(9999)).unwrap();
        assert!(result.is_none());
    }
}
