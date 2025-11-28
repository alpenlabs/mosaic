//! SQLite-specific error types.

use mosaic_db_types::DbError;
use thiserror::Error;

/// SQLite-specific errors.
#[derive(Debug, Error)]
pub enum SqliteError {
    /// A rusqlite error occurred.
    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// JSON serialization/deserialization error.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// The database connection is poisoned (mutex was held during panic).
    #[error("database connection poisoned")]
    Poisoned,
}

/// Result type for SQLite operations.
pub type SqliteResult<T> = Result<T, SqliteError>;

impl From<SqliteError> for DbError {
    fn from(err: SqliteError) -> Self {
        match err {
            SqliteError::Sqlite(e) => {
                // Map rusqlite errors to appropriate DbError variants
                match e {
                    rusqlite::Error::QueryReturnedNoRows => {
                        DbError::NotFound("no rows returned".to_string())
                    }
                    rusqlite::Error::SqliteFailure(err, msg) => {
                        let detail = msg.unwrap_or_else(|| err.to_string());
                        if err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
                            || err.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_PRIMARYKEY
                        {
                            DbError::ConstraintViolation(detail)
                        } else {
                            DbError::Internal(detail)
                        }
                    }
                    _ => DbError::Internal(e.to_string()),
                }
            }
            SqliteError::Json(e) => DbError::Serialization(e.to_string()),
            SqliteError::Poisoned => DbError::Connection("connection poisoned".to_string()),
        }
    }
}
