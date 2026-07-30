//! Job priority levels — re-exported from `mosaic-job-api`.
//!
//! The enum lives in the API crate so [`PendingCircuitJob`] can carry it
//! into the garbling coordinator; scheduler-internal code keeps using
//! `crate::priority::Priority`.
//!
//! [`PendingCircuitJob`]: mosaic_job_api::PendingCircuitJob

pub(crate) use mosaic_job_api::Priority;
