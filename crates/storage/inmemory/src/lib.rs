//! In-memory implementation for state machine states

pub mod error;
pub mod evaluator;
pub mod garbler;
/// In-memory storage provider and mutable session handles.
pub mod provider;

pub use provider::InMemoryStorageProvider;

#[cfg(test)]
mod garbler_tests {
    use super::InMemoryStorageProvider;

    mosaic_storage_api::garbler_store_tests!(InMemoryStorageProvider::new());
}

#[cfg(test)]
mod evaluator_tests {
    use super::InMemoryStorageProvider;

    mosaic_storage_api::evaluator_store_tests!(InMemoryStorageProvider::new());
}
