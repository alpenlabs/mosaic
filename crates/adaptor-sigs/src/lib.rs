//! Mosaic adaptor signatures library.

mod adaptor;
mod error;
mod fixed_base;

pub use adaptor::{Adaptor, Signature, deserialize_field, serialize_field};
pub use error::Error;
