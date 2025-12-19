//! CaC protocol type definitions.
//!
//! This is for types that the bridge client might end up using, so we want to
//! expose in the RPC interface.  These are defined separately from the main CaC
//! types crate because those are more internally-focused that the bridge client
//! won't be expected to use.

#![allow(
    missing_docs,
    reason = "these as standins that we'll define properly at a future time"
)]

// random standin defs that we'll define more concretely later

mod bytes;
mod commit;
mod export;
mod game;
mod id;
mod reveal;

pub use bytes::*;
pub use commit::*;
pub use export::*;
pub use game::*;
pub use id::*;
pub use reveal::*;
