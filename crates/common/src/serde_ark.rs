//! Macro for implementing serde Serialize/Deserialize using ark-serialize.
//!
//! This module provides a macro to implement serde's `Serialize` and `Deserialize`
//! traits for types that implement arkworks' `CanonicalSerialize` and
//! `CanonicalDeserialize`, using compressed serialization.

/// Re-export of serde for use by the `impl_serde_ark!` macro.
///
/// This re-export is required so that types using the macro don't need to
/// explicitly import serde themselves. The macro references serde types through
/// `$crate::serde_ark::serde`, which resolves to this re-export.
pub use serde;
/// Implements serde `Serialize` and `Deserialize` for a type using ark-serialize.
///
/// This macro generates implementations that bridge serde's serialization with
/// arkworks' canonical serialization, using compressed mode for efficiency.
///
/// # Requirements
///
/// The type must implement:
/// - `ark_serialize::CanonicalSerialize`
/// - `ark_serialize::CanonicalDeserialize`
///
/// # Example
///
/// ```ignore
/// use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
///
/// #[derive(CanonicalSerialize, CanonicalDeserialize)]
/// struct MyFieldElement {
///     // ... fields ...
/// }
///
/// impl_serde_ark!(MyFieldElement);
/// ```
#[macro_export]
macro_rules! impl_serde_ark {
    ($type:ty) => {
        impl $crate::serde_ark::serde::Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: $crate::serde_ark::serde::Serializer,
            {
                use ark_serialize::{CanonicalSerialize, Compress};
                use $crate::serde_ark::serde::ser::Error;

                let mut bytes = Vec::with_capacity(self.serialized_size(Compress::Yes));
                self.serialize_with_mode(&mut bytes, Compress::Yes)
                    .map_err(|e| S::Error::custom(format!("ark serialization failed: {}", e)))?;

                serializer.serialize_bytes(&bytes)
            }
        }

        impl<'de> $crate::serde_ark::serde::Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: $crate::serde_ark::serde::Deserializer<'de>,
            {
                use ark_serialize::{CanonicalDeserialize, Compress, Validate};
                use $crate::serde_ark::serde::de::Error;

                let bytes: Vec<u8> =
                    $crate::serde_ark::serde::Deserialize::deserialize(deserializer)?;
                <$type>::deserialize_with_mode(&bytes[..], Compress::Yes, Validate::Yes)
                    .map_err(|e| D::Error::custom(format!("ark deserialization failed: {}", e)))
            }
        }
    };
}
