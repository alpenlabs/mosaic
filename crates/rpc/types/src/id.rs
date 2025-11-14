//! Identifiers.

use serde::{Deserialize, Serialize};

macro_rules! gen_id_inst {
    (
        $docstring:literal
        $name:ident => $inner:ty
    ) => {
        #[derive(
            Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd, Deserialize, Serialize,
        )]
        #[doc = $docstring]
        pub struct $name($inner);

        impl $name {
            /// Constructs a new instance.
            pub fn new(v: $inner) -> Self {
                Self::from(v)
            }

            /// Gets a ref to the inner value.
            pub fn inner(&self) -> &$inner {
                &self.0
            }
        }

        impl From<$inner> for $name {
            fn from(v: $inner) -> Self {
                Self(v)
            }
        }

        impl From<$name> for $inner {
            fn from(v: $name) -> Self {
                v.0
            }
        }
    };
}

gen_id_inst!(
    "Job identifier"
    JobId => u64
);

gen_id_inst!(
    "Tableset identifier"
    TablesetId => u64
);
