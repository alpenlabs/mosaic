use serde::{Deserialize, Serialize};

use crate::HeapArray;

impl<T: Serialize, const N: usize> Serialize for HeapArray<T, N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(N))?;
        for item in self.iter() {
            seq.serialize_element(item)?;
        }
        seq.end()
    }
}

impl<'de, T: Deserialize<'de>, const N: usize> Deserialize<'de> for HeapArray<T, N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct HeapArrayVisitor<T, const N: usize>(std::marker::PhantomData<T>);

        impl<'de, T: Deserialize<'de>, const N: usize> serde::de::Visitor<'de> for HeapArrayVisitor<T, N> {
            type Value = HeapArray<T, N>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(formatter, "a sequence of {} elements", N)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut vec = Vec::with_capacity(N);
                for i in 0..N {
                    match seq.next_element()? {
                        Some(value) => vec.push(value),
                        None => {
                            return Err(serde::de::Error::invalid_length(i, &self));
                        }
                    }
                }

                // Ensure there are no extra elements
                if seq.next_element::<T>()?.is_some() {
                    return Err(serde::de::Error::custom(format!(
                        "expected {} elements, but found more",
                        N
                    )));
                }

                HeapArray::try_from_vec(vec)
                    .ok_or_else(|| serde::de::Error::custom("internal error: vec length mismatch"))
            }
        }

        deserializer.deserialize_seq(HeapArrayVisitor(std::marker::PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_roundtrip() {
        let arr: HeapArray<i32, 5> = HeapArray::new(|i| i as i32 * 10);

        let encoded = postcard::to_allocvec(&arr).unwrap();
        let decoded: HeapArray<i32, 5> = postcard::from_bytes(&encoded).unwrap();

        assert_eq!(arr, decoded);
    }

    #[test]
    fn test_serde_string_array() {
        let arr: HeapArray<String, 3> = HeapArray::new(|i| format!("item_{}", i));

        let encoded = postcard::to_allocvec(&arr).unwrap();
        let decoded: HeapArray<String, 3> = postcard::from_bytes(&encoded).unwrap();

        assert_eq!(arr, decoded);
    }

    #[test]
    fn test_serde_wrong_length_too_few() {
        // Create array with 3 elements and try to deserialize as array with 5 elements
        let arr: HeapArray<i32, 3> = HeapArray::new(|i| i as i32);
        let encoded = postcard::to_allocvec(&arr).unwrap();
        let result: Result<HeapArray<i32, 5>, _> = postcard::from_bytes(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_serde_wrong_length_too_many() {
        // Create array with 5 elements and try to deserialize as array with 3 elements
        let arr: HeapArray<i32, 5> = HeapArray::new(|i| i as i32);
        let encoded = postcard::to_allocvec(&arr).unwrap();
        let result: Result<HeapArray<i32, 3>, _> = postcard::from_bytes(&encoded);
        assert!(result.is_err());
    }

    #[test]
    fn test_serde_empty_array() {
        let arr: HeapArray<i32, 0> = HeapArray::new(|_| unreachable!());

        let encoded = postcard::to_allocvec(&arr).unwrap();
        let decoded: HeapArray<i32, 0> = postcard::from_bytes(&encoded).unwrap();

        assert_eq!(arr, decoded);
    }
}
