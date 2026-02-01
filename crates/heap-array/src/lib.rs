//! A heap-allocated fixed-size array that avoids stack allocation during construction.
//!
//! This crate provides [`HeapArray<T, N>`], a type that behaves like `Box<[T; N]>` but
//! constructs elements directly on the heap via a `Vec`, avoiding LLVM optimization
//! issues that can occur with large fixed-size arrays on the stack.

use std::ops::{Deref, DerefMut, Index, IndexMut};
use std::slice::SliceIndex;

use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, Read, SerializationError, Valid, Validate,
    Write,
};

/// A heap-allocated array of `N` elements of type `T`.
///
/// This type is similar to `Box<[T; N]>`, but constructs elements via a `Vec`
/// to avoid stack allocation and LLVM optimization issues with large arrays.
///
/// # Example
///
/// ```
/// use mosaic_heap_array::HeapArray;
///
/// let arr: HeapArray<u64, 100> = HeapArray::new(|i| i as u64 * 2);
/// assert_eq!(arr[0], 0);
/// assert_eq!(arr[50], 100);
/// assert_eq!(arr.len(), 100);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HeapArray<T, const N: usize> {
    inner: Box<[T; N]>,
}

impl<T, const N: usize> HeapArray<T, N> {
    /// Creates a new `HeapArray` by calling `f` for each index `0..N`.
    ///
    /// The closure receives the index and should return the element for that position.
    ///
    /// # Example
    ///
    /// ```
    /// use mosaic_heap_array::HeapArray;
    ///
    /// let squares: HeapArray<i32, 10> = HeapArray::new(|i| (i * i) as i32);
    /// assert_eq!(squares[3], 9);
    /// ```
    #[inline]
    pub fn new<F>(f: F) -> Self
    where
        F: FnMut(usize) -> T,
    {
        let vec: Vec<T> = (0..N).map(f).collect();
        Self::from_vec(vec)
    }

    /// Creates a new `HeapArray` from an existing `Vec<T>`.
    ///
    /// # Panics
    ///
    /// Panics if `vec.len() != N`.
    #[inline]
    pub fn from_vec(vec: Vec<T>) -> Self {
        assert_eq!(
            vec.len(),
            N,
            "HeapArray::from_vec: expected {} elements, got {}",
            N,
            vec.len()
        );

        let boxed_slice = vec.into_boxed_slice();
        // SAFETY: We verified that the slice has exactly N elements.
        let boxed_array = unsafe { Box::from_raw(Box::into_raw(boxed_slice) as *mut [T; N]) };

        Self { inner: boxed_array }
    }

    /// Creates a new `HeapArray` from an existing `Vec<T>`, returning `None` if
    /// the length doesn't match.
    #[inline]
    pub fn try_from_vec(vec: Vec<T>) -> Option<Self> {
        if vec.len() != N {
            return None;
        }

        let boxed_slice = vec.into_boxed_slice();
        // SAFETY: We verified that the slice has exactly N elements.
        let boxed_array = unsafe { Box::from_raw(Box::into_raw(boxed_slice) as *mut [T; N]) };

        Some(Self { inner: boxed_array })
    }

    /// Returns the number of elements in the array.
    #[inline]
    pub const fn len(&self) -> usize {
        N
    }

    /// Returns `true` if the array has no elements (i.e., `N == 0`).
    #[inline]
    pub const fn is_empty(&self) -> bool {
        N == 0
    }

    /// Consumes the `HeapArray` and returns the underlying `Box<[T; N]>`.
    #[inline]
    pub fn into_boxed_array(self) -> Box<[T; N]> {
        self.inner
    }

    /// Consumes the `HeapArray` and returns the elements as a `Vec<T>`.
    #[inline]
    pub fn into_vec(self) -> Vec<T> {
        let boxed_slice: Box<[T]> = self.inner;
        boxed_slice.into_vec()
    }

    /// Returns a slice containing the entire array.
    #[inline]
    pub fn as_slice(&self) -> &[T] {
        &*self.inner
    }

    /// Returns a mutable slice containing the entire array.
    #[inline]
    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut *self.inner
    }

    /// Returns an iterator over references to the elements.
    #[inline]
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.inner.iter()
    }

    /// Returns an iterator over mutable references to the elements.
    #[inline]
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, T> {
        self.inner.iter_mut()
    }
}

impl<T: Default, const N: usize> Default for HeapArray<T, N> {
    #[inline]
    fn default() -> Self {
        Self::new(|_| T::default())
    }
}

impl<T: Clone, const N: usize> HeapArray<T, N> {
    /// Creates a new `HeapArray` where every element is a clone of `value`.
    #[inline]
    pub fn from_elem(value: T) -> Self {
        Self::from_vec(vec![value; N])
    }
}

impl<T, const N: usize> Deref for HeapArray<T, N> {
    type Target = [T; N];

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T, const N: usize> DerefMut for HeapArray<T, N> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<T, I, const N: usize> Index<I> for HeapArray<T, N>
where
    I: SliceIndex<[T]>,
{
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        &self.inner[index]
    }
}

impl<T, I, const N: usize> IndexMut<I> for HeapArray<T, N>
where
    I: SliceIndex<[T]>,
{
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        &mut self.inner[index]
    }
}

impl<T, const N: usize> AsRef<[T; N]> for HeapArray<T, N> {
    #[inline]
    fn as_ref(&self) -> &[T; N] {
        &self.inner
    }
}

impl<T, const N: usize> AsMut<[T; N]> for HeapArray<T, N> {
    #[inline]
    fn as_mut(&mut self) -> &mut [T; N] {
        &mut self.inner
    }
}

impl<T, const N: usize> AsRef<[T]> for HeapArray<T, N> {
    #[inline]
    fn as_ref(&self) -> &[T] {
        &*self.inner
    }
}

impl<T, const N: usize> AsMut<[T]> for HeapArray<T, N> {
    #[inline]
    fn as_mut(&mut self) -> &mut [T] {
        &mut *self.inner
    }
}

impl<T, const N: usize> From<Box<[T; N]>> for HeapArray<T, N> {
    #[inline]
    fn from(boxed: Box<[T; N]>) -> Self {
        Self { inner: boxed }
    }
}

impl<T, const N: usize> From<HeapArray<T, N>> for Box<[T; N]> {
    #[inline]
    fn from(arr: HeapArray<T, N>) -> Self {
        arr.inner
    }
}

impl<T, const N: usize> From<HeapArray<T, N>> for Vec<T> {
    #[inline]
    fn from(arr: HeapArray<T, N>) -> Self {
        arr.into_vec()
    }
}

impl<T, const N: usize> IntoIterator for HeapArray<T, N> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.into_vec().into_iter()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a HeapArray<T, N> {
    type Item = &'a T;
    type IntoIter = std::slice::Iter<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T, const N: usize> IntoIterator for &'a mut HeapArray<T, N> {
    type Item = &'a mut T;
    type IntoIter = std::slice::IterMut<'a, T>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

// ============================================================================
// ark-serialize implementations
// ============================================================================

impl<T: CanonicalSerialize, const N: usize> CanonicalSerialize for HeapArray<T, N> {
    fn serialize_with_mode<W: Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.as_slice().serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.as_slice().serialized_size(compress)
    }
}

impl<T: CanonicalDeserialize, const N: usize> CanonicalDeserialize for HeapArray<T, N> {
    fn deserialize_with_mode<R: Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let vec = Vec::<T>::deserialize_with_mode(reader, compress, validate)?;
        Self::try_from_vec(vec).ok_or(SerializationError::InvalidData)
    }
}

impl<T: Valid, const N: usize> Valid for HeapArray<T, N> {
    fn check(&self) -> Result<(), SerializationError> {
        for item in self.iter() {
            item.check()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let arr: HeapArray<i32, 5> = HeapArray::new(|i| i as i32 * 10);
        assert_eq!(arr[0], 0);
        assert_eq!(arr[1], 10);
        assert_eq!(arr[4], 40);
        assert_eq!(arr.len(), 5);
    }

    #[test]
    fn test_from_elem() {
        let arr: HeapArray<String, 3> = HeapArray::from_elem("hello".to_string());
        assert_eq!(arr[0], "hello");
        assert_eq!(arr[1], "hello");
        assert_eq!(arr[2], "hello");
    }

    #[test]
    fn test_default() {
        let arr: HeapArray<i32, 4> = HeapArray::default();
        assert_eq!(arr.as_slice(), &[0, 0, 0, 0]);
    }

    #[test]
    fn test_from_vec() {
        let vec = vec![1, 2, 3, 4, 5];
        let arr: HeapArray<i32, 5> = HeapArray::from_vec(vec);
        assert_eq!(arr.as_slice(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_try_from_vec() {
        let vec = vec![1, 2, 3];
        let arr: Option<HeapArray<i32, 3>> = HeapArray::try_from_vec(vec);
        assert!(arr.is_some());

        let vec = vec![1, 2, 3];
        let arr: Option<HeapArray<i32, 5>> = HeapArray::try_from_vec(vec);
        assert!(arr.is_none());
    }

    #[test]
    fn test_into_vec() {
        let arr: HeapArray<i32, 3> = HeapArray::new(|i| i as i32);
        let vec = arr.into_vec();
        assert_eq!(vec, vec![0, 1, 2]);
    }

    #[test]
    fn test_iter() {
        let arr: HeapArray<i32, 3> = HeapArray::new(|i| i as i32 + 1);
        let sum: i32 = arr.iter().sum();
        assert_eq!(sum, 6);
    }

    #[test]
    fn test_into_iter() {
        let arr: HeapArray<i32, 3> = HeapArray::new(|i| i as i32 + 1);
        let collected: Vec<i32> = arr.into_iter().collect();
        assert_eq!(collected, vec![1, 2, 3]);
    }

    #[test]
    fn test_deref() {
        let arr: HeapArray<i32, 3> = HeapArray::new(|i| i as i32);
        let slice: &[i32; 3] = &*arr;
        assert_eq!(slice, &[0, 1, 2]);
    }

    #[test]
    fn test_empty_array() {
        let arr: HeapArray<i32, 0> = HeapArray::new(|_| unreachable!());
        assert!(arr.is_empty());
        assert_eq!(arr.len(), 0);
    }

    #[test]
    fn test_large_array() {
        // This should not cause stack overflow
        let arr: HeapArray<u8, 10_000_000> = HeapArray::new(|i| (i % 256) as u8);
        assert_eq!(arr.len(), 10_000_000);
        assert_eq!(arr[0], 0);
        assert_eq!(arr[255], 255);
        assert_eq!(arr[256], 0);
    }
}
