//! Boxed array utils

use std::{alloc::alloc_zeroed, mem::MaybeUninit};

/// Initialize a large fixed-size array directly on the heap, avoiding stack overflow.
///
/// The closure receives each index and a mutable reference to uninitialized memory,
/// which must be written to using [`MaybeUninit::write`].
///
/// # Safety Contract
///
/// The caller **must** write to every slot via [`MaybeUninit::write`]. Failing to
/// initialize a slot results in undefined behavior when the array is accessed.
///
/// # Panic Safety
///
/// If the initializer panics, all previously completed elements (from earlier iterations)
/// are properly dropped. However, if the closure panics *after* calling `slot.write()`
/// but before returning, that element will leak. For simple closures that only call
/// `slot.write(value)` without additional logic, this is not a concern.
///
/// # Examples
///
/// 1D array:
/// ```
/// use common::array::init_in_place;
///
/// let arr: Box<[u64; 1000]> = init_in_place(|i, slot| {
///     slot.write(i as u64 * 2);
/// });
/// assert_eq!(arr[0], 0);
/// assert_eq!(arr[999], 1998);
/// ```
///
/// 2D array (no intermediate stack allocation):
/// ```
/// use common::array::{init_in_place, uninit_array_mut};
///
/// let arr: Box<[[u64; 50]; 100]> = init_in_place(|i, slot| {
///     for (j, inner) in uninit_array_mut(slot).iter_mut().enumerate() {
///         inner.write((i * 50 + j) as u64);
///     }
/// });
/// assert_eq!(arr[2][3], 103);
/// ```
///
/// 3D array:
/// ```
/// use common::array::{init_in_place, uninit_array_mut};
///
/// let arr: Box<[[[u64; 10]; 50]; 100]> = init_in_place(|i, slot| {
///     for (j, middle) in uninit_array_mut(slot).iter_mut().enumerate() {
///         for (k, inner) in uninit_array_mut(middle).iter_mut().enumerate() {
///             inner.write((i * 500 + j * 10 + k) as u64);
///         }
///     }
/// });
/// assert_eq!(arr[1][2][3], 523);
/// ```
pub fn init_in_place<V, const N: usize, F>(mut init: F) -> Box<[V; N]>
where
    F: FnMut(usize, &mut MaybeUninit<V>),
{
    let mut b: Box<MaybeUninit<[V; N]>> = Box::new_uninit();
    let p: *mut V = b.as_mut_ptr().cast();

    let mut initialized = 0usize;

    let guard = DropGuard {
        ptr: p,
        initialized: &mut initialized,
    };

    // SAFETY:
    // - `p.add(idx)` is valid for idx in 0..N since p points to a contiguous [V; N]
    // - Casting to `*mut MaybeUninit<V>` is valid since V and MaybeUninit<V> have same layout
    // - `assume_init()` is sound because caller contract requires all slots to be initialized
    // - If `init` panics, DropGuard cleans up already-initialized elements
    unsafe {
        for idx in 0..N {
            let slot = &mut *(p.add(idx) as *mut MaybeUninit<V>);
            init(idx, slot);
            *guard.initialized += 1;
        }
        std::mem::forget(guard); // Success, don't drop
        b.assume_init()
    }
}

// Guard to drop initialized elements on panic
struct DropGuard<'a, V> {
    ptr: *mut V,
    initialized: &'a mut usize,
}

impl<V> Drop for DropGuard<'_, V> {
    fn drop(&mut self) {
        // SAFETY:
        // - Only called on panic; `initialized` tracks how many elements were written
        // - `self.ptr.add(i)` is valid for i < initialized since they're contiguous
        // - Each element at i < initialized has been fully initialized by the closure
        unsafe {
            for i in 0..*self.initialized {
                self.ptr.add(i).drop_in_place();
            }
        }
    }
}

/// Reinterpret `MaybeUninit<[T; N]>` as `[MaybeUninit<T>; N]` for element-wise initialization.
///
/// This is useful for initializing nested arrays without intermediate stack allocations.
///
/// # Safety Contract
///
/// The caller **must** write to every element in the returned slice. Leaving any
/// element uninitialized and then using the parent array results in undefined behavior.
#[inline]
pub fn uninit_array_mut<T, const N: usize>(
    slot: &mut MaybeUninit<[T; N]>,
) -> &mut [MaybeUninit<T>; N] {
    // SAFETY: MaybeUninit<[T; N]> and [MaybeUninit<T>; N] have the same layout
    unsafe { &mut *(slot.as_mut_ptr() as *mut [MaybeUninit<T>; N]) }
}
