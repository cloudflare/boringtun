/// Check that the size of type `T` is `size`. If not, panic.
///
/// Returns `size` for convenience.
pub const fn size_must_be<T>(size: usize) -> usize {
    if size_of::<T>() == size {
        size
    } else {
        panic!("Size of T is wrong!")
    }
}
