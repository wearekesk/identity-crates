//! A simple generic pair (2-tuple) type.

/// A pair of two values of potentially different types.
///
/// # Examples
/// ```
/// use dmrtd::types::pair::Pair;
/// let p = Pair::new(1u8, "hello");
/// assert_eq!(p.first, 1u8);
/// assert_eq!(p.second, "hello");
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Pair<T1, T2> {
    /// The first element of the pair.
    pub first: T1,
    /// The second element of the pair.
    pub second: T2,
}

impl<T1, T2> Pair<T1, T2> {
    /// Creates a new [`Pair`] from `first` and `second`.
    pub fn new(first: T1, second: T2) -> Self {
        Self { first, second }
    }
}

impl<T1, T2> From<(T1, T2)> for Pair<T1, T2> {
    fn from((first, second): (T1, T2)) -> Self {
        Self { first, second }
    }
}

impl<T1, T2> From<Pair<T1, T2>> for (T1, T2) {
    fn from(pair: Pair<T1, T2>) -> Self {
        (pair.first, pair.second)
    }
}
