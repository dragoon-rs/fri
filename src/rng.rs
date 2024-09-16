//! Related to random things
use std::mem::size_of;

use ark_ff::Field;
use derive_more::AsRef;
use derive_where::derive_where;
use rs_merkle::Hasher;

/// A seed-based pseudo-random number generator.
pub trait ReseedableRng {
    type Seed;

    /// Sets the seed to be used in future calls to [`Self::next_bytes`].
    fn reseed(&mut self, seed: Self::Seed);
    /// Generates a pseudo-random value using the provided closure. The size of the slice passed to the closure
    /// is implementation-dependent.
    ///
    /// This method should also update the state of the object, such that subsequent calls may produce
    /// seemingly unrelated (and unpredictable) values.
    fn next_bytes<T, F>(&mut self, f: F) -> T
    where
        F: FnOnce(&[u8]) -> T;

    /// Draws a pseudo-random number from field `F`. This does not need to be overriden.
    ///
    /// # Panics
    /// This panics if this object is not able to draw a random value from this field.
    fn draw_alpha<F: Field>(&mut self) -> F {
        // This has never failed during tests, but this should be tested with other fields.
        loop {
            if let Some(alpha) = self.next_bytes(|bytes| F::from_random_bytes(bytes)) {
                return alpha;
            }
        }
    }

    /// Draws a [`Vec`] of `count` positions, each of them being strictly less than `domain_size`.
    /// This does not need to be overriden.
    ///
    /// `domain_size` must be a power of two; otherwise, the result is unspecified
    /// (the implementation may either return incorrect positions or panic).
    fn draw_positions(&mut self, count: usize, domain_size: usize) -> Vec<usize> {
        debug_assert!(
            domain_size.is_power_of_two(),
            "Domain size must be a power of two"
        );

        let mask = domain_size - 1;
        let mut positions = Vec::with_capacity(count);
        for _ in 0..count {
            let number = self.next_bytes(|bytes| {
                usize::from_le_bytes(bytes[0..size_of::<usize>()].try_into().unwrap())
            });
            positions.push(number & mask);
        }
        positions
    }
}

/// This struct is designed to be used as the pseudo-random number generator in the
/// non-interactive version of FRI.
///
/// # Example
/// ```ignore
/// use fri::{algorithms::Blake3, rng::{FriChallenger, ReseedableRng}};
///
/// let mut challenger = FriChallenger::<Blake3>::default();
///
/// // For each FRI layer:
/// challenger.reseed(/* FRI commitment */);
/// let alpha = challenger.draw_alpha();
/// ```
#[derive_where(Clone, PartialEq;)]
#[derive_where(Debug; H::Hash)]
pub struct FriChallenger<H: Hasher> {
    seed: H::Hash,
    counter: usize,
}

impl<H: Hasher> Default for FriChallenger<H> {
    fn default() -> Self {
        Self {
            seed: H::hash(&[]),
            counter: 0,
        }
    }
}

impl<H: Hasher> ReseedableRng for FriChallenger<H>
where
    H::Hash: AsRef<[u8]>,
{
    type Seed = H::Hash;

    fn reseed(&mut self, seed: Self::Seed) {
        self.seed = H::concat_and_hash(&self.seed, Some(&seed));
        self.counter = 0;
    }
    fn next_bytes<T, F>(&mut self, f: F) -> T
    where
        F: FnOnce(&[u8]) -> T,
    {
        self.counter += 1;
        let hash = H::concat_and_hash(&self.seed, Some(&H::hash(&self.counter.to_le_bytes())));
        f(hash.as_ref())
    }
}

impl<H: Hasher> FriChallenger<H> {
    /// Resets this object to its initial state.
    ///
    /// # Example
    /// ```rust
    /// use rs_merkle::Hasher;
    /// use fri::{algorithms::Blake3, rng::{FriChallenger, ReseedableRng}};
    ///
    /// let mut challenger1 = FriChallenger::<Blake3>::default();
    ///
    /// challenger1.reseed(Blake3::hash(&[5]));
    /// let hash1 = challenger1.next_bytes(|bytes| bytes.to_vec());
    ///
    /// challenger1.reset();
    /// let hash2 = challenger1.next_bytes(|bytes| bytes.to_vec());
    ///
    /// let mut challenger2 = FriChallenger::<Blake3>::default();
    /// let hash3 = challenger2.next_bytes(|bytes| bytes.to_vec());
    ///
    /// assert_ne!(hash1, hash2);
    /// assert_eq!(hash2, hash3);
    /// ```
    pub fn reset(&mut self) {
        self.seed = H::hash(&[]);
        self.counter = 0;
    }
}

/// A wrapper for a [`ReseedableRng`] that memorizes the last drawn positions.
///
/// Use [`MemoryRng::default`] to wrap the default value of `R` and [`MemoryRng::from`] to wrap an already
/// existing `R`.
///
/// Call [`MemoryRng::into_inner`] to forget the last drawn positions and return ownership of the underlying `R`.
#[derive(AsRef, Default, Clone, PartialEq, Eq, Debug)]
pub struct MemoryRng<R> {
    #[as_ref]
    inner: R,
    last_positions: Vec<usize>,
}

impl<R> From<R> for MemoryRng<R> {
    fn from(value: R) -> Self {
        Self {
            inner: value,
            last_positions: vec![],
        }
    }
}

impl<R: ReseedableRng> ReseedableRng for MemoryRng<R> {
    type Seed = R::Seed;

    fn reseed(&mut self, seed: Self::Seed) {
        self.inner.reseed(seed);
    }
    fn next_bytes<T, F>(&mut self, f: F) -> T
    where
        F: FnOnce(&[u8]) -> T,
    {
        self.inner.next_bytes(f)
    }
    fn draw_positions(&mut self, count: usize, domain_size: usize) -> Vec<usize> {
        self.last_positions = self.inner.draw_positions(count, domain_size);
        self.last_positions.clone()
    }
}

impl<R> MemoryRng<R> {
    /// Returns the last positions drawn with [`MemoryRng::draw_positions`].
    /// If [`MemoryRng::draw_positions`] has not been called yet, this returns an empty slice.
    ///
    /// This cannot return positions drawn by the underlying `R` before it was wrapped by this [`MemoryRng`].
    pub fn last_positions(&self) -> &[usize] {
        &self.last_positions
    }
    /// Same as [`MemoryRng::last_positions`] but returns a mutable reference.
    pub fn last_positions_mut(&mut self) -> &mut Vec<usize> {
        &mut self.last_positions
    }
    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<'a, R> ReseedableRng for &'a mut R
where
    R: ReseedableRng + ?Sized,
{
    type Seed = R::Seed;

    fn reseed(&mut self, seed: Self::Seed) {
        (**self).reseed(seed);
    }
    fn next_bytes<T, F>(&mut self, f: F) -> T
    where
        F: FnOnce(&[u8]) -> T,
    {
        (**self).next_bytes(f)
    }

    fn draw_alpha<F: Field>(&mut self) -> F {
        (**self).draw_alpha()
    }
    fn draw_positions(&mut self, count: usize, domain_size: usize) -> Vec<usize> {
        (**self).draw_positions(count, domain_size)
    }
}
