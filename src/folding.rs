use std::{
    borrow::{Borrow, Cow},
    ops::{Deref, Index},
};

use ark_ff::FftField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};

use crate::{utils::horner_evaluate, AssertPowerOfTwo};

/// An owned view over folded evaluations.
/// `N` is the folding factor. It should be a power of two.
///
/// It implements [`Deref`] to [`FoldedEvaluationsSlice`], meaning that all the methods
/// on [`FoldedEvaluationsSlice`] are available on `FoldedEvaluations` as well.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FoldedEvaluations<const N: usize, F>(Vec<F>);

impl<const N: usize, F> FoldedEvaluations<N, F> {
    /// Folds `evaluations` of a polynomial, in such a way that the `N` evaluations necessary
    /// to compute the `i`th evaluation in the next FRI layer are gathered into cell `i`.
    ///
    /// This allocates a new vector.
    ///
    /// `evaluations` is the evaluations of the polynomial on the `n`^th roots of unity, where `n` is the
    /// len of `evaluations`. If `w` is `F::get_root_of_unity(n).unwrap()`, then `evaluations[i]` is the
    /// evaluation at `w^i`.
    ///
    /// See [https://eprint.iacr.org/2022/1216.pdf].
    ///
    /// # Panics
    /// This may either panic or have unspecified behaviour if `N` is not a power of two or
    /// `evaluations.len()` is not a multiple of `N`.
    pub fn new(evaluations: &[F]) -> Self
    where
        F: Clone,
    {
        Self::check_slice(evaluations);

        let bound = evaluations.len() / N;
        let mut folded = Vec::with_capacity(evaluations.len());
        for i in 0..bound {
            folded.extend(evaluations.iter().skip(i).step_by(bound).cloned());
        }

        Self::from_flat_evaluations_unchecked(folded)
    }
    /// Returns the underlying, flattened vector.
    ///
    /// It contains evaluations such that the items necessary to compute the `i`th evaluation
    /// in the next FRI layer are at `N*i..N*(i+1)`.
    ///
    /// This vector can **not** be used as-is as the input of [`crate::utils::to_polynomial`] or other functions
    /// that expect ordered evaluations over the roots of unity.
    #[inline]
    pub fn into_flat_evaluations(self) -> Vec<F> {
        self.0
    }
    /// Wraps a flatten vector of folded evaluations.
    ///
    /// `evaluations` should be the return value of [`Self::into_flat_evaluations`].
    ///
    /// # Panics
    /// This may either panic or have unspecified behaviour if `N` is not a power of two or
    /// `evaluations.len()` is not a multiple of `N`.
    ///
    /// When debug assertions are disabled, this is currently equivalent to
    /// [`Self::from_flat_evaluations_unchecked`], but this may change in the future.
    #[inline]
    pub fn from_flat_evaluations(evaluations: Vec<F>) -> Self {
        Self::check_slice(&evaluations);
        Self(evaluations)
    }
    /// Same as [`Self::from_flat_evaluations`], but does not panic.
    ///
    /// `Self::from_flat_evaluations_unchecked(folded_evaluations.into_flat_evaluations())` is a no-op.
    ///
    /// It is incorrect to call this method if `N` is not a power of two or
    /// `evaluations.len()` is not a multiple of `N`, but this won't cause undefined behaviour.
    #[inline]
    pub fn from_flat_evaluations_unchecked(evaluations: Vec<F>) -> Self {
        Self(evaluations)
    }

    /// When debug assertions are enabled, panics if `evaluations.len() % N != 0`.
    /// When debug assertions are disabled, this is a no-op.
    #[inline]
    fn check_slice(evaluations: &[F]) {
        debug_assert!(
            evaluations.len() % N == 0,
            "Domain size must be a multiple of `N`"
        );
    }
}

/* #region delegates to `FoldedEvaluationsSlice` */

impl<const N: usize, F> Deref for FoldedEvaluations<N, F> {
    type Target = FoldedEvaluationsSlice<N, F>;
    #[inline]
    fn deref(&self) -> &Self::Target {
        FoldedEvaluationsSlice::from_flat_evaluations_unchecked(&self.0)
    }
}
impl<const N: usize, F> Borrow<FoldedEvaluationsSlice<N, F>> for FoldedEvaluations<N, F> {
    #[inline]
    fn borrow(&self) -> &FoldedEvaluationsSlice<N, F> {
        self
    }
}
impl<const N: usize, F> AsRef<FoldedEvaluationsSlice<N, F>> for FoldedEvaluations<N, F> {
    #[inline]
    fn as_ref(&self) -> &FoldedEvaluationsSlice<N, F> {
        self
    }
}

impl<const N: usize, F, R: ?Sized> AsRef<R> for FoldedEvaluations<N, F>
where
    FoldedEvaluationsSlice<N, F>: AsRef<R>,
{
    #[inline]
    fn as_ref(&self) -> &R {
        (**self).as_ref()
    }
}

impl<'a, const N: usize, F> IntoIterator for &'a FoldedEvaluations<N, F> {
    type Item = <&'a FoldedEvaluationsSlice<N, F> as IntoIterator>::Item;
    type IntoIter = <&'a FoldedEvaluationsSlice<N, F> as IntoIterator>::IntoIter;
    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        (**self).into_iter()
    }
}

/* #endregion */

/// A borrowed view over folded evaluations.
/// `N` is the folding factor. It should be a power of two.
///
/// This is an unsized type and must be used behind a pointer like `&`.
///
/// `folded_evaluations[i]` yields a slice of size `N` containing the evaluations necessary to
/// compute the `i`th evaluations in the FRI next layer.
#[derive(PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct FoldedEvaluationsSlice<const N: usize, F>([F]);

impl<const N: usize, F> Index<usize> for FoldedEvaluationsSlice<N, F> {
    type Output = [F; N];
    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        (&self.0[index * N..(index + 1) * N]).try_into().unwrap()
    }
}

impl<const N: usize, F> FoldedEvaluationsSlice<N, F> {
    /// Wraps a flattened slice of folded evaluations.
    /// See [`FoldedEvaluations::from_flat_evaluations`].
    ///
    ///  # Panics
    /// This may either panic or have unspecified behaviour if `N` is not a power of two or
    /// `evaluations.len()` is not a multiple of `N`.
    #[inline]
    pub fn from_flat_evaluations(evaluations: &[F]) -> &Self {
        FoldedEvaluations::<N, _>::check_slice(evaluations);
        Self::from_flat_evaluations_unchecked(evaluations)
    }
    /// Same as [`Self::from_flat_evaluations`], but does not panic.
    #[inline]
    pub const fn from_flat_evaluations_unchecked(evaluations: &[F]) -> &Self {
        // SAFETY: `Self` and `[F]` have the same layout.
        // See [https://rust-lang.github.io/unsafe-code-guidelines/layout/structs-and-tuples.html#single-field-structs]
        unsafe { &*(evaluations as *const [F] as *const Self) }
    }
    /// Yields the underlying slice. See [`FoldedEvaluations::into_flat_evaluations`].
    #[inline]
    pub const fn as_flat_evaluations(&self) -> &[F] {
        &self.0
    }
    /// Returns the size of the domain the evaluations were initially computed on.
    #[inline]
    pub const fn domain_size(&self) -> usize {
        self.0.len()
    }
    /// Returns the size of the folded domain. This corresponds to the number of leaves in the Merkle tree.
    #[inline]
    pub const fn folded_len(&self) -> usize {
        self.0.len() / N
    }
}

impl<const N: usize, F> AsRef<[[F; N]]> for FoldedEvaluationsSlice<N, F> {
    #[inline]
    fn as_ref(&self) -> &[[F; N]] {
        // SAFETY: size_of::<[F; N]>() == N * size_of::<F>().
        //
        // `self.folded_len()` rounds towards 0, so this is safe even if `self.domain_size()` is not
        // a multiple of `N` (but some items will be missing from the resulting slice).
        unsafe { core::slice::from_raw_parts(self.0.as_ptr() as *const [F; N], self.folded_len()) }
    }
}

impl<'a, const N: usize, F> IntoIterator for &'a FoldedEvaluationsSlice<N, F> {
    type Item = &'a [F; N];
    type IntoIter = core::slice::Iter<'a, [F; N]>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.as_ref().iter()
    }
}

/// Reduces the polynomial by factor `N` using FRI algorithm.
///
/// - `N` is the reduction factor. It must be a power of two. Typical values include 2, 4 and 8.
/// - `evaluations` is the folded evaluations of the polynomial on the `n`^th roots of unity, where `n` is the
///    len of `evaluations`. `n` must be a power of two greater than the degree-bound of the polynomial.
///    See [`FoldedEvaluations::new`].
/// - `alpha` is the "challenge" used to reduce the polynomial.
/// - `domain`, if provided, is the pre-computed evaluation domain of size `N`.
///
/// # Returns
/// If `evaluations` corresponds to `P(X) = a_0 + a_1 X + ... + a_(n-1) X^(n-1)` in coefficient form, then `P` is
/// decomposed in `P_i(X) = a_i + a_(N+i) X + ... + a_(kN+i) X^k` where `k=n/N`.
///
/// This function returns the evaluations of `Q(X) = P_0(X^N) + alpha P_1(X^N) + ... + alpha^(N-1) P_(N-1)(X^N)` on
/// the `n/N`th roots of unity.
///
/// # Panics
/// This may panic if `N` or `evaluations.len()` are not powers of two, if `N > evaluations.len()` and if
/// `F` does not contain subgroups of size `evaluations.len()` and `N`.
///
/// # Credits
/// This is partly based on equation (4) from [https://eprint.iacr.org/2022/1216.pdf].
pub fn reduce_polynomial<const N: usize, F: FftField>(
    evaluations: &FoldedEvaluations<N, F>,
    alpha: F,
    domain: Option<&GeneralEvaluationDomain<F>>,
) -> Vec<F> {
    let domain = domain.map_or_else(
        || Cow::Owned(GeneralEvaluationDomain::new(N).unwrap()),
        Cow::Borrowed,
    );

    let _: () = AssertPowerOfTwo::<N>::OK;
    debug_assert_eq!(domain.size(), N, "Evaluation domain must be of size N");

    let mut buffer = Vec::with_capacity(N);
    let mut new_evaluations = Vec::with_capacity(evaluations.folded_len());

    let root_inv = F::get_root_of_unity(evaluations.domain_size() as u64)
        .unwrap()
        .pow([evaluations.domain_size() as u64 - 1]);
    let mut offset = F::ONE;

    for batch in evaluations {
        buffer.extend_from_slice(batch);
        domain.ifft_in_place(&mut buffer);

        new_evaluations.push(horner_evaluate(&buffer, alpha * offset));

        offset *= root_inv;
        buffer.clear();
    }
    new_evaluations
}

/// Folds positions. This discards duplicates. This has time complexity `O(l^2)`, where `l`
/// is the len of `positions`.
///
/// - `positions` is a list of positions in a domain of size `n`.
///    The domain should have the following form: `(w^0, ..., w^n)`
/// - `folded_domain_size` is the size of the domain after folding.
///
/// `n` must be a multiple of `folded_domain_size`. Let `n = N * folded_domain_size`.
/// If a position corresponds to `x` in the initial domain, the associated folded position will
/// correspond to `x^N` in the folded domain.
///
/// # Example
/// ```rust
/// use fri::folding::fold_positions;
///
/// // Domain (1, w, ..., w^7), where w^8 = 1
/// let positions = vec![7, 2, 4, 4, 1, 3];
///
/// // Folding factor = 2
/// // Folded domain (1, w^2, w^4, w^6), of size 4
/// let folded_positions = fold_positions(&positions, 4);
///
/// // Position `7` corresponds to `w^7` in the initial domain.
/// // `(w^7)^2 = w^14 = w^6`, which is at position `3` in the folded domain.
/// assert_eq!(folded_positions, vec![3, 2, 0, 1]);
/// ```
pub fn fold_positions(positions: &[usize], folded_domain_size: usize) -> Vec<usize> {
    let mask = folded_domain_size - 1;
    let mut new_positions = vec![];
    for &position in positions {
        let pos = position & mask;
        if !new_positions.contains(&pos) {
            new_positions.push(pos);
        }
    }
    new_positions
}
