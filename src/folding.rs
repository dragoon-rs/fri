use std::{borrow::Cow, ops::Index};

use ark_ff::FftField;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial,
};

use crate::AssertPowerOfTwo;

pub struct FoldedEvaluations<const N: usize, F>(Vec<F>);

impl<const N: usize, F> Index<usize> for FoldedEvaluations<N, F> {
    type Output = [F; N];
    fn index(&self, index: usize) -> &Self::Output {
        // TODO check if `unwrap_unchecked` is faster
        (&self.0[index * N..(index + 1) * N]).try_into().unwrap()
    }
}

impl<const N: usize, F> FoldedEvaluations<N, F> {
    pub fn new(evaluations: &[F]) -> Self
    where
        F: Clone,
    {
        let bound = evaluations.len().div_ceil(N);
        let mut folded = Vec::with_capacity(evaluations.len());
        for i in 0..bound {
            folded.extend(evaluations.iter().skip(i).step_by(bound).cloned());
        }

        Self::from_flat_evaluations(folded)
    }
    #[inline]
    pub fn into_flat_evaluations(self) -> Vec<F> {
        self.0
    }
    #[inline]
    pub fn from_flat_evaluations(evaluations: Vec<F>) -> Self {
        assert!(
            evaluations.len() % N == 0,
            "Domain size must be a multiple of `N`"
        );
        debug_assert!(
            evaluations.len().is_power_of_two(),
            "Number of evaluations must be a power of two"
        );
        Self(evaluations)
    }
    #[inline]
    pub unsafe fn from_flat_evaluations_unchecked(evaluations: Vec<F>) -> Self {
        Self(evaluations)
    }
    #[inline]
    pub fn domain_size(&self) -> usize {
        self.0.len()
    }
    #[inline]
    pub fn folded_len(&self) -> usize {
        self.0.len() / N
    }
}

impl<const N: usize, F> AsRef<[[F; N]]> for FoldedEvaluations<N, F> {
    #[inline]
    fn as_ref(&self) -> &[[F; N]] {
        unsafe { core::slice::from_raw_parts(self.0.as_ptr() as *const [F; N], self.folded_len()) }
    }
}

impl<'a, const N: usize, F> IntoIterator for &'a FoldedEvaluations<N, F> {
    type Item = &'a [F; N];
    type IntoIter = core::slice::Iter<'a, [F; N]>;

    #[inline]
    fn into_iter(self) -> Self::IntoIter {
        self.as_ref().into_iter()
    }
}

/// Reduces the polynomial by factor `N` using FRI algorithm.
///
/// - `N` is the reduction factor. It must be a power of two. Typical values include 2, 4 and 8.
/// - `evaluations` is the evaluations of the polynomial on the `n`^th roots of unity, where `n` is the
///    len of `evaluations`. `n` must be a power of two strictly greater than the degree-bound of the polynomial.
///    If `w` is `F::get_root_of_unity(n).unwrap()`, `evaluations[i]` is the evaluation at `w^i`.
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
#[must_use]
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

        let mut factor = F::ONE;
        for coeff in &mut buffer {
            // FIXME: rust-analyzer fails to infer type of `coeff` on VS Code
            *(coeff as &mut F) *= factor;
            factor *= offset;
        }
        offset *= root_inv;

        let poly = DensePolynomial { coeffs: buffer };
        new_evaluations.push(poly.evaluate(&alpha));

        buffer = poly.coeffs;
        buffer.clear();
    }
    new_evaluations
}
