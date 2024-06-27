use ark_ff::FftField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use rs_merkle::{Hasher, MerkleTree};
use ark_serialize::CanonicalSerialize;

/// Compile-time check that `N` is a power of two.
/// 
/// # Example
/// ```ignore
/// // OK:
/// let _ = AssertPowerOfTwo::<16>::OK;
/// 
/// // This does not compile:
/// let _ = AssertPowerOfTwo::<7>::OK;
/// ```
pub(crate) struct AssertPowerOfTwo<const N: usize>;

impl<const N: usize> AssertPowerOfTwo<N> {
    pub const OK: () = assert!(N.is_power_of_two(), "`N` must be a power of two");
}

pub trait HasherExt: Hasher {
    /// Uses the implementation of [`CanonicalSerialize`] to convert `value` into bytes then return the
    /// hash value of those bytes.
    /// 
    /// `buffer` is used to store the serialized bytes. Its content when the function returns is unspecified.
    /// If it is not empty initially, it will be cleared first.
    fn hash_item_with<S: CanonicalSerialize>(value: &S, buffer: &mut Vec<u8>) -> Self::Hash;

    /// Uses the implementation of [`CanonicalSerialize`] to convert `value` into bytes then return the
    /// hash value of those bytes.
    /// 
    /// This allocates a new temporary vector to store the serialized bytes.
    fn hash_item<S: CanonicalSerialize>(value: &S) -> Self::Hash {
        Self::hash_item_with(value, &mut Vec::with_capacity(value.compressed_size()))
    }
    /// Convenience function to hash a slice of values.
    fn hash_many<S: CanonicalSerialize>(values: &[S]) -> Vec<Self::Hash> {
        let mut hashes = Vec::with_capacity(values.len());
        let mut bytes = Vec::with_capacity(values.get(0).map_or(0, S::compressed_size));
        for evaluation in values {
            hashes.push(Self::hash_item_with(evaluation, &mut bytes));
        }
        hashes
    }
}
impl<H: Hasher> HasherExt for H {
    fn hash_item_with<S: CanonicalSerialize>(value: &S, buffer: &mut Vec<u8>) -> Self::Hash {
        buffer.clear();
        value
            .serialize_compressed(&mut *buffer)
            .expect("Serialization failed");
        H::hash(buffer)
    }
}

pub(crate) trait MerkleTreeExt {
    /// Hash the evaluations and create a Merkle tree using the hashes as the leaves.
    fn from_evaluations<S: CanonicalSerialize>(evaluations: &[S]) -> Self;
}

impl<H: Hasher> MerkleTreeExt for MerkleTree<H> {
    fn from_evaluations<S: CanonicalSerialize>(evaluations: &[S]) -> Self {
        let hashes = H::hash_many(evaluations);
        Self::from_leaves(&hashes)
    }
}

/// Converts `polynomial` from coefficient form to evaluations over roots of unity.
/// 
/// `domain_size` must be a power of two and strictly greater than the degree of the polynomial.
/// 
/// # Example
/// ```
/// use ark_ff::FftField;
/// use ark_poly::{Polynomial, DenseUVPolynomial, univariate::DensePolynomial};
/// use rand::{thread_rng, Rng};
/// 
/// use fri::utils::{to_evaluations, to_polynomial};
/// use fri_test_utils::Fq;
/// 
/// const POLY_COEFFS_LEN: usize = 32;
/// const DOMAIN_SIZE: usize = 128;
/// 
/// let mut rng = thread_rng();
/// let polynomial: Vec<Fq> = (0..POLY_COEFFS_LEN).map(|_| rng.gen()).collect();
/// let evaluations = to_evaluations(polynomial.clone(), DOMAIN_SIZE);
/// let dense_poly = DensePolynomial::from_coefficients_vec(polynomial.clone());
/// 
/// let w = Fq::get_root_of_unity(DOMAIN_SIZE as u64).unwrap();
/// 
/// assert_eq!(evaluations[1], dense_poly.evaluate(&w));
/// 
/// let interpolated = to_polynomial(evaluations, polynomial.len());
/// 
/// assert_eq!(polynomial, interpolated);
/// ```
#[inline]
pub fn to_evaluations<F: FftField>(mut polynomial: Vec<F>, domain_size: usize) -> Vec<F> {
    debug_assert!(
        domain_size.is_power_of_two(),
        "Domain size must be a power of two"
    );

    let domain = GeneralEvaluationDomain::<F>::new(domain_size).unwrap();
    domain.fft_in_place(&mut polynomial);
    polynomial
}

/// Interpolates the coefficient form from the evaluations over the roots of unity. 
/// This is the counterpart of [`to_evaluations`].
/// 
/// `degree_bound` must be strictly greater than the degree of the polynomial. Otherwise, this
/// may either panic or truncate higher degree coefficients.
#[inline]
pub fn to_polynomial<F: FftField>(mut evaluations: Vec<F>, degree_bound: usize) -> Vec<F> {
    debug_assert!(
        evaluations.len().is_power_of_two(),
        "Domain size must be a power of two"
    );

    let domain = GeneralEvaluationDomain::<F>::new(evaluations.len()).unwrap();
    domain.ifft_in_place(&mut evaluations);

    debug_assert!(
        evaluations[degree_bound..].iter().all(|c| *c == F::ZERO),
        "Degree of polynomial is not bound by {degree_bound}"
    );

    evaluations.truncate(degree_bound);
    evaluations
}