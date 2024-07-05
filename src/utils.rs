use std::{borrow::Borrow, fmt::Debug};

use ark_ff::FftField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Valid};
use derive_more::{AsRef, Deref, From, Into};
use rs_merkle::{Hasher, MerkleTree};

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

/// A transparent wrapper for a [`rs_merkle::MerkleProof`] that implements additional utility traits.
///
/// This allows to use `#[derive(...)]` in objects that use Merkle proofs.
#[derive(From, Into, AsRef, Deref)]
#[repr(transparent)]
pub struct MerkleProof<H: Hasher>(rs_merkle::MerkleProof<H>);

impl<H: Hasher> MerkleProof<H> {
    /// See [`rs_merkle::MerkleProof::new`]
    pub fn new(hashes: Vec<H::Hash>) -> Self {
        rs_merkle::MerkleProof::new(hashes).into()
    }
}

impl<H: Hasher> Clone for MerkleProof<H> {
    fn clone(&self) -> Self {
        Self(rs_merkle::MerkleProof::new(self.proof_hashes().to_vec()))
    }
}

impl<H: Hasher> Debug for MerkleProof<H>
where
    H::Hash: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut dbg = f.debug_tuple("MerkleProof");
        for hash in self.proof_hashes() {
            dbg.field(hash);
        }
        dbg.finish()
    }
}

impl<H: Hasher> PartialEq for MerkleProof<H> {
    fn eq(&self, other: &Self) -> bool {
        self.proof_hashes() == other.proof_hashes()
    }
}

impl<H: Hasher> CanonicalSerialize for MerkleProof<H>
where
    H::Hash: CanonicalSerialize,
{
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), ark_serialize::SerializationError> {
        self.proof_hashes().serialize_with_mode(writer, compress)
    }
    fn serialized_size(&self, compress: Compress) -> usize {
        self.proof_hashes().serialized_size(compress)
    }
}

impl<H: Hasher> Valid for MerkleProof<H>
where
    H::Hash: Valid,
{
    fn check(&self) -> Result<(), ark_serialize::SerializationError> {
        H::Hash::batch_check(self.proof_hashes().iter())
    }
}

impl<H: Hasher> CanonicalDeserialize for MerkleProof<H>
where
    H::Hash: CanonicalDeserialize,
{
    fn deserialize_with_mode<R: ark_serialize::Read>(
        reader: R,
        compress: Compress,
        validate: ark_serialize::Validate,
    ) -> Result<Self, ark_serialize::SerializationError> {
        <Vec<H::Hash>>::deserialize_with_mode(reader, compress, validate).map(Self::new)
    }
}

impl<H: Hasher> Borrow<rs_merkle::MerkleProof<H>> for MerkleProof<H> {
    fn borrow(&self) -> &rs_merkle::MerkleProof<H> {
        self
    }
}

pub trait HasherExt: Hasher {
    /// Uses the implementation of [`CanonicalSerialize`] to convert `value` into bytes then return the
    /// hash value of those bytes.
    ///
    /// `buffer` is used to store the serialized bytes. Its content when the function returns is unspecified.
    /// If it is not empty initially, it will be cleared first.
    fn hash_item_with<S: CanonicalSerialize + ?Sized>(
        value: &S,
        buffer: &mut Vec<u8>,
    ) -> Self::Hash;

    /// Uses the implementation of [`CanonicalSerialize`] to convert `value` into bytes then return the
    /// hash value of those bytes.
    ///
    /// This allocates a new temporary vector to store the serialized bytes.
    fn hash_item<S: CanonicalSerialize + ?Sized>(value: &S) -> Self::Hash {
        Self::hash_item_with(value, &mut Vec::with_capacity(value.compressed_size()))
    }
    /// Convenience function to hash a slice of values.
    fn hash_many<S: CanonicalSerialize>(values: &[S]) -> Vec<Self::Hash> {
        let mut hashes = Vec::with_capacity(values.len());
        let mut bytes = Vec::with_capacity(values.first().map_or(0, S::compressed_size));
        for evaluation in values {
            hashes.push(Self::hash_item_with(evaluation, &mut bytes));
        }
        hashes
    }
}
impl<H: Hasher> HasherExt for H {
    fn hash_item_with<S: CanonicalSerialize + ?Sized>(
        value: &S,
        buffer: &mut Vec<u8>,
    ) -> Self::Hash {
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
