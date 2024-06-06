use std::{borrow::Cow, fmt::Debug};

use ark_ff::{FftField, Field};
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial,
};
use ark_serialize::Compress;
use rs_merkle::{Hasher, MerkleTree};

#[cfg(feature = "blake3")]
pub mod blake3;
#[cfg(feature = "sha3")]
pub mod sha3;

#[cfg(test)]
pub mod tests;

pub struct FriCommitments<H: Hasher> {
    layers: Vec<MerkleTree<H>>,
}

impl<H: Hasher> FriCommitments<H> {
    pub fn layers(&self) -> &[MerkleTree<H>] {
        &self.layers
    }
}

impl<H: Hasher> Debug for FriCommitments<H>
where
    H::Hash: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut str = f.debug_struct("FriCommitments");
        str.field("layers", &MerkleTreeDebug(&self.layers)).finish()
    }
}

struct MerkleTreeDebug<'a, H: Hasher>(&'a [MerkleTree<H>]);

impl<H: Hasher> Debug for MerkleTreeDebug<'_, H>
where
    H::Hash: Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.0.iter().map(MerkleTree::root))
            .finish()
    }
}

struct Layer<H: Hasher> {
    seed: H::Hash,
    tree: MerkleTree<H>,
}

impl<H: Hasher> Layer<H> {
    #[inline]
    #[must_use]
    pub fn new<F: Field>(evaluations: &[F]) -> Self {
        let tree = build_merkle_tree(evaluations);
        let seed = tree.root().expect("failed to get merkle tree root");
        Self { seed, tree }
    }
}

struct Prover<H: Hasher> {
    seed: H::Hash,
    layers: Vec<MerkleTree<H>>,
}

impl<H: Hasher> Prover<H> {
    #[inline]
    #[must_use]
    pub fn new<F: Field>(evaluations: &[F], folding_factor: usize) -> Self {
        let layer = Layer::new(evaluations);

        let mut layers =
            Vec::with_capacity(evaluations.len().ilog2().div_ceil(folding_factor.ilog2()) as usize);
        layers.push(layer.tree);
        Self {
            seed: layer.seed,
            layers,
        }
    }
    #[inline]
    pub fn commit<F: Field>(&mut self, evaluations: &[F]) {
        let layer = Layer::new(evaluations);
        self.seed = layer.seed;
        self.layers.push(layer.tree);
    }
    #[inline]
    pub fn draw_alpha<F: FftField>(&mut self) -> F
    where
        H::Hash: AsRef<[u8]>,
    {
        for i in 0u64..1000 {
            let hash = H::concat_and_hash(&self.seed, Some(&H::hash(&i.to_le_bytes())));

            if let Some(elt) = F::from_random_bytes(hash.as_ref()) {
                return elt;
            }
        }
        panic!("Failed to draw alpha after 1000 attempts");
    }
    #[inline]
    #[must_use]
    pub fn finish(self) -> FriCommitments<H> {
        FriCommitments {
            layers: self.layers,
        }
    }
}

/// Commits the polynomial according to FRI algorithm.
///
/// - `polynomial` is the list of coefficients of the polynomial
/// 
/// TODO write documentation
#[must_use]
pub fn commit_polynomial<const N: usize, F, P, H>(
    polynomial: Vec<F>,
    blowup_factor: usize,
    remainder_degree: usize,
) -> FriCommitments<H>
where
    F: FftField,
    H: Hasher,
    H::Hash: AsRef<[u8]>,
{
    // Convert the polynonial to evaluation form:
    let domain_size = (polynomial.len() * blowup_factor)
        .checked_next_power_of_two()
        .unwrap_or_else(|| panic!(
            "Domain size out of bounds for blowup factor {blowup_factor} and polynomial of degree-bound {}", polynomial.len()
        ));
    let mut evaluations = to_evaluations(polynomial, domain_size);

    // Reduce the polynomial from its evaluations:
    let mut prover = Prover::new(&evaluations, N);
    let domain = GeneralEvaluationDomain::<F>::new(N).unwrap();
    while evaluations.len() > remainder_degree {
        evaluations = reduce_polynomial::<N, _>(&evaluations, prover.draw_alpha(), Some(&domain));
        prover.commit(&evaluations);
    }
    prover.finish()
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
    evaluations: &[F],
    alpha: F,
    domain: Option<&GeneralEvaluationDomain<F>>,
) -> Vec<F> {
    let domain = domain.map_or_else(
        || Cow::Owned(GeneralEvaluationDomain::new(N).unwrap()),
        Cow::Borrowed,
    );

    debug_assert!(
        evaluations.len().is_power_of_two(),
        "Number of evaluations must be a power of two"
    );
    debug_assert!(
        N < evaluations.len(),
        "Too few evaluations to reduce polynomial by N"
    );
    debug_assert!(N.is_power_of_two(), "Folding factor must be a power of two");
    debug_assert_eq!(domain.size(), N, "Evaluation domain must be of size N");

    let mut buffer = Vec::with_capacity(N);

    let bound = evaluations.len().div_ceil(N);
    let mut new_evaluations = Vec::with_capacity(bound);

    let root_inv = F::get_root_of_unity(evaluations.len() as u64)
        .unwrap()
        .pow([evaluations.len() as u64 - 1]);
    let mut offset = F::ONE;

    for i in 0..bound {
        buffer.extend(evaluations.iter().skip(i).step_by(bound).copied());
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

#[must_use]
fn build_merkle_tree<F: Field, H: Hasher>(evaluations: &[F]) -> MerkleTree<H> {
    let mut hashes = Vec::with_capacity(evaluations.len());
    let mut bytes = vec![];
    for evaluation in evaluations {
        evaluation
            .serialize_with_mode(&mut bytes, Compress::Yes)
            .expect("Serialization failed");
        hashes.push(H::hash(&bytes));
        bytes.clear();
    }
    MerkleTree::from_leaves(&hashes)
}
