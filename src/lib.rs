use ark_ff::FftField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::CanonicalSerialize;
use prover::FriLayer;
use rng::ReseedableRng;
use rs_merkle::{Hasher, MerkleProof, MerkleTree};

mod folding;
pub use folding::{reduce_polynomial, FoldedEvaluations};

pub mod prover;
pub use prover::FriCommitments;

pub mod rng;

#[cfg(feature = "blake3")]
pub mod blake3;
#[cfg(feature = "sha3")]
pub mod sha3;

#[cfg(test)]
pub mod tests;

struct AssertPowerOfTwo<const N: usize>;

impl<const N: usize> AssertPowerOfTwo<N> {
    const OK: () = assert!(N.is_power_of_two(), "`N` must be a power of two");
}

trait HasherExt: Hasher {
    fn hash_item<S: CanonicalSerialize>(value: &S) -> Self::Hash;
    fn hash_many<S: CanonicalSerialize>(values: &[S]) -> Vec<Self::Hash>;
}
impl<H: Hasher> HasherExt for H {
    fn hash_item<S: CanonicalSerialize>(value: &S) -> Self::Hash {
        let mut bytes = vec![];
        value
            .serialize_compressed(&mut bytes)
            .expect("Serialization failed");
        H::hash(&bytes)
    }
    fn hash_many<S: CanonicalSerialize>(values: &[S]) -> Vec<Self::Hash> {
        let mut hashes: Vec<<H as Hasher>::Hash> = Vec::with_capacity(values.len());
        let mut bytes = vec![];
        for evaluation in values {
            evaluation
                .serialize_compressed(&mut bytes)
                .expect("Serialization failed");
            hashes.push(H::hash(&bytes));
            bytes.clear();
        }
        hashes
    }
}

trait MerkleTreeExt {
    fn from_evaluations<S: CanonicalSerialize>(evaluations: &[S]) -> Self;
}

impl<H: Hasher> MerkleTreeExt for MerkleTree<H> {
    fn from_evaluations<S: CanonicalSerialize>(evaluations: &[S]) -> Self {
        let hashes = H::hash_many(evaluations);
        Self::from_leaves(&hashes)
    }
}

pub struct FriProofLayer<F, H: Hasher> {
    proof: MerkleProof<H>,
    evaluations: Vec<F>,
}

pub struct FriProof<F, H: Hasher> {
    layers: Vec<FriProofLayer<F, H>>,
    remainder: Vec<F>,
}

/// Commits the polynomial according to FRI algorithm.
///
/// - `polynomial` is the list of coefficients of the polynomial
///
/// TODO write documentation
pub fn commit_polynomial<const N: usize, F, H, R>(
    polynomial: Vec<F>,
    mut rng: R,
    blowup_factor: usize,
    remainder_degree: usize,
) -> FriCommitments<N, F, H>
where
    F: FftField,
    H: Hasher,
    R: ReseedableRng<Seed = H::Hash>,
{
    let _: () = AssertPowerOfTwo::<N>::OK;

    // Convert the polynonial to evaluation form:
    let num_coeffs = polynomial.len();
    let mut prover = FriCommitments::new(num_coeffs);
    let domain_size = (polynomial.len() * blowup_factor)
        .checked_next_power_of_two()
        .unwrap_or_else(|| panic!(
            "Domain size out of bounds for blowup factor {blowup_factor} and polynomial of degree-bound {}", polynomial.len()
        ));
    let mut evaluations = to_evaluations(polynomial, domain_size);

    // Reduce the polynomial from its evaluations:
    let domain = GeneralEvaluationDomain::<F>::new(N).unwrap();
    while evaluations.len() > remainder_degree * blowup_factor {
        let layer = FriLayer::new(&evaluations);
        rng.reseed(layer.tree().root().expect("cannot get tree root"));
        evaluations =
            reduce_polynomial::<N, _>(layer.evaluations(), rng.draw_alpha(), Some(&domain));
        prover.commit_layer(layer);
    }

    // Commit remainder directly
    let poly = to_polynomial(evaluations, num_coeffs);
    rng.reseed(H::hash_item(&poly));
    prover.set_remainder(poly);
    prover
}

pub fn prove<const N: usize, F, H, R>(
    commitments: FriCommitments<N, F, H>,
    mut rng: R,
    num_queries: usize,
) -> FriProof<F, H>
where
    F: FftField,
    H: Hasher,
    R: ReseedableRng<Seed = H::Hash>,
{
    let mut domain_size = commitments.layers()[0].evaluations().domain_size();
    let mut positions = rng.draw_positions(num_queries, domain_size);
    let mut layers = Vec::with_capacity(commitments.layers().len());

    for layer in commitments.layers() {
        let proof = layer.tree().proof(&positions);
        let mut evaluations = Vec::with_capacity(num_queries);
        for &pos in &positions {
            evaluations.extend_from_slice(&layer.evaluations()[pos]);
        }
        layers.push(FriProofLayer { proof, evaluations });

        domain_size /= N;
        let mask = domain_size - 1;
        let mut new_positions = Vec::with_capacity(domain_size);
        for position in positions {
            let pos = position & mask;
            if !new_positions.contains(&pos) {
                new_positions.push(pos);
            }
        }
        positions = new_positions;
    }
    FriProof {
        layers,
        remainder: commitments.remainder(),
    }
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
