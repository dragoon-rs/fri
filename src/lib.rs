use std::iter::zip;

use ark_ff::FftField;
use ark_poly::{
    univariate::DensePolynomial, EvaluationDomain, GeneralEvaluationDomain, Polynomial,
};
use folding::{fold_positions, reduce_polynomial, FoldedEvaluationsSlice};
use prover::{FriCommitments, FriLayer};
use rng::ReseedableRng;
use rs_merkle::{Hasher, MerkleProof};
use utils::{to_evaluations, to_polynomial, AssertPowerOfTwo, HasherExt};

pub mod algorithms;
pub mod folding;
pub mod prover;
pub mod rng;
pub mod utils;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VerifyError {
    BadFoldingFactor(usize),
    BadDomainSize(usize),
    BadDegreeBound(usize),
    DegreeTruncation { depth: usize },
    CommitmentMismatch { depth: usize },
    InvalidFolding { depth: usize },
    WrongNumberOfEvaluations { depth: usize },
    InvalidRemainderDegree,
    InvalidRemainder,
}

// TODO: serialization!
/// A FRI proof.
pub struct FriProof<F, H: Hasher> {
    layers: Vec<FriProofLayer<F, H>>,
    remainder: Vec<F>,
}

struct FriProofLayer<F, H: Hasher> {
    proof: MerkleProof<H>,
    /// TODO: store separately?
    commitment: H::Hash,
    /// Flattened vector of **folded** evaluations
    evaluations: Vec<F>,
}

impl<F: Copy, H: Hasher> FriProofLayer<F, H> {
    /// Returns `None` if the number of evaluations stored in this layer is inconsistent with folding factor `N`.
    fn evaluations<const N: usize>(&self) -> Option<&FoldedEvaluationsSlice<N, F>> {
        (self.evaluations.len() % N == 0).then(|| {
            FoldedEvaluationsSlice::<N, _>::from_flat_evaluations_unchecked(&self.evaluations)
        })
    }
    /// Extracts the actually-queried evaluations from the evaluations stored in the layer.
    ///
    /// Computing the evaluations in the next layer requires to store `N` evaluations per position, but
    /// only one (per position) is actually used to verify this particular layer.
    ///
    /// `domain_size` must be a power of two, otherwise the result is unspecified.
    ///
    /// Returns `None` if the number of evaluations in this layer is inconsistent with folding factor `N` or
    /// if the evaluations are inconsistent with the requested positions.
    fn queried_evaluations<const N: usize>(
        &self,
        positions: &[usize],
        folded_positions: &[usize],
        domain_size: usize,
    ) -> Option<Vec<F>> {
        let mask = domain_size / N - 1;
        let folded_evals = self.evaluations::<N>()?;

        let mut vec = Vec::with_capacity(positions.len());
        for pos in positions {
            let index = folded_positions.iter().position(|&p| p == pos & mask)?;
            let queried = folded_evals
                .as_ref()
                .get(index)?
                .get(pos / (domain_size / N))?;
            vec.push(*queried);
        }
        Some(vec)
    }
}

/// Commits the polynomial according to FRI algorithm.
///
/// - `N` is the folding factor. It should be a power of two.
/// - `polynomial` is the list of coefficients of the polynomial.
/// - `rng` is the pseudo-random number generator to be used by the algorithm.
/// - The initial evaluation domain will have size at least `polynomial.len() * blowup_factor` (rounded up to
///   the next power of two).
/// - `remainder_degree` is the degree of the remainder polynomial in the last FRI layer.
///   It should be a power of `N`.
///
/// # Panics
/// This panics if `polynomial.len() * blowup_factor > 2^63` and if `F` does not contain a subgroup of the size
/// of the requested evaluation domain.
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
    let poly = to_polynomial(evaluations, remainder_degree);
    rng.reseed(H::hash_item(&poly));
    prover.set_remainder(poly);
    prover
}

// TODO? create a function that combines `commit_polynomial` and `build_proof`?
/// Constructs a FRI proof by making queries to the `commitments`.
///
/// - `rng` *must* be in the same state as it was when `commit_polynomial` has returned.
/// - `num_queries` is the number of random points to query in the first layer; this number decreases
///   in the following layers as the evaluation domain is reduced.
///
/// `num_queries` should be large enough to provide reasonable security, but small compared to `domain_size` to
/// avoid duplicates.
///
/// More than `num_queries` will be stored in the proof (approximately `N` times more) because each layer must
/// also store the evaluations necessary to compute the evaluations in the next layer.
pub fn build_proof<const N: usize, F, H, R>(
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
        domain_size /= N;
        positions = fold_positions(&positions, domain_size);

        // `layer.tree().proof(...)` requires sorted positions
        let mut positions_sorted = positions.clone();
        positions_sorted.sort_unstable();
        let proof = layer.tree().proof(&positions_sorted);

        let mut evaluations = Vec::with_capacity(N * positions.len());
        for &pos in &positions {
            evaluations.extend_from_slice(&layer.evaluations()[pos]);
        }

        layers.push(FriProofLayer {
            proof,
            evaluations,
            commitment: layer.tree().root().unwrap(),
        });
    }
    FriProof {
        layers,
        remainder: commitments.remainder(),
    }
}

impl<F: FftField, H: Hasher> FriProof<F, H> {
    /// Verify a FRI proof. This checks the proof was properly built from a polynomial with degree lower than
    /// `degree_bound`.
    ///
    /// - `rng` must be consistent with the random number generator used to generate the proof.
    /// - `num_queries` must match the value used in [`build_proof`].
    /// - `degree_bound` must be a power of two strictly greater than the degree of the polynomial.
    ///    If `polynomial.len()` was not already a power of two in [`commit_polynomial`], the next power
    ///    of two must be used.
    /// - `domain_size` must be a power of two and multiple of `degree_bound` such that
    ///   `domain_size / degree_bound = blowup_factor > 1`.
    ///
    /// # Errors
    /// This returns an error if the proof is not valid or any of the parameters is not consistent with it.
    pub fn verify<const N: usize, R: ReseedableRng<Seed = H::Hash>>(
        &self,
        mut rng: R,
        num_queries: usize,
        mut degree_bound: usize,
        mut domain_size: usize,
    ) -> Result<(), VerifyError> {
        // Initial checks
        let _ = AssertPowerOfTwo::<N>::OK;

        if !domain_size.is_power_of_two() || domain_size <= degree_bound {
            return Err(VerifyError::BadDomainSize(domain_size));
        }
        if !degree_bound.is_power_of_two() {
            return Err(VerifyError::BadDegreeBound(degree_bound));
        }
        let Some(domain) = GeneralEvaluationDomain::<F>::new(N) else {
            return Err(VerifyError::BadFoldingFactor(N));
        };
        let Some(mut root) = F::get_root_of_unity(domain_size as u64) else {
            return Err(VerifyError::BadDomainSize(domain_size));
        };

        // Preparation
        let mut alphas = Vec::<F>::with_capacity(self.layers.len());
        for layer in &self.layers {
            rng.reseed(layer.commitment);
            alphas.push(rng.draw_alpha());
        }
        rng.reseed(H::hash_item(&self.remainder));

        let mut positions = rng.draw_positions(num_queries, domain_size);

        // TODO provide as argument
        let mut evaluations = self.layers[0]
            .queried_evaluations::<N>(
                &positions,
                &fold_positions(&positions, domain_size / N),
                domain_size,
            )
            .ok_or_else(|| VerifyError::WrongNumberOfEvaluations { depth: 0 })?;

        // Check layers
        for (depth, layer) in self.layers.iter().enumerate() {
            let folded_positions = fold_positions(&positions, domain_size / N);

            let layer_evaluations = layer
                .evaluations::<N>()
                .ok_or_else(|| VerifyError::WrongNumberOfEvaluations { depth })?;

            let queried_evaluations = layer
                .queried_evaluations::<N>(&positions, &folded_positions, domain_size)
                .ok_or_else(|| VerifyError::WrongNumberOfEvaluations { depth })?;

            if queried_evaluations != evaluations {
                return Err(VerifyError::InvalidFolding { depth });
            }

            if folded_positions.len() != layer_evaluations.folded_len() {
                return Err(VerifyError::WrongNumberOfEvaluations { depth });
            }

            evaluations.clear();
            let mut buffer = Vec::with_capacity(N);

            for (&pos, eval) in std::iter::zip(&folded_positions, layer_evaluations) {
                buffer.extend_from_slice(eval);
                domain.ifft_in_place(&mut buffer);

                let poly = DensePolynomial { coeffs: buffer };
                let offset = root.pow([(domain_size - pos % (domain_size / N)) as u64]);
                evaluations.push(poly.evaluate(&(alphas[depth] * offset)));
                buffer = poly.coeffs;
                buffer.clear();
            }

            if domain_size % N != 0 || degree_bound % N != 0 {
                return Err(VerifyError::DegreeTruncation { depth });
            }
            root = root.pow([N as u64]);
            domain_size /= N;
            degree_bound /= N;

            positions = folded_positions;

            if !layer.proof.verify(
                layer.commitment,
                &positions,
                &H::hash_many(layer_evaluations.as_ref()),
                domain_size,
            ) {
                return Err(VerifyError::CommitmentMismatch { depth });
            }
        }

        // Check remainder
        if self.remainder.len() != degree_bound
            && self.remainder[degree_bound..]
                .iter()
                .any(|&coeff| coeff != F::ZERO)
        {
            return Err(VerifyError::InvalidRemainderDegree);
        }
        let remainder = DensePolynomial {
            coeffs: self.remainder.clone(),
        };
        for (position, &evaluation) in zip(positions, &evaluations) {
            if remainder.evaluate(&root.pow([position as u64])) != evaluation {
                return Err(VerifyError::InvalidRemainder);
            }
        }

        Ok(())
    }
}
