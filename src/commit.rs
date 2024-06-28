use ark_ff::FftField;
use ark_poly::{EvaluationDomain, GeneralEvaluationDomain};
use ark_serialize::CanonicalSerialize;
use rs_merkle::{Hasher, MerkleTree};

use crate::{
    folding::{reduce_polynomial, FoldedEvaluations},
    rng::ReseedableRng,
    utils::{to_polynomial, AssertPowerOfTwo, HasherExt, MerkleTreeExt},
};

#[derive(Clone)]
pub(crate) struct FriLayer<const N: usize, F, H: Hasher> {
    tree: MerkleTree<H>,
    evaluations: FoldedEvaluations<N, F>,
}

impl<const N: usize, F, H: Hasher> FriLayer<N, F, H> {
    pub fn new(evaluations: &[F]) -> Self
    where
        F: CanonicalSerialize + Clone,
    {
        let evaluations = FoldedEvaluations::new(evaluations);
        let tree = MerkleTree::from_evaluations(evaluations.as_ref());
        Self { tree, evaluations }
    }
    pub const fn tree(&self) -> &MerkleTree<H> {
        &self.tree
    }
    pub const fn evaluations(&self) -> &FoldedEvaluations<N, F> {
        &self.evaluations
    }
}

/// Result of a polynomial folding (FRI COMMIT phase).
///
/// Use [`crate::commit_polynomial`] to create a [`FriCommitments`] from a polynomial in coefficient form,
/// or [`FriCommitments::new`] to create it from the evaluations directly.
///
/// Use [`crate::build_proof`] to get an actual FRI proof from a [`FriCommitments`].
#[derive(Clone)]
pub struct FriCommitments<const N: usize, F, H: Hasher> {
    layers: Vec<FriLayer<N, F, H>>,
    remainder: Vec<F>,
}

impl<const N: usize, F: FftField, H: Hasher> FriCommitments<N, F, H> {
    /// Commits the polynomial according to FRI algorithm.
    /// - `evaluations` is the list of evaluations of the polynomial on the `n`-th roots of unity
    ///    (where `n = evaluations.len()`).
    ///
    /// See [`crate::commit_polynomial`] for information about the other parameters.
    ///
    /// # Panics
    /// This may either panic or have unspecified behaviour if `remainder_degree_plus_one` is inconsistent with
    /// the degree-bound of the polynomial and the folding factor, or if `F` does not contain a subgroup of size
    /// `evaluations.len()`.
    pub fn new<R>(
        mut evaluations: Vec<F>,
        mut rng: R,
        blowup_factor: usize,
        remainder_degree_plus_one: usize,
    ) -> Self
    where
        R: ReseedableRng<Seed = H::Hash>,
    {
        let _: () = AssertPowerOfTwo::<N>::OK;

        let degree_bound = evaluations.len() / blowup_factor;
        debug_assert!(
            (degree_bound.ilog2() - remainder_degree_plus_one.ilog2()) % N.ilog2() == 0,
            "Invalid remainder degree {} for polynomial of degree {} and folding factor {N} (would result in degree truncation)",
            remainder_degree_plus_one - 1,
            degree_bound - 1
        );

        let mut layers = Vec::with_capacity(
            ((degree_bound.ilog2() - remainder_degree_plus_one.ilog2()) / N.ilog2()) as usize,
        );

        // Reduce the polynomial from its evaluations:
        let domain = GeneralEvaluationDomain::<F>::new(N).unwrap();
        while evaluations.len() > remainder_degree_plus_one * blowup_factor {
            let layer = FriLayer::new(&evaluations);
            rng.reseed(layer.tree().root().expect("cannot get tree root"));
            evaluations =
                reduce_polynomial::<N, _>(layer.evaluations(), rng.draw_alpha(), Some(&domain));

            layers.push(layer);
        }

        // Commit remainder directly
        let poly = to_polynomial(evaluations, remainder_degree_plus_one);
        rng.reseed(H::hash_item(&poly));

        Self {
            layers,
            remainder: poly,
        }
    }
    pub(crate) fn layers(&self) -> &[FriLayer<N, F, H>] {
        &self.layers
    }
    pub(crate) fn remainder(self) -> Vec<F> {
        self.remainder
    }
}
