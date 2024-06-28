//! Implementation of FRIDA scheme above FRI
//! [https://eprint.iacr.org/2024/248.pdf]
//!
//! This module is gated by crate feature `frida`.

use ark_ff::{FftField, Field};
use derive_more::From;
use derive_where::derive_where;
use fri_proc_macros::{CanonicalDeserializeAlt, CanonicalSerializeAlt};
use rs_merkle::{Hasher, MerkleTree};

use crate::{
    build_proof,
    folding::fold_positions,
    rng::{MemoryRng, ReseedableRng},
    utils::{HasherExt, MerkleProof},
    FriCommitments, FriProof, VerifyError,
};

#[cfg(feature = "frida_pcs")]
mod pcs;
#[cfg(feature = "frida_pcs")]
pub use pcs::*;

#[derive(From, Clone, Copy, PartialEq, Eq, Debug)]
pub enum FridaError {
    InvalidFriProof(VerifyError),
    InvalidZippedQueries,
}

/// This is the base entry point when creating proofs using FRIDA.
#[derive_where(Clone; F)]
pub struct FridaBuilder<F, H: Hasher> {
    tree: MerkleTree<H>,
    fri_proof: FriProof<F, H>,
    zipped_queries: Vec<Vec<F>>,
}

impl<F: FftField, H: Hasher> FridaBuilder<F, H> {
    /// Creates a [`FridaBuilder`]. This computes a bacthed FRI proof.
    ///
    /// - `evaluations` must contain `m` vectors of the same size, corresponding to the evaluations of `m`
    ///    polynomials over the same domain, of size `M`.
    ///
    /// See [`FriCommitments::new`] and [`build_proof`] for more information.
    ///
    /// # Panics
    /// This panics if the arguments are invalid. See [`FriCommitments::new`] and [`build_proof`].
    pub fn new<const N: usize, R>(
        evaluations: &[Vec<F>],
        mut rng: R,
        blowup_factor: usize,
        remainder_degree_plus_one: usize,
        num_queries: usize,
    ) -> Self
    where
        R: ReseedableRng<Seed = H::Hash>,
    {
        let domain_size = evaluations[0].len();
        let mut batched = Vec::with_capacity(domain_size);

        let mut leaf = Vec::with_capacity(evaluations.len());
        for i in 0..domain_size {
            leaf.extend(nth_evaluations(evaluations, i));
            batched.push(H::hash_item(&leaf));
            leaf.clear();
        }
        let tree = MerkleTree::<H>::from_leaves(&batched);

        rng.reseed(tree.root().unwrap());

        let alpha = rng.draw_alpha();
        let combined_poly = batch_polynomials(evaluations, alpha);

        let commitments = FriCommitments::<N, _, _>::new(
            combined_poly,
            &mut rng,
            blowup_factor,
            remainder_degree_plus_one,
        );

        let mut rng = MemoryRng::from(rng);
        let proof = build_proof(commitments, &mut rng, num_queries);

        let positions = rng.last_positions();
        let zipped_queries = positions
            .iter()
            .map(|&pos| nth_evaluations(evaluations, pos).collect())
            .collect();

        Self {
            tree,
            fri_proof: proof,
            zipped_queries,
        }
    }

    /// Creates a proof for the shards at `positions`.
    /// The `positions` must be sorted, otherwise the proof won't be valid.
    ///
    /// Using more than one position makes the shards interdependent: all the shards will be
    /// necessary to check the proof later.
    #[inline]
    pub fn prove_shards(&self, positions: &[usize]) -> MerkleProof<H> {
        self.tree.proof(positions).into()
    }

    #[inline]
    fn tree_root(&self) -> H::Hash {
        self.tree.root().unwrap()
    }
}

/// The common commitment of FRIDA. A commitment can be created from a [`FridaBuilder`]:
/// `let commitment = builder.into();`
///
/// Here, the word "commitment" refers to commitments in polynomial commitment schemes, and not to
/// the COMMIT phase in FRI.
#[derive_where(Clone, PartialEq; F)]
#[derive(CanonicalDeserializeAlt, CanonicalSerializeAlt)]
pub struct FridaCommitment<F, H: Hasher> {
    zipped_root: H::Hash,
    zipped_queries: Vec<Vec<F>>,
    fri_proof: FriProof<F, H>,
}

impl<F: FftField, H: Hasher> FridaCommitment<F, H> {
    /// The root of the Merkle tree of the initial polynomials. Only this root is necessary to verify individual
    /// shards (under the assumption the [`FridaCommitment`] is already verified).
    #[inline]
    pub const fn tree_root(&self) -> H::Hash {
        self.zipped_root
    }
    /// Verifies the commitment is valid.
    ///
    /// After the commitment is verified, individual shards can be verified without verifying the commitment
    /// again.
    pub fn verify<const N: usize, R: ReseedableRng<Seed = H::Hash>>(
        &self,
        rng: R,
        num_queries: usize,
        degree_bound: usize,
        domain_size: usize,
    ) -> Result<(), FridaError> {
        let mut rng = MemoryRng::from(rng);
        rng.reseed(self.zipped_root);
        let alpha = rng.draw_alpha();

        self.fri_proof
            .verify::<N, _>(&mut rng, num_queries, degree_bound, domain_size)?;

        let positions = rng.last_positions();
        let folded_postions = fold_positions(positions, domain_size / N);
        let queried = self
            .fri_proof
            .first_layer()
            .queried_evaluations::<N>(positions, &folded_postions, domain_size)
            .unwrap();

        if queried != batch_polynomials(&self.zipped_queries, alpha) {
            return Err(FridaError::InvalidZippedQueries);
        }

        Ok(())
    }
}

impl<F: FftField, H: Hasher> From<FridaBuilder<F, H>> for FridaCommitment<F, H> {
    fn from(value: FridaBuilder<F, H>) -> Self {
        let zipped_root = value.tree_root();
        Self {
            zipped_root,
            zipped_queries: value.zipped_queries,
            fri_proof: value.fri_proof,
        }
    }
}

/// Returns the evaluations of the polynomial `P` which is the linear combination of the input polynomials `P_i`.
/// 
/// `P = P_0 + alpha*P_1 + ... + alpha^(n-1)P_n-1)`
pub fn batch_polynomials<F: Field>(evaluations: &[Vec<F>], alpha: F) -> Vec<F> {
    let mut combined_poly = Vec::with_capacity(evaluations[0].len());
    for i in 0..evaluations[0].len() {
        combined_poly.push(
            nth_evaluations(evaluations, i).rfold(F::ZERO, |result, eval| result * alpha + eval),
        )
    }
    combined_poly
}

/// Returns `(poly[n] for poly in evaluations)`
#[inline]
fn nth_evaluations<F: Copy>(
    evaluations: &[Vec<F>],
    n: usize,
) -> impl DoubleEndedIterator<Item = F> + '_ {
    evaluations.iter().map(move |poly| poly[n])
}
