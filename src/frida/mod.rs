//! Implementation of FRIDA scheme above FRI
//! <https://eprint.iacr.org/2024/248.pdf>
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
    utils::{horner_evaluate, HasherExt, MerkleProof},
    FriCommitments, FriProof, VerifyError,
};

#[cfg(test)]
mod tests;

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
    zipped_queries: Vec<F>,
    zipped_proof: MerkleProof<H>,
    num_poly: usize,
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

        let mut positions = std::mem::take(rng.last_positions_mut());
        let zipped_queries = positions
            .iter()
            .flat_map(|&pos| nth_evaluations(evaluations, pos))
            .collect();

        // `tree.proof` requires a sorted slice of positions without duplicates
        positions.sort_unstable();
        positions.dedup();
        let zipped_proof = tree.proof(&positions).into();

        Self {
            tree,
            fri_proof: proof,
            zipped_queries,
            zipped_proof,
            num_poly: evaluations.len(),
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
    zipped_queries: Vec<F>,
    zipped_proof: MerkleProof<H>,
    num_poly: usize,
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

        let mut positions = std::mem::take(rng.last_positions_mut());
        let folded_postions = fold_positions(&positions, domain_size / N);
        let queried = self
            .fri_proof
            .first_layer()
            .queried_evaluations::<N>(&positions, &folded_postions, domain_size)
            .unwrap();

        if queried.len() * self.num_poly != self.zipped_queries.len() {
            return Err(FridaError::InvalidZippedQueries);
        }

        let mut indices = (0..positions.len()).collect::<Vec<_>>();
        indices.sort_unstable_by(|&i, &j| positions[i].cmp(&positions[j]));
        indices.dedup_by(|&mut a, &mut b| positions[a] == positions[b]);

        positions.sort_unstable();
        positions.dedup();

        let hashes = indices
            .iter()
            .map(|i| {
                H::hash_item(&self.zipped_queries[(i * self.num_poly)..((i + 1) * self.num_poly)])
            })
            .collect::<Vec<_>>();
        if !self
            .zipped_proof
            .verify(self.zipped_root, &positions, &hashes, domain_size)
        {
            return Err(FridaError::InvalidZippedQueries);
        }

        for (i, &query) in queried.iter().enumerate() {
            if query
                != horner_evaluate(
                    &self.zipped_queries[(i * self.num_poly)..((i + 1) * self.num_poly)],
                    alpha,
                )
            {
                return Err(FridaError::InvalidZippedQueries);
            }
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
            zipped_proof: value.zipped_proof,
            fri_proof: value.fri_proof,
            num_poly: value.num_poly,
        }
    }
}

/// Returns the evaluations of the polynomial `P` which is the linear combination of the input polynomials `P_i`.
///
/// `P = P_0 + alpha*P_1 + ... + alpha^(n-1)P_n-1)`
pub fn batch_polynomials<F: Field>(evaluations: &[Vec<F>], alpha: F) -> Vec<F> {
    let mut combined_poly = Vec::with_capacity(evaluations[0].len());
    for i in 0..evaluations[0].len() {
        combined_poly.push(horner_evaluate(nth_evaluations(evaluations, i), alpha))
    }
    combined_poly
}

/// Returns `(poly[n] for poly in evaluations)`
#[inline]
pub fn nth_evaluations<F: Copy>(
    evaluations: &[Vec<F>],
    n: usize,
) -> impl DoubleEndedIterator<Item = F> + '_ {
    evaluations.iter().map(move |poly| poly[n])
}
