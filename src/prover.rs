use ark_ff::FftField;
use ark_serialize::CanonicalSerialize;
use rs_merkle::{Hasher, MerkleTree};

use crate::{FoldedEvaluations, MerkleTreeExt};

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
    pub fn tree(&self) -> &MerkleTree<H> {
        &self.tree
    }
    pub fn evaluations(&self) -> &FoldedEvaluations<N, F> {
        &self.evaluations
    }
}

#[must_use]
pub struct FriCommitments<const N: usize, F, H: Hasher> {
    layers: Vec<FriLayer<N, F, H>>,
    remainder: Vec<F>,
}

impl<const N: usize, F: FftField, H: Hasher> FriCommitments<N, F, H> {
    #[inline]
    pub(crate) fn new(degree_bound: usize) -> Self {
        let layers = Vec::with_capacity(degree_bound.ilog2().div_ceil(N.ilog2()) as usize);
        Self {
            layers,
            remainder: vec![],
        }
    }
    pub(crate) fn layers(&self) -> &[FriLayer<N, F, H>] {
        &self.layers
    }
    pub(crate) fn remainder(self) -> Vec<F> {
        self.remainder
    }
    #[inline]
    pub(crate) fn commit_layer(&mut self, layer: FriLayer<N, F, H>) {
        self.layers.push(layer);
    }
    pub(crate) fn set_remainder(&mut self, polynomial: Vec<F>) {
        self.remainder = polynomial;
    }
}
