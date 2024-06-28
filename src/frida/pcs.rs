//! Implementation of trait `PolynomialCommitmentScheme` from `pcs-fec-id`.
//! See [https://gitlab.isae-supaero.fr/dragoon/pcs-fec-id.git]
//!
//! This should probably be moved directly into `pcs-fec-id` eventually.

use std::marker::PhantomData;

use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use derive_where::derive_where;
use fec::Shard;
use fri_proc_macros::{CanonicalDeserializeAlt, CanonicalSerializeAlt};
use proofs::PolynomialCommitmentScheme;
use rs_merkle::Hasher;

use crate::{
    rng::{FriChallenger, ReseedableRng},
    utils::{HasherExt, MerkleProof},
};

use super::{nth_evaluations, FridaBuilder, FridaCommitment};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FridaScheme<const N: usize, F, H> {
    field: PhantomData<F>,
    hasher: PhantomData<H>,
}

impl<const N: usize, F: FftField, H: Hasher> PolynomialCommitmentScheme for FridaScheme<N, F, H>
where
    H::Hash: AsRef<[u8]> + PartialEq,
{
    type Commit = FridaBuilder<F, H>;
    type Data = ([u8; 32], usize, Vec<Vec<F>>);
    type Point = usize;
    type Proof = FridaBlock<F, H>;
    type Setup<'a> = FridaOptions<H::Hash>;
    type VerifierKey<'b> = FridaOptions<H::Hash>;

    fn commit(
        data: Self::Data,
        setup: Option<Self::Setup<'_>>,
    ) -> Result<Self::Commit, proofs::Error> {
        let Some(options) = setup else {
            return Err(proofs::Error::SetupError);
        };
        let (_, _, evaluations) = data;

        let mut rng = FriChallenger::<H>::default();
        if let Some(seed) = options.init_seed {
            rng.reseed(seed);
        }
        Ok(FridaBuilder::new::<N, _>(
            &evaluations,
            rng,
            options.blowup_factor,
            options.remainder_degree + 1,
            options.num_queries,
        ))
    }
    fn prove(
        commit: Self::Commit,
        data: Self::Data,
        points: Option<&[Self::Point]>,
        setup: Option<Self::Setup<'_>>,
    ) -> Result<Vec<Self::Proof>, proofs::Error> {
        let Some(options) = setup else {
            return Err(proofs::Error::SetupError);
        };
        let Some(points) = points else {
            return Err(proofs::Error::ProofPointMissingError);
        };

        let (hash, nb_bytes, evaluations) = data;
        let k: u32 = (evaluations[0].len() / options.blowup_factor)
            .try_into()
            .unwrap();

        points
            .iter()
            .map(|&p| {
                let shard = nth_evaluations(&evaluations, p).collect::<Vec<_>>();
                let mut data = Vec::with_capacity(shard.compressed_size());
                // Consider adding an impl From<SerializationError> for proofs::Error
                shard
                    .serialize_compressed(&mut data)
                    .map_err(proofs::Error::SerializationError)?;

                let shard = Shard {
                    k,
                    i: p as u32,
                    hash: hash.to_vec(),
                    bytes: data,
                    size: nb_bytes,
                };

                // FIXME: the commitment is duplicated for each block,
                Ok(FridaBlock {
                    data: shard,
                    proof: commit.prove_shards(&[p]),
                    commitment: commit.clone().into(),
                })
            })
            .collect()
    }
    fn verify(
        proof: &Self::Proof,
        verifier_key: Option<Self::VerifierKey<'_>>,
    ) -> Result<bool, proofs::Error> {
        let Some(options) = verifier_key else {
            return Err(proofs::Error::VerifierKeyError);
        };
        if !verify_commitment::<N, _, _>(proof, options) {
            return Ok(false);
        }
        verify_proof(proof, options.blowup_factor)
    }
    fn batch_verify(
        proofs: &[Self::Proof],
        verifier_key: Option<Self::VerifierKey<'_>>,
    ) -> Result<bool, proofs::Error> {
        let Some(options) = verifier_key else {
            return Err(proofs::Error::VerifierKeyError);
        };

        let mut last_proof = None;
        for proof in proofs {
            //FIXME: is it safe to assume (without checking) that all the commitments are the same?
            if last_proof.map_or(true, |l| l != proof) {
                last_proof = Some(proof);
                if !verify_commitment::<N, _, _>(proof, options) {
                    return Ok(false);
                }
            }
            if !verify_proof(proof, options.blowup_factor)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[derive(Clone, Copy, Debug, CanonicalDeserializeAlt, CanonicalSerializeAlt)]
pub struct FridaOptions<H> {
    pub blowup_factor: usize,
    pub remainder_degree: usize,
    pub num_queries: usize,
    pub init_seed: Option<H>,
}

#[derive_where(Clone, PartialEq; F)]
#[derive(CanonicalDeserializeAlt, CanonicalSerializeAlt)]
pub struct FridaBlock<F, H: Hasher> {
    data: Shard,
    commitment: FridaCommitment<F, H>,
    proof: MerkleProof<H>,
}

fn verify_commitment<const N: usize, F: FftField, H: Hasher>(
    proof: &FridaBlock<F, H>,
    options: FridaOptions<H::Hash>,
) -> bool
where
    H::Hash: AsRef<[u8]>,
{
    let degree_bound = proof.data.k as usize;
    let mut rng = FriChallenger::<H>::default();
    if let Some(seed) = options.init_seed {
        rng.reseed(seed);
    }

    proof
        .commitment
        .verify::<N, _>(
            rng,
            options.num_queries,
            degree_bound,
            degree_bound * options.blowup_factor,
        )
        .is_ok()
}

fn verify_proof<F: FftField, H: Hasher>(
    proof: &FridaBlock<F, H>,
    blowup_factor: usize,
) -> Result<bool, proofs::Error> {
    let degree_bound = proof.data.k as usize;
    let data = <Vec<F>>::deserialize_compressed(&proof.data.bytes[..])
        .map_err(proofs::Error::SerializationError)?;

    Ok(proof.proof.verify(
        proof.commitment.tree_root(),
        &[proof.data.i as usize],
        &[H::hash_item(&data)],
        degree_bound * blowup_factor,
    ))
}
