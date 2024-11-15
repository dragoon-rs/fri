use ark_ff::FftField;
use rand::{
    distributions::{Distribution, Standard},
    thread_rng, Rng,
};
use rs_merkle::Hasher;

use dragoonfri::{
    algorithms::Sha3_512,
    frida::{nth_evaluations, FridaBuilder, FridaCommitment},
    rng::FriChallenger,
    utils::{to_evaluations, HasherExt},
};
use dragoonfri_test_utils::Fq;

struct Params {
    nb_coeffs: usize,
    blowup_factor: usize,
    remainder_plus_one: usize,
    nb_queries: usize,
    domain_size: usize,
}

fn run<const N: usize, F: FftField, H: Hasher>(data: Vec<Vec<F>>, params: &Params)
where
    <H as rs_merkle::Hasher>::Hash: AsRef<[u8]>,
    Standard: Distribution<F>,
{
    let evaluations = data
        .into_iter()
        .map(|poly| to_evaluations(poly, params.domain_size))
        .collect::<Vec<_>>();

    let builder = FridaBuilder::<F, H>::new::<N, _>(
        &evaluations,
        FriChallenger::<H>::default(),
        params.blowup_factor,
        params.remainder_plus_one,
        params.nb_queries,
    );

    let mut rng = thread_rng();
    let position = rng.gen_range(0..params.domain_size);

    let proof = builder.prove_shards(&[position]);

    let commit = FridaCommitment::from(builder);

    commit
        .verify::<N, _>(
            FriChallenger::<H>::default(),
            params.nb_queries,
            params.nb_coeffs,
            params.domain_size,
        )
        .unwrap();

    assert!(proof.verify(
        commit.tree_root(),
        &[position],
        &[H::hash_item(
            &nth_evaluations(&evaluations, position).collect::<Vec<_>>()
        )],
        params.domain_size
    ));
}

fn main() {
    const PARAMS: Params = Params {
        nb_coeffs: 4096,
        blowup_factor: 4,
        domain_size: 4096 * 4,
        remainder_plus_one: 1,
        nb_queries: 32,
    };

    const M: usize = 3;

    run::<4, Fq, Sha3_512>(
        dragoonfri_test_utils::random_file::<Fq>(PARAMS.nb_coeffs, M),
        &PARAMS,
    );
}
