use ark_ff::{FftField, UniformRand};
use rand::thread_rng;

use fri::{
    algorithms::Sha3_512, build_proof, commit_polynomial, rng::FriChallenger,
    utils::to_evaluations, FriProof,
};
use fri_test_utils::Fq;

use rs_merkle::Hasher;

struct Params {
    nb_coeffs: usize,
    blowup_factor: usize,
    remainder_plus_one: usize,
    nb_queries: usize,
    domain_size: usize,
}

fn run_manual<const N: usize, F: FftField, H: Hasher>(poly: Vec<F>, params: &Params)
where
    <H as rs_merkle::Hasher>::Hash: AsRef<[u8]>,
{
    let mut challenge = FriChallenger::<H>::default();
    let commitments = commit_polynomial::<N, F, H, _>(
        poly,
        &mut challenge,
        params.blowup_factor,
        params.remainder_plus_one,
    );
    let proof = build_proof(commitments, challenge, params.nb_queries);

    let challenge = FriChallenger::<H>::default();
    let () = proof
        .verify::<N, _>(
            challenge,
            params.nb_queries,
            params.nb_coeffs,
            params.domain_size,
        )
        .unwrap();
}

fn run_simple<const N: usize, F: FftField, H: Hasher>(poly: Vec<F>, params: &Params)
where
    <H as rs_merkle::Hasher>::Hash: AsRef<[u8]>,
{
    let proof = FriProof::<F, H>::prove::<N, _>(
        to_evaluations(poly, params.domain_size),
        FriChallenger::<H>::default(),
        params.blowup_factor,
        params.remainder_plus_one,
        params.nb_queries,
    );

    let challenge = FriChallenger::<H>::default();
    let () = proof
        .verify::<N, _>(
            challenge,
            params.nb_queries,
            params.nb_coeffs,
            params.domain_size,
        )
        .unwrap();
}

fn main() {
    let params = Params {
        nb_coeffs: 4096,
        blowup_factor: 4,
        domain_size: 4096 * 4,
        remainder_plus_one: 1,
        nb_queries: 32,
    };

    let mut rng = thread_rng();
    let poly: Vec<Fq> = (0..params.nb_coeffs).map(|_| Fq::rand(&mut rng)).collect();

    run_manual::<4, Fq, Sha3_512>(poly.clone(), &params);
    run_simple::<4, Fq, Sha3_512>(poly.clone(), &params);
}
