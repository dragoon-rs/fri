use ark_ff::FftField;
use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use fri::{
    algorithms::{Blake3, Sha3_256, Sha3_512},
    build_proof, commit_polynomial,
    rng::{FriChallenger, ReseedableRng},
};
use fri_test_utils::{do_for_multiple_folding_factors, Fq};
use rand::thread_rng;
use rs_merkle::Hasher;

struct Params {
    nb_coeffs: usize,
    folding_factor: usize,
    blowup_factor: usize,
    remainder_plus_one: usize,
    nb_queries: usize,
    domain_size: usize,
}

impl std::fmt::Display for Params {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "k={},N={},bf={},rpo={},q={},d={}",
            self.nb_coeffs,
            self.folding_factor,
            self.blowup_factor,
            self.remainder_plus_one,
            self.nb_queries,
            self.domain_size
        )
    }
}

fn bench_commit_template<const N: usize, F: FftField, H: Hasher, R: ReseedableRng<Seed = H::Hash>>(
    c: &mut Criterion,
    params: &Params,
) where
    <H as rs_merkle::Hasher>::Hash: AsRef<[u8]>,
{
    c.bench_function(
        &format!("commit {},h='{}'", params, std::any::type_name::<H>(),),
        |b| {
            b.iter_batched(
                || {
                    let mut rng = thread_rng();
                    (0..params.nb_coeffs).map(|_| F::rand(&mut rng)).collect()
                },
                |poly| {
                    let rng = FriChallenger::<H>::default();
                    let _c = commit_polynomial::<N, F, H, _>(
                        poly,
                        rng,
                        params.blowup_factor,
                        params.remainder_plus_one,
                    );
                },
                BatchSize::SmallInput,
            )
        },
    );
}

fn bench_query_template<const N: usize, F: FftField, H: Hasher, R: ReseedableRng<Seed = H::Hash>>(
    c: &mut Criterion,
    params: &Params,
) where
    <H as rs_merkle::Hasher>::Hash: AsRef<[u8]>,
{
    c.bench_function(
        &format!("query {},h='{}'", params, std::any::type_name::<H>(),),
        |b| {
            b.iter_batched(
                || {
                    let mut rng = thread_rng();
                    let poly = (0..params.nb_coeffs).map(|_| F::rand(&mut rng)).collect();
                    let mut rng = FriChallenger::<H>::default();
                    let commitments = commit_polynomial::<N, F, H, _>(
                        poly,
                        &mut rng,
                        params.blowup_factor,
                        params.remainder_plus_one,
                    );
                    (rng, commitments)
                },
                |(rng, commitments)| {
                    let _c = build_proof(commitments, rng, params.nb_queries);
                },
                BatchSize::SmallInput,
            )
        },
    );
}

fn bench_verify_template<const N: usize, F: FftField, H: Hasher, R: ReseedableRng<Seed = H::Hash>>(
    c: &mut Criterion,
    params: &Params,
) where
    <H as rs_merkle::Hasher>::Hash: AsRef<[u8]>,
{
    c.bench_function(
        &format!("verify {},h='{}'", params, std::any::type_name::<H>(),),
        |b| {
            b.iter_batched(
                || {
                    let mut rng = thread_rng();
                    let poly = (0..params.nb_coeffs).map(|_| F::rand(&mut rng)).collect();
                    let mut rng = FriChallenger::<H>::default();
                    let commitments = commit_polynomial::<N, F, H, _>(
                        poly,
                        &mut rng,
                        params.blowup_factor,
                        params.remainder_plus_one,
                    );
                    build_proof(commitments, rng, params.nb_queries)
                },
                |proof| {
                    let rng = FriChallenger::<H>::default();
                    let () = proof
                        .verify::<N, _>(
                            rng,
                            params.nb_queries,
                            params.nb_coeffs,
                            params.domain_size,
                        )
                        .unwrap();
                },
                BatchSize::SmallInput,
            )
        },
    );
}

fn bench_fri<F: FftField, H: Hasher, R: ReseedableRng<Seed = H::Hash>>(c: &mut Criterion)
where
    <H as rs_merkle::Hasher>::Hash: AsRef<[u8]>,
{
    for (k, bf, rpo, q, d) in [(4096, 4, 1, 32, 4 * 4096)] {
        do_for_multiple_folding_factors!(N = 4 => {
            let params = Params {
                nb_coeffs: k,
                folding_factor: N,
                blowup_factor: bf,
                remainder_plus_one: rpo,
                nb_queries: q,
                domain_size: d,
            };
            bench_commit_template::<N, F, H, R>(c, &params);
            bench_query_template::<N, F, H, R>(c, &params);
            bench_verify_template::<N, F, H, R>(c, &params);
        })
    }
}

criterion_group!(
    benches,
    bench_fri::<Fq, Blake3, FriChallenger<Blake3>>,
    bench_fri::<Fq, Sha3_256, FriChallenger<Sha3_256>>,
    bench_fri::<Fq, Sha3_512, FriChallenger<Sha3_512>>,
);
criterion_main!(benches);
