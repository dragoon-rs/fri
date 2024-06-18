use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use fri::{algorithms::Blake3, build_proof, commit_polynomial, rng::FriChallenger};
use fri_test_utils::{Fq, BLOWUP_FACTOR, DOMAIN_SIZE, NUM_QUERIES, POLY_COEFFS_LEN};
use rand::{thread_rng, Rng};

fn bench_commit(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("commit", |b| {
        b.iter_batched(
            || (0..POLY_COEFFS_LEN).map(|_| rng.gen()).collect(),
            |poly| {
                let rng = FriChallenger::<Blake3>::default();
                let _c = commit_polynomial::<4, Fq, Blake3, _>(poly, rng, BLOWUP_FACTOR, 4);
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_query(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("query", |b| {
        b.iter_batched(
            || {
                let poly = (0..POLY_COEFFS_LEN).map(|_| rng.gen()).collect();
                let mut rng = FriChallenger::<Blake3>::default();
                let commitments =
                    commit_polynomial::<4, Fq, Blake3, _>(poly, &mut rng, BLOWUP_FACTOR, 4);
                (rng, commitments)
            },
            |(rng, commitments)| {
                let _c = build_proof(commitments, rng, NUM_QUERIES);
            },
            BatchSize::SmallInput,
        )
    });
}

fn bench_verify(c: &mut Criterion) {
    let mut rng = thread_rng();
    c.bench_function("verify", |b| {
        b.iter_batched(
            || {
                let poly = (0..POLY_COEFFS_LEN).map(|_| rng.gen()).collect();
                let mut rng = FriChallenger::<Blake3>::default();
                let commitments =
                    commit_polynomial::<4, Fq, Blake3, _>(poly, &mut rng, BLOWUP_FACTOR, 4);
                build_proof(commitments, &mut rng, NUM_QUERIES)
            },
            |proof| {
                let rng = FriChallenger::<Blake3>::default();
                let _c = proof
                    .verify::<4, _>(rng, NUM_QUERIES, POLY_COEFFS_LEN, DOMAIN_SIZE)
                    .unwrap();
            },
            BatchSize::SmallInput,
        )
    });
}

criterion_group!(benches, bench_commit, bench_query, bench_verify);
criterion_main!(benches);
