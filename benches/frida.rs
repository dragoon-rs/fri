use std::path::Path;

use ark_ff::PrimeField;

use ark_serialize::CanonicalSerialize;
use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use fri::{
    algorithms::Blake3, dynamic_folding_factor, frida::{nth_evaluations, FridaBuilder, FridaCommitment}, rng::FriChallenger, utils::{to_evaluations, HasherExt}
};
use fri_test_utils::{
    random_file, Fq, BLOWUP_FACTOR, NUMBER_OF_POLYNOMIALS, NUM_QUERIES, POLY_COEFFS_LEN,
};
use rand::{thread_rng, Rng};

/// Parameter to use as the input variable of a parametric bench
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
enum ParameterOfInterest {
    #[default]
    FileSize,
    DegreeBound,
    #[allow(dead_code)]
    NumberOfPolynomials,
    FoldingFactor,
}

impl ParameterOfInterest {
    fn get(self, folding_factor: usize, file_size: usize, k: usize, m: usize) -> usize {
        match self {
            Self::FileSize => file_size,
            Self::DegreeBound => k,
            Self::NumberOfPolynomials => m,
            Self::FoldingFactor => folding_factor,
        }
    }
}

struct FridaParametricBencher<'a> {
    criterion: &'a mut Criterion,
    id: String,
    parameters: Vec<(usize, usize, usize, usize)>,
    interest: ParameterOfInterest,
}

impl<'a> FridaParametricBencher<'a> {
    /// `id` should be a unique and clear identifier of this bench.
    fn new<S: ToString>(c: &'a mut Criterion, id: S) -> Self {
        if !Path::new("target/proof_sizes").try_exists().unwrap() {
            std::fs::create_dir("target/proof_sizes").unwrap();
        }
        Self {
            criterion: c,
            id: id.to_string(),
            parameters: vec![],
            interest: ParameterOfInterest::default(),
        }
    }

    /// Sets the parameter that is tested by this [`FridaParameterBencher`].
    /// The default value is [`ParameterOfInterest::FileSize`].
    /// 
    /// `add_parameters` should not be called (and should not have been called until now) twice with the 
    // same value for this parameter.
    fn set_parameter_of_interest(&mut self, parameter: ParameterOfInterest) {
        self.interest = parameter;
    }

    /// Adds a set of parameters to be benchmarked.
    /// 
    /// - `byte_size` must be `Fq::MODULUS_BIT_SIZE / 8 * k * m`. It is still required as an argument
    ///   because it is computed anyway in the caller functions.
    /// - Note that `k` is the degree bound of the polynomial; the actual domain size in FRI will be
    ///   [`BLOWUP_FACTOR`] times greater. 
    /// - `folding_factor` must be 2, 4, 8 or 16. 
    /// - `k` must be a power of `folding_factor`
    fn add_parameters(&mut self, folding_factor: usize, byte_size: usize, k: usize, m: usize) {
        self.parameters.push((folding_factor, byte_size, k, m));
    }

    /// Benchmarks, for each set of parameters specified in `add_parameters`,
    ///  - the time to build a Frida commitment + one proof for each shard
    ///  - the total byte size of the commitment + the proofs,
    ///  - the time to verify a Frida commitment,
    ///  - the time to verify the proof for a random shard in the domain.
    /// 
    /// This blocks until all the benches complete. This panics if any of the combination of parameters specified
    /// in `add_parameters` is invalid.
    fn bench(self) {
        let c = self.criterion;
        let id = &self.id;

        // BENCH BUILD PROOF
        let mut group_prove = c.benchmark_group(format!("prove_time_{id}"));
        group_prove.sample_size(10);

        let mut sizes =
            csv::Writer::from_path(format!("target/proof_sizes/proof_size_{id}.csv")).unwrap();

        for &(folding_factor, file_size, k, m) in &self.parameters {
            let parameter = self.interest.get(folding_factor, file_size, k, m);
            group_prove.bench_with_input(BenchmarkId::from_parameter(parameter), &m, |b, &m| {
                b.iter_batched(
                    || random_evaluations(k, m),
                    |file_evals| {
                        let builder: _ = frida_builder(folding_factor, &file_evals);

                        for i in 0..(k * BLOWUP_FACTOR) {
                            black_box(builder.prove_shards(&[i]));
                        }
                    },
                    BatchSize::LargeInput,
                );
            });

            let builder: _ = frida_builder(folding_factor, &random_evaluations(k, m));

            let mut size = 0;
            for i in 0..(k * BLOWUP_FACTOR) {
                size += builder.prove_shards(&[i]).compressed_size();
            }
            size += FridaCommitment::from(builder).compressed_size();

            sizes
                .write_record(&[parameter.to_string(), size.to_string()])
                .unwrap();
        }
        group_prove.finish();
        sizes.flush().unwrap();

        // BENCH VERIFY COMMIT
        let mut group_verify_commit = c.benchmark_group(format!("verify_commit_time_{id}"));
        group_verify_commit.sample_size(10);
        for &(folding_factor, file_size, k, m) in &self.parameters {
            group_verify_commit.bench_with_input(
                BenchmarkId::from_parameter(self.interest.get(folding_factor, file_size, k, m)),
                &m,
                |b, &m| {
                    b.iter_batched(
                        || {
                            FridaCommitment::from(frida_builder(
                                folding_factor,
                                &random_evaluations(k, m),
                            ))
                        },
                        |commit| {
                            dynamic_folding_factor!(let N = folding_factor =>
                                commit
                                    .verify::<N, _>(
                                        FriChallenger::<Blake3>::default(),
                                        NUM_QUERIES,
                                        k,
                                        k * BLOWUP_FACTOR,
                                    )
                                    .unwrap())
                        },
                        BatchSize::LargeInput,
                    )
                },
            );
        }
        group_verify_commit.finish();

        // BENCH VERIFY ONE PROOF
        let mut group_verify_proof = c.benchmark_group(format!("verify_proof_time_{id}"));
        group_verify_proof.sample_size(10);
        for &(folding_factor, file_size, k, m) in &self.parameters {
            group_verify_proof.bench_with_input(
                BenchmarkId::from_parameter(self.interest.get(folding_factor, file_size, k, m)),
                &m,
                |b, &m| {
                    b.iter_batched(
                        || {
                            let evals = random_evaluations(k, m);
                            let builder: _ = frida_builder(folding_factor, &evals);
                            let pos = thread_rng().gen_range(0..(k * BLOWUP_FACTOR));
                            let proof = builder.prove_shards(&[pos]);
                            (
                                FridaCommitment::from(builder),
                                proof,
                                pos,
                                Blake3::hash_item(
                                    &nth_evaluations(&evals, pos).collect::<Vec<_>>(),
                                ),
                            )
                        },
                        |(commit, proof, pos, eval)| {
                            assert!(proof.verify(
                                commit.tree_root(),
                                &[pos],
                                &[eval],
                                k * BLOWUP_FACTOR
                            ))
                        },
                        BatchSize::LargeInput,
                    )
                },
            );
        }
        group_verify_proof.finish();
    }
}

fn parametric_num_poly(c: &mut Criterion, k: usize, max_file_size: usize, folding_factor: usize) {
    let mut bencher = FridaParametricBencher::new(c, format!("k={k}_m=#,N={folding_factor}"));

    let mut num_poly = 1usize;
    let mut byte_size = k * Fq::MODULUS_BIT_SIZE as usize / 8;

    while byte_size <= max_file_size {
        bencher.add_parameters(folding_factor, byte_size, k, num_poly);
        num_poly *= 2;
        byte_size *= 2;
    }

    bencher.bench()
}

fn parametric_degree_bound(c: &mut Criterion, m: usize, max_file_size: usize, folding_factor: usize) {
    let mut bencher = FridaParametricBencher::new(c, format!("k=#_m={m},N={folding_factor}"));

    let mut k = folding_factor;
    let mut byte_size = k * m * Fq::MODULUS_BIT_SIZE as usize / 8;

    while byte_size <= max_file_size {
        bencher.add_parameters(folding_factor, byte_size, k, m);
        k *= folding_factor;
        byte_size *= folding_factor;
    }

    bencher.bench()
}

fn parametric_degree_bound_fixed_size(c: &mut Criterion, file_size: usize, folding_factor: usize) {
    let mut bencher = FridaParametricBencher::new(c, format!("k=#_m=#,N={folding_factor},nbytes={file_size}"));
    bencher.set_parameter_of_interest(ParameterOfInterest::DegreeBound);

    let mut k = folding_factor;
    let mut m = file_size * 8 / Fq::MODULUS_BIT_SIZE as usize / k;

    while k * m * Fq::MODULUS_BIT_SIZE as usize / 8 == file_size {
        bencher.add_parameters(folding_factor, file_size, k, m);
        k *= folding_factor;
        m /= folding_factor;
    }
    if m > 0 {
        println!(
            "Warning: Min `m` = {}. Cannot divide by {folding_factor} anymore.",
            file_size * 8 * folding_factor / Fq::MODULUS_BIT_SIZE as usize / k
        );
    }

    bencher.bench()
}

fn parametric_folding_factor(c: &mut Criterion, k: usize, m: usize) {
    let mut bencher = FridaParametricBencher::new(c, format!("k={k}_m={m},N=#"));
    bencher.set_parameter_of_interest(ParameterOfInterest::FoldingFactor);

    let file_size = m * k * Fq::MODULUS_BIT_SIZE as usize / 8;

    for folding_factor in [2, 4, 8, 16] {
        bencher.add_parameters(folding_factor, file_size, k, m);
    }

    bencher.bench()
}

fn random_evaluations(k: usize, m: usize) -> Vec<Vec<Fq>> {
    random_file::<Fq>(k, m)
        .into_iter()
        .map(|poly| to_evaluations(poly, k * BLOWUP_FACTOR))
        .collect()
}

fn frida_builder(folding_factor: usize, evaluations: &[Vec<Fq>]) -> FridaBuilder<Fq, Blake3> {
    dynamic_folding_factor!(let N = folding_factor =>
        FridaBuilder::<_, Blake3>::new::<N, _>(
            evaluations,
            FriChallenger::<Blake3>::default(),
            BLOWUP_FACTOR,
            1,
            NUM_QUERIES,
    ))
}

fn measure_frida(c: &mut Criterion) {
    /// Like in PCS-FED-ID, but not adapted to FRI
    const K1: usize = 64;
    /// More suitable degree for FRI
    const K2: usize = POLY_COEFFS_LEN;
    const MAX_FILE_SIZE: usize = 134_217_728; // 128 MiB
    const FOLDING_FACTOR: usize = 4;

    // Increasing file size with fixed `k`
    parametric_num_poly(c, K1, MAX_FILE_SIZE, FOLDING_FACTOR);
    parametric_num_poly(c, K2, MAX_FILE_SIZE, FOLDING_FACTOR);

    // Increasing file size with fixed `m`
    parametric_degree_bound(c, NUMBER_OF_POLYNOMIALS, MAX_FILE_SIZE, FOLDING_FACTOR);
    
    // Finding best folding factor
    parametric_folding_factor(c, K2, NUMBER_OF_POLYNOMIALS);

    // Finding best `k` for fixed file size
    parametric_degree_bound_fixed_size(c, 67_108_864, FOLDING_FACTOR);

}

criterion_group!(benches, measure_frida);
criterion_main!(benches);
