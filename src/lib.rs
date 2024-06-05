use ark_ff::FftField;
use ark_poly::{
    univariate::DensePolynomial, DenseUVPolynomial, EvaluationDomain, GeneralEvaluationDomain,
    Polynomial,
};
use rs_merkle::{Hasher, MerkleTree};

pub fn commit_polynomial<const N: usize, F: FftField, P: DenseUVPolynomial<F>>(
    polynomial: &P,
    commitments: &mut Vec<Vec<F>>,
    blowup_factor: usize,
    remainder_degree: usize,
) {
    let domain_size = (polynomial.coeffs().len() * blowup_factor)
        .checked_next_power_of_two()
        .expect(&format!(
            "Domain size out of bounds for blowup factor {blowup_factor} and polynomial of degree-bound {}", polynomial.coeffs().len()
        ));

    let domain = GeneralEvaluationDomain::<F>::new(domain_size).unwrap();
    let mut evaluations = polynomial.coeffs().to_vec();
    domain.fft_in_place(&mut evaluations);

    let domain = GeneralEvaluationDomain::<F>::new(N).unwrap();
    while evaluations.len() > remainder_degree {
        commitments.push(evaluations.clone());
        evaluations = reduce_polynomial::<N, _, _>(&evaluations, &domain, F::GENERATOR);
    }

    // TODO commit last
    commitments.push(evaluations);
}

fn reduce_polynomial<const N: usize, F: FftField, D: EvaluationDomain<F>>(
    evaluations: &[F],
    domain: &D,
    alpha: F,
) -> Vec<F> {
    debug_assert!(
        evaluations.len().is_power_of_two(),
        "Number of evaluations must be a power of two"
    );
    debug_assert!(
        N < evaluations.len(),
        "Too few evaluations to reduce polynomial by N"
    );
    debug_assert!(N.is_power_of_two(), "Folding factor must be a power of two");
    debug_assert_eq!(domain.size(), N, "Evaluation domain must be of size N");

    let mut buffer = Vec::with_capacity(N);

    let bound = evaluations.len().div_ceil(N);
    let mut new_evaluations = Vec::with_capacity(bound);

    let root_inv = F::get_root_of_unity(evaluations.len() as u64)
        .unwrap()
        .pow([evaluations.len() as u64 - 1]);
    let mut offset = F::ONE;

    for i in 0..bound {
        buffer.extend(evaluations.iter().skip(i).step_by(bound));
        domain.ifft_in_place(&mut buffer);

        let mut factor = F::ONE;
        for coeff in &mut buffer {
            *coeff *= factor;
            factor *= offset;
        }
        offset *= root_inv;

        let poly = DensePolynomial { coeffs: buffer };
        new_evaluations.push(poly.evaluate(&alpha));

        buffer = poly.coeffs;
        buffer.clear();
    }
    new_evaluations
}
