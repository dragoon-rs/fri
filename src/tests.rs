use fri_test_utils::{Fq, BLOWUP_FACTOR, DOMAIN_SIZE, NUMBER_OF_POLYNOMIALS, NUM_QUERIES, POLY_COEFFS_LEN};
use rand::{thread_rng, Rng};
use winter_math::{fields::f128::BaseElement, FieldElement, StarkField};
use winter_rand_utils::{rand_value, rand_vector};
use winter_utils::transpose_slice;

use crate::{
    algorithms::Blake3,
    build_proof, commit_polynomial,
    folding::FoldedEvaluations,
    rng::FriChallenger,
    utils::to_evaluations,
};

macro_rules! do_for_multiple_folding_factors {
    ($factor: ident = $($factors: literal),* => $action: block) => {
        {
            $({
                const $factor: usize = $factors;
                $action;
            })*
        }
    };
}

// This assumes winterfri is correct
#[test]
fn test_reduction() {
    for i in 0..NUMBER_OF_POLYNOMIALS {
        println!("Testing on polynomial {i}");

        let poly = rand_vector(POLY_COEFFS_LEN);
        let poly2 = convert_many(&poly);

        do_for_multiple_folding_factors!(FACTOR = 2, 4, 8, 16 => {
            println!("--Folding factor={FACTOR}");
            let mut evaluations = prepare_winterfell_poly(poly.clone());
            let mut evaluations2 = to_evaluations(poly2.clone(), DOMAIN_SIZE);
            assert_eq!(convert_many(&evaluations), evaluations2);

            while evaluations.len() > FACTOR {
                let alpha = rand_value();
                let alpha2 = convert(&alpha);

                let transposed = transpose_slice::<_, FACTOR>(&evaluations);
                evaluations = winter_fri::folding::apply_drp(&transposed, BaseElement::ONE, alpha);
                let folded = FoldedEvaluations::new(&evaluations2);
                evaluations2 = super::reduce_polynomial::<FACTOR, _>(&folded, alpha2, None);

                assert_eq!(convert_many(&evaluations), evaluations2);
            }
        });
    }
}

#[test]
fn test_prove_verify() {
    let mut rng = thread_rng();
    let poly: Vec<Fq> = (0..POLY_COEFFS_LEN).map(|_| rng.gen()).collect();

    do_for_multiple_folding_factors!(FACTOR = 2, 4, 8, 16 => {
        println!("--Folding factor={FACTOR}");

        let mut rng = FriChallenger::<Blake3>::default();
        let commitments = commit_polynomial::<FACTOR, _, Blake3, _>(poly.clone(), &mut rng, BLOWUP_FACTOR, FACTOR);
        let proof = build_proof(commitments, &mut rng, NUM_QUERIES);

        rng.reset();
        proof.verify::<FACTOR, _>(&mut rng, NUM_QUERIES, POLY_COEFFS_LEN, DOMAIN_SIZE).unwrap();

        assert!(proof.verify::<{FACTOR*2}, _>(&mut rng, NUM_QUERIES, POLY_COEFFS_LEN, DOMAIN_SIZE).is_err());
        assert!(proof.verify::<{FACTOR/2}, _>(&mut rng, NUM_QUERIES, POLY_COEFFS_LEN, DOMAIN_SIZE).is_err());

        assert!(proof.verify::<FACTOR, _>(&mut rng, NUM_QUERIES, POLY_COEFFS_LEN, DOMAIN_SIZE * 2).is_err());
        assert!(proof.verify::<FACTOR, _>(&mut rng, NUM_QUERIES, POLY_COEFFS_LEN, DOMAIN_SIZE / 2).is_err());

        assert!(proof.verify::<FACTOR, _>(&mut rng, NUM_QUERIES, POLY_COEFFS_LEN * 2, DOMAIN_SIZE).is_err());
        assert!(proof.verify::<FACTOR, _>(&mut rng, NUM_QUERIES, POLY_COEFFS_LEN / 2, DOMAIN_SIZE).is_err());

    });
}

fn prepare_winterfell_poly<F: StarkField>(mut poly: Vec<F>) -> Vec<F> {
    use winter_math::fft::{evaluate_poly, get_twiddles};
    poly.resize(DOMAIN_SIZE, F::ZERO);
    let twiddles = get_twiddles(DOMAIN_SIZE);
    evaluate_poly(&mut poly, &twiddles);
    poly
}

fn convert(value: &BaseElement) -> Fq {
    Fq::from(value.as_int())
}

fn convert_many(values: &[BaseElement]) -> Vec<Fq> {
    values.iter().map(convert).collect()
}
