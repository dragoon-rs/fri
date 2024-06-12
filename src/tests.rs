use ark_ff::{Fp128, MontBackend, MontConfig};
use winter_math::{fields::f128::BaseElement, FieldElement, StarkField};
use winter_rand_utils::{rand_value, rand_vector};
use winter_utils::transpose_slice;

use crate::{to_evaluations, FoldedEvaluations};

const NUMBER_OF_POLYNOMIALS: usize = 10;
const POLY_COEFFS_LEN: usize = 2048;
const BLOWUP_FACTOR: usize = 4;

const DOMAIN_SIZE: usize = (POLY_COEFFS_LEN * BLOWUP_FACTOR).next_power_of_two();

/// Matches `BaseElement` from winterfell
#[derive(MontConfig)]
#[modulus = "340282366920938463463374557953744961537"]
#[generator = "3"]
pub struct Test;
/// A prime, fft-friendly field isomorph to [`winter_math::fields::f128::BaseElement`].
pub type Fq = Fp128<MontBackend<Test, 2>>;

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

        let poly = rand_vector(DOMAIN_SIZE);
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

#[inline]
fn prepare_winterfell_poly<F: StarkField>(mut poly: Vec<F>) -> Vec<F> {
    use winter_math::fft::{evaluate_poly, get_twiddles};
    poly.resize(DOMAIN_SIZE, F::ZERO);
    let twiddles = get_twiddles(DOMAIN_SIZE);
    evaluate_poly(&mut poly, &twiddles);
    poly
}

#[inline]
pub fn convert(value: &BaseElement) -> Fq {
    Fq::from(value.as_int())
}

#[inline]
pub fn convert_many(values: &[BaseElement]) -> Vec<Fq> {
    values.iter().map(convert).collect()
}
