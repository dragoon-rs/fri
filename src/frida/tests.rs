use fri_test_utils::{
    do_for_multiple_folding_factors, random_file, Fq, BLOWUP_FACTOR, DOMAIN_SIZE,
    NUMBER_OF_POLYNOMIALS, NUM_QUERIES, POLY_COEFFS_LEN,
};
use rand::{thread_rng, Rng};

use crate::{
    algorithms::Blake3,
    frida::{nth_evaluations, FridaCommitment},
    rng::FriChallenger,
    utils::{to_evaluations, HasherExt},
};

use super::FridaBuilder;

#[test]
fn test_frida() {
    let rng = FriChallenger::<Blake3>::default();
    let file = random_file::<Fq>(POLY_COEFFS_LEN, NUMBER_OF_POLYNOMIALS)
        .into_iter()
        .map(|poly| to_evaluations(poly, DOMAIN_SIZE))
        .collect::<Vec<_>>();

    do_for_multiple_folding_factors!(FACTOR = 2, 4, 8, 16 => {
        let builder =
            FridaBuilder::<_, Blake3>::new::<FACTOR, _>(&file, rng.clone(), BLOWUP_FACTOR, 1, NUM_QUERIES);

        let mut rng = thread_rng();

        let position = rng.gen_range(0..DOMAIN_SIZE);
        let proof = builder.prove_shards(&[position]);

        let mut positions = [rng.gen_range(0..DOMAIN_SIZE), rng.gen_range(0..DOMAIN_SIZE)];
        positions.sort();
        let proof2 = builder.prove_shards(&positions);

        let commit = FridaCommitment::from(builder);

        let rng = FriChallenger::<Blake3>::default();
        commit
            .verify::<FACTOR, _>(rng.clone(), NUM_QUERIES, POLY_COEFFS_LEN, DOMAIN_SIZE)
            .unwrap();

        assert!(commit.verify::<{FACTOR*2}, _>(rng.clone(), NUM_QUERIES, POLY_COEFFS_LEN, DOMAIN_SIZE).is_err());
        assert!(commit.verify::<{FACTOR/2}, _>(rng.clone(), NUM_QUERIES, POLY_COEFFS_LEN, DOMAIN_SIZE).is_err());

        assert!(commit.verify::<FACTOR, _>(rng.clone(), NUM_QUERIES, POLY_COEFFS_LEN, DOMAIN_SIZE / 2).is_err());
        assert!(commit.verify::<FACTOR, _>(rng.clone(), NUM_QUERIES, POLY_COEFFS_LEN, DOMAIN_SIZE * 2).is_err());

        assert!(commit.verify::<FACTOR, _>(rng.clone(), NUM_QUERIES, POLY_COEFFS_LEN / 2, DOMAIN_SIZE).is_err());

        assert!(proof.verify(commit.tree_root(), &[position], &[Blake3::hash_item(&nth_evaluations(&file, position).collect::<Vec<_>>())], DOMAIN_SIZE));
        assert!(!proof.verify(commit.tree_root(), &[position], &[Blake3::hash_item(&nth_evaluations(&file, position + 1).collect::<Vec<_>>())], DOMAIN_SIZE));

        assert!(proof2.verify(commit.tree_root(), &positions, &Blake3::hash_many(&positions.iter().map(|&p| nth_evaluations(&file, p).collect::<Vec<_>>()).collect::<Vec<_>>()), DOMAIN_SIZE));

    });
}
