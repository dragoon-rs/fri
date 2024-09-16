//! Implements _Lagrange's polynomial interpolation_ as defined in
//! [Alin Bostan et al. 2018](https://mathexp.eu/chyzak/aecf-distrib/pdf/aecf-screen-1.1.pdf)
//!
//! This module focuses on section 5.3 of the book, entitled _Interpolation de Lagrange_, from page
//! 98 to page 103.

use std::{fmt::Debug, iter::zip, ops::Deref};

use ark_ff::FftField;
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    DenseUVPolynomial,
};

/// Stores a complete binary tree in a contiguous memory allocation
///
/// > this is the _owned_ version of [`VecBinarySubTree`]
#[derive(Clone, PartialEq, Eq)]
struct VecBinaryTree<F>(Vec<F>);
impl<F> Deref for VecBinaryTree<F> {
    type Target = VecBinarySubTree<F>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        VecBinarySubTree::from_slice(&self.0)
    }
}
impl<F: Debug> Debug for VecBinaryTree<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        (**self).fmt(f)
    }
}

#[derive(PartialEq, Eq)]
/// A binary tree where nodes are stored in a flat structure.
///
/// > this is the _sliced_ version of [`VecBinarySubTree`]
///
/// # Example
/// the following binary tree
/// ```text
/// 1
/// |--- 2
/// |    |--- 4
/// |    `--- 5
/// `--- 3
///      |--- 6
///      `--- 7
/// ```
/// will be stored in a [`VecBinarySubTree`] as follows
/// ```text
/// [4, 5, 2, 6, 7, 3, 1]
///  \_____/  \_____/  |
///   left     right  root
/// ```
struct VecBinarySubTree<F>([F]);

impl<F> VecBinarySubTree<F> {
    #[inline]
    const fn from_slice(slice: &[F]) -> &Self {
        unsafe { &*(slice as *const [F] as *const Self) }
    }
    #[inline]
    pub const fn root(&self) -> &F {
        &self.0[self.0.len() - 1]
    }
    #[inline]
    pub fn left_child(&self) -> Option<&Self> {
        (self.0.len() > 1).then(|| Self::from_slice(&self.0[..((self.0.len() - 1) / 2)]))
    }

    #[inline]
    pub fn right_child(&self) -> Option<&Self> {
        (self.0.len() > 1)
            .then(|| Self::from_slice(&self.0[((self.0.len() - 1) / 2)..(self.0.len() - 1)]))
    }
}

impl<F: Debug> Debug for VecBinarySubTree<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "\"{:?}\": [{:?}, {:?}]",
            self.root(),
            self.left_child(),
            self.right_child()
        )
    }
}

/// Implements the _Fast sub-product tree_ algorithm
///
/// > see algorithm 5.3 on page 101
#[inline]
fn subproduct_tree<F: FftField>(x: &[F]) -> VecBinaryTree<DensePolynomial<F>> {
    assert!(
        x.len().is_power_of_two(),
        "Number of points must be a power of two, found {}",
        x.len(),
    );

    let mut buffer = Vec::with_capacity(2 * x.len() - 1);
    aux(x, &mut buffer);
    return VecBinaryTree(buffer);

    fn aux<F: FftField>(x: &[F], tree: &mut Vec<DensePolynomial<F>>) {
        if x.len() == 1 {
            tree.push(DensePolynomial::from_coefficients_slice(&[-x[0], F::ONE]));
        } else {
            let offset = tree.len();
            let (x1, x2) = x.split_at(x.len() / 2);
            aux(x1, tree);
            aux(x2, tree);

            let len = tree.len();
            let poly1 = &tree[offset + (len - offset) / 2 - 1];
            let poly2 = &tree[len - 1];

            // Multiplication is in `O(d*ln(d))`
            tree.push(poly1 * poly2);
        }
    }
}

/// Implements the _Fast fraction sum_ algorithm
///
/// > see algorithm 5.6 on page 103
fn fast_fraction_sum<F: FftField>(
    subproducts: &VecBinarySubTree<DensePolynomial<F>>,
    c: &[F],
) -> DensePolynomial<F> {
    if c.len() == 1 {
        DensePolynomial::from_coefficients_slice(&[c[0]])
    } else {
        let a1 = subproducts.left_child().unwrap();
        let a2 = subproducts.right_child().unwrap();
        let (c1, c2) = c.split_at(c.len() / 2);

        let n1 = fast_fraction_sum(a1, c1);
        let n2 = fast_fraction_sum(a2, c2);

        let p1 = a1.root();
        let p2 = a2.root();

        &n1 * p2 + &n2 * p1
    }
}

/// Evaluates `poly`, which is of degree `d`, on each value of `points`, which is of size `n`.
///
/// > /!\ **Warning**
/// >
/// > `n` must be a power of two strictly greater than `d`
///
/// This is more efficient than computing the evaluations separately.
///
/// This function is intended to be used when the structure of `points` has no particular property.
/// If `points` is an FFT domain, consider using [`DensePolynomial::evaluate_over_domain`] instead.
///
/// > :bulb: **Reference**
/// >
/// > see algorithm 5.5 page 102
#[inline]
fn multipoint_evaluation<F: FftField>(
    poly: DensePolynomial<F>,
    subproducts: &VecBinarySubTree<DensePolynomial<F>>,
) -> Vec<F> {
    let mut output = Vec::with_capacity((subproducts.0.len() + 1) / 2);
    aux(poly, subproducts, &mut output);
    return output;

    fn aux<F: FftField>(
        poly: DensePolynomial<F>,
        subproducts: &VecBinarySubTree<DensePolynomial<F>>,
        output: &mut Vec<F>,
    ) {
        if poly.len() == 1 {
            output.push(poly[0]);
        } else {
            let left_tree = subproducts.left_child().unwrap();
            let right_tree = subproducts.right_child().unwrap();

            // TODO: check complexity of ark_poly division and optimize if needed
            let poly = DenseOrSparsePolynomial::from(poly);

            let p0 = poly
                .divide_with_q_and_r(&left_tree.root().into())
                .unwrap()
                .1;
            let p1 = poly
                .divide_with_q_and_r(&right_tree.root().into())
                .unwrap()
                .1;

            aux(p0, left_tree, output);
            aux(p1, right_tree, output);
        }
    }
}

/// Interpolates multiple polynomials based on their evaluations on the same evaluation points.
///
/// - `shards` must contain `m` vectors of size `k`, where `m` is the number of polynomials to interpolate, and
/// `k` is **a power of two** strictly greater than the degree of all the polynomials.
/// - `positions` must contain `k` distinct evaluation points, such that `shards[i][j]` is equal to
/// `P_i(positions[j])`.
///
/// If `positions` is an FFT domain, consider using an inverse FFT instead.
///
/// # Returns
/// A vector containing the `m` interpolated polynomials `P_i` in coefficient form.
///
/// # Panic
/// This function panics if:
/// - The number of evaluations of one of the polynomials does not match the number of evaluation points.
/// - `k` is not a power of two
pub fn interpolate_polynomials<F: FftField>(shards: &[Vec<F>], positions: &[F]) -> Vec<Vec<F>> {
    if shards.is_empty() {
        return vec![];
    }
    assert!(
        shards.iter().all(|shard| shard.len() == positions.len()),
        "The size of all the shards must match the number of positions"
    );

    let subproducts = subproduct_tree(positions);

    let mut root = subproducts.root().clone();

    for i in 1..root.coeffs.len() {
        root.coeffs[i - 1] = root.coeffs[i] * F::from(i as u64);
    }
    root.coeffs.pop();

    let d_inv = multipoint_evaluation(root, &subproducts)
        .into_iter()
        .map(|di| di.inverse().unwrap())
        .collect::<Vec<_>>();

    let mut polynomials = Vec::with_capacity(shards.len());

    for shard in shards {
        let c = zip(shard, &d_inv)
            .map(|(&bi, &di)| bi * di)
            .collect::<Vec<_>>();

        let r = fast_fraction_sum(&subproducts, &c);
        polynomials.push(r.coeffs);
    }

    polynomials
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, iter::zip, time};

    use crate::{
        interpolation::{multipoint_evaluation, subproduct_tree},
        utils::to_evaluations,
    };
    use ark_ff::{FftField, Field, Fp64, MontBackend, MontConfig};
    use ark_poly::{univariate::DensePolynomial, DenseUVPolynomial};
    use fri_test_utils::{random_file, Fq};
    use rand::{thread_rng, Rng};

    use super::interpolate_polynomials;

    #[derive(MontConfig)]
    #[modulus = "17"]
    #[generator = "3"]
    pub struct TestSmall;
    /// A very small, fft-friendly prime field to help debugging.
    pub type Fsmall = Fp64<MontBackend<TestSmall, 1>>;

    macro_rules! array_in_f {
        [$($i: expr),*] => {
            [$(Fsmall::from($i)),*]
        };
    }

    #[test]
    fn test_subproducts_and_multipoint() {
        let points = array_in_f![1, 5, 2, 6].to_vec();
        let tree = subproduct_tree(&points);

        assert_eq!(&tree.root().coeffs, &array_in_f![9, 7, 14, 3, 1]);
        assert_eq!(
            &tree.left_child().unwrap().root().coeffs,
            &array_in_f![5, 11, 1]
        );
        assert_eq!(
            &tree.right_child().unwrap().root().coeffs,
            &array_in_f![12, 9, 1]
        );
        assert_eq!(
            &tree
                .left_child()
                .unwrap()
                .left_child()
                .unwrap()
                .root()
                .coeffs,
            &array_in_f![16, 1]
        );
        assert_eq!(
            &tree
                .left_child()
                .unwrap()
                .right_child()
                .unwrap()
                .root()
                .coeffs,
            &array_in_f![12, 1]
        );
        assert_eq!(
            &tree
                .right_child()
                .unwrap()
                .left_child()
                .unwrap()
                .root()
                .coeffs,
            &array_in_f![15, 1]
        );
        assert_eq!(
            &tree
                .right_child()
                .unwrap()
                .right_child()
                .unwrap()
                .root()
                .coeffs,
            &array_in_f![11, 1]
        );

        let poly = DensePolynomial::from_coefficients_vec(array_in_f![4, 7, 2].to_vec());

        assert_eq!(
            &multipoint_evaluation(poly, &tree),
            &array_in_f![13, 4, 9, 16]
        );
    }

    #[test]
    fn test_interpolate_polynomials() {
        // NOTE: The parameters below are low to allow the test to run fast (< 1 second) even in debug mode.
        // If you increase `NUM_COEFFS` or `NUM_POLY`, make sure to run the test with optimizations (`--release`).

        const NUM_COEFFS: usize = 1024;
        const DOMAIN_SIZE: usize = 4096;
        const NUM_POLY: usize = 2;

        let polys = random_file::<Fq>(NUM_COEFFS, NUM_POLY);
        let evaluations = polys
            .clone()
            .into_iter()
            .map(|poly| to_evaluations(poly, DOMAIN_SIZE))
            .collect::<Vec<_>>();

        let mut shards = Vec::with_capacity(NUM_POLY);
        shards.resize_with(NUM_POLY, || Vec::with_capacity(NUM_COEFFS));

        let mut positions = Vec::with_capacity(NUM_COEFFS);
        let mut positions_set = HashSet::with_capacity(NUM_COEFFS);
        let mut rng = thread_rng();
        let root = Fq::get_root_of_unity(DOMAIN_SIZE as u64).unwrap();
        while positions.len() < NUM_COEFFS {
            let p = rng.gen_range(0..DOMAIN_SIZE);
            if !positions_set.contains(&p) {
                positions.push(root.pow(&[p as u64]));
                positions_set.insert(p);

                for (evaluation, shard) in zip(&evaluations, &mut shards) {
                    shard.push(evaluation[p]);
                }
            }
        }
        drop(positions_set);

        let start = time::Instant::now();
        let polys_inter = interpolate_polynomials(&shards, &positions);
        let end = time::Instant::now();

        assert_eq!(polys, polys_inter);

        println!("Total time: {} seconds", (end - start).as_secs_f64());
        println!(
            "Average time per polynomial: {} seconds",
            (end - start).as_secs_f64() / NUM_POLY as f64
        );
    }
}
