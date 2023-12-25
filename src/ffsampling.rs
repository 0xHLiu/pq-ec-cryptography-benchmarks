use itertools::{Either, Itertools};
use num_complex::{Complex, Complex64};
use rand_distr::num_traits::{One, Zero};

use crate::fft::split_fft;

/// Computes the Gram matrix. The argument must be a 2x2 matrix
/// whose elements are equal-length vectors of complex numbers,
/// representing polynomials in evaluation domain.
pub fn gram(b: [Vec<Complex64>; 4]) -> [Vec<Complex64>; 4] {
    const N: usize = 2;
    let mut g: [Vec<Complex<f64>>; 4] = (0..4)
        .map(|_| (0..b[0].len()).map(|_| Complex64::zero()).collect_vec())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    for i in 0..N {
        for j in 0..N {
            for k in 0..N {
                g[N * i + j] = g[N * i + j]
                    .iter()
                    .zip(
                        b[N * i + k]
                            .iter()
                            .zip(b[N * j + k].iter().map(|c| c.conj()))
                            .map(|(a, b)| a * b),
                    )
                    .map(|(a, b)| a + b)
                    .collect_vec();
            }
        }
    }
    g
}

pub fn ldl(g: [Vec<Complex64>; 4]) -> ([Vec<Complex64>; 4], [Vec<Complex64>; 4]) {
    let n = g[0].len();
    const N: usize = 2;

    let zero = (0..n).map(|_| Complex64::zero()).collect_vec();
    let one = (0..n).map(|_| Complex64::one()).collect_vec();

    let l10 = g[2]
        .iter()
        .zip(g[0].iter())
        .map(|(a, b)| a / b)
        .collect_vec();
    let bc = l10.iter().map(|c| c * c.conj());
    let abc = g[0].iter().zip(bc).map(|(a, bc)| a * bc);
    let d11 = g[3]
        .iter()
        .zip(abc)
        .map(|(g11, abc)| g11 - abc)
        .collect_vec();

    let l = [one.clone(), zero.clone(), l10.clone(), one];
    let d = [g[0].clone(), zero.clone(), zero, d11];
    (l, d)
}

#[derive(Debug, Clone)]
pub struct LdlTree {
    pub left: Either<Box<LdlTree>, Complex64>,
    pub right: Either<Box<LdlTree>, Complex64>,
    pub value: Vec<Complex64>,
}

/// Compute the LDL tree of G. Corresponds to Algorithm 9 of the
/// specification.
pub fn ffldl(g: [Vec<Complex64>; 4]) -> LdlTree {
    let n = g[0].len();
    let (l, d) = ldl(g);

    if n > 2 {
        let (d00, d01) = split_fft(&d[0]);
        let (d10, d11) = split_fft(&d[3]);
        let g0 = [
            d00.clone(),
            d01.clone(),
            d01.iter().map(|c| c.conj()).collect_vec(),
            d00,
        ];
        let g1 = [
            d10.clone(),
            d11.clone(),
            d11.iter().map(|c| c.conj()).collect_vec(),
            d10,
        ];
        LdlTree {
            left: Either::Left(Box::new(ffldl(g0))),
            right: Either::Left(Box::new(ffldl(g1))),
            value: l[2].clone(),
        }
    } else {
        LdlTree {
            left: Either::Right(d[0][0]),
            right: Either::Right(d[3][0]),
            value: l[2].clone(),
        }
    }
}

pub fn normalize_tree(tree: &mut LdlTree, sigma: f64) {
    match tree.left.as_mut() {
        Either::Left(left_tree) => normalize_tree(left_tree, sigma),
        Either::Right(r) => {
            *r = sigma / r.sqrt();
        }
    }
    match tree.right.as_mut() {
        Either::Left(right_tree) => normalize_tree(right_tree, sigma),
        Either::Right(r) => {
            *r = sigma / r.sqrt();
        }
    }
}

#[cfg(test)]
mod test {
    use itertools::Itertools;
    use num_complex::{Complex, Complex64};
    use rand::{thread_rng, Rng};
    use rand_distr::num_traits::Zero;

    use crate::ffsampling::gram;

    #[test]
    fn test_gram() {
        let mut rng = thread_rng();
        let n = rng.gen_range(2..10);
        let a: [Vec<Complex64>; 4] = (0..4)
            .map(|_| {
                (0..n)
                    .map(|_| Complex::new(rng.gen(), rng.gen()))
                    .collect_vec()
            })
            .collect_vec()
            .try_into()
            .unwrap();
        let mut b = a.clone();
        b[0] = a[0].iter().map(|c| c.conj()).collect_vec();
        b[2] = a[1].iter().map(|c| c.conj()).collect_vec();
        b[1] = a[2].iter().map(|c| c.conj()).collect_vec();
        b[3] = a[3].iter().map(|c| c.conj()).collect_vec();

        let mut c: [Vec<Complex64>; 4] = (0..4)
            .map(|_| (0..n).map(|_| Complex64::zero()).collect_vec())
            .collect_vec()
            .try_into()
            .unwrap();
        for i in 0..2 {
            for j in 0..2 {
                for k in 0..2 {
                    c[2 * i + j] = c[2 * i + j]
                        .iter()
                        .zip(
                            a[2 * i + k]
                                .iter()
                                .zip(b[2 * k + j].iter())
                                .map(|(aa, bb)| aa * bb),
                        )
                        .map(|(cc, ab)| cc + ab)
                        .collect_vec();
                }
            }
        }

        let g = gram(a);

        assert_eq!(c, g);
    }
}
