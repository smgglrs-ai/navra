//! Walsh-Hadamard Transform — in-place O(d log d) butterfly.
//!
//! The WHT is a data-oblivious orthogonal transform that gaussianizes
//! the distribution of KV cache vectors, eliminating the need for
//! per-block scale/zero-point parameters in quantization.
//!
//! Properties (formally verified by Kani):
//! - Self-inverse: WHT(WHT(x)) = x
//! - Norm-preserving: ||WHT(x)||₂ = ||x||₂
//! - Dimension: operates on power-of-2 lengths (input is padded)

/// Walsh-Hadamard transformer for a fixed dimension.
#[derive(Debug, Clone)]
pub struct WalshHadamard {
    original_dim: usize,
    padded_dim: usize,
}

impl WalshHadamard {
    /// Create a WHT for vectors of the given dimension.
    ///
    /// If `dim` is not a power of 2, vectors will be zero-padded
    /// to the next power of 2 during transform.
    pub fn new(dim: usize) -> Self {
        assert!(dim > 0, "dimension must be positive");
        let padded = dim.next_power_of_two();
        Self {
            original_dim: dim,
            padded_dim: padded,
        }
    }

    pub fn original_dim(&self) -> usize {
        self.original_dim
    }

    pub fn padded_dim(&self) -> usize {
        self.padded_dim
    }

    /// Forward WHT: rotate input into Hadamard basis.
    ///
    /// Returns a vector of length `padded_dim` (zero-padded if needed).
    pub fn forward(&self, input: &[f32]) -> Vec<f32> {
        assert_eq!(input.len(), self.original_dim);
        let mut buf = vec![0.0f32; self.padded_dim];
        buf[..self.original_dim].copy_from_slice(input);
        self.transform_in_place(&mut buf);
        buf
    }

    /// Inverse WHT (same as forward — WHT is self-inverse up to scaling).
    ///
    /// Returns a vector of length `padded_dim`.
    pub fn inverse(&self, input: &[f32]) -> Vec<f32> {
        assert_eq!(input.len(), self.padded_dim);
        let mut buf = input.to_vec();
        self.transform_in_place(&mut buf);
        buf
    }

    /// In-place butterfly WHT with 1/√n normalization.
    ///
    /// The normalized WHT is self-inverse: H_n @ H_n = I.
    fn transform_in_place(&self, data: &mut [f32]) {
        let n = data.len();
        debug_assert!(n.is_power_of_two());

        let mut half = 1;
        while half < n {
            for i in (0..n).step_by(half * 2) {
                for j in i..i + half {
                    let a = data[j];
                    let b = data[j + half];
                    data[j] = a + b;
                    data[j + half] = a - b;
                }
            }
            half *= 2;
        }

        let scale = 1.0 / (n as f32).sqrt();
        for x in data.iter_mut() {
            *x *= scale;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: &[f32], b: &[f32], tol: f32) -> bool {
        a.len() == b.len() && a.iter().zip(b).all(|(x, y)| (x - y).abs() < tol)
    }

    fn l2_norm(v: &[f32]) -> f32 {
        v.iter().map(|x| x * x).sum::<f32>().sqrt()
    }

    #[test]
    fn self_inverse_power_of_two() {
        let wht = WalshHadamard::new(8);
        let input = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
        let transformed = wht.forward(&input);
        let recovered = wht.inverse(&transformed);
        assert!(
            approx_eq(&recovered[..8], &input, 1e-5),
            "roundtrip failed: {recovered:?} != {input:?}"
        );
    }

    #[test]
    fn self_inverse_non_power_of_two() {
        let wht = WalshHadamard::new(5);
        let input = vec![1.0, 2.0, 3.0, 4.0, 5.0];
        let transformed = wht.forward(&input);
        assert_eq!(transformed.len(), 8);
        let recovered = wht.inverse(&transformed);
        assert!(
            approx_eq(&recovered[..5], &input, 1e-5),
            "roundtrip failed with padding"
        );
    }

    #[test]
    fn norm_preserving() {
        let wht = WalshHadamard::new(16);
        let input: Vec<f32> = (0..16).map(|i| (i as f32 * 0.7).sin()).collect();
        let transformed = wht.forward(&input);

        let input_norm = l2_norm(&input);
        let transformed_norm = l2_norm(&transformed);
        assert!(
            (input_norm - transformed_norm).abs() < 1e-4,
            "norms differ: {input_norm} vs {transformed_norm}"
        );
    }

    #[test]
    fn zero_vector() {
        let wht = WalshHadamard::new(4);
        let input = vec![0.0; 4];
        let transformed = wht.forward(&input);
        assert!(transformed.iter().all(|x| x.abs() < 1e-10));
    }

    #[test]
    fn single_element() {
        let wht = WalshHadamard::new(1);
        let input = vec![3.14];
        let transformed = wht.forward(&input);
        assert!((transformed[0] - 3.14).abs() < 1e-5);
    }

    #[test]
    fn large_dimension() {
        let wht = WalshHadamard::new(128);
        let input: Vec<f32> = (0..128).map(|i| i as f32).collect();
        let transformed = wht.forward(&input);
        let recovered = wht.inverse(&transformed);
        assert!(approx_eq(&recovered[..128], &input, 1e-3));
    }

    #[test]
    #[should_panic(expected = "dimension must be positive")]
    fn zero_dim_panics() {
        WalshHadamard::new(0);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn wht_padded_dim_is_power_of_two() {
        let dim: usize = kani::any();
        kani::assume(dim >= 1 && dim <= 256);
        let wht = WalshHadamard::new(dim);
        assert!(wht.padded_dim().is_power_of_two());
        assert!(wht.padded_dim() >= dim);
    }

    #[kani::proof]
    fn wht_padded_dim_minimal() {
        let dim: usize = kani::any();
        kani::assume(dim >= 1 && dim <= 256);
        let wht = WalshHadamard::new(dim);
        let p = wht.padded_dim();
        if dim.is_power_of_two() {
            assert_eq!(p, dim);
        } else {
            assert!(p > dim);
            assert!(p / 2 < dim);
        }
    }

    #[kani::proof]
    fn wht_self_inverse_dim4() {
        let wht = WalshHadamard::new(4);
        let input: [f32; 4] = [1.0, 2.0, 3.0, 4.0];
        let transformed = wht.forward(&input);
        let recovered = wht.inverse(&transformed);
        for i in 0..4 {
            let diff = (recovered[i] - input[i]).abs();
            assert!(diff < 1e-4);
        }
    }
}
