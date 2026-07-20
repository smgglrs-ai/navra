//! QJL (Quantized Johnson-Lindenstrauss) 1-bit residual sketch.
//!
//! After polar quantization, the residual (original - dequantized) still
//! carries useful information. QJL projects it via a random sign matrix
//! S ∈ {-1,+1}^{m×d} and stores only the sign of each projection:
//!
//!   sketch = sign(S @ residual)     — m bits
//!   correction ≈ S^T @ sketch / √m  — unbiased estimator (JL lemma)
//!
//! The sign matrix is generated deterministically from a seed, so both
//! compress and decompress produce the same matrix without storing it.

/// QJL 1-bit sketch for residual correction.
#[derive(Debug, Clone)]
pub struct QjlSketch {
    /// Number of projection dimensions (output bits).
    projections: usize,
    /// Input dimension.
    dim: usize,
    /// Seed for deterministic sign matrix generation.
    seed: u64,
}

impl QjlSketch {
    /// Create a QJL sketch with `m` projections over `d`-dimensional input.
    pub fn new(projections: usize, dim: usize, seed: u64) -> Self {
        assert!(projections > 0, "projections must be positive");
        assert!(dim > 0, "dimension must be positive");
        Self {
            projections,
            dim,
            seed,
        }
    }

    /// Compute the 1-bit sketch of a residual vector.
    ///
    /// Returns packed bits: bit j = 1 if the j-th projection is negative.
    pub fn sketch(&self, residual: &[f32]) -> Vec<u8> {
        assert_eq!(residual.len(), self.dim);

        let mut bits = vec![0u8; (self.projections + 7) / 8];

        for j in 0..self.projections {
            let dot = self.projection_dot(j, residual);
            if dot < 0.0 {
                bits[j / 8] |= 1 << (j % 8);
            }
        }

        bits
    }

    /// Reconstruct the correction vector from a 1-bit sketch.
    ///
    /// Returns an approximation of the original residual via
    /// S^T @ sketch_signs / √m.
    pub fn reconstruct(&self, sketch_bits: &[u8]) -> Vec<f32> {
        let scale = 1.0 / (self.projections as f32).sqrt();
        let mut correction = vec![0.0f32; self.dim];

        for j in 0..self.projections {
            let bit_set = (sketch_bits[j / 8] >> (j % 8)) & 1 == 1;
            let sketch_sign: f32 = if bit_set { -1.0 } else { 1.0 };

            let mut state = self.row_seed(j);
            for i in 0..self.dim {
                state = xorshift64(state);
                let sign = if state & 1 == 0 { 1.0f32 } else { -1.0f32 };
                correction[i] += sign * sketch_sign * scale;
            }
        }

        correction
    }

    /// Compute dot product of j-th row of S with the residual.
    fn projection_dot(&self, j: usize, residual: &[f32]) -> f32 {
        let mut state = self.row_seed(j);
        let mut dot = 0.0f32;

        for i in 0..self.dim {
            state = xorshift64(state);
            let sign = if state & 1 == 0 { 1.0f32 } else { -1.0f32 };
            dot += sign * residual[i];
        }

        dot
    }

    /// Deterministic seed for the j-th row of the sign matrix.
    fn row_seed(&self, j: usize) -> u64 {
        self.seed ^ (j as u64).wrapping_mul(0x517cc1b727220a95)
    }
}

/// xorshift64 PRNG — fast, deterministic, sufficient for sign generation.
fn xorshift64(mut state: u64) -> u64 {
    state ^= state << 13;
    state ^= state >> 7;
    state ^= state << 17;
    state
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sketch_dimensions() {
        let qjl = QjlSketch::new(32, 64, 42);
        let residual = vec![0.1f32; 64];
        let sketch = qjl.sketch(&residual);
        assert_eq!(sketch.len(), 4); // 32 bits = 4 bytes
    }

    #[test]
    fn reconstruct_dimensions() {
        let qjl = QjlSketch::new(32, 64, 42);
        let sketch = vec![0u8; 4];
        let correction = qjl.reconstruct(&sketch);
        assert_eq!(correction.len(), 64);
    }

    #[test]
    fn deterministic_sketch() {
        let qjl = QjlSketch::new(16, 32, 42);
        let residual: Vec<f32> = (0..32).map(|i| (i as f32 * 0.1).sin()).collect();
        let s1 = qjl.sketch(&residual);
        let s2 = qjl.sketch(&residual);
        assert_eq!(s1, s2);
    }

    #[test]
    fn deterministic_reconstruct() {
        let qjl = QjlSketch::new(16, 32, 42);
        let sketch = vec![0xABu8; 2];
        let r1 = qjl.reconstruct(&sketch);
        let r2 = qjl.reconstruct(&sketch);
        assert_eq!(r1, r2);
    }

    #[test]
    fn zero_residual_sketch() {
        let qjl = QjlSketch::new(64, 128, 42);
        let residual = vec![0.0f32; 128];
        let sketch = qjl.sketch(&residual);
        assert!(sketch.iter().all(|&b| b == 0));
    }

    #[test]
    fn reconstruction_has_nonzero_correlation() {
        let qjl = QjlSketch::new(256, 64, 42);
        let residual: Vec<f32> = (0..64).map(|i| (i as f32 * 0.5).sin()).collect();

        let sketch = qjl.sketch(&residual);
        let correction = qjl.reconstruct(&sketch);

        let dot: f32 = residual
            .iter()
            .zip(correction.iter())
            .map(|(r, c)| r * c)
            .sum();

        assert!(
            dot > 0.0,
            "correction should correlate positively with residual, got dot={dot}"
        );
    }

    #[test]
    fn xorshift_nonzero() {
        let mut state = 42u64;
        for _ in 0..100 {
            state = xorshift64(state);
            assert_ne!(state, 0);
        }
    }

    #[test]
    #[should_panic(expected = "projections must be positive")]
    fn zero_projections_panics() {
        QjlSketch::new(0, 64, 42);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn sketch_output_bytes_correct() {
        let m: usize = kani::any();
        let d: usize = kani::any();
        kani::assume(m >= 1 && m <= 64);
        kani::assume(d >= 1 && d <= 16);
        let qjl = QjlSketch::new(m, d, 42);
        let residual = vec![0.0f32; d];
        let sketch = qjl.sketch(&residual);
        assert_eq!(sketch.len(), (m + 7) / 8);
    }

    #[kani::proof]
    fn reconstruct_output_dim_correct() {
        let m: usize = kani::any();
        let d: usize = kani::any();
        kani::assume(m >= 1 && m <= 32);
        kani::assume(d >= 1 && d <= 16);
        let qjl = QjlSketch::new(m, d, 42);
        let sketch = vec![0u8; (m + 7) / 8];
        let correction = qjl.reconstruct(&sketch);
        assert_eq!(correction.len(), d);
    }

    #[kani::proof]
    fn xorshift64_nonzero() {
        let state: u64 = kani::any();
        kani::assume(state != 0);
        let next = xorshift64(state);
        assert_ne!(next, 0);
    }
}
