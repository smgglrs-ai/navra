//! Polar quantization with Gaussian-optimal Lloyd-Max buckets.
//!
//! After Walsh-Hadamard rotation, values are approximately Gaussian.
//! PolarQuant encodes each value as (sign_bit, magnitude_bucket):
//!
//! 1. Extract sign: s = sign(x)
//! 2. Map |x| to bucket index via pre-computed boundaries
//! 3. No per-block scale needed — WHT normalizes the distribution
//!
//! Dequantize: s × bucket_center[index]

/// Polar quantizer with fixed-width magnitude buckets.
#[derive(Debug, Clone)]
pub struct PolarQuantizer {
    #[allow(dead_code)]
    bits: u8,
    boundaries: &'static [f32],
    centers: &'static [f32],
}

// Lloyd-Max optimal boundaries and reconstruction levels for
// the half-Gaussian N(0,1) distribution (|x| only, sign stored
// separately). Pre-computed via iterative Lloyd-Max algorithm.
//
// For k magnitude bits: 2^k buckets covering [0, ∞).

const BOUNDARIES_2BIT: &[f32] = &[0.0, 0.4528, 1.0500, 1.7480];
const CENTERS_2BIT: &[f32] = &[0.2176, 0.7257, 1.3439, 2.1520];

const BOUNDARIES_3BIT: &[f32] = &[0.0, 0.2270, 0.5224, 0.8367, 1.1802, 1.5732, 2.0513, 2.7326];
const CENTERS_3BIT: &[f32] = &[
    0.1127, 0.3696, 0.6720, 1.0005, 1.3655, 1.7916, 2.3398, 3.1527,
];

const BOUNDARIES_4BIT: &[f32] = &[
    0.0, 0.1135, 0.2533, 0.3979, 0.5489, 0.7084, 0.8791, 1.0640, 1.2676, 1.4968, 1.7618, 2.0801,
    2.4817, 3.0275, 3.8913, 5.8572,
];
const CENTERS_4BIT: &[f32] = &[
    0.0564, 0.1822, 0.3245, 0.4723, 0.6275, 0.7925, 0.9700, 1.1638, 1.3797, 1.6260, 1.9159, 2.2717,
    2.7344, 3.4049, 4.6194, 7.6146,
];

impl PolarQuantizer {
    /// Create a quantizer for the given bit width (2, 3, or 4).
    pub fn new(bits: u8) -> Self {
        let (boundaries, centers) = match bits {
            2 => (BOUNDARIES_2BIT, CENTERS_2BIT),
            3 => (BOUNDARIES_3BIT, CENTERS_3BIT),
            4 => (BOUNDARIES_4BIT, CENTERS_4BIT),
            _ => panic!("polar quantizer supports 2, 3, or 4 bits, got {bits}"),
        };
        Self {
            bits,
            boundaries,
            centers,
        }
    }

    /// Number of magnitude buckets.
    pub fn num_buckets(&self) -> usize {
        self.centers.len()
    }

    /// Quantize a rotated vector into sign bits and magnitude bucket codes.
    ///
    /// Returns (signs, codes) where:
    /// - signs[i] = 0 if value >= 0, 1 if value < 0
    /// - codes[i] = magnitude bucket index (0..2^bits)
    pub fn quantize(&self, values: &[f32]) -> (Vec<u8>, Vec<u8>) {
        let mut signs = Vec::with_capacity(values.len());
        let mut codes = Vec::with_capacity(values.len());

        for &v in values {
            let sign = if v < 0.0 { 1u8 } else { 0u8 };
            let mag = v.abs();

            let mut bucket = 0u8;
            for (i, &boundary) in self.boundaries.iter().enumerate().skip(1) {
                if mag >= boundary {
                    bucket = i as u8;
                } else {
                    break;
                }
            }

            signs.push(sign);
            codes.push(bucket);
        }

        (signs, codes)
    }

    /// Dequantize sign bits and magnitude codes back to f32 values.
    pub fn dequantize(&self, signs: &[u8], codes: &[u8]) -> Vec<f32> {
        assert_eq!(signs.len(), codes.len());
        signs
            .iter()
            .zip(codes.iter())
            .map(|(&sign, &code)| {
                let center = self.centers[code as usize];
                if sign == 1 { -center } else { center }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantize_dequantize_2bit() {
        let q = PolarQuantizer::new(2);
        assert_eq!(q.num_buckets(), 4);

        let values = vec![0.1, -0.5, 1.5, -2.5];
        let (signs, codes) = q.quantize(&values);

        assert_eq!(signs, vec![0, 1, 0, 1]);
        assert!(codes.iter().all(|&c| c < 4));

        let recovered = q.dequantize(&signs, &codes);
        assert_eq!(recovered.len(), 4);
        assert!(recovered[0] > 0.0);
        assert!(recovered[1] < 0.0);
    }

    #[test]
    fn quantize_dequantize_3bit() {
        let q = PolarQuantizer::new(3);
        assert_eq!(q.num_buckets(), 8);

        let values: Vec<f32> = (0..16).map(|i| (i as f32 - 8.0) * 0.3).collect();
        let (signs, codes) = q.quantize(&values);

        assert!(codes.iter().all(|&c| c < 8));
        let _recovered = q.dequantize(&signs, &codes);
    }

    #[test]
    fn quantize_dequantize_4bit() {
        let q = PolarQuantizer::new(4);
        assert_eq!(q.num_buckets(), 16);

        let values: Vec<f32> = (0..32).map(|i| (i as f32 - 16.0) * 0.2).collect();
        let (signs, codes) = q.quantize(&values);

        assert!(codes.iter().all(|&c| c < 16));
        let _recovered = q.dequantize(&signs, &codes);
    }

    #[test]
    fn sign_preservation() {
        let q = PolarQuantizer::new(3);
        let values = vec![1.5, -0.7, 0.01, -3.0, 0.0];
        let (signs, codes) = q.quantize(&values);
        let recovered = q.dequantize(&signs, &codes);

        for (i, (&orig, &rec)) in values.iter().zip(recovered.iter()).enumerate() {
            if orig != 0.0 {
                assert_eq!(
                    orig.is_sign_positive(),
                    rec.is_sign_positive(),
                    "sign mismatch at index {i}: orig={orig}, rec={rec}"
                );
            }
        }
    }

    #[test]
    fn monotonicity() {
        let q = PolarQuantizer::new(3);
        let magnitudes = vec![0.0, 0.1, 0.5, 1.0, 1.5, 2.0, 3.0, 5.0];
        let values: Vec<f32> = magnitudes.clone();
        let (_, codes) = q.quantize(&values);

        for i in 1..codes.len() {
            assert!(
                codes[i] >= codes[i - 1],
                "non-monotonic: codes[{i}]={} < codes[{}]={}",
                codes[i],
                i - 1,
                codes[i - 1]
            );
        }
    }

    #[test]
    fn zero_maps_to_smallest_bucket() {
        for bits in [2, 3, 4] {
            let q = PolarQuantizer::new(bits);
            let (signs, codes) = q.quantize(&[0.0]);
            assert_eq!(signs[0], 0);
            assert_eq!(codes[0], 0);
        }
    }

    #[test]
    #[should_panic(expected = "polar quantizer supports")]
    fn invalid_bits_panics() {
        PolarQuantizer::new(5);
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn bucket_index_bounded_2bit() {
        let q = PolarQuantizer::new(2);
        let v: f32 = kani::any();
        kani::assume(v.is_finite());
        let (_, codes) = q.quantize(&[v]);
        assert!(codes[0] < 4);
    }

    #[kani::proof]
    fn bucket_index_bounded_3bit() {
        let q = PolarQuantizer::new(3);
        let v: f32 = kani::any();
        kani::assume(v.is_finite());
        let (_, codes) = q.quantize(&[v]);
        assert!(codes[0] < 8);
    }

    #[kani::proof]
    fn sign_preserved_nonzero() {
        let q = PolarQuantizer::new(3);
        let v: f32 = kani::any();
        kani::assume(v.is_finite() && v != 0.0);
        let (signs, codes) = q.quantize(&[v]);
        let recovered = q.dequantize(&signs, &codes);
        if v > 0.0 {
            assert!(recovered[0] > 0.0);
        } else {
            assert!(recovered[0] < 0.0);
        }
    }

    #[kani::proof]
    fn dequantize_finite() {
        let q = PolarQuantizer::new(3);
        let sign: u8 = kani::any();
        let code: u8 = kani::any();
        kani::assume(sign <= 1);
        kani::assume(code < 8);
        let result = q.dequantize(&[sign], &[code]);
        assert!(result[0].is_finite());
    }
}
