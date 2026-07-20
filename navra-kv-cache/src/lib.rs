//! TurboQuant KV cache compression: PolarQuant + QJL in pure Rust.
//!
//! Implements the two-stage compression pipeline from TurboQuant
//! (ICLR 2026): Walsh-Hadamard rotation → polar quantization for
//! gaussianized vectors, with optional QJL 1-bit residual sketching
//! for bias correction.
//!
//! This crate is a pure math library with no inference engine
//! dependencies. It provides compress/decompress for `&[f32]` vectors
//! representing individual KV cache entries (one head, one position).

pub mod pack;
pub mod polar;
pub mod qjl;
pub mod wht;

/// Quantization level for KV cache compression.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuantLevel {
    /// 2-bit polar quantization + 0.5-bit QJL sketch ≈ 2.5 bits/value.
    Turbo2,
    /// 3-bit polar quantization + QJL correction ≈ 3 bits/value.
    Turbo3,
    /// 3.5-bit polar quantization (finer buckets, no QJL) ≈ 3.5 bits/value.
    Turbo4,
}

impl QuantLevel {
    /// Number of bits used for polar quantization (excluding sign bit).
    pub fn polar_bits(self) -> u8 {
        match self {
            Self::Turbo2 => 2,
            Self::Turbo3 => 3,
            Self::Turbo4 => 4,
        }
    }

    /// Whether this level includes QJL residual sketching.
    pub fn uses_qjl(self) -> bool {
        matches!(self, Self::Turbo2 | Self::Turbo3)
    }

    /// Approximate bits per value (including sign + optional QJL).
    pub fn bits_per_value(self) -> f32 {
        match self {
            Self::Turbo2 => 2.5,
            Self::Turbo3 => 3.0,
            Self::Turbo4 => 3.5,
        }
    }
}

/// A compressed KV cache vector (one attention head, one sequence position).
#[derive(Debug, Clone)]
pub struct CompressedKvEntry {
    /// Packed sign bits (1 bit per value).
    pub signs: Vec<u8>,
    /// Packed magnitude bucket codes.
    pub codes: Vec<u8>,
    /// QJL 1-bit sketch for residual correction (if level uses QJL).
    pub sketch: Option<Vec<u8>>,
    /// Original vector dimension (before padding).
    pub dim: usize,
    /// Quantization level used.
    pub level: QuantLevel,
}

impl CompressedKvEntry {
    /// Compressed size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.signs.len() + self.codes.len() + self.sketch.as_ref().map_or(0, |s| s.len())
    }

    /// Compression ratio vs f32 original.
    pub fn compression_ratio(&self) -> f32 {
        let original = self.dim * 4; // f32 = 4 bytes
        if original == 0 {
            return 1.0;
        }
        original as f32 / self.size_bytes() as f32
    }
}

/// KV cache compressor combining WHT + PolarQuant + optional QJL.
pub struct KvCompressor {
    wht: wht::WalshHadamard,
    quantizer: polar::PolarQuantizer,
    sketch: Option<qjl::QjlSketch>,
    level: QuantLevel,
}

impl KvCompressor {
    /// Create a compressor for vectors of the given dimension.
    ///
    /// `dim` is the attention head dimension (e.g., 128 for most models).
    /// `level` selects the compression aggressiveness.
    /// `qjl_seed` is the deterministic seed for the QJL sign matrix.
    pub fn new(dim: usize, level: QuantLevel, qjl_seed: u64) -> Self {
        let wht = wht::WalshHadamard::new(dim);
        let quantizer = polar::PolarQuantizer::new(level.polar_bits());
        let sketch = if level.uses_qjl() {
            let m = dim / 2;
            Some(qjl::QjlSketch::new(m, wht.padded_dim(), qjl_seed))
        } else {
            None
        };
        Self {
            wht,
            quantizer,
            sketch,
            level,
        }
    }

    /// Compress a KV cache vector.
    pub fn compress(&self, vector: &[f32]) -> CompressedKvEntry {
        assert_eq!(vector.len(), self.wht.original_dim());

        let rotated = self.wht.forward(vector);

        let (signs, codes) = self.quantizer.quantize(&rotated);

        let sketch = self.sketch.as_ref().map(|s| {
            let dequantized = self.quantizer.dequantize(&signs, &codes);
            let mut residual = vec![0.0f32; rotated.len()];
            for i in 0..rotated.len() {
                residual[i] = rotated[i] - dequantized[i];
            }
            s.sketch(&residual)
        });

        // Pack signs and codes into byte arrays
        let packed_signs = pack::pack_bits(&signs);
        let packed_codes = pack::pack_nbits(&codes, self.level.polar_bits());

        CompressedKvEntry {
            signs: packed_signs,
            codes: packed_codes,
            sketch,
            dim: vector.len(),
            level: self.level,
        }
    }

    /// Decompress a KV cache vector.
    pub fn decompress(&self, entry: &CompressedKvEntry) -> Vec<f32> {
        assert_eq!(entry.dim, self.wht.original_dim());

        let signs = pack::unpack_bits(&entry.signs, self.wht.padded_dim());
        let codes = pack::unpack_nbits(&entry.codes, self.level.polar_bits(), self.wht.padded_dim());

        let mut result = self.quantizer.dequantize(&signs, &codes);

        if let (Some(s), Some(sketch_bits)) = (&self.sketch, &entry.sketch) {
            let correction = s.reconstruct(sketch_bits);
            for i in 0..result.len() {
                result[i] += correction[i];
            }
        }

        let recovered = self.wht.inverse(&result);
        recovered[..entry.dim].to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quant_level_properties() {
        assert_eq!(QuantLevel::Turbo2.polar_bits(), 2);
        assert_eq!(QuantLevel::Turbo3.polar_bits(), 3);
        assert_eq!(QuantLevel::Turbo4.polar_bits(), 4);
        assert!(QuantLevel::Turbo2.uses_qjl());
        assert!(QuantLevel::Turbo3.uses_qjl());
        assert!(!QuantLevel::Turbo4.uses_qjl());
    }

    #[test]
    fn compress_decompress_roundtrip_turbo3() {
        let dim = 128;
        let compressor = KvCompressor::new(dim, QuantLevel::Turbo3, 42);

        let vector: Vec<f32> = (0..dim).map(|i| (i as f32 * 0.1).sin()).collect();
        let compressed = compressor.compress(&vector);
        let recovered = compressor.decompress(&compressed);

        assert_eq!(recovered.len(), dim);

        let mse: f32 = vector
            .iter()
            .zip(recovered.iter())
            .map(|(a, b)| (a - b) * (a - b))
            .sum::<f32>()
            / dim as f32;
        assert!(
            mse < 5.0,
            "mean squared error {mse} exceeds threshold for 3-bit quantization"
        );
    }

    #[test]
    fn compress_decompress_roundtrip_turbo4() {
        let dim = 64;
        let compressor = KvCompressor::new(dim, QuantLevel::Turbo4, 42);

        let vector: Vec<f32> = (0..dim).map(|i| (i as f32 * 0.3).cos()).collect();
        let compressed = compressor.compress(&vector);
        assert!(compressed.sketch.is_none());
        let recovered = compressor.decompress(&compressed);

        assert_eq!(recovered.len(), dim);
    }

    #[test]
    fn compression_ratio() {
        let dim = 128;
        let compressor = KvCompressor::new(dim, QuantLevel::Turbo3, 42);

        let vector: Vec<f32> = vec![1.0; dim];
        let compressed = compressor.compress(&vector);

        let ratio = compressed.compression_ratio();
        assert!(ratio > 5.0, "expected compression ratio > 5x, got {ratio}");
    }

    #[test]
    fn zero_vector_roundtrip() {
        let dim = 64;
        let compressor = KvCompressor::new(dim, QuantLevel::Turbo4, 42);

        let vector = vec![0.0f32; dim];
        let compressed = compressor.compress(&vector);
        let recovered = compressor.decompress(&compressed);

        let mse: f32 =
            recovered.iter().map(|x| x * x).sum::<f32>() / dim as f32;
        assert!(
            mse < 1.0,
            "zero vector MSE {mse} too large (quantization noise expected)"
        );
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn quant_level_polar_bits_bounded() {
        let level = match kani::any::<u8>() % 3 {
            0 => QuantLevel::Turbo2,
            1 => QuantLevel::Turbo3,
            _ => QuantLevel::Turbo4,
        };
        let bits = level.polar_bits();
        assert!(bits >= 2 && bits <= 4);
    }

    #[kani::proof]
    fn quant_level_bits_per_value_positive() {
        let level = match kani::any::<u8>() % 3 {
            0 => QuantLevel::Turbo2,
            1 => QuantLevel::Turbo3,
            _ => QuantLevel::Turbo4,
        };
        assert!(level.bits_per_value() > 0.0);
        assert!(level.bits_per_value() <= 4.0);
    }

    #[kani::proof]
    fn compressed_entry_size_nonneg() {
        let entry = CompressedKvEntry {
            signs: vec![0u8; 8],
            codes: vec![0u8; 16],
            sketch: None,
            dim: 64,
            level: QuantLevel::Turbo4,
        };
        assert!(entry.size_bytes() > 0);
        assert!(entry.compression_ratio() > 0.0);
    }
}
