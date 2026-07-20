//! Bit packing utilities for compressed KV cache entries.
//!
//! Packs sign bits (1 bit each) and magnitude codes (n bits each)
//! into compact byte arrays.

/// Pack 1-bit values into bytes (MSB-first within each byte).
pub fn pack_bits(bits: &[u8]) -> Vec<u8> {
    let num_bytes = (bits.len() + 7) / 8;
    let mut packed = vec![0u8; num_bytes];
    for (i, &bit) in bits.iter().enumerate() {
        if bit != 0 {
            packed[i / 8] |= 1 << (i % 8);
        }
    }
    packed
}

/// Unpack 1-bit values from bytes.
pub fn unpack_bits(packed: &[u8], count: usize) -> Vec<u8> {
    let mut bits = Vec::with_capacity(count);
    for i in 0..count {
        let bit = (packed[i / 8] >> (i % 8)) & 1;
        bits.push(bit);
    }
    bits
}

/// Pack n-bit codes (2, 3, or 4 bits) into bytes.
///
/// Codes are packed sequentially: for 3-bit, code 0 occupies bits 0-2,
/// code 1 occupies bits 3-5, etc. Codes that straddle byte boundaries
/// are split across bytes.
pub fn pack_nbits(codes: &[u8], bits: u8) -> Vec<u8> {
    assert!(bits >= 1 && bits <= 8, "bits must be 1..=8");
    let total_bits = codes.len() * bits as usize;
    let num_bytes = (total_bits + 7) / 8;
    let mut packed = vec![0u8; num_bytes];

    let mask = (1u8 << bits) - 1;
    let mut bit_pos = 0usize;

    for &code in codes {
        let code = code & mask;
        let byte_idx = bit_pos / 8;
        let bit_offset = bit_pos % 8;

        packed[byte_idx] |= code << bit_offset;
        if bit_offset + bits as usize > 8 {
            packed[byte_idx + 1] |= code >> (8 - bit_offset);
        }

        bit_pos += bits as usize;
    }

    packed
}

/// Unpack n-bit codes from bytes.
pub fn unpack_nbits(packed: &[u8], bits: u8, count: usize) -> Vec<u8> {
    assert!(bits >= 1 && bits <= 8, "bits must be 1..=8");
    let mask = (1u8 << bits) - 1;
    let mut codes = Vec::with_capacity(count);
    let mut bit_pos = 0usize;

    for _ in 0..count {
        let byte_idx = bit_pos / 8;
        let bit_offset = bit_pos % 8;

        let mut code = packed[byte_idx] >> bit_offset;
        if bit_offset + bits as usize > 8 {
            code |= packed[byte_idx + 1] << (8 - bit_offset);
        }
        codes.push(code & mask);

        bit_pos += bits as usize;
    }

    codes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_unpack_bits_roundtrip() {
        let bits = vec![1, 0, 1, 1, 0, 0, 1, 0, 1];
        let packed = pack_bits(&bits);
        let unpacked = unpack_bits(&packed, bits.len());
        assert_eq!(unpacked, bits);
    }

    #[test]
    fn pack_unpack_2bit_roundtrip() {
        let codes = vec![0, 1, 2, 3, 2, 1, 0, 3];
        let packed = pack_nbits(&codes, 2);
        let unpacked = unpack_nbits(&packed, 2, codes.len());
        assert_eq!(unpacked, codes);
    }

    #[test]
    fn pack_unpack_3bit_roundtrip() {
        let codes = vec![0, 1, 2, 3, 4, 5, 6, 7, 3, 5];
        let packed = pack_nbits(&codes, 3);
        let unpacked = unpack_nbits(&packed, 3, codes.len());
        assert_eq!(unpacked, codes);
    }

    #[test]
    fn pack_unpack_4bit_roundtrip() {
        let codes: Vec<u8> = (0..16).collect();
        let packed = pack_nbits(&codes, 4);
        let unpacked = unpack_nbits(&packed, 4, codes.len());
        assert_eq!(unpacked, codes);
    }

    #[test]
    fn empty_input() {
        assert!(pack_bits(&[]).is_empty());
        assert!(unpack_bits(&[], 0).is_empty());
        assert!(pack_nbits(&[], 3).is_empty());
        assert!(unpack_nbits(&[], 3, 0).is_empty());
    }

    #[test]
    fn pack_bits_size() {
        assert_eq!(pack_bits(&[1; 8]).len(), 1);
        assert_eq!(pack_bits(&[1; 9]).len(), 2);
        assert_eq!(pack_bits(&[1; 16]).len(), 2);
    }

    #[test]
    fn pack_nbits_size() {
        assert_eq!(pack_nbits(&[0; 8], 3).len(), 3); // 8×3=24 bits = 3 bytes
        assert_eq!(pack_nbits(&[0; 4], 4).len(), 2); // 4×4=16 bits = 2 bytes
    }
}

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    #[kani::proof]
    fn pack_unpack_bits_roundtrip_4() {
        let b0: u8 = kani::any();
        let b1: u8 = kani::any();
        let b2: u8 = kani::any();
        let b3: u8 = kani::any();
        kani::assume(b0 <= 1 && b1 <= 1 && b2 <= 1 && b3 <= 1);
        let bits = vec![b0, b1, b2, b3];
        let packed = pack_bits(&bits);
        let unpacked = unpack_bits(&packed, 4);
        assert_eq!(unpacked[0], b0);
        assert_eq!(unpacked[1], b1);
        assert_eq!(unpacked[2], b2);
        assert_eq!(unpacked[3], b3);
    }

    #[kani::proof]
    fn pack_unpack_3bit_roundtrip_2() {
        let c0: u8 = kani::any();
        let c1: u8 = kani::any();
        kani::assume(c0 < 8 && c1 < 8);
        let codes = vec![c0, c1];
        let packed = pack_nbits(&codes, 3);
        let unpacked = unpack_nbits(&packed, 3, 2);
        assert_eq!(unpacked[0], c0);
        assert_eq!(unpacked[1], c1);
    }

    #[kani::proof]
    fn pack_nbits_size_bounded() {
        let n: usize = kani::any();
        let bits: u8 = kani::any();
        kani::assume(n >= 1 && n <= 16);
        kani::assume(bits >= 1 && bits <= 8);
        let codes = vec![0u8; n];
        let packed = pack_nbits(&codes, bits);
        let total_bits = n * bits as usize;
        let expected_bytes = (total_bits + 7) / 8;
        assert_eq!(packed.len(), expected_bytes);
    }
}
