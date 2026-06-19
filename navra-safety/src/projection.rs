//! Sparse projection matrix for cross-tokenizer knowledge distillation.
//!
//! Implements NVIDIA's X-Token Projection technique: a sparse matrix that
//! maps token logits from a teacher model's vocabulary to a student model's
//! vocabulary based on token-piece overlap. This enables distilling safety
//! knowledge from large models (GPT-4, Claude, LlamaGuard) into navra's
//! compact ONNX classifiers without requiring shared vocabularies.
//!
//! The projection matrix is precomputed offline from two tokenizer
//! vocabularies and stored in CSR (Compressed Sparse Row) format.

use std::path::Path;

/// A sparse matrix in CSR (Compressed Sparse Row) format.
///
/// Maps teacher vocabulary (rows) → student vocabulary (columns).
/// Each row contains the projection weights for one teacher token
/// to the student tokens it overlaps with.
#[derive(Debug, Clone)]
pub struct SparseProjectionMatrix {
    pub teacher_vocab_size: usize,
    pub student_vocab_size: usize,
    /// Row pointers: `row_ptr[i]` is the index into `col_indices` and
    /// `values` where row `i` starts. Length = teacher_vocab_size + 1.
    pub row_ptr: Vec<usize>,
    /// Column indices for each non-zero entry.
    pub col_indices: Vec<usize>,
    /// Values for each non-zero entry (projection weights).
    pub values: Vec<f32>,
}

/// Error loading or applying a projection matrix.
#[derive(Debug, thiserror::Error)]
pub enum ProjectionError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid matrix format: {0}")]
    Format(String),
    #[error("dimension mismatch: expected {expected}, got {got}")]
    DimensionMismatch { expected: usize, got: usize },
}

impl SparseProjectionMatrix {
    /// Build a projection matrix from two tokenizer vocabularies.
    ///
    /// For each teacher token, finds student tokens that share at least
    /// one character n-gram (n=3). The weight is the fraction of shared
    /// n-grams relative to the union.
    pub fn from_vocabularies(teacher_vocab: &[String], student_vocab: &[String]) -> Self {
        let student_ngrams: Vec<std::collections::HashSet<String>> = student_vocab
            .iter()
            .map(|token| char_ngrams(token, 3))
            .collect();

        let mut row_ptr = vec![0usize];
        let mut col_indices = Vec::new();
        let mut values = Vec::new();

        for teacher_token in teacher_vocab {
            let teacher_ng = char_ngrams(teacher_token, 3);
            if teacher_ng.is_empty() {
                row_ptr.push(col_indices.len());
                continue;
            }

            for (j, student_ng) in student_ngrams.iter().enumerate() {
                if student_ng.is_empty() {
                    continue;
                }
                let intersection = teacher_ng.intersection(student_ng).count();
                if intersection > 0 {
                    let union = teacher_ng.union(student_ng).count();
                    let weight = intersection as f32 / union as f32;
                    col_indices.push(j);
                    values.push(weight);
                }
            }
            row_ptr.push(col_indices.len());
        }

        Self {
            teacher_vocab_size: teacher_vocab.len(),
            student_vocab_size: student_vocab.len(),
            row_ptr,
            col_indices,
            values,
        }
    }

    /// Apply the projection: map teacher logits → student logits.
    ///
    /// For each student token j, the projected logit is:
    ///   student_logits[j] = sum_i(teacher_logits[i] * P[i,j])
    pub fn project(&self, teacher_logits: &[f32]) -> Result<Vec<f32>, ProjectionError> {
        if teacher_logits.len() != self.teacher_vocab_size {
            return Err(ProjectionError::DimensionMismatch {
                expected: self.teacher_vocab_size,
                got: teacher_logits.len(),
            });
        }

        let mut student_logits = vec![0.0f32; self.student_vocab_size];

        for i in 0..self.teacher_vocab_size {
            let start = self.row_ptr[i];
            let end = self.row_ptr[i + 1];
            let teacher_val = teacher_logits[i];

            if teacher_val == 0.0 {
                continue;
            }

            for idx in start..end {
                let j = self.col_indices[idx];
                let weight = self.values[idx];
                student_logits[j] += teacher_val * weight;
            }
        }

        Ok(student_logits)
    }

    /// Number of non-zero entries in the matrix.
    pub fn nnz(&self) -> usize {
        self.values.len()
    }

    /// Sparsity ratio (fraction of zero entries).
    pub fn sparsity(&self) -> f64 {
        let total = self.teacher_vocab_size as f64 * self.student_vocab_size as f64;
        if total == 0.0 {
            return 1.0;
        }
        1.0 - (self.nnz() as f64 / total)
    }

    /// Save the matrix to a binary file.
    ///
    /// Format: [teacher_vocab_size: u32][student_vocab_size: u32][nnz: u32]
    ///         [row_ptr: (teacher_vocab_size+1) * u32]
    ///         [col_indices: nnz * u32][values: nnz * f32]
    pub fn save(&self, path: &Path) -> Result<(), ProjectionError> {
        use std::io::Write;
        let mut file = std::io::BufWriter::new(std::fs::File::create(path)?);

        let write_u32 =
            |f: &mut std::io::BufWriter<std::fs::File>, v: u32| -> Result<(), ProjectionError> {
                f.write_all(&v.to_le_bytes()).map_err(ProjectionError::Io)
            };

        write_u32(&mut file, self.teacher_vocab_size as u32)?;
        write_u32(&mut file, self.student_vocab_size as u32)?;
        write_u32(&mut file, self.nnz() as u32)?;

        for &ptr in &self.row_ptr {
            write_u32(&mut file, ptr as u32)?;
        }
        for &col in &self.col_indices {
            write_u32(&mut file, col as u32)?;
        }
        for &val in &self.values {
            file.write_all(&val.to_le_bytes())
                .map_err(ProjectionError::Io)?;
        }

        Ok(())
    }

    /// Load a matrix from a binary file.
    pub fn load(path: &Path) -> Result<Self, ProjectionError> {
        let data = std::fs::read(path)?;
        if data.len() < 12 {
            return Err(ProjectionError::Format("file too small".into()));
        }

        let read_u32 = |offset: usize| -> u32 {
            u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ])
        };

        let teacher_vocab_size = read_u32(0) as usize;
        let student_vocab_size = read_u32(4) as usize;
        let nnz = read_u32(8) as usize;

        let row_ptr_start = 12;
        let row_ptr_len = teacher_vocab_size + 1;
        let col_start = row_ptr_start + row_ptr_len * 4;
        let val_start = col_start + nnz * 4;
        let expected_len = val_start + nnz * 4;

        if data.len() < expected_len {
            return Err(ProjectionError::Format(format!(
                "file too small: expected {expected_len} bytes, got {}",
                data.len()
            )));
        }

        let mut row_ptr = Vec::with_capacity(row_ptr_len);
        for i in 0..row_ptr_len {
            row_ptr.push(read_u32(row_ptr_start + i * 4) as usize);
        }

        let mut col_indices = Vec::with_capacity(nnz);
        for i in 0..nnz {
            col_indices.push(read_u32(col_start + i * 4) as usize);
        }

        let mut values = Vec::with_capacity(nnz);
        for i in 0..nnz {
            let offset = val_start + i * 4;
            let val = f32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]);
            values.push(val);
        }

        Ok(Self {
            teacher_vocab_size,
            student_vocab_size,
            row_ptr,
            col_indices,
            values,
        })
    }
}

fn char_ngrams(token: &str, n: usize) -> std::collections::HashSet<String> {
    let chars: Vec<char> = token.chars().collect();
    if chars.len() < n {
        let mut set = std::collections::HashSet::new();
        if !token.is_empty() {
            set.insert(token.to_string());
        }
        return set;
    }
    chars.windows(n).map(|w| w.iter().collect()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn teacher_vocab() -> Vec<String> {
        vec![
            "hello".into(),
            "world".into(),
            "unsafe".into(),
            "safe".into(),
        ]
    }

    fn student_vocab() -> Vec<String> {
        vec![
            "hel".into(),
            "lo".into(),
            "wor".into(),
            "ld".into(),
            "un".into(),
            "safe".into(),
        ]
    }

    #[test]
    fn build_projection_from_vocabularies() {
        let proj = SparseProjectionMatrix::from_vocabularies(&teacher_vocab(), &student_vocab());
        assert_eq!(proj.teacher_vocab_size, 4);
        assert_eq!(proj.student_vocab_size, 6);
        assert!(proj.nnz() > 0);
        assert!(proj.sparsity() > 0.0);
        assert!(proj.sparsity() < 1.0);
    }

    #[test]
    fn project_teacher_logits() {
        let proj = SparseProjectionMatrix::from_vocabularies(&teacher_vocab(), &student_vocab());
        let teacher_logits = vec![0.9, 0.1, 0.8, 0.2];
        let student_logits = proj.project(&teacher_logits).unwrap();
        assert_eq!(student_logits.len(), 6);
        // "safe" in student vocab should get contribution from both "unsafe" and "safe" teacher tokens
        let safe_idx = 5;
        assert!(student_logits[safe_idx] > 0.0);
    }

    #[test]
    fn project_dimension_mismatch() {
        let proj = SparseProjectionMatrix::from_vocabularies(&teacher_vocab(), &student_vocab());
        let bad_logits = vec![1.0, 2.0]; // wrong size
        let result = proj.project(&bad_logits);
        assert!(result.is_err());
    }

    #[test]
    fn project_zero_logits() {
        let proj = SparseProjectionMatrix::from_vocabularies(&teacher_vocab(), &student_vocab());
        let zeros = vec![0.0; 4];
        let result = proj.project(&zeros).unwrap();
        assert!(result.iter().all(|v| *v == 0.0));
    }

    #[test]
    fn save_and_load_roundtrip() {
        let proj = SparseProjectionMatrix::from_vocabularies(&teacher_vocab(), &student_vocab());
        let dir = std::env::temp_dir().join("navra_projection_test");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("test_projection.bin");

        proj.save(&path).unwrap();
        let loaded = SparseProjectionMatrix::load(&path).unwrap();

        assert_eq!(loaded.teacher_vocab_size, proj.teacher_vocab_size);
        assert_eq!(loaded.student_vocab_size, proj.student_vocab_size);
        assert_eq!(loaded.nnz(), proj.nnz());
        assert_eq!(loaded.row_ptr, proj.row_ptr);
        assert_eq!(loaded.col_indices, proj.col_indices);
        assert_eq!(loaded.values, proj.values);

        // Verify projection gives same results
        let logits = vec![0.9, 0.1, 0.8, 0.2];
        let orig = proj.project(&logits).unwrap();
        let from_disk = loaded.project(&logits).unwrap();
        assert_eq!(orig, from_disk);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn load_invalid_file() {
        let dir = std::env::temp_dir().join("navra_projection_test_bad");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("bad.bin");
        std::fs::write(&path, b"short").unwrap();

        let result = SparseProjectionMatrix::load(&path);
        assert!(result.is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sparsity_of_small_matrix() {
        let proj = SparseProjectionMatrix::from_vocabularies(&teacher_vocab(), &student_vocab());
        let sp = proj.sparsity();
        // 4x6 = 24 total entries, typically most are zero
        assert!(sp > 0.5, "sparsity should be high: {sp}");
    }

    #[test]
    fn empty_vocabularies() {
        let proj = SparseProjectionMatrix::from_vocabularies(&[], &[]);
        assert_eq!(proj.teacher_vocab_size, 0);
        assert_eq!(proj.student_vocab_size, 0);
        assert_eq!(proj.nnz(), 0);
    }

    #[test]
    fn char_ngrams_short_token() {
        let ngrams = char_ngrams("ab", 3);
        assert_eq!(ngrams.len(), 1);
        assert!(ngrams.contains("ab"));
    }

    #[test]
    fn char_ngrams_normal_token() {
        let ngrams = char_ngrams("hello", 3);
        assert!(ngrams.contains("hel"));
        assert!(ngrams.contains("ell"));
        assert!(ngrams.contains("llo"));
    }

    #[test]
    fn graceful_load_nonexistent() {
        let result = SparseProjectionMatrix::load(Path::new("/nonexistent/path.bin"));
        assert!(result.is_err());
    }
}
