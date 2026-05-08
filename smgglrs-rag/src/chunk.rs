//! Text chunking engine for RAG indexing.
//!
//! Splits documents into overlapping chunks suitable for embedding.
//! Strategy:
//! 1. Split by paragraph boundaries (double newline)
//! 2. Merge short paragraphs to reach target size
//! 3. Split long paragraphs at sentence boundaries
//! 4. Add overlap between adjacent chunks

/// A chunk of text with byte offsets into the source document.
#[derive(Debug, Clone)]
pub struct Chunk {
    /// The chunk text content.
    pub content: String,
    /// Byte offset of the start in the source document.
    pub start_byte: usize,
    /// Byte offset of the end (exclusive) in the source document.
    pub end_byte: usize,
    /// Zero-based chunk index within the document.
    pub index: usize,
}

/// Configuration for the chunking engine.
#[derive(Debug, Clone)]
pub struct ChunkConfig {
    /// Target chunk size in characters (approximate).
    pub target_size: usize,
    /// Overlap between adjacent chunks in characters.
    pub overlap: usize,
    /// Minimum chunk size — don't create chunks smaller than this.
    pub min_size: usize,
}

impl Default for ChunkConfig {
    fn default() -> Self {
        Self {
            target_size: 1024,
            overlap: 128,
            min_size: 64,
        }
    }
}

/// Split a document into chunks.
pub fn chunk_text(text: &str, config: &ChunkConfig) -> Vec<Chunk> {
    if text.is_empty() {
        return Vec::new();
    }

    // Phase 1: split into paragraphs
    let paragraphs = split_paragraphs(text);

    // Phase 2: merge short paragraphs, split long ones
    let segments = normalize_segments(text, &paragraphs, config);

    // Phase 3: build chunks with overlap
    build_chunks_with_overlap(&segments, text, config)
}

/// A text segment with its byte range in the source.
struct Segment {
    start: usize,
    end: usize,
}

/// Split text into paragraphs (separated by blank lines).
fn split_paragraphs(text: &str) -> Vec<Segment> {
    let mut segments = Vec::new();
    let mut start = 0;
    let bytes = text.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        // Find double newline (paragraph boundary)
        if i + 1 < len && bytes[i] == b'\n' && bytes[i + 1] == b'\n' {
            if i > start {
                segments.push(Segment { start, end: i });
            }
            // Skip blank lines
            while i < len && bytes[i] == b'\n' {
                i += 1;
            }
            start = i;
        } else {
            i += 1;
        }
    }

    // Last segment
    if start < len {
        let end = text.trim_end().len().max(start);
        if end > start {
            segments.push(Segment { start, end });
        }
    }

    if segments.is_empty() && !text.trim().is_empty() {
        segments.push(Segment {
            start: 0,
            end: text.trim_end().len(),
        });
    }

    segments
}

/// Merge short segments and split long ones to approximate target_size.
fn normalize_segments(text: &str, paragraphs: &[Segment], config: &ChunkConfig) -> Vec<Segment> {
    let mut result = Vec::new();
    let mut current_start = None;
    let mut current_len = 0;

    for para in paragraphs {
        let para_len = para.end - para.start;

        if para_len > config.target_size * 2 {
            // Flush accumulated short segments first
            if let Some(start) = current_start.take() {
                result.push(Segment {
                    start,
                    end: para.start,
                });
                current_len = 0;
            }
            // This paragraph is too long — split at sentence/statement boundaries
            result.extend(split_at_sentences(text, para.start, para.end, config.target_size));
            continue;
        }

        match current_start {
            None => {
                current_start = Some(para.start);
                current_len = para_len;
            }
            Some(start) => {
                let merged_len = para.end - start;
                if merged_len > config.target_size {
                    // Current accumulation is big enough, flush it
                    result.push(Segment {
                        start,
                        end: para.start,
                    });
                    current_start = Some(para.start);
                    current_len = para_len;
                } else {
                    current_len = merged_len;
                }
            }
        }
    }

    // Flush remaining
    if let Some(start) = current_start {
        if current_len > 0 {
            let end = paragraphs.last().map(|p| p.end).unwrap_or(start);
            result.push(Segment { start, end });
        }
    }

    result
}

/// Split a long text segment at sentence or statement boundaries.
///
/// For prose, splits at ". ", "! ", "? ", or paragraph breaks.
/// For code, splits at blank lines or lines starting with `fn `,
/// `pub `, `impl `, `struct `, `enum `, `mod `, `class `, `def `,
/// `function ` — common top-level declaration patterns.
fn split_at_sentences(text: &str, start: usize, end: usize, target: usize) -> Vec<Segment> {
    let mut result = Vec::new();
    let mut seg_start = start;
    let slice = &text[start..end];

    // Detect code-like content: high ratio of lines with leading whitespace
    // or braces/semicolons.
    let is_code = {
        let lines: Vec<&str> = slice.lines().take(20).collect();
        let code_indicators = lines.iter().filter(|l| {
            let t = l.trim();
            t.ends_with(';') || t.ends_with('{') || t.ends_with('}')
                || t.starts_with("fn ") || t.starts_with("pub ")
                || t.starts_with("def ") || t.starts_with("class ")
                || t.starts_with("import ") || t.starts_with("use ")
        }).count();
        code_indicators > lines.len() / 3
    };

    if is_code {
        // Code splitting: find function/struct/impl boundaries
        let code_boundaries = [
            "\nfn ", "\npub ", "\nimpl ", "\nstruct ", "\nenum ", "\nmod ",
            "\nclass ", "\ndef ", "\nfunction ", "\n\n",
        ];
        while seg_start < end {
            let remaining = &text[seg_start..end];
            if remaining.len() <= target {
                result.push(Segment { start: seg_start, end });
                break;
            }
            // Search for a boundary near the target
            let search_end = target.min(remaining.len());
            let search_zone = &remaining[..search_end];
            let best = code_boundaries.iter()
                .filter_map(|b| search_zone.rfind(b).map(|p| p + 1)) // +1 to keep \n with previous
                .max();
            let split_at = match best {
                Some(p) if p > target / 4 => seg_start + p,
                _ => {
                    // No boundary found — fall back to newline
                    if let Some(nl) = search_zone.rfind('\n') {
                        seg_start + nl + 1
                    } else {
                        seg_start + search_end
                    }
                }
            };
            result.push(Segment { start: seg_start, end: split_at });
            seg_start = split_at;
        }
    } else {
        // Prose splitting: find sentence boundaries
        let sentence_ends = [". ", ".\n", "! ", "!\n", "? ", "?\n"];
        while seg_start < end {
            let remaining = &text[seg_start..end];
            if remaining.len() <= target {
                result.push(Segment { start: seg_start, end });
                break;
            }
            let search_end = target.min(remaining.len());
            let search_zone = &remaining[..search_end];
            let best = sentence_ends.iter()
                .filter_map(|s| search_zone.rfind(s).map(|p| p + s.len()))
                .max();
            let split_at = match best {
                Some(p) if p > target / 4 => seg_start + p,
                _ => {
                    if let Some(nl) = search_zone.rfind('\n') {
                        seg_start + nl + 1
                    } else {
                        seg_start + search_end
                    }
                }
            };
            result.push(Segment { start: seg_start, end: split_at });
            seg_start = split_at;
        }
    }

    if result.is_empty() {
        result.push(Segment { start, end });
    }
    result
}

/// Build final chunks with overlap from normalized segments.
fn build_chunks_with_overlap(
    segments: &[Segment],
    text: &str,
    config: &ChunkConfig,
) -> Vec<Chunk> {
    let mut chunks = Vec::new();

    for (i, seg) in segments.iter().enumerate() {
        // Extend start backward for overlap (except first chunk)
        let start = if i > 0 && seg.start > config.overlap {
            seg.start - config.overlap
        } else {
            seg.start
        };

        let end = seg.end.min(text.len());
        let content = &text[start..end];

        if content.trim().len() < config.min_size {
            continue;
        }

        chunks.push(Chunk {
            content: content.to_string(),
            start_byte: start,
            end_byte: end,
            index: chunks.len(),
        });
    }

    // If no chunks were created but text meets minimum size, create a single chunk
    if chunks.is_empty() && text.trim().len() >= config.min_size {
        chunks.push(Chunk {
            content: text.to_string(),
            start_byte: 0,
            end_byte: text.len(),
            index: 0,
        });
    }

    chunks
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_text_no_chunks() {
        let chunks = chunk_text("", &ChunkConfig::default());
        assert!(chunks.is_empty());
    }

    #[test]
    fn short_text_single_chunk() {
        let config = ChunkConfig {
            min_size: 5,
            ..ChunkConfig::default()
        };
        let chunks = chunk_text("Hello, world!", &config);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].content, "Hello, world!");
        assert_eq!(chunks[0].start_byte, 0);
        assert_eq!(chunks[0].index, 0);
    }

    #[test]
    fn paragraphs_merged_when_short() {
        let text = "Short paragraph one.\n\nShort paragraph two.\n\nShort paragraph three.";
        let config = ChunkConfig {
            target_size: 1000,
            overlap: 0,
            min_size: 10,
        };
        let chunks = chunk_text(text, &config);
        // All paragraphs should be merged into one chunk (total < target)
        assert_eq!(chunks.len(), 1);
        assert!(chunks[0].content.contains("one"));
        assert!(chunks[0].content.contains("three"));
    }

    #[test]
    fn paragraphs_split_when_large() {
        let para1 = "A ".repeat(100);
        let para2 = "B ".repeat(100);
        let para3 = "C ".repeat(100);
        let text = format!("{}\n\n{}\n\n{}", para1.trim(), para2.trim(), para3.trim());
        let config = ChunkConfig {
            target_size: 250,
            overlap: 0,
            min_size: 10,
        };
        let chunks = chunk_text(&text, &config);
        assert!(chunks.len() >= 2, "Should split into multiple chunks, got {}", chunks.len());
    }

    #[test]
    fn chunks_have_sequential_indices() {
        let text = "A ".repeat(500) + "\n\n" + &"B ".repeat(500) + "\n\n" + &"C ".repeat(500);
        let config = ChunkConfig {
            target_size: 300,
            overlap: 0,
            min_size: 10,
        };
        let chunks = chunk_text(&text, &config);
        for (i, chunk) in chunks.iter().enumerate() {
            assert_eq!(chunk.index, i);
        }
    }

    #[test]
    fn overlap_extends_start() {
        let para1 = "First paragraph content here.";
        let para2 = "Second paragraph content here.";
        let text = format!("{}\n\n{}", para1, para2);
        let config = ChunkConfig {
            target_size: 30,
            overlap: 10,
            min_size: 10,
        };
        let chunks = chunk_text(&text, &config);
        if chunks.len() >= 2 {
            // Second chunk should start before the paragraph boundary
            assert!(chunks[1].start_byte < text.find("Second").unwrap());
        }
    }

    #[test]
    fn whitespace_only_no_chunks() {
        let chunks = chunk_text("   \n\n\n   ", &ChunkConfig::default());
        assert!(chunks.is_empty());
    }

    #[test]
    fn very_short_paragraphs_filtered() {
        let text = "Hi\n\nBye";
        let config = ChunkConfig {
            target_size: 1000,
            overlap: 0,
            min_size: 100,
        };
        let chunks = chunk_text(text, &config);
        // Content is too short for min_size, but single-chunk fallback kicks in
        // Actually "Hi\n\nBye" is 7 chars which is < 100, so no chunks
        assert!(chunks.is_empty());
    }

    #[test]
    fn code_splits_at_function_boundaries() {
        let code = "\
use std::fs;\n\
\n\
fn first_function() {\n\
    let x = 1;\n\
    let y = 2;\n\
    println!(\"{}\", x + y);\n\
}\n\
\n\
fn second_function() {\n\
    let a = fs::read_to_string(\"test\");\n\
    println!(\"{:?}\", a);\n\
}\n\
\n\
pub fn third_function() {\n\
    for i in 0..10 {\n\
        println!(\"{}\", i);\n\
    }\n\
}\n";
        let config = ChunkConfig {
            target_size: 80,
            overlap: 0,
            min_size: 10,
        };
        let chunks = chunk_text(code, &config);
        assert!(chunks.len() >= 2,
            "Code should split into 2+ chunks at function boundaries, got {}", chunks.len());
        // No chunk should start mid-line
        for chunk in &chunks {
            let first_char = chunk.content.chars().next().unwrap_or(' ');
            assert!(first_char != ' ' && first_char != '\t',
                "Chunk should not start with indentation: {:?}", &chunk.content[..20.min(chunk.content.len())]);
        }
    }

    #[test]
    fn prose_splits_at_sentence_boundaries() {
        let prose = "This is the first sentence. This is the second sentence. \
            This is the third sentence. And here is a fourth one. \
            Finally the fifth sentence arrives. The sixth wraps it up.";
        let config = ChunkConfig {
            target_size: 60,
            overlap: 0,
            min_size: 10,
        };
        let chunks = chunk_text(prose, &config);
        assert!(chunks.len() >= 2,
            "Prose should split into 2+ chunks, got {}", chunks.len());
        // Each chunk (except last) should end at a sentence boundary
        for chunk in &chunks[..chunks.len()-1] {
            let trimmed = chunk.content.trim_end();
            assert!(trimmed.ends_with('.') || trimmed.ends_with('!') || trimmed.ends_with('?'),
                "Chunk should end at sentence boundary: {:?}",
                &trimmed[trimmed.len().saturating_sub(30)..]);
        }
    }
}
