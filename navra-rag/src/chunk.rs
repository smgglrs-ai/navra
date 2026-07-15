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
    /// Structural breadcrumb: heading hierarchy path for this chunk.
    /// Example: `"AMD > Financial Statements > Cash Flows"`.
    /// Set by [`inject_breadcrumbs`] after chunking.
    pub breadcrumb: Option<String>,
    /// Parent section byte range (heading to next heading).
    /// Set by [`inject_section_pointers`] after chunking.
    pub section_start_byte: Option<usize>,
    pub section_end_byte: Option<usize>,
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
    /// Skip chunks with predicted value below this threshold (0.0–1.0).
    /// `None` = index everything (default).
    pub graphability_threshold: Option<f32>,
}

impl Default for ChunkConfig {
    fn default() -> Self {
        Self {
            target_size: 1024,
            overlap: 128,
            min_size: 64,
            graphability_threshold: None,
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
            result.extend(split_at_sentences(
                text,
                para.start,
                para.end,
                config.target_size,
            ));
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
    if let Some(start) = current_start
        && current_len > 0
    {
        let end = paragraphs.last().map(|p| p.end).unwrap_or(start);
        result.push(Segment { start, end });
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
        let code_indicators = lines
            .iter()
            .filter(|l| {
                let t = l.trim();
                t.ends_with(';')
                    || t.ends_with('{')
                    || t.ends_with('}')
                    || t.starts_with("fn ")
                    || t.starts_with("pub ")
                    || t.starts_with("def ")
                    || t.starts_with("class ")
                    || t.starts_with("import ")
                    || t.starts_with("use ")
            })
            .count();
        code_indicators > lines.len() / 3
    };

    if is_code {
        // Code splitting: find function/struct/impl boundaries
        let code_boundaries = [
            "\nfn ",
            "\npub ",
            "\nimpl ",
            "\nstruct ",
            "\nenum ",
            "\nmod ",
            "\nclass ",
            "\ndef ",
            "\nfunction ",
            "\n\n",
        ];
        while seg_start < end {
            let remaining = &text[seg_start..end];
            if remaining.len() <= target {
                result.push(Segment {
                    start: seg_start,
                    end,
                });
                break;
            }
            // Search for a boundary near the target
            let search_end = target.min(remaining.len());
            let search_zone = &remaining[..search_end];
            let best = code_boundaries
                .iter()
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
            result.push(Segment {
                start: seg_start,
                end: split_at,
            });
            seg_start = split_at;
        }
    } else {
        // Prose splitting: find sentence boundaries
        let sentence_ends = [". ", ".\n", "! ", "!\n", "? ", "?\n"];
        while seg_start < end {
            let remaining = &text[seg_start..end];
            if remaining.len() <= target {
                result.push(Segment {
                    start: seg_start,
                    end,
                });
                break;
            }
            let search_end = target.min(remaining.len());
            let search_zone = &remaining[..search_end];
            let best = sentence_ends
                .iter()
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
            result.push(Segment {
                start: seg_start,
                end: split_at,
            });
            seg_start = split_at;
        }
    }

    if result.is_empty() {
        result.push(Segment { start, end });
    }
    result
}

/// Build final chunks with overlap from normalized segments.
fn build_chunks_with_overlap(segments: &[Segment], text: &str, config: &ChunkConfig) -> Vec<Chunk> {
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
            breadcrumb: None,
            section_start_byte: None,
            section_end_byte: None,
        });
    }

    // If no chunks were created but text meets minimum size, create a single chunk
    if chunks.is_empty() && text.trim().len() >= config.min_size {
        chunks.push(Chunk {
            content: text.to_string(),
            start_byte: 0,
            end_byte: text.len(),
            index: 0,
            breadcrumb: None,
            section_start_byte: None,
            section_end_byte: None,
        });
    }

    chunks
}

/// Inject section byte ranges into chunks based on heading structure.
///
/// Each chunk gets the byte range of its containing section (heading
/// to next heading). On retrieval, the full section can be loaded
/// instead of the chunk fragment.
pub fn inject_section_pointers(chunks: &mut [Chunk], source: &str) {
    let headings = parse_headings(source);
    if headings.is_empty() {
        return;
    }

    for chunk in chunks.iter_mut() {
        let (start, end) = section_range_at(&headings, chunk.start_byte, source.len());
        chunk.section_start_byte = Some(start);
        chunk.section_end_byte = Some(end);
    }
}

fn section_range_at(headings: &[Heading], byte_pos: usize, doc_len: usize) -> (usize, usize) {
    let mut section_start = 0;
    let mut section_end = doc_len;
    for (i, h) in headings.iter().enumerate() {
        if h.byte_offset <= byte_pos {
            section_start = h.byte_offset;
            section_end = headings
                .get(i + 1)
                .map(|next| next.byte_offset)
                .unwrap_or(doc_len);
        }
    }
    (section_start, section_end)
}

/// Inject breadcrumbs into chunks based on the source document's heading structure.
///
/// Parses Markdown `#` headings from the source text, builds a hierarchical
/// path, and assigns the active heading path to each chunk based on its byte
/// position. The breadcrumb is prepended to `content` so embeddings capture
/// both structural position and semantic content.
///
/// For documents without headings, chunks are left unchanged.
pub fn inject_breadcrumbs(chunks: &mut [Chunk], source: &str) {
    let headings = parse_headings(source);
    if headings.is_empty() {
        return;
    }

    for chunk in chunks.iter_mut() {
        let path = heading_path_at(&headings, chunk.start_byte);
        if !path.is_empty() {
            let breadcrumb = path.join(" > ");
            chunk.breadcrumb = Some(breadcrumb.clone());
            chunk.content = format!("{breadcrumb}\n\n{}", chunk.content);
        }
    }
}

struct Heading {
    level: usize,
    title: String,
    byte_offset: usize,
}

fn parse_headings(text: &str) -> Vec<Heading> {
    let mut headings = Vec::new();
    let mut offset = 0;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            let level = trimmed.chars().take_while(|&c| c == '#').count();
            if level <= 6 {
                let title = trimmed[level..].trim_start_matches(' ').trim().to_string();
                if !title.is_empty() {
                    headings.push(Heading {
                        level,
                        title,
                        byte_offset: offset,
                    });
                }
            }
        }
        offset += line.len() + 1; // +1 for newline
    }
    headings
}

fn heading_path_at(headings: &[Heading], byte_pos: usize) -> Vec<String> {
    let mut stack: Vec<(usize, String)> = Vec::new();

    for h in headings {
        if h.byte_offset > byte_pos {
            break;
        }
        while stack.last().is_some_and(|(lvl, _)| *lvl >= h.level) {
            stack.pop();
        }
        stack.push((h.level, h.title.clone()));
    }

    stack.into_iter().map(|(_, title)| title).collect()
}

/// Quality metrics for a set of chunks produced by the chunking engine.
#[derive(Debug, Clone)]
pub struct ChunkQuality {
    /// Fraction of chunks that preserve structural block integrity (0.0–1.0).
    /// A chunk with unbalanced code fences, mid-list splits, or mid-table
    /// splits scores 0; intact chunks score 1.
    pub block_integrity: f32,
    /// Fraction of chunks whose size falls within target_size ± 50% (0.0–1.0).
    pub size_compliance: f32,
    /// Total number of chunks evaluated.
    pub chunk_count: usize,
}

/// Evaluate the quality of a set of chunks against configuration targets.
///
/// Checks structural integrity (balanced code fences, no mid-list/table splits)
/// and size compliance (within target ± 50%).
pub fn evaluate_quality(chunks: &[Chunk], config: &ChunkConfig) -> ChunkQuality {
    if chunks.is_empty() {
        return ChunkQuality {
            block_integrity: 1.0,
            size_compliance: 1.0,
            chunk_count: 0,
        };
    }

    let mut intact = 0usize;
    let mut compliant = 0usize;
    let lower = config.target_size / 2;
    let upper = config.target_size + config.target_size / 2;

    for chunk in chunks {
        // Block integrity: check for split code fences, mid-list, mid-table
        let fences = chunk.content.matches("```").count();
        let has_split_fence = fences % 2 != 0;

        // Mid-list: chunk ends with a list item pattern but the content
        // continues with list items (heuristic: ends mid-list if last
        // non-empty line starts with "- " or "* " or a numbered pattern
        // and doesn't look like a complete section)
        let lines: Vec<&str> = chunk.content.lines().collect();
        let has_mid_list = if let Some(last) = lines.last() {
            let trimmed = last.trim();
            let is_list_item = trimmed.starts_with("- ")
                || trimmed.starts_with("* ")
                || (trimmed.len() > 2
                    && trimmed.as_bytes()[0].is_ascii_digit()
                    && trimmed.contains(". "));
            // Only flag if the chunk starts with non-list content
            // (a pure list chunk is fine)
            let first_list = lines
                .iter()
                .position(|l| {
                    let t = l.trim();
                    t.starts_with("- ") || t.starts_with("* ")
                })
                .unwrap_or(lines.len());
            is_list_item && first_list > 0
        } else {
            false
        };

        // Mid-table: chunk contains table separator (|---|) but doesn't
        // have a balanced structure
        let has_mid_table = {
            let pipe_lines = lines
                .iter()
                .filter(|l| l.trim_start().starts_with('|'))
                .count();
            // A table needs at least header + separator + 1 row = 3 pipe lines
            // If we have 1-2 pipe lines, likely a split table
            pipe_lines > 0 && pipe_lines < 3
        };

        if !has_split_fence && !has_mid_list && !has_mid_table {
            intact += 1;
        }

        // Size compliance
        let size = chunk.content.len();
        if size >= lower && size <= upper {
            compliant += 1;
        }
    }

    ChunkQuality {
        block_integrity: intact as f32 / chunks.len() as f32,
        size_compliance: compliant as f32 / chunks.len() as f32,
        chunk_count: chunks.len(),
    }
}

/// Document type classification for adaptive chunking strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocumentType {
    /// Source code (high ratio of indentation, braces, semicolons).
    Code,
    /// Natural language prose (sentences, paragraphs).
    Prose,
    /// Markdown with headings, lists, and mixed content.
    Markdown,
    /// Structured data (JSON, YAML, TOML, XML, CSV).
    Structured,
}

const LOW_VALUE_HEADINGS: &[&str] = &[
    "appendix",
    "license",
    "changelog",
    "references",
    "disclaimer",
    "contributors",
    "acknowledgments",
    "acknowledgements",
    "table of contents",
    "legal",
    "copyright",
];

/// Predict the indexing value of a chunk (0.0–1.0).
///
/// High-value chunks contain substantive prose that answers questions.
/// Low-value chunks are boilerplate (license, changelog, appendix)
/// that pollute retrieval results.
pub fn predict_chunk_value(chunk: &Chunk, config: &ChunkConfig) -> f32 {
    let mut score: f32 = 1.0;

    // Breadcrumb-based signals
    if let Some(ref bc) = chunk.breadcrumb {
        let bc_lower = bc.to_lowercase();

        // Low-value heading keywords
        for keyword in LOW_VALUE_HEADINGS {
            if bc_lower.contains(keyword) {
                return 0.1;
            }
        }

        // Depth penalty: sections deeper than 3 levels are increasingly niche
        let depth = bc.matches(" > ").count() + 1;
        if depth > 3 {
            score -= 0.1 * (depth - 3) as f32;
        }
    }

    // Size outlier penalty
    let len = chunk.content.len();
    if len < config.min_size {
        score -= 0.3;
    } else if len > config.target_size * 3 {
        score -= 0.2;
    }

    // Code-only detection: high ratio of code indicators without prose
    let lines: Vec<&str> = chunk.content.lines().collect();
    let total_lines = lines.len().max(1);
    let code_lines = lines
        .iter()
        .filter(|l| {
            let t = l.trim();
            t.starts_with("//")
                || t.starts_with('#')
                || t.starts_with("/*")
                || t.ends_with(';')
                || t.ends_with('{')
                || t.ends_with('}')
                || t.starts_with("fn ")
                || t.starts_with("pub ")
                || t.starts_with("use ")
                || t.starts_with("impl ")
                || t.starts_with("struct ")
        })
        .count();
    if total_lines > 3 && code_lines as f32 / total_lines as f32 > 0.8 {
        score = score.min(0.5);
    }

    score.clamp(0.0, 1.0)
}

/// Detect the document type from text content using line pattern heuristics.
pub fn detect_document_type(text: &str) -> DocumentType {
    let lines: Vec<&str> = text.lines().take(50).collect();
    if lines.is_empty() {
        return DocumentType::Prose;
    }

    let total = lines.len();

    // Check for structured data first (JSON, YAML, TOML, XML, CSV)
    let first_non_empty = lines.iter().find(|l| !l.trim().is_empty());
    if let Some(first) = first_non_empty {
        let trimmed = first.trim();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            return DocumentType::Structured;
        }
        if trimmed.starts_with("<?xml") || trimmed.starts_with("<!DOCTYPE") {
            return DocumentType::Structured;
        }
    }

    // Count YAML/TOML indicators
    let yaml_toml_lines = lines
        .iter()
        .filter(|l| {
            let t = l.trim();
            t.contains(": ") && !t.starts_with('#') && !t.starts_with("//")
                || t.starts_with('[') && t.ends_with(']') && !t.contains("](")
                || t == "---"
        })
        .count();
    if yaml_toml_lines > total / 2 {
        return DocumentType::Structured;
    }

    // Count Markdown indicators
    let markdown_lines = lines
        .iter()
        .filter(|l| {
            let t = l.trim();
            t.starts_with('#')
                || t.starts_with("- ")
                || t.starts_with("* ")
                || t.starts_with("> ")
                || t.starts_with("```")
                || t.starts_with("| ")
                || (t.len() > 3 && t.as_bytes()[0] == b'[' && t.contains("]("))
        })
        .count();

    // Count code indicators
    let code_lines = lines
        .iter()
        .filter(|l| {
            let t = l.trim();
            t.ends_with(';')
                || t.ends_with('{')
                || t.ends_with('}')
                || t.starts_with("fn ")
                || t.starts_with("pub ")
                || t.starts_with("def ")
                || t.starts_with("class ")
                || t.starts_with("import ")
                || t.starts_with("use ")
                || t.starts_with("const ")
                || t.starts_with("let ")
                || t.starts_with("var ")
                || t.starts_with("func ")
                || t.starts_with("#include")
                || t.starts_with("package ")
        })
        .count();

    if code_lines > total / 3 {
        return DocumentType::Code;
    }
    if markdown_lines > total / 4 {
        return DocumentType::Markdown;
    }

    DocumentType::Prose
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
            graphability_threshold: None,
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
            graphability_threshold: None,
        };
        let chunks = chunk_text(&text, &config);
        assert!(
            chunks.len() >= 2,
            "Should split into multiple chunks, got {}",
            chunks.len()
        );
    }

    #[test]
    fn chunks_have_sequential_indices() {
        let text = format!("{}\n\n{}\n\n{}", "A ".repeat(500), "B ".repeat(500), "C ".repeat(500));
        let config = ChunkConfig {
            target_size: 300,
            overlap: 0,
            min_size: 10,
            graphability_threshold: None,
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
            graphability_threshold: None,
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
            graphability_threshold: None,
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
            graphability_threshold: None,
        };
        let chunks = chunk_text(code, &config);
        assert!(
            chunks.len() >= 2,
            "Code should split into 2+ chunks at function boundaries, got {}",
            chunks.len()
        );
        // No chunk should start mid-line
        for chunk in &chunks {
            let first_char = chunk.content.chars().next().unwrap_or(' ');
            assert!(
                first_char != ' ' && first_char != '\t',
                "Chunk should not start with indentation: {:?}",
                &chunk.content[..20.min(chunk.content.len())]
            );
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
            graphability_threshold: None,
        };
        let chunks = chunk_text(prose, &config);
        assert!(
            chunks.len() >= 2,
            "Prose should split into 2+ chunks, got {}",
            chunks.len()
        );
        // Each chunk (except last) should end at a sentence boundary
        for chunk in &chunks[..chunks.len() - 1] {
            let trimmed = chunk.content.trim_end();
            assert!(
                trimmed.ends_with('.') || trimmed.ends_with('!') || trimmed.ends_with('?'),
                "Chunk should end at sentence boundary: {:?}",
                &trimmed[trimmed.len().saturating_sub(30)..]
            );
        }
    }

    #[test]
    fn breadcrumb_parse_markdown_headings() {
        let headings = parse_headings("# Top\n## Sub\nContent\n### Deep\nMore");
        assert_eq!(headings.len(), 3);
        assert_eq!(headings[0].title, "Top");
        assert_eq!(headings[0].level, 1);
        assert_eq!(headings[1].title, "Sub");
        assert_eq!(headings[1].level, 2);
        assert_eq!(headings[2].title, "Deep");
        assert_eq!(headings[2].level, 3);
    }

    #[test]
    fn breadcrumb_heading_path_at_position() {
        let text = "# A\n## B\nContent here\n## C\nMore content\n### D\n";
        let headings = parse_headings(text);
        let pos = text.find("Content").unwrap();
        let path = heading_path_at(&headings, pos);
        assert_eq!(path, vec!["A", "B"]);

        let pos = text.find("More").unwrap();
        let path = heading_path_at(&headings, pos);
        assert_eq!(path, vec!["A", "C"]);
    }

    #[test]
    fn breadcrumb_inject_prepends_to_content() {
        let source = "# Project\n## Setup\nInstall dependencies.\n## Usage\nRun the app.";
        let config = ChunkConfig {
            target_size: 30,
            overlap: 0,
            min_size: 5,
            graphability_threshold: None,
        };
        let mut chunks = chunk_text(source, &config);
        inject_breadcrumbs(&mut chunks, source);

        for chunk in &chunks {
            assert!(chunk.breadcrumb.is_some());
            assert!(chunk.content.contains(" > ") || chunk.content.starts_with("Project"));
        }
    }

    #[test]
    fn breadcrumb_no_headings_unchanged() {
        let source = "Just plain text without any headings at all.";
        let config = ChunkConfig {
            target_size: 1000,
            overlap: 0,
            min_size: 5,
            graphability_threshold: None,
        };
        let mut chunks = chunk_text(source, &config);
        let original_content = chunks[0].content.clone();
        inject_breadcrumbs(&mut chunks, source);
        assert!(chunks[0].breadcrumb.is_none());
        assert_eq!(chunks[0].content, original_content);
    }

    #[test]
    fn breadcrumb_sibling_headings_reset() {
        let text = "# Root\n## A\nUnder A\n## B\nUnder B";
        let headings = parse_headings(text);
        let pos = text.find("Under B").unwrap();
        let path = heading_path_at(&headings, pos);
        assert_eq!(path, vec!["Root", "B"]);
    }

    // --- Adaptive chunking metrics tests (7m) ---

    #[test]
    fn quality_detects_split_code_fences() {
        // A chunk with an unbalanced code fence has bad block integrity
        let chunks = vec![
            Chunk {
                content: "```rust\nfn main() {}\n```".to_string(),
                start_byte: 0,
                end_byte: 24,
                index: 0,
                breadcrumb: None,
                section_start_byte: None,
                section_end_byte: None,
            },
            Chunk {
                content: "Some text\n```python\nimport os".to_string(),
                start_byte: 24,
                end_byte: 55,
                index: 1,
                breadcrumb: None,
                section_start_byte: None,
                section_end_byte: None,
            },
        ];
        let config = ChunkConfig::default();
        let quality = evaluate_quality(&chunks, &config);
        assert_eq!(quality.chunk_count, 2);
        // First chunk has balanced fences (2 ```) → intact
        // Second chunk has unbalanced fence (1 ```) → broken
        assert!(
            quality.block_integrity < 1.0,
            "Should detect split code fence, got {}",
            quality.block_integrity
        );
        assert!(
            quality.block_integrity > 0.0,
            "First chunk should be intact"
        );
    }

    #[test]
    fn quality_perfect_for_well_formed_chunks() {
        let config = ChunkConfig {
            target_size: 100,
            overlap: 0,
            min_size: 10,
            graphability_threshold: None,
        };
        let content = "A ".repeat(40); // 80 chars, within 50-150 range
        let chunks = vec![Chunk {
            content: content.clone(),
            start_byte: 0,
            end_byte: content.len(),
            index: 0,
            breadcrumb: None,
            section_start_byte: None,
            section_end_byte: None,
        }];
        let quality = evaluate_quality(&chunks, &config);
        assert_eq!(quality.block_integrity, 1.0);
        assert_eq!(quality.size_compliance, 1.0);
    }

    #[test]
    fn quality_size_compliance_rejects_outliers() {
        let config = ChunkConfig {
            target_size: 100,
            overlap: 0,
            min_size: 10,
            graphability_threshold: None,
        };
        // A very short chunk (10 chars) is below lower bound (50)
        let chunks = vec![Chunk {
            content: "tiny chunk".to_string(),
            start_byte: 0,
            end_byte: 10,
            index: 0,
            breadcrumb: None,
            section_start_byte: None,
            section_end_byte: None,
        }];
        let quality = evaluate_quality(&chunks, &config);
        assert_eq!(
            quality.size_compliance, 0.0,
            "10-char chunk should not comply with target 100"
        );
    }

    #[test]
    fn detect_document_type_code() {
        let code = "use std::io;\n\nfn main() {\n    println!(\"hello\");\n}\n";
        assert_eq!(detect_document_type(code), DocumentType::Code);
    }

    #[test]
    fn detect_document_type_prose() {
        let prose = "This is a paragraph about natural language processing. \
            It contains multiple sentences that describe concepts in detail. \
            The text flows naturally from one idea to the next.";
        assert_eq!(detect_document_type(prose), DocumentType::Prose);
    }

    #[test]
    fn detect_document_type_markdown() {
        let md = "# Title\n\n## Section One\n\n- Item A\n- Item B\n- Item C\n\n> A blockquote\n\n## Section Two\n\nSome text.\n";
        assert_eq!(detect_document_type(md), DocumentType::Markdown);
    }

    #[test]
    fn graphability_scores_appendix_low() {
        let config = ChunkConfig::default();
        let chunk = Chunk {
            content: "This appendix lists supplementary data.".to_string(),
            start_byte: 0,
            end_byte: 40,
            index: 0,
            breadcrumb: Some("Document > Appendix A".to_string()),
            section_start_byte: None,
            section_end_byte: None,
        };
        let score = predict_chunk_value(&chunk, &config);
        assert!(score <= 0.2, "appendix should score low, got {score}");
    }

    #[test]
    fn graphability_scores_license_low() {
        let config = ChunkConfig::default();
        let chunk = Chunk {
            content: "MIT License. Copyright 2026.".to_string(),
            start_byte: 0,
            end_byte: 28,
            index: 0,
            breadcrumb: Some("License".to_string()),
            section_start_byte: None,
            section_end_byte: None,
        };
        let score = predict_chunk_value(&chunk, &config);
        assert!(score <= 0.2, "license should score low, got {score}");
    }

    #[test]
    fn graphability_scores_normal_prose_high() {
        let config = ChunkConfig::default();
        let chunk = Chunk {
            content: "The authentication module validates bearer tokens against \
                      the configured identity provider. Tokens are checked for \
                      expiry, scope, and issuer before granting access."
                .to_string(),
            start_byte: 0,
            end_byte: 180,
            index: 0,
            breadcrumb: Some("Architecture > Authentication".to_string()),
            section_start_byte: None,
            section_end_byte: None,
        };
        let score = predict_chunk_value(&chunk, &config);
        assert!(score >= 0.7, "normal prose should score high, got {score}");
    }

    #[test]
    fn graphability_no_breadcrumb_defaults_high() {
        let config = ChunkConfig::default();
        let chunk = Chunk {
            content: "Regular content without section context.".to_string(),
            start_byte: 0,
            end_byte: 42,
            index: 0,
            breadcrumb: None,
            section_start_byte: None,
            section_end_byte: None,
        };
        let score = predict_chunk_value(&chunk, &config);
        assert!(
            score >= 0.7,
            "no breadcrumb should default high, got {score}"
        );
    }
}
