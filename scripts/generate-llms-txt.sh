#!/usr/bin/env bash
# Generate llms.txt and llms-full.txt from Zola markdown content.
# Run after `zola build` — outputs go into docs/public/.
set -euo pipefail

DOCS_ROOT="$(cd "$(dirname "$0")/../docs" && pwd)"
CONTENT_DIR="$DOCS_ROOT/content/docs"
OUT_DIR="$DOCS_ROOT/public"
BASE_URL="https://navra.smgglrs.ai/docs"

mkdir -p "$OUT_DIR"

# Strip Zola +++ frontmatter from a markdown file, print the body.
strip_frontmatter() {
    awk 'BEGIN{n=0} /^\+\+\+$/{n++; next} n>=2{print}' "$1"
}

# Extract the title from Zola frontmatter.
extract_title() {
    awk '/^\+\+\+$/{ n++; next } n==1 && /^title *= *"/{
        gsub(/^title *= *"/, ""); gsub(/".*/, ""); print; exit
    }' "$1"
}

# Extract the description from Zola frontmatter.
extract_description() {
    awk '/^\+\+\+$/{ n++; next } n==1 && /^description *= *"/{
        gsub(/^description *= *"/, ""); gsub(/".*/, ""); print; exit
    }' "$1"
}

# Convert a file path to its URL path.
# docs/content/docs/security/_index.md -> /docs/security/
# docs/content/docs/guides/flows.md   -> /docs/guides/flows/
file_to_url() {
    local rel="${1#$CONTENT_DIR/}"
    rel="${rel%_index.md}"
    rel="${rel%.md}/"
    # Clean up double slashes
    rel="${rel//\/\//\/}"
    echo "${BASE_URL%/docs}/${rel%/}/"
}

# Collect all markdown files, sorted by path for stable output.
mapfile -t files < <(find "$CONTENT_DIR" -name "*.md" -type f | sort)

# --- llms.txt (index) ---
{
    echo "# navra"
    echo ""
    echo "> Secure MCP gateway daemon for Linux desktops."
    echo "> Capability tokens, IFC, safety hooks, audit blackbox, multi-agent flows."
    echo ""
    echo "## Docs"
    echo ""
    for f in "${files[@]}"; do
        title="$(extract_title "$f")"
        desc="$(extract_description "$f")"
        url="$(file_to_url "$f")"
        if [[ -n "$title" ]]; then
            if [[ -n "$desc" ]]; then
                echo "- [$title]($url): $desc"
            else
                echo "- [$title]($url)"
            fi
        fi
    done
} > "$OUT_DIR/llms.txt"

# --- llms-full.txt (concatenated) ---
{
    echo "# navra — Full Documentation"
    echo ""
    echo "Secure MCP gateway daemon for Linux desktops."
    echo ""
    for f in "${files[@]}"; do
        title="$(extract_title "$f")"
        [[ -z "$title" ]] && continue
        url="$(file_to_url "$f")"
        echo "---"
        echo ""
        echo "# $title"
        echo ""
        echo "Source: $url"
        echo ""
        strip_frontmatter "$f"
        echo ""
    done
} > "$OUT_DIR/llms-full.txt"

index_count=$(wc -l < "$OUT_DIR/llms.txt")
full_size=$(du -h "$OUT_DIR/llms-full.txt" | cut -f1)
echo "Generated llms.txt ($index_count lines) and llms-full.txt ($full_size) in $OUT_DIR/"
