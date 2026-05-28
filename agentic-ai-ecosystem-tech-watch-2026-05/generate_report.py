#!/usr/bin/env python3
"""Generate markdown research report from JSON results."""

import json
import os
import re
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
RESULTS_DIR = SCRIPT_DIR / "results"
FIELDS_PATH = SCRIPT_DIR / "fields.yaml"
OUTLINE_PATH = SCRIPT_DIR / "outline.yaml"
OUTPUT_PATH = SCRIPT_DIR / "report.md"

TOC_FIELDS = [
    ("smgglrs_relevance.impact_level", "Impact"),
    ("smgglrs_relevance.relevance_category", "Category"),
    ("basic_info.type", "Type"),
]

CATEGORY_MAPPING = {
    "basic_info": ["basic_info", "Basic Info"],
    "summary": ["summary", "Summary"],
    "smgglrs_relevance": ["smgglrs_relevance", "Smgglrs Relevance"],
    "actionable_insights": ["actionable_insights", "Actionable Insights"],
    "competitive_position": ["competitive_position", "Competitive Position"],
    "ecosystem_context": ["ecosystem_context", "Ecosystem Context"],
    "economics": ["economics", "Economics"],
}

INTERNAL_FIELDS = {"_source_file", "uncertain"}
CATEGORY_KEYS = set(CATEGORY_MAPPING.keys())

FIELD_ORDER = [
    "basic_info",
    "summary",
    "smgglrs_relevance",
    "actionable_insights",
    "competitive_position",
    "ecosystem_context",
    "economics",
]


def slugify(name: str) -> str:
    s = name.lower().strip()
    s = re.sub(r"[^a-z0-9\s-]", "", s)
    s = re.sub(r"[\s]+", "-", s)
    return s


def resolve_field(data: dict, dotted_key: str):
    parts = dotted_key.split(".")
    cur = data
    for p in parts:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return None
    return cur


def is_uncertain(field_name: str, value, uncertain_list: list) -> bool:
    if field_name in uncertain_list:
        return True
    if isinstance(value, str) and "[uncertain]" in value:
        return True
    if value is None or value == "":
        return True
    return False


def format_value(value, indent=0) -> str:
    prefix = "  " * indent
    if isinstance(value, list):
        if not value:
            return "N/A"
        if all(isinstance(v, dict) for v in value):
            lines = []
            for item in value:
                parts = [f"{k}: {v}" for k, v in item.items()]
                lines.append(f"{prefix}- {' | '.join(parts)}")
            return "\n".join(lines)
        if all(isinstance(v, str) for v in value):
            if sum(len(v) for v in value) < 120 and len(value) <= 4:
                return ", ".join(value)
            return "\n".join(f"{prefix}- {v}" for v in value)
        return "\n".join(f"{prefix}- {v}" for v in value)

    if isinstance(value, dict):
        lines = []
        for k, v in value.items():
            formatted = format_value(v, indent + 1)
            if "\n" in formatted:
                lines.append(f"{prefix}- **{k}**:\n{formatted}")
            else:
                lines.append(f"{prefix}- **{k}**: {formatted}")
        return "\n".join(lines)

    s = str(value)
    if len(s) > 200:
        s = s.replace(". ", ".\n> ")
        return f"> {s}"
    return s


def pretty_field_name(name: str) -> str:
    return name.replace("_", " ").title()


def render_item(data: dict) -> str:
    lines = []
    name = resolve_field(data, "basic_info.name") or "Unknown"
    lines.append(f"### {name}")
    lines.append("")

    uncertain_list = data.get("uncertain", [])

    for cat_key in FIELD_ORDER:
        cat_data = data.get(cat_key)
        if not cat_data or not isinstance(cat_data, dict):
            continue

        cat_title = pretty_field_name(cat_key)
        lines.append(f"**{cat_title}**")
        lines.append("")

        for field_name, field_value in cat_data.items():
            if is_uncertain(field_name, field_value, uncertain_list):
                continue
            if field_name in INTERNAL_FIELDS:
                continue

            display_name = pretty_field_name(field_name)
            formatted = format_value(field_value)

            if "\n" in formatted:
                lines.append(f"- **{display_name}**:")
                lines.append(formatted)
            else:
                lines.append(f"- **{display_name}**: {formatted}")

        lines.append("")

    extra_fields = {}
    for k, v in data.items():
        if k in CATEGORY_KEYS or k in INTERNAL_FIELDS or k == "uncertain":
            continue
        extra_fields[k] = v

    if extra_fields:
        lines.append("**Other Info**")
        lines.append("")
        for k, v in extra_fields.items():
            formatted = format_value(v)
            lines.append(f"- **{pretty_field_name(k)}**: {formatted}")
        lines.append("")

    if uncertain_list:
        lines.append("**Uncertain Fields**")
        lines.append("")
        for f in uncertain_list:
            lines.append(f"- {f}")
        lines.append("")

    lines.append("---")
    lines.append("")
    return "\n".join(lines)


def load_outline_order() -> list[str]:
    """Extract item IDs from outline.yaml to preserve intended ordering."""
    try:
        text = OUTLINE_PATH.read_text()
        ids = re.findall(r"^\s+- id:\s+(\S+)", text, re.MULTILINE)
        return ids
    except Exception:
        return []


def item_sort_key(filename: str, outline_ids: list[str]) -> tuple:
    """Sort items by: impact (high first), then category, then filename."""
    try:
        data = json.loads((RESULTS_DIR / filename).read_text())
    except Exception:
        return (9, "", filename)

    impact = resolve_field(data, "smgglrs_relevance.impact_level") or "low"
    impact_order = {"high": 0, "medium": 1, "low": 2}.get(impact, 3)

    category = resolve_field(data, "smgglrs_relevance.relevance_category") or "reference"
    cat_order = {"threat": 0, "competitor": 1, "opportunity": 2, "validation": 3, "reference": 4}.get(category, 5)

    return (impact_order, cat_order, filename)


def main():
    json_files = sorted(
        [f for f in os.listdir(RESULTS_DIR) if f.endswith(".json")],
        key=lambda f: item_sort_key(f, load_outline_order()),
    )

    if not json_files:
        print("No JSON results found.", file=sys.stderr)
        sys.exit(1)

    items = []
    for f in json_files:
        with open(RESULTS_DIR / f) as fp:
            data = json.load(fp)
        data["_source_file"] = f
        items.append(data)

    lines = []
    lines.append("# Agentic AI Ecosystem Tech Watch — May 2026")
    lines.append("")
    lines.append("> Research report for the **smgglrs** gateway project.")
    lines.append(f"> {len(items)} items analyzed across inference optimization, agent frameworks,")
    lines.append("> security/auth protocols, RAG patterns, memory architectures, and business models.")
    lines.append("> All smgglrs relevance assessments verified against code-level analysis of the 18-crate workspace.")
    lines.append("")

    # Summary stats
    by_impact = {"high": 0, "medium": 0, "low": 0}
    by_category = {}
    for item in items:
        impact = resolve_field(item, "smgglrs_relevance.impact_level") or "low"
        by_impact[impact] = by_impact.get(impact, 0) + 1
        cat = resolve_field(item, "smgglrs_relevance.relevance_category") or "reference"
        by_category[cat] = by_category.get(cat, 0) + 1

    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Impact | Count | Categories | Count |")
    lines.append(f"|--------|-------|------------|-------|")
    cats = sorted(by_category.items(), key=lambda x: x[1], reverse=True)
    impacts = [("high", by_impact.get("high", 0)), ("medium", by_impact.get("medium", 0)), ("low", by_impact.get("low", 0))]
    max_rows = max(len(impacts), len(cats))
    for i in range(max_rows):
        imp = impacts[i] if i < len(impacts) else ("", "")
        cat = cats[i] if i < len(cats) else ("", "")
        lines.append(f"| {imp[0]} | {imp[1]} | {cat[0]} | {cat[1]} |")
    lines.append("")

    # TOC
    lines.append("## Table of Contents")
    lines.append("")

    current_impact = None
    for idx, item in enumerate(items, 1):
        name = resolve_field(item, "basic_info.name") or "Unknown"
        slug = slugify(name)
        impact = resolve_field(item, "smgglrs_relevance.impact_level") or "low"

        if impact != current_impact:
            current_impact = impact
            lines.append(f"### {impact.upper()} Impact")
            lines.append("")

        toc_parts = []
        for dotted_key, label in TOC_FIELDS:
            val = resolve_field(item, dotted_key)
            if val:
                toc_parts.append(f"{label}: {val}")

        suffix = f" — {' | '.join(toc_parts)}" if toc_parts else ""
        lines.append(f"{idx}. [{name}](#{slug}){suffix}")

    lines.append("")
    lines.append("---")
    lines.append("")

    # Detailed content
    lines.append("## Detailed Analysis")
    lines.append("")

    for item in items:
        lines.append(render_item(item))

    # Write report
    OUTPUT_PATH.write_text("\n".join(lines))
    print(f"Report generated: {OUTPUT_PATH}")
    print(f"  Items: {len(items)}")
    print(f"  High impact: {by_impact.get('high', 0)}")
    print(f"  Medium impact: {by_impact.get('medium', 0)}")
    print(f"  Low impact: {by_impact.get('low', 0)}")


if __name__ == "__main__":
    main()
