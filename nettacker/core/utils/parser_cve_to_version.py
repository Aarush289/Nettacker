#!/usr/bin/env python3
"""
vuln_range_mapper.py

Maintains, per-product, a JSON file that maps *disjoint* version ranges to the
list of CVEs applicable in that range. New vulnerabilities (which may carry
multiple, possibly overlapping, affected-version ranges) are merged into the
existing per-product file: overlapping ranges are split at their boundaries
and the CVE sets for each resulting sub-range are unioned. Adjacent sub-ranges
that end up with an identical CVE set are re-merged so the file stays compact.

-------------------------------------------------------------------------
STORAGE LAYOUT (one file per product)
-------------------------------------------------------------------------
<PRODUCT_DB_DIR>/<product>.json

[
  {
    "range_start": "1.0.0",
    "range_end": "1.2.3",      // null/None means "still unfixed / unbounded"
    "cves": [
      {"cve_id": "CVE-2024-0001", "summary": "..."}
    ]
  },
  ...
]

Ranges are treated as HALF-OPEN intervals: [range_start, range_end). This
matches the usual "introduced" / "fixed" convention (the "fixed" version
itself is NOT vulnerable). It also means ranges compose cleanly when split.

-------------------------------------------------------------------------
INPUT FORMAT (what you feed in when reporting new vulnerabilities)
-------------------------------------------------------------------------
{
  "nginx": [
    {
      "cve_id": "CVE-2024-7347",
      "summary": "Buffer over-read in ngx_http_mp4_module ...",
      "vulnerable_ranges": [
        {"introduced": "1.5.13", "fixed": "1.26.2"},
        {"introduced": "1.27.0", "fixed": "1.27.1"}
      ]
    }
  ],
  "wordpress": [ ... ]
}

You only ever need to supply the *new* CVE(s) - the script reads whatever
already exists in <product>.json, does the interval overlay, and rewrites it.
If <product>.json doesn't exist yet, it's created.

-------------------------------------------------------------------------
CLI USAGE
-------------------------------------------------------------------------
Ingest new vulnerabilities:
    python3 vuln_range_mapper.py ingest --input new_vulns.json --db-dir /path/to/product/db

Query which CVEs affect a given product/version:
    python3 vuln_range_mapper.py query --product nginx --version 1.26.0 --db-dir /path/to/product/db

--db-dir is optional; if omitted, it falls back to the DEFAULT_PRODUCT_DB_DIR
constant below. This makes it easy to hardcode a default for your deployment
while still allowing overrides (e.g. from another script, tests, or CI).
"""

import os
import re
import json
import math
import argparse
from typing import List, Dict, Optional, Tuple, Any

# =========================================================================
# DEFAULT OUTPUT LOCATION - used whenever a db_dir isn't explicitly passed
# in (e.g. via --db-dir on the CLI). Change this to your preferred default,
# or just always pass --db-dir / db_dir= explicitly.
# =========================================================================
DEFAULT_PRODUCT_DB_DIR = "../Vulerability_mapping"


# -------------------------------------------------------------------------
# Version parsing / comparison
# -------------------------------------------------------------------------
# We avoid a hard dependency on `packaging` so this script runs anywhere.
# Versions are split on '.', '-', '+' into components; purely numeric
# components sort as numbers, anything else sorts as a string. This is
# "good enough" for typical dotted-numeric versions (nginx, wordpress,
# most CVE feeds). If you need strict SemVer prerelease precedence,
# swap parse_version() for packaging.version.parse().

_INFINITY_KEY = (math.inf,)


def parse_version(v: Optional[str]) -> Tuple:
    """Return a tuple that sorts correctly against other parsed versions.
    None represents an unbounded/open end (e.g. 'not yet fixed')."""
    if v is None:
        return _INFINITY_KEY
    parts = re.split(r"[.\-+]", v.strip())
    key = []
    for p in parts:
        if p.isdigit():
            key.append((0, int(p)))
        else:
            key.append((1, p))
    return tuple(key)


def fmt_version(v: Optional[str]) -> str:
    return "unfixed" if v is None else v


# -------------------------------------------------------------------------
# Data model helpers
# -------------------------------------------------------------------------

def product_path(product: str, db_dir: str = DEFAULT_PRODUCT_DB_DIR) -> str:
    safe_name = product.strip().lower().replace("/", "_")
    return os.path.join(db_dir, f"{safe_name}.json")


def load_segments(product: str, db_dir: str = DEFAULT_PRODUCT_DB_DIR) -> List[Dict[str, Any]]:
    path = product_path(product, db_dir)
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        data = json.load(f)
    return data


def save_segments(product: str, segments: List[Dict[str, Any]], db_dir: str = DEFAULT_PRODUCT_DB_DIR) -> str:
    os.makedirs(db_dir, exist_ok=True)
    path = product_path(product, db_dir)
    # keep output sorted by range_start for readability
    segments_sorted = sorted(segments, key=lambda s: parse_version(s["range_start"]))
    with open(path, "w") as f:
        json.dump(segments_sorted, f, indent=2)
    return path


def ranges_overlap(s1, e1, s2, e2) -> bool:
    """Half-open interval overlap test: [s1,e1) vs [s2,e2)."""
    return parse_version(s1) < parse_version(e2) and parse_version(s2) < parse_version(e1)


# -------------------------------------------------------------------------
# Core merge algorithm
# -------------------------------------------------------------------------

def merge_vulnerability_into_segments(
    existing_segments: List[Dict[str, Any]],
    new_cve: Dict[str, Any],
    new_ranges: List[Dict[str, Optional[str]]],
) -> List[Dict[str, Any]]:
    """
    Overlay `new_ranges` (all belonging to `new_cve`) onto `existing_segments`
    and return the resulting, still-disjoint, segment list.
    """
    new_cve_entry = {"cve_id": new_cve["cve_id"], "summary": new_cve.get("summary", "")}

    # Normalize new ranges to (start, end) pairs.
    norm_new_ranges = [(r.get("introduced"), r.get("fixed")) for r in new_ranges]

    # Split existing segments into those untouched by any new range, and
    # those that overlap and therefore need to be recomputed.
    untouched = []
    touched = []
    for seg in existing_segments:
        overlaps_any = any(
            ranges_overlap(seg["range_start"], seg["range_end"], ns, ne)
            for ns, ne in norm_new_ranges
        )
        (touched if overlaps_any else untouched).append(seg)

    # Build the list of "sources" to overlay: touched existing segments +
    # all new ranges (each carrying their own cve set).
    sources: List[Tuple[Optional[str], Optional[str], List[Dict[str, Any]]]] = []
    for seg in touched:
        sources.append((seg["range_start"], seg["range_end"], seg["cves"]))
    for ns, ne in norm_new_ranges:
        sources.append((ns, ne, [new_cve_entry]))

    if not sources:
        # New CVE didn't overlap anything existing; just add its ranges as
        # brand-new segments (still need to merge/dedupe overlaps *among*
        # the new ranges themselves, so route through the general path).
        sources = [(ns, ne, [new_cve_entry]) for ns, ne in norm_new_ranges]

    # Collect all boundary points among the sources.
    boundary_points = set()
    for s, e, _ in sources:
        boundary_points.add(parse_version(s))
        boundary_points.add(parse_version(e))
    sorted_points = sorted(boundary_points)

    # For each minimal interval between consecutive boundary points,
    # determine the union of CVEs whose source range covers it.
    raw_pieces: List[Tuple[Tuple, Tuple, Dict[str, Dict[str, Any]]]] = []
    for i in range(len(sorted_points) - 1):
        lo, hi = sorted_points[i], sorted_points[i + 1]
        if lo == hi:
            continue
        cve_map: Dict[str, Dict[str, Any]] = {}
        for s, e, cves in sources:
            s_key, e_key = parse_version(s), parse_version(e)
            if s_key <= lo and hi <= e_key:
                for c in cves:
                    cve_map[c["cve_id"]] = c
        if cve_map:
            raw_pieces.append((lo, hi, cve_map))

    # Merge adjacent minimal pieces that share an identical CVE set.
    merged_touched_region: List[Dict[str, Any]] = []
    for lo, hi, cve_map in raw_pieces:
        cve_ids = frozenset(cve_map.keys())
        if (
            merged_touched_region
            and merged_touched_region[-1]["_end_key"] == lo
            and merged_touched_region[-1]["_cve_ids"] == cve_ids
        ):
            merged_touched_region[-1]["_end_key"] = hi
        else:
            merged_touched_region.append(
                {"_start_key": lo, "_end_key": hi, "_cve_ids": cve_ids, "_cve_map": cve_map}
            )

    # Convert internal keys back to the original string representations.
    # We need a lookup from parsed-key -> original string. Build it from
    # every start/end value we saw.
    key_to_str: Dict[Tuple, Optional[str]] = {}
    for s, e, _ in sources:
        key_to_str[parse_version(s)] = s
        key_to_str[parse_version(e)] = e

    final_touched_segments = []
    for piece in merged_touched_region:
        start_str = key_to_str.get(piece["_start_key"])
        end_str = key_to_str.get(piece["_end_key"])
        final_touched_segments.append(
            {
                "range_start": start_str,
                "range_end": end_str,
                "cves": sorted(piece["_cve_map"].values(), key=lambda c: c["cve_id"]),
            }
        )

    result = untouched + final_touched_segments

    # Final pass: merge any adjacent segments (touched/untouched boundary)
    # that happen to share an identical CVE set, for a compact file.
    result.sort(key=lambda s: parse_version(s["range_start"]))
    compacted: List[Dict[str, Any]] = []
    for seg in result:
        if compacted:
            prev = compacted[-1]
            prev_ids = {c["cve_id"] for c in prev["cves"]}
            cur_ids = {c["cve_id"] for c in seg["cves"]}
            if parse_version(prev["range_end"]) == parse_version(seg["range_start"]) and prev_ids == cur_ids:
                prev["range_end"] = seg["range_end"]
                continue
        compacted.append(dict(seg))

    return compacted


def ingest_vulnerability(product: str, cve: Dict[str, Any], db_dir: str = DEFAULT_PRODUCT_DB_DIR) -> str:
    """Load, merge, save. Returns the path written."""
    existing = load_segments(product, db_dir)
    updated = merge_vulnerability_into_segments(existing, cve, cve["vulnerable_ranges"])
    return save_segments(product, updated, db_dir)


def ingest_file(input_path: str, db_dir: str = DEFAULT_PRODUCT_DB_DIR) -> None:
    with open(input_path, "r") as f:
        payload = json.load(f)

    for product, cve_list in payload.items():
        for cve in cve_list:
            path = ingest_vulnerability(product, cve, db_dir)
            print(f"[ok] {cve['cve_id']} merged into {path}")


# -------------------------------------------------------------------------
# Query
# -------------------------------------------------------------------------

def query_version(product: str, version: str, db_dir: str = DEFAULT_PRODUCT_DB_DIR) -> List[Dict[str, Any]]:
    segments = load_segments(product, db_dir)
    v_key = parse_version(version)
    hits = []
    for seg in segments:
        if parse_version(seg["range_start"]) <= v_key < parse_version(seg["range_end"]):
            hits.extend(seg["cves"])
    return hits


# -------------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="Product version-range -> CVE mapper")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_ingest = sub.add_parser("ingest", help="Ingest new vulnerabilities from a JSON file")
    p_ingest.add_argument("--input", required=True, help="Path to input JSON file")
    p_ingest.add_argument(
        "--db-dir", default=DEFAULT_PRODUCT_DB_DIR,
        help=f"Directory holding per-product JSON files (default: {DEFAULT_PRODUCT_DB_DIR})",
    )

    p_query = sub.add_parser("query", help="List CVEs affecting product@version")
    p_query.add_argument("--product", required=True)
    p_query.add_argument("--version", required=True)
    p_query.add_argument(
        "--db-dir", default=DEFAULT_PRODUCT_DB_DIR,
        help=f"Directory holding per-product JSON files (default: {DEFAULT_PRODUCT_DB_DIR})",
    )

    args = parser.parse_args()

    if args.cmd == "ingest":
        ingest_file(args.input, args.db_dir)
    elif args.cmd == "query":
        hits = query_version(args.product, args.version, args.db_dir)
        if not hits:
            print(f"No known vulnerabilities for {args.product}@{args.version}")
        else:
            print(f"{args.product}@{args.version} is affected by:")
            for c in hits:
                print(f"  - {c['cve_id']}: {c.get('summary', '')}")


if __name__ == "__main__":
    main()