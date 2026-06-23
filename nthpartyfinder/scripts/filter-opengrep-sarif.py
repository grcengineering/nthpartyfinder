#!/usr/bin/env python3
"""filter-opengrep-sarif.py — drop ONLY genuinely-test-code findings of the
report-only WARNING rules (no-unwrap-in-prod / no-eprintln-in-prod) from the
Opengrep SARIF before it is uploaded to GitHub code scanning.

WHY: those rules target PRODUCTION code, but Opengrep's experimental Rust matcher
does not exclude `.unwrap()` / `eprintln!` inside inline `#[cfg(test)]` test code,
flooding the dashboard with ~1.7k test-code false positives.

CORRECTNESS (this is the part that matters for zero-suppression): a finding is
treated as test code — and dropped — ONLY if its line falls inside the brace span
of a `#[cfg(test)]`- or `#[test]`/`#[tokio::test]`-annotated item. We do NOT use a
naive "after the first #[cfg(test)] line" heuristic: a file like
`discovery/subfinder.rs` has `#[cfg(test)] use ...;` at the very top, so a
line-threshold would wrongly classify the entire production file as test code and
could silently hide a real production finding. By matching the *enclosing item's
brace span* (a `use`/`const` spans only its own line; a `mod`/`impl`/`fn` spans to
its matching `}`), production findings OUTSIDE every test span are always kept.

ERROR-severity findings and every other rule are untouched. Run from the crate
dir (SARIF paths are crate-relative, e.g. `src/foo.rs`). Idempotent. stdlib only.
"""
import json
import re
import sys

TARGET_RULE = re.compile(r"no-unwrap-in-prod|no-eprintln-in-prod")
CFG_TEST = re.compile(r"#\[\s*cfg\s*\(\s*test\s*\)\s*\]")
TEST_ATTR = re.compile(r"#\[\s*(tokio::)?test\s*\]")


def test_spans(path):
    """Return a list of (start_line, end_line) 1-based inclusive ranges that are
    test-only code, derived from #[cfg(test)] / #[test] / #[tokio::test] items by
    matching the annotated item's brace span (or its single line for use/const)."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
    except OSError:
        return []

    spans = []
    n = len(lines)
    for i, line in enumerate(lines):
        if not (CFG_TEST.search(line) or TEST_ATTR.search(line)):
            continue
        # Find the annotated item: first non-blank, non-attribute line at/after i.
        j = i
        while j < n:
            s = lines[j].strip()
            if s == "" or s.startswith("#["):
                j += 1
                continue
            break
        if j >= n:
            spans.append((i + 1, n))
            continue
        # Scan forward for the first '{' (braced item) vs ';' (statement).
        depth = 0
        started = False
        k = j
        end = None
        while k < n:
            for ch in lines[k]:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
                    if started and depth == 0:
                        end = k
                        break
                elif ch == ";" and not started:
                    end = k  # single statement (use/const/type alias) — its line
                    break
            if end is not None:
                break
            k += 1
        if end is None:
            end = n - 1
        spans.append((i + 1, end + 1))  # 1-based inclusive
    return spans


def in_test_code(path, line, cache):
    if path not in cache:
        cache[path] = test_spans(path)
    return any(a <= line <= b for (a, b) in cache[path])


def main():
    sarif_path = sys.argv[1] if len(sys.argv) > 1 else "opengrep.sarif"
    try:
        with open(sarif_path, "r", encoding="utf-8") as fh:
            sarif = json.load(fh)
    except (OSError, json.JSONDecodeError) as e:
        print(f"filter-opengrep-sarif: no usable SARIF at {sarif_path} ({e}); nothing to do")
        return 0

    cache = {}
    before = after = 0
    for run in sarif.get("runs", []):
        kept = []
        for res in run.get("results", []) or []:
            before += 1
            rule = res.get("ruleId", "") or ""
            if TARGET_RULE.search(rule):
                loc = (res.get("locations") or [{}])[0]
                phys = loc.get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                ln = phys.get("region", {}).get("startLine", 0)
                if uri and ln and in_test_code(uri, ln, cache):
                    continue  # drop test-code WARNING false positive
            kept.append(res)
        after += len(kept)
        run["results"] = kept

    with open(sarif_path, "w", encoding="utf-8") as fh:
        json.dump(sarif, fh)
    print(f"filter-opengrep-sarif: {before} -> {after} results "
          f"({before - after} test-code WARNING findings dropped)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
