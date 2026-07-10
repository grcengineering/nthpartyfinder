---
description: Run an nthpartyfinder Nth-party vendor relationship scan for a domain.
argument-hint: "<domain> [-r depth] [-f json|csv|markdown|html]"
allowed-tools: "Bash(nthpartyfinder *)"
---

Run an nthpartyfinder scan using the domain and options in `$ARGUMENTS` (e.g. `nthpartyfinder -d <domain> [-r <depth>] [-f json]`) and summarize the discovered vendor relationships for the user.

- Default output format is CSV; pass `-f json` for machine-readable output or `-f markdown` for a readable table.
- `-r <depth>` recurses to that Nth-party depth; omit to let the scanner recurse until no new vendors are found.
- This is a non-interactive run — do not attempt to answer interactive prompts.

If the user then wants to verify or correct the inferred organization names, hand off to `/npf-review <domain>` (or the **vendor-mapping-review** skill), which adds `--review-json` and validates each mapping with independent evidence.
