# Embedded attribution data

## companies.tsv — domain → organization

**Source:** [AdGuard companiesdb](https://github.com/AdguardTeam/companiesdb) (`dist/trackers.json` + `dist/companies.json`), snapshot `2026-07-06T11:33:18.098Z`.

**License: CC BY-SA 4.0** — full text in `LICENSE.CC-BY-SA-4.0`. This is *not* the MIT license the rest of this repository is under.

### What this means in practice

- The file is a **verbatim-derived redistribution** of the AdGuard dataset (domain → company-name pairs, reshaped to TSV). It stays a standalone artifact under its own license, credited to AdGuard.
- **Do not merge this data into the MIT-licensed curated vendor files** (`config/known_vendors.json`, `config/vendors/*.json`, `known_vendors_local.json`). Combining them into one generated table would be an *adaptation* of a ShareAlike work and would pull the curated list under CC BY-SA. The code keeps the two tiers physically and logically separate, and the curated tiers always take precedence.
- Any modification of `companies.tsv` itself must remain CC BY-SA 4.0 and keep this attribution.

### Refreshing

Re-vendor from upstream `dist/` and regenerate the TSV; update `dataset_version` in the header comment. The version string is surfaced by the scanner so a stale mapping is auditable rather than silently asserted.
