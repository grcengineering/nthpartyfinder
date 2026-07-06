# Changelog — nthpartyfinder plugin

## 0.1.0 — 2026-07-05

Initial release.

- **Headline Skill `vendor-mapping-review`** (model-invoked, claude.ai-portable): validates
  the domain↔org mappings nthpartyfinder surfaces for review using ≥2 independent, quoted,
  distinct-layer web signals (RDAP/WHOIS · site/legal + TLS cert · attestation), with a hard
  abstain path, an infrastructure/registrar/privacy denylist, and entity-resolution rules;
  saves accepted/corrected mappings via the CLI's sole safe writer, stamped `claude_verified`.
- **Commands**: `/npf-review`, `/npf-overrides`, `/npf-scan`, `/npf-cache`.
- Relies on the additive, opt-in **`review` contract** in nthpartyfinder v1.1.1+:
  `--review-json` export, `review apply` (atomic, merged, idempotent, provenance-gated,
  `--dry-run`, JSONL audit trail), `review list`, `review revert`, `review path`.

Requires `nthpartyfinder` v1.1.1+ on `PATH`.
