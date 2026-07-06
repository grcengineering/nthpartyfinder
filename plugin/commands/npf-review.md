---
description: Review + validate + save nthpartyfinder's inferred domain↔org vendor mappings for a domain, with cited web evidence.
argument-hint: "<domain> [-r depth]"
allowed-tools: "Bash(nthpartyfinder *) Bash(whois *) Bash(curl *) Bash(openssl *) Bash(dig *) Bash(jq *) WebFetch WebSearch Read Write"
---

Review and correct the vendor domain→org mappings nthpartyfinder inferred for the domain in `$ARGUMENTS`, using the **vendor-mapping-review** skill's accuracy protocol.

1. Scan and export the uncertain set:
   `nthpartyfinder -d <domain> [-r <depth>] --review-json ./npf-review.json`
   (take `<domain>` and any flags from `$ARGUMENTS`).
2. Read `./npf-review.json`. If `unverified_orgs` is empty, report "nothing to review" and stop.
3. For each uncertain mapping, independently verify the true operating organization with **≥2 quoted signals from ≥2 distinct layers** (registration: RDAP/WHOIS · presentation: the domain's own site/legal page or TLS cert `O=` · attestation: press/search). Abstain when you cannot corroborate, or when the mapping resolves only to an infrastructure/registrar/privacy provider.
4. Write `./npf-decisions.json`, preview with `nthpartyfinder review apply --in ./npf-decisions.json --dry-run`, then apply: `nthpartyfinder review apply --in ./npf-decisions.json`.
5. Confirm with `nthpartyfinder review list --source claude_verified` and give the user a table of every domain → chosen org, the action (accept/correct/abstain), and the evidence that justified it. Remind them any entry can be undone with `/npf-overrides revert <domain>`.
