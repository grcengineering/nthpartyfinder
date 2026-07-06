---
name: vendor-mapping-review
description: >-
  Validate and accept/correct+save the domain↔organization vendor mappings that
  the nthpartyfinder CLI surfaces for human decision. Use this whenever the user
  wants to review, confirm, verify, correct, or save nthpartyfinder's inferred
  vendor org names / domain-to-org (or org-to-domain) mappings, or asks "who
  really owns/operates this domain" for a scan. Independently verifies the true
  company↔domain relationship with cited web evidence (RDAP/WHOIS registrant, the
  domain's own site/legal page, the TLS certificate organization, and corroborating
  search) instead of trusting a domain-name guess, then writes the result into the
  tool's local override store so the next scan is more accurate.
allowed-tools: "Bash(nthpartyfinder *) Bash(whois *) Bash(curl *) Bash(openssl *) Bash(dig *) Bash(jq *) WebFetch WebSearch Read Write"
---

# Vendor Mapping Review — validate → accept/correct → save

nthpartyfinder discovers vendor domains and **guesses** an operating organization
for each from the domain name. When unsure it asks a human to accept or correct
the guess (TTY-only). A human rubber-stamping guesses produces wrong attributions,
and the saved override then **wins over every other lookup source forever**.

Your job is to replace the guess-and-rubber-stamp loop with **evidence**: for each
uncertain mapping, independently establish which organization actually *operates*
the domain, then save an accepted or corrected mapping — or **abstain** when you
cannot corroborate it. Accuracy is the whole point; a confidently-wrong write is
worse than no write.

You are the sole *judge*. The CLI is the sole *writer* (`review apply`) — it enforces
a deterministic backstop, so a decision that lacks real evidence is rejected even if
you slip.

---

## 0. Contract with the CLI (how decisions get in and out)

Everything is non-interactive JSON — no TTY, no scraping.

- **Get the uncertain set OUT** (per scan): add `--review-json <path>` to a scan.
  It writes the exact set the interactive prompt would have shown:
  ```bash
  nthpartyfinder -d <domain> --review-json ./review.json     # add -r <depth> as needed
  ```
  `review.json` = `{ schema, root_domain, resolved_overrides_path, unverified_orgs:[{domain, inferred_org}], pending_mappings:[{org_name, inferred_domain, source_domain}], instructions }`.
  - `unverified_orgs` = **domain→org** guesses (the primary target — this is what the override store holds).
  - `pending_mappings` = **org→domain** guesses from subprocessor pages (advisory; see §5).
  - `resolved_overrides_path` = the file the next scan will READ. `review apply` writes exactly there — never write it yourself.
- **Where the store lives:** `nthpartyfinder review path` prints the resolved path.
- **Put validated decisions IN** (the only writer):
  ```bash
  nthpartyfinder review apply --in ./decisions.json --dry-run   # preview
  nthpartyfinder review apply --in ./decisions.json             # write
  ```
- **Inspect / undo:**
  ```bash
  nthpartyfinder review list --source claude_verified
  nthpartyfinder review revert <domain>
  ```

`decisions.json`:
```json
{
  "schema": "nthpartyfinder.decisions/v1",
  "decisions": [
    {
      "type": "domain_org",
      "domain": "sub.example.com",
      "organization": "Example, Inc.",
      "source": "claude_verified",
      "action": "accept",
      "signals": [
        {"layer": "registration", "tool": "rdap",     "url": "https://rdap.org/domain/example.com", "quote": "Registrant Organization: Example, Inc."},
        {"layer": "presentation", "tool": "webfetch", "url": "https://example.com/legal",           "quote": "© 2026 Example, Inc. All rights reserved."}
      ],
      "note": "operating entity as of 2026-07; parent: none"
    }
  ]
}
```
- `action`: `accept` (guess is right), `correct` (guess is wrong → use `organization`), or `abstain` (could not corroborate → nothing written).
- `source`: use `claude_verified` (or `whois_verified`). A human `user_confirmed` **cannot** be set here — `review apply` rejects it.
- `allow_infra_operator` (default false): set `true` ONLY when the named organization is itself an infrastructure/registrar/privacy provider that *genuinely* operates the domain (e.g. `status.aws.amazon.com` → Amazon). Otherwise an infra org is rejected.

**`review apply` re-checks every decision deterministically and REJECTS it (exit 3) if it:** uses a `source` other than `claude_verified`/`whois_verified`; has fewer than 2 quoted signals across 2 distinct layers; does **not** name the SAME `organization` **word-for-word in quoted spans from ≥2 distinct layers** (the layers must AGREE on the org — a name in only one layer is a single-source claim and is rejected); or names an infrastructure/registrar/privacy org without `allow_infra_operator`. So sloppy — or prompt-injected — evidence fails at the writer, not just in prose. Build decisions the checks will accept: quote the exact span that names the org, from two different layers, and make sure both quotes name that same org.

---

## 1. The accuracy protocol (non-negotiable)

For every `unverified_orgs[]` entry, determine **who operates the domain** using
signals from three independent LAYERS. Count and cite them honestly.

**The layers (independence comes from layer diversity, not signal count):**

| layer | what it establishes | how to fetch | quote to record |
|-------|---------------------|--------------|-----------------|
| `registration` | who registered the domain | `curl -s https://rdap.org/domain/<apex> \| jq -r '..\|.vcardArray?'` or `whois <apex>` | the **Registrant Organization** value |
| `presentation` | who the site says it is | WebFetch `https://<domain>`, `/about`, `/legal`, `/privacy`, `/terms`; and TLS cert: `echo \| openssl s_client -connect <domain>:443 -servername <domain> 2>/dev/null \| openssl x509 -noout -subject` | the copyright/legal entity, or the cert `O=` |
| `attestation` | third-party confirmation | WebSearch `"<domain>" operated by OR owned by OR company`, press, registry-of-record, the operator's official site linking the domain | the sentence naming the operator |

**Hard rules — enforced by both you and `review apply`:**

1. **≥2 signals from ≥2 DISTINCT layers** must agree before you `accept`/`correct`.
   Two signals from the *same* layer, or two that reflect the *same* upstream fact
   (e.g. RDAP registrant + WHOIS of the same record), count as **one**. `review apply`
   rejects any accept/correct with fewer than 2 distinct-layer quoted signals.
2. **Every signal carries a fetched, verbatim `quote`.** Never write a quote from
   memory — fetch it this session. An empty/paraphrased quote is not evidence and
   is rejected (defeats "citation laundering").
3. **Operator ≠ infrastructure.** The registrant/cert org is often the CDN, registrar,
   registry, or WHOIS-privacy service — NOT the vendor. If the only agreeing signals
   resolve to an infrastructure/registrar/privacy provider (see the denylist below),
   **ABSTAIN** — do not record an infra company as the vendor. (This is the BUG-006 /
   BUG-011 false-positive class the tool already fights.)
4. **Entity resolution:** attribute to the entity that **operates the domain as of the
   scan date**. If it is a subsidiary/rebrand/post-acquisition, use the current operating
   name and note the parent/acquirer in `note` (e.g. `"parent: BigCo (acq. 2025)"`).
5. **Parked / lander pages are not presentation evidence.** A registrar parking page,
   a for-sale lander, or a bare "coming soon" does not name an operator — treat it as
   *no* presentation signal and lean on registration + attestation, or ABSTAIN.
6. **Conflicts → ABSTAIN.** If signals name different real operators and you cannot
   resolve which is authoritative, abstain and surface the conflict to the user.

**Infrastructure/registrar/privacy denylist (ABSTAIN if the mapping resolves only to these):**
Cloudflare, Amazon / AWS / Amazon Technologies, Google / Google LLC / Google Cloud,
Microsoft / Azure, Akamai, Fastly, Vercel, Netlify, DigitalOcean, Linode, Oracle Cloud,
GitHub, Heroku, Squarespace, Wix, WP Engine, Automattic / WordPress, GoDaddy, Namecheap,
MarkMonitor, CSC Corporate Domains, Gandi, Google Domains, Tucows / OpenSRS, Sucuri,
Imperva / Incapsula, Domains By Proxy, Whois Privacy / Privacy Protect / Redacted for Privacy,
Identity Protection Service, Contact Privacy Inc.

> A domain whose genuine operator IS one of these (e.g. `status.aws.amazon.com`) is fine
> to attribute to that company — the rule forbids attributing a *different* vendor's domain
> to its infrastructure provider.

---

## 2. Workflow

1. **Scan + export** (if you don't already have a `review.json`):
   `nthpartyfinder -d <domain> --review-json ./review.json` (add `-r <depth>` for more layers).
   Read `review.json`. If `unverified_orgs` is empty, tell the user there is nothing to
   review and stop.
2. **Validate each `unverified_orgs[]` entry** per §1. Work the apex domain for
   registration signals; the full host for presentation/cert.
3. **Decide** `accept` / `correct` / `abstain` and build `decisions.json` with the
   layered, quoted signals. Prefer abstaining over guessing.
4. **Dry-run:** `nthpartyfinder review apply --in ./decisions.json --dry-run` and read the
   report (written / would-write / unchanged / abstained / skipped(precedence) / rejected).
   If anything is **rejected**, fix the evidence (usually: not enough distinct layers, or a
   missing quote) — do not lower the bar.
5. **Apply:** `nthpartyfinder review apply --in ./decisions.json`. A non-zero exit means at
   least one decision was rejected — investigate, don't ignore.
6. **Confirm it took:** `nthpartyfinder review list --source claude_verified`. Optionally
   re-scan (`nthpartyfinder -d <domain> -f json`) and confirm the corrected org now appears
   for that domain.
7. **Report to the user:** a short table of each domain → chosen org, the action, the
   layers/quotes that justified it, and anything you abstained on with the reason.

Never skip the human-visible summary. The user must be able to see *why* each mapping was
saved and undo any of them with `review revert <domain>`.

---

## 3. Precedence & idempotency (so you can't do harm)

- A `user_confirmed` (human) entry is **never** silently downgraded by a `claude_verified`
  write — `review apply` skips it and reports `skipped(precedence)`. If you believe the human
  entry is wrong, surface it; don't overwrite it.
- Re-applying the same `decisions.json` is a **no-op** (`unchanged`) — safe to re-run.
- Writes are atomic; a crash mid-write cannot corrupt the store.
- Every write appends a JSONL **audit trail** (`known_vendors_local.audit.jsonl`, beside the
  store) recording the domain, chosen org, source, and the cited signals — so an accepted
  mapping's evidence survives even after `decisions.json` is gone. Undo any entry with
  `nthpartyfinder review revert <domain>`.
- A `claude_verified` write replaces an existing equal-rank machine entry (`whois_verified`/
  `claude_verified` — fresher machine verification wins) but **never** a human `user_confirmed`.
  An override with no recorded source is treated as human-authoritative and left untouched; if
  it's wrong, correct it through the human TTY flow, not `review apply`.

---

## 4. Worked micro-example

`review.json` has `{"domain":"e.customeriomail.com","inferred_org":"Customeriomail"}`.

- registration: `whois customeriomail.com` → `Registrant Organization: Customer.io` — quote it.
- presentation: WebFetch `https://customer.io/legal` → `© 2026 Peaberry Software, Inc. (Customer.io)` — quote it.
- attestation: WebSearch → press confirms Customer.io is the brand of Peaberry Software.
- Decision: `correct` → `organization: "Customer.io"`, note `"legal entity Peaberry Software, Inc."`,
  signals = registration + presentation (2 distinct layers, both quoted). Not infra → allowed.

If instead the only signals were `Registrant: Cloudflare, Inc.` + cert `O=Cloudflare, Inc.`
(both the CDN), that is one layer's worth of *infra* → **abstain**.

---

## 5. org→domain pending mappings (advisory)

`pending_mappings[]` are org→domain guesses from subprocessor pages. The durable writer
targets the domain→org override store (what wins lookups), so these are **advisory**: use
them to spot a wrong inferred domain and, if it maps to a real vendor domain you can verify,
add the corresponding **domain→org** decision for that domain. Do not fabricate a domain you
cannot confirm resolves/serves the vendor.

---

## 6. Running inside claude.ai (no local binary)

On claude.ai there is no `nthpartyfinder` binary or local override store. In that case:
1. Ask the user to paste their `review.json` (or the list of domains + inferred orgs).
2. Run the **same validation protocol** (§1) with WebFetch/WebSearch.
3. Produce a downloadable `decisions.json` for the user to apply locally with
   `nthpartyfinder review apply --in decisions.json`.
The methodology is identical; only the transport differs.
