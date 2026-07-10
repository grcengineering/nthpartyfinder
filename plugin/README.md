# nthpartyfinder — Claude Code plugin

Drive the [`nthpartyfinder`](https://github.com/grcengineering/nthpartyfinder) CLI
from Claude, and — the headline capability — **validate then accept/correct+save the
domain↔organization vendor mappings the scanner surfaces for human decision**, using
independent, cited web evidence instead of a domain-name guess.

nthpartyfinder maps Nth-party vendor relationships and infers an operating
organization for each discovered domain. When unsure it asks a human to confirm or
correct the guess, and the saved answer becomes a **local override that wins over
every other lookup source**. This plugin puts Claude in that seat with an evidence-first
protocol, so every saved mapping is independently verified and auditable — and the
tool's next scan is measurably more accurate.

## What's in the box

| Component | What it does |
|-----------|--------------|
| **Skill: `vendor-mapping-review`** | The headline. Model-invoked: validates each uncertain mapping with ≥2 independent, quoted, distinct-layer signals (RDAP/WHOIS registrant · the domain's own site/legal page or TLS cert `O=` · corroborating search), abstains when it can't corroborate, and saves accepted/corrected mappings via the CLI's sole safe writer. Portable to claude.ai as an Agent Skill. |
| `/npf-review <domain>` | Scan a domain, export its uncertain mappings, and run the review skill end-to-end. |
| `/npf-overrides [list\|revert <domain>]` | Inspect or undo local overrides (filter with `--source claude_verified`). |
| `/npf-scan <domain>` | Run a plain Nth-party scan and summarize the results. |
| `/npf-cache …` | Manage the subprocessor URL cache. |

The plugin does **not** re-implement the scanner or change its output. It relies on a
small, additive, opt-in **`review` contract** shipped in the CLI itself:

```bash
nthpartyfinder -d <domain> --review-json ./review.json   # emit the uncertain set (non-interactive)
nthpartyfinder review apply --in decisions.json           # the SOLE writer of validated overrides
nthpartyfinder review apply --in decisions.json --dry-run # preview, write nothing
nthpartyfinder review list  [--source claude_verified]    # inspect
nthpartyfinder review revert <domain>                     # undo
nthpartyfinder review path                                # where the store lives
```

## Prerequisites

- `nthpartyfinder` **v1.1.1+** on your `PATH` (the `review` subcommands and `--review-json`
  flag ship in that version). Build from the repo with `cargo build --release` and put
  `target/release/nthpartyfinder` on your `PATH`.
- Claude Code (plugins are a Claude Code feature). The `vendor-mapping-review` **Skill**
  additionally works on claude.ai when uploaded as an Agent Skill (see *Portability*).

## Install

**Quick, session-only (no install — best for trying it):**
```bash
claude --plugin-dir /path/to/nthpartyfinder/plugin
```

**Via the local marketplace (persistent):**
```text
/plugin marketplace add /path/to/nthpartyfinder      # dir containing .claude-plugin/marketplace.json
/plugin install nthpartyfinder@nthpartyfinder-marketplace
```
Then `/plugin` to enable/disable, and `/help` to see the `/npf-*` commands.

Verify it loaded: `/plugin` lists **nthpartyfinder**, and `/npf-review`, `/npf-overrides`,
`/npf-scan`, `/npf-cache` appear in the `/` menu. `claude --debug` logs plugin loading.

## Usage

```text
/npf-review vanta.com
```
Claude will scan, pull the domains whose organization the tool only *guessed*, and for
each one independently verify the true operator before saving a confirmed or corrected
mapping (or abstaining). You get a table of what was saved, the evidence behind it, and
how to undo any of it.

Or ask in plain language — the skill auto-activates on intents like *"review the vendor
mappings for this scan"* or *"who actually operates these domains?"*.

## The accuracy protocol (why it's trustworthy)

The `vendor-mapping-review` skill enforces, and `nthpartyfinder review apply`
**independently re-checks**, these rules:

- **≥2 independent signals from ≥2 distinct layers** — registration, presentation,
  attestation. Two signals sharing a layer or an upstream fact count as one.
- **Every signal is a fetched, verbatim quote** — no memory, no paraphrase. `review apply`
  rejects any accept/correct lacking real provenance (defeats "citation laundering").
- **Operator ≠ infrastructure** — a registrant/cert that resolves only to a CDN, registrar,
  registry, or WHOIS-privacy service triggers an **abstain**, never a write. This is the
  false-positive class (attributing a vendor's domain to Cloudflare/AWS/etc.) that plagues
  naive attribution.
- **Entity resolution** — attribute to the operating entity as of the scan date; record
  parent/acquirer in a note.
- **Precedence & safety** — a human `user_confirmed` entry is never silently downgraded;
  re-applying the same decisions is a no-op; writes are atomic; every write is revertible;
  and each write appends a JSONL **audit trail** (`known_vendors_local.audit.jsonl`) recording
  the cited signals behind every accepted mapping.

## Portability — Claude Code vs claude.ai

Claude Code **plugins** are a Claude Code feature. The **Skill** inside this plugin
(`skills/vendor-mapping-review/SKILL.md`) follows the portable Agent Skills standard, so
its methodology also runs on claude.ai: there is no local binary there, so the skill runs
the same validation protocol and produces a downloadable `decisions.json` you apply locally
later with `nthpartyfinder review apply --in decisions.json`. Same accuracy protocol; only
the transport differs.

## License

MIT — see the repository.
