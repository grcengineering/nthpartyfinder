# Nth Party Finder

[![CI](https://github.com/grcengineering/nthpartyfinder/actions/workflows/build.yml/badge.svg)](https://github.com/grcengineering/nthpartyfinder/actions/workflows/build.yml)
[![Security](https://github.com/grcengineering/nthpartyfinder/actions/workflows/security.yml/badge.svg)](https://github.com/grcengineering/nthpartyfinder/actions/workflows/security.yml)
[![OpenSSF Scorecard](https://github.com/grcengineering/nthpartyfinder/actions/workflows/scorecard.yml/badge.svg)](https://github.com/grcengineering/nthpartyfinder/actions/workflows/scorecard.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Map your vendor risk surface to the Nth degree.** `nthpartyfinder` is a fast, cross-platform CLI that discovers third-, fourth-, and deeper-party vendor relationships for a domain — the inherited supply-chain risk that stops at "4th party" in most TPRM tooling — using DNS, certificate transparency, trust-center subprocessor pages, runtime web traffic, SaaS-tenant probing, and subdomain enumeration. Built in Rust; runs offline with an embedded NER model.

A [GRC Engineering](https://grc.engineering) tool: it turns a manual, incomplete vendor-mapping exercise into a repeatable, evidence-producing command.

---

## Why

Security GRC teams own third-party cyber risk, but most of that risk is *inherited* — your vendor's vendors, and theirs in turn. That graph is tedious to build by hand and usually stops one hop deep. `nthpartyfinder` walks it recursively from public signals only, so you can see which Nth parties actually sit behind a domain before you assess it.

## What it discovers

Every relationship carries the **evidence** it was inferred from — the raw DNS record, the observed network request, the trust-center URL — so a finding is auditable, not asserted.

| Method | Signal | Default |
|--------|--------|---------|
| **DNS** | SPF / DMARC / DKIM / MX / NS / CNAME / verification TXT records | Always on |
| **Subprocessor** | Vendor/subprocessor lists linked from trust centers | On |
| **Web Traffic** | Third-party SDKs in page source + runtime network requests (headless Chrome) | Config/flag |
| **SaaS Tenant** | Tenant subdomains (e.g. `company.slack.com`) | Config/flag |
| **Subfinder** | Subdomain enumeration via CNAME discovery | Config/flag |
| **CT Logs** | Certificate Transparency logs — round-robined across multiple providers | Config/flag |

Organization names are resolved through WHOIS/RDAP, a curated known-vendor dataset, and an optional offline GLiNER NER model — never a paid API, and no configuration required for a default scan.

### Certificate Transparency providers

CT-log discovery **round-robins across multiple providers** on a shared cursor (spreading load so no single aggregator is overloaded — crt.sh returns HTTP 429 under a wide fan-out) and **fails over** to the next provider on any error, so a throttle or outage becomes a recovered lookup rather than a silent gap.

| Provider | Default | Credential (optional) |
|----------|---------|----------------------|
| [crt.sh](https://crt.sh) | Always on (anonymous) | — |
| [SSLMate Cert Spotter](https://sslmate.com/ct_search_api/) | Always on (anonymous) | `NTHPARTYFINDER_CERTSPOTTER_TOKEN` raises the rate limit |
| [MerkleMap](https://www.merklemap.com) | Joins when configured | `NTHPARTYFINDER_MERKLEMAP_TOKEN` (free API key) |
| [Censys](https://censys.com) | Joins when configured | `NTHPARTYFINDER_CENSYS_PAT` + `NTHPARTYFINDER_CENSYS_ORG_ID` |

crt.sh and Cert Spotter are anonymous and always in the rotation. MerkleMap and Censys — the two remaining well-regarded CT query APIs (every once-anonymous alternative, including Google's, Entrust's, and Meta's, has been discontinued) — have no anonymous tier, so they join the rotation only when their API credentials are set in the environment. Set any subset; the round-robin adapts to whichever providers are configured.

## Install

### Docker

```bash
docker pull ghcr.io/grcengineering/nthpartyfinder:latest
docker run -v "$(pwd)/output:/output" ghcr.io/grcengineering/nthpartyfinder:latest \
  -d example.com -r 2 -f json -o /output/results
```

### Pre-built binaries

Download the archive for your platform from [Releases](https://github.com/grcengineering/nthpartyfinder/releases/latest) and extract it:

| Platform | Asset |
|----------|-------|
| macOS (Apple Silicon) | `nthpartyfinder-aarch64-apple-darwin.tgz` |
| macOS (Intel) | `nthpartyfinder-x86_64-apple-darwin.tgz` |
| Linux (x86-64) | `nthpartyfinder-x86_64-unknown-linux-gnu.tgz` |
| Windows (x86-64) | `nthpartyfinder-x86_64-pc-windows-msvc.tgz` |

Each archive ships with a `.sha256` checksum, and every release publishes [SLSA build provenance](https://slsa.dev) (`multiple.intoto.jsonl`) so you can verify the binary was built by this repo's release workflow.

### Build from source

```bash
git clone https://github.com/grcengineering/nthpartyfinder.git
cd nthpartyfinder/nthpartyfinder

# Default build embeds the NER model (~175 MB binary):
cargo build --release

# Or a slim build with no NER (~15 MB):
cargo build --release --no-default-features
```

**Prerequisite:** a `whois` client on `PATH` (`apt install whois` / `brew install whois`; Windows via WSL or SysInternals).

## Usage

```bash
# Default scan (CSV to your Desktop)
nthpartyfinder -d example.com

# Bounded depth, JSON output, named file
nthpartyfinder -d example.com --depth 2 -f json -o example_vendors.json

# Deep scan: enable every discovery method, no timeout, HTML report
nthpartyfinder -d example.com --depth 3 -f html \
  --enable-subdomain-discovery --enable-saas-tenant-discovery \
  --enable-ct-discovery --enable-web-traffic-discovery --timeout 0

# DNS-only, fast and quiet
nthpartyfinder -d example.com --dns-only
```

Run `nthpartyfinder --help` for the full flag reference. A few worth knowing:

- `-r, --depth <N>` — recursion depth. Omit to recurse until no new vendors are found.
- `-f, --output-format` — `csv` (default), `json`, `markdown`, or `html`.
- `--timeout <SECONDS>` — default `600`, tuned for a depth-1 scan. **Deep or cold-cache scans routinely exceed 600s** (often 1500–3000s); raise it (`--timeout 1800`) or disable it (`--timeout 0`). On timeout the scan writes a checkpoint and exits non-zero rather than emitting an empty report.
- `--include-infra` — by default AWS/Google/Cloudflare/etc. are filtered as noise; this keeps them.
- `--input-file <FILE>` + `--batch-parallel <N>` — batch-scan many domains from a CSV/JSON list.

### Responsible scanning

`nthpartyfinder` reads only public signals, but a deep multi-method scan opens many concurrent connections. Global DNS/HTTP/WHOIS rate limiters are always on (defaults: 50 DNS qps, 10 HTTP rps per domain, 2 WHOIS qps), and `--parallel-jobs` caps in-flight analyses. Scan domains you're authorized to assess, and prefer bounded depth on shared networks.

## Output

**CSV** (default) — one row per relationship: root customer domain/org, Nth-party domain/org, layer, the customer that references it, the source record type (`DNS::TXT::SPF`, `HTTP::SUBPROCESSOR`, `DISCOVERY::WEBPAGE_NETWORK`, `DISCOVERY::CT_LOG`, …), and the raw evidence.

**JSON** — the same relationships plus a summary block:

```json
{
  "summary": {
    "total_relationships": 12,
    "max_depth": 3,
    "unique_domains": 8,
    "unique_organizations": 6
  },
  "relationships": [ … ]
}
```

**HTML** — an interactive, layered vendor-graph report. **Markdown** — a readable summary for tickets and docs.

## How it works

1. **DNS analysis** — query TXT/MX/NS/CNAME records for the target.
2. **Extended discovery** — optionally add trust-center subprocessors, CT logs, web traffic, SaaS tenants, and subdomains.
3. **Organization resolution** — WHOIS/RDAP → curated dataset → offline NER, with provenance tracked per attribution.
4. **Recursion** — repeat for each discovered vendor, up to the configured depth, stopping at common infrastructure denominators to prevent runaway graphs.
5. **Export** — CSV / JSON / Markdown / HTML, every relationship carrying its evidence.

## Configuration

CLI flags override an optional TOML config:

```bash
nthpartyfinder --init          # writes ./config/nthpartyfinder.toml
```

Sections: `[http]`, `[dns]`, `[patterns]`, `[analysis]`, `[discovery]`, `[rate_limits]`. Every setting has a working default — the config file is entirely optional.

## Security & supply chain

This tool is for legitimate security and GRC use. It ships with a security policy ([SECURITY.md](SECURITY.md)), SHA-pinned GitHub Actions, CodeQL SAST, dependency/advisory scanning (`cargo audit` / `cargo deny`), secret scanning, an OpenSSF Scorecard, and signed SLSA provenance on every release.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the build, test, and PR workflow. The crate lives in [`nthpartyfinder/`](nthpartyfinder/); its [README](nthpartyfinder/README.md) covers crate-level detail.

## License

[MIT](LICENSE).
