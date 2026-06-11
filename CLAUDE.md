# nthpartyfinder — project rules

- **Always invoke cargo via the full path `~/.cargo/bin/cargo`** in agent shells on this machine. Bare `cargo` gets wrapped through the Socket Firewall proxy (`sfw`, a package-manager network filter); when its proxy degrades it MITMs loopback wiremock test traffic (405 "Connection Required" pages) and hangs live-network tests indefinitely. CI does not have this wrapper — full-path local + CI green is the authoritative pair.
- **The project ISA at `./ISA.md` is the system of record** — read it at task start (criteria, decisions, verification history, open follow-ups TF-RERUN/TF-COV/TF-SLSA/TF-CATO/TF-SILENT).
- **Run `cargo test` from `nthpartyfinder/`** (the crate dir), not the repo root.
- No live DNS in the unit/integration suite (wiremock only; live smoke tests are `#[ignore]`-gated). DoH endpoints must serve the JSON GET API (`application/dns-json`) — verify any new provider live before adding it.
- DNS failure-visibility contract: provider failures are classed (`DNS_THROTTLE` = 429/5xx with backoff+rotation; `DNS_ENDPOINT` = 4xx/bad-RCODE/non-dns-json with immediate rotation), counted at the `note_throttle` choke point for the exit-3 guard, and logged warn-once-per-provider. Don't add code that converts a provider error into an empty result without classification + counting.
- Logging goes through tracing (subscriber initialized in `app.rs`, default WARN, `-v` INFO, `-vv` DEBUG) and is emitted via `logger::ProgressAwareWriter` — bar-safe on TTYs, plain stderr otherwise. `AnalysisLogger::warn` prints at default verbosity; don't re-gate it.
- A second `--init` refuses to overwrite an existing config by design.
