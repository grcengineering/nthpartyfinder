//! Non-interactive "review" contract for the domain↔org mappings the scanner
//! surfaces for human decision.
//!
//! Normally nthpartyfinder prompts a human (TTY-only, see `app.rs` /
//! `interactive.rs`) to accept or correct the organizations it *inferred* for
//! discovered domains. Those inferences are guesses from the domain name; a human
//! confirming dozens of them under time pressure rubber-stamps wrong attributions,
//! and the resulting local overrides win over every other lookup source forever.
//!
//! This module exposes the same uncertain sets as a machine contract so an
//! automated reviewer (the Claude Code plugin) can independently validate the TRUE
//! company↔domain relationship with cited evidence and persist the result safely:
//!
//! - `--review-json <PATH>` on a scan writes the uncertain sets as JSON (export).
//! - `nthpartyfinder review apply --in <decisions.json>` is the SOLE writer that
//!   persists validated decisions into the local override store, stamped with a
//!   distinguishing provenance (`claude_verified`) and GATED by a deterministic
//!   backstop: each accepted decision must (a) come from a machine-verification
//!   source (a human `user_confirmed` can never be set here), (b) carry ≥2 quoted
//!   signals from ≥2 DISTINCT verification layers, (c) name the SAME organization
//!   (word-for-word) in quoted spans from ≥2 of those distinct layers — the layers
//!   must AGREE on the org, not merely each carry a quote — and (d) not attribute
//!   the domain to a known infrastructure/registrar/privacy provider unless
//!   explicitly asserted. These checks run at the writer — not just in prose — so
//!   empty or paraphrased quotes, single-layer or single-source guesses, unsupported
//!   free-text orgs, cross-layer disagreement, source-laundering, and the infra
//!   false-positive class are all rejected even if the model upstream slips.
//!
//! All decision *judgement* (which organization) is the reviewer's; this module
//! only provides the transport, the validation backstop, and a precedence-aware,
//! idempotent apply that never downgrades a higher-trust human confirmation.

use crate::interactive::UnverifiedOrgMapping;
use crate::known_vendors::KnownVendors;
use crate::subprocessor::PendingOrgMapping;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Schema tag written into the export so consumers can version-gate.
pub const REVIEW_EXPORT_SCHEMA: &str = "nthpartyfinder.review/v1";
/// Schema tag expected (informationally) on a decisions file.
pub const DECISIONS_SCHEMA: &str = "nthpartyfinder.decisions/v1";
/// The verification layers that count toward corroboration. Two signals from the
/// SAME layer (or an unknown layer) count as one — independence requires layer
/// diversity, not just a second URL that reflects the same upstream fact.
pub const VALID_LAYERS: [&str; 3] = ["registration", "presentation", "attestation"];

const INSTRUCTIONS: &str = "For each unverified_orgs[] entry, independently verify which organization actually OPERATES the domain (never the registrar/CDN/registry/privacy-service). Corroborate with >=2 signals from DISTINCT layers -- registration (RDAP/WHOIS registrant), presentation (the domain's own site/legal page or TLS certificate Subject Organization), attestation (press/registry-of-record/search) -- each carrying a fetched, quoted span. If signals conflict, are thin, or all resolve to shared infrastructure, ABSTAIN (do not write). Emit a decisions file {schema:\"nthpartyfinder.decisions/v1\", decisions:[{type:\"domain_org\", domain, organization, source:\"claude_verified\", action:\"accept|correct|abstain\", signals:[{layer, tool, url, quote}], note}]} and persist with: nthpartyfinder review apply --in decisions.json";

// ----------------------------------------------------------------------------
// Export: the uncertain set OUT (what a scan emits with --review-json)
// ----------------------------------------------------------------------------

/// A domain→org attribution the scanner inferred and is unsure about.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnverifiedOrgOut {
    pub domain: String,
    pub inferred_org: String,
}

/// An org→domain mapping the scanner inferred via generic fallback (subprocessor
/// pages). Exported for the reviewer's awareness; the writer targets domain→org
/// overrides (the store that wins all lookups).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingMappingOut {
    pub org_name: String,
    pub inferred_domain: String,
    pub source_domain: String,
}

/// The full export written to the `--review-json` path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReviewExport {
    pub schema: String,
    pub generated: String,
    pub root_domain: String,
    /// The resolved store path where `review apply` will write — same discovery
    /// logic the next scan uses to READ, so the reviewer writes the right file.
    pub resolved_overrides_path: String,
    pub unverified_orgs: Vec<UnverifiedOrgOut>,
    pub pending_mappings: Vec<PendingMappingOut>,
    pub instructions: String,
}

/// Build the export from the scanner's two transient uncertain sets. Pure and
/// testable — the timestamp and resolved path are injected by the caller.
pub fn build_review_export(
    root_domain: &str,
    pending: &[PendingOrgMapping],
    unverified: &[UnverifiedOrgMapping],
    resolved_overrides_path: &str,
    generated: &str,
) -> ReviewExport {
    ReviewExport {
        schema: REVIEW_EXPORT_SCHEMA.to_string(),
        generated: generated.to_string(),
        root_domain: root_domain.to_string(),
        resolved_overrides_path: resolved_overrides_path.to_string(),
        unverified_orgs: unverified
            .iter()
            .map(|u| UnverifiedOrgOut {
                domain: u.domain.clone(),
                inferred_org: u.inferred_org.clone(),
            })
            .collect(),
        pending_mappings: pending
            .iter()
            .map(|p| PendingMappingOut {
                org_name: p.org_name.clone(),
                inferred_domain: p.inferred_domain.clone(),
                source_domain: p.source_domain.clone(),
            })
            .collect(),
        instructions: INSTRUCTIONS.to_string(),
    }
}

/// Serialize an export to pretty JSON.
pub fn export_to_json(export: &ReviewExport) -> Result<String> {
    serde_json::to_string_pretty(export).context("serialize review export")
}

// ----------------------------------------------------------------------------
// Decisions: validated attributions IN (what `review apply` consumes)
// ----------------------------------------------------------------------------

/// What the reviewer decided for a single attribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum DecisionAction {
    /// The inferred organization is correct — confirm it.
    #[default]
    Accept,
    /// The inferred organization is wrong — replace with `organization`.
    Correct,
    /// Could not corroborate — do not write anything.
    Abstain,
}

/// One piece of cited evidence backing a decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    /// registration | presentation | attestation (see `VALID_LAYERS`).
    pub layer: String,
    #[serde(default)]
    pub tool: String,
    #[serde(default)]
    pub url: String,
    /// The fetched, verbatim quoted span that proves the claim. A quote must be
    /// non-empty AND the chosen organization must be named (word-for-word) in
    /// quotes from ≥2 distinct layers (see `validate_provenance`) — together these
    /// defeat citation laundering and single-source attribution.
    #[serde(default)]
    pub quote: String,
}

/// A single reviewed attribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    #[serde(default = "default_decision_type", rename = "type")]
    pub decision_type: String,
    pub domain: String,
    #[serde(default)]
    pub organization: String,
    #[serde(default = "default_source")]
    pub source: String,
    #[serde(default)]
    pub action: DecisionAction,
    #[serde(default)]
    pub signals: Vec<Signal>,
    #[serde(default)]
    pub note: String,
    /// Explicit assertion that the named infrastructure/registrar/privacy
    /// organization GENUINELY operates this domain (e.g. `aws.amazon.com` → Amazon).
    /// Without it, an org matching the infra denylist is rejected — the
    /// BUG-006/BUG-011 false-positive guard.
    #[serde(default)]
    pub allow_infra_operator: bool,
}

fn default_decision_type() -> String {
    "domain_org".to_string()
}
fn default_source() -> String {
    "claude_verified".to_string()
}

/// The decisions file consumed by `review apply`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionsFile {
    #[serde(default)]
    pub schema: String,
    pub decisions: Vec<Decision>,
}

/// Parse a decisions file from JSON.
pub fn parse_decisions(json: &str) -> Result<DecisionsFile> {
    serde_json::from_str(json).context("parse decisions JSON")
}

/// Trust ranking used for precedence: a human confirmation outranks a
/// machine-verified one, which outranks a bare inference. Applied so an
/// automated `claude_verified` write never silently downgrades a `user_confirmed`.
fn source_rank(source: &str) -> u8 {
    match source {
        "user_confirmed" => 3,
        "claude_verified" | "whois_verified" => 2,
        _ => 1,
    }
}

/// Provenance sources `review apply` is permitted to WRITE. A human
/// `user_confirmed` is deliberately NOT here — it can only be set by the
/// interactive TTY flow, so a decisions file can never launder a machine guess
/// in at human trust and clobber a real confirmation.
pub const MACHINE_SOURCES: [&str; 2] = ["claude_verified", "whois_verified"];

/// Infrastructure / registrar / privacy-service org names. A mapping whose
/// organization resolves to one of these is the classic false-positive
/// (attributing a vendor's domain to its CDN/registrar) and is rejected unless
/// the reviewer explicitly asserts `allow_infra_operator`.
pub const INFRA_ORG_DENYLIST: &[&str] = &[
    "cloudflare",
    "amazon",
    "aws",
    "google",
    "microsoft",
    "azure",
    "akamai",
    "fastly",
    "vercel",
    "netlify",
    "digitalocean",
    "linode",
    "oracle",
    "github",
    "heroku",
    "squarespace",
    "automattic",
    "wordpress",
    "godaddy",
    "namecheap",
    "markmonitor",
    "csc corporate",
    "gandi",
    "tucows",
    "opensrs",
    "sucuri",
    "imperva",
    "incapsula",
    "domains by proxy",
    "whois privacy",
    "privacy protect",
    "redacted for privacy",
    "identity protection",
    "contact privacy",
];

/// Significant lowercase word tokens of an organization name — words ≥3 chars
/// that are not generic legal/corporate stopwords. Used to check the org is
/// actually named in the cited evidence.
fn significant_tokens(org: &str) -> Vec<String> {
    const STOP: &[&str] = &[
        "inc",
        "llc",
        "ltd",
        "corp",
        "the",
        "and",
        "gmbh",
        "plc",
        "group",
        "holdings",
        "company",
        "limited",
        "incorporated",
        "co",
    ];
    org.split(|c: char| !c.is_alphanumeric())
        .filter(|w| w.len() >= 3)
        .map(|w| w.to_lowercase())
        .filter(|w| !STOP.contains(&w.as_str()))
        .collect()
}

/// Number of DISTINCT valid verification layers whose quoted span actually names
/// the organization (word-for-word). Corroboration requires the layers to AGREE
/// on the org — a name that appears in only one layer's quote is a single-source
/// claim, not independent corroboration, and (crucially) does NOT rule out a
/// second layer's quote naming a DIFFERENT org. Falls back to a whole-string word
/// match when the org has no significant tokens (e.g. a short acronym).
fn layers_naming_org(org: &str, signals: &[Signal]) -> usize {
    let tokens = significant_tokens(org);
    let targets: Vec<String> = if tokens.is_empty() {
        let whole = org.trim().to_lowercase();
        if whole.is_empty() {
            return 0;
        }
        vec![whole]
    } else {
        tokens
    };
    let mut layers: BTreeSet<String> = BTreeSet::new();
    for s in signals {
        let layer = s.layer.trim().to_lowercase();
        if !VALID_LAYERS.contains(&layer.as_str()) {
            continue;
        }
        let words: std::collections::HashSet<String> = s
            .quote
            .split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .map(|w| w.to_lowercase())
            .collect();
        if targets.iter().any(|t| words.contains(t)) {
            layers.insert(layer);
        }
    }
    layers.len()
}

/// True if the organization name matches a known infrastructure/registrar/privacy provider.
fn is_infra_org(org: &str) -> bool {
    let o = org.trim().to_lowercase();
    INFRA_ORG_DENYLIST.iter().any(|k| o.contains(k))
}

/// Validate an accept/correct decision at the writer — the deterministic backstop
/// that holds even if the model upstream slips. Requires: supported type;
/// non-empty domain + organization; ≥2 quoted signals from ≥2 DISTINCT layers; a
/// machine-verification `source` (never a human `user_confirmed`); the SAME
/// organization named (word-for-word) in quoted spans from ≥2 distinct layers
/// (cross-layer agreement, not just a lone mention); and — unless explicitly
/// asserted — a non-infrastructure organization. Returns an error naming the
/// deficiency (used to REJECT the decision).
pub fn validate_provenance(d: &Decision) -> Result<()> {
    if d.decision_type != "domain_org" {
        return Err(anyhow!(
            "unsupported decision type '{}': only 'domain_org' is applied",
            d.decision_type
        ));
    }
    if d.domain.trim().is_empty() {
        return Err(anyhow!("decision has empty domain"));
    }
    if d.organization.trim().is_empty() {
        return Err(anyhow!(
            "decision for '{}' has empty organization",
            d.domain
        ));
    }
    let mut layers: BTreeSet<String> = BTreeSet::new();
    let mut quoted = 0usize;
    for s in &d.signals {
        let layer = s.layer.trim().to_lowercase();
        if !VALID_LAYERS.contains(&layer.as_str()) {
            continue; // unknown layer does not count toward corroboration
        }
        if s.quote.trim().is_empty() {
            continue; // a signal without a fetched, quoted span is not evidence
        }
        layers.insert(layer);
        quoted += 1;
    }
    if quoted < 2 || layers.len() < 2 {
        return Err(anyhow!(
            "decision for '{}' lacks retrieval provenance: need >=2 quoted signals from >=2 distinct layers (got {} quoted across {} layer(s))",
            d.domain,
            quoted,
            layers.len()
        ));
    }
    // The write source must be a machine-verification source. `user_confirmed` is
    // human-only (set by the TTY flow) and can never be laundered in here to
    // clobber a real human confirmation.
    if !MACHINE_SOURCES.contains(&d.source.as_str()) {
        return Err(anyhow!(
            "decision for '{}' has non-machine source '{}': review apply only writes claude_verified/whois_verified",
            d.domain,
            d.source
        ));
    }
    // The chosen organization must be NAMED (word-for-word) in a quoted span from
    // ≥2 DISTINCT layers — the layers must corroborate the SAME org, not merely
    // each carry some quote. A name in only one layer is a single-source claim and
    // leaves room for the other layer's quote to name a different entity.
    let naming = layers_naming_org(&d.organization, &d.signals);
    if naming < 2 {
        return Err(anyhow!(
            "decision for '{}': organization '{}' is named in only {} distinct layer(s) — need >=2 layers to corroborate the same org (unsupported/uncorroborated attribution)",
            d.domain,
            d.organization,
            naming
        ));
    }
    // Refuse to attribute a domain to an infrastructure/registrar/privacy provider
    // unless the reviewer explicitly asserts it genuinely operates the domain
    // (the BUG-006/BUG-011 false-positive class).
    if is_infra_org(&d.organization) && !d.allow_infra_operator {
        return Err(anyhow!(
            "decision for '{}': organization '{}' is an infrastructure/registrar/privacy provider — abstain, or set allow_infra_operator=true if it genuinely operates this domain",
            d.domain,
            d.organization
        ));
    }
    Ok(())
}

/// Outcome of applying a decisions file. Every decision lands in exactly one bucket.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ApplyReport {
    /// (domain, organization) actually written.
    pub written: Vec<(String, String)>,
    /// (domain, organization) that WOULD be written under `--dry-run`.
    pub would_write: Vec<(String, String)>,
    /// Domains whose store entry already matched exactly (idempotent no-op).
    pub unchanged: Vec<String>,
    /// Domains the reviewer abstained on (never written).
    pub abstained: Vec<String>,
    /// Domains skipped because a higher-trust entry (e.g. user_confirmed) exists.
    pub skipped_precedence: Vec<String>,
    /// (domain, reason) rejected for insufficient/malformed provenance.
    pub rejected: Vec<(String, String)>,
}

impl ApplyReport {
    /// One-line human summary.
    pub fn summary(&self) -> String {
        format!(
            "{} written, {} would-write, {} unchanged, {} abstained, {} skipped(precedence), {} rejected",
            self.written.len(),
            self.would_write.len(),
            self.unchanged.len(),
            self.abstained.len(),
            self.skipped_precedence.len(),
            self.rejected.len()
        )
    }
}

/// Apply a decisions file against the override store with precedence + idempotency.
///
/// - `abstain` decisions are recorded and never written.
/// - accept/correct decisions are validated (provenance backstop); failures are
///   rejected, not applied, and do not abort the batch.
/// - an entry that already matches exactly is an idempotent no-op (no write).
/// - a decision is skipped if a strictly higher-trust source already owns the domain.
/// - `dry_run` computes the same buckets but performs no write.
pub fn apply_decisions(
    kv: &KnownVendors,
    df: &DecisionsFile,
    dry_run: bool,
) -> Result<ApplyReport> {
    let mut report = ApplyReport::default();
    for d in &df.decisions {
        if d.action == DecisionAction::Abstain {
            report.abstained.push(d.domain.clone());
            continue;
        }
        if let Err(e) = validate_provenance(d) {
            report.rejected.push((d.domain.clone(), e.to_string()));
            continue;
        }
        let domain = d.domain.trim().to_lowercase();
        if let Some(existing) = kv.override_entry(&domain) {
            if existing.organization == d.organization && existing.source == d.source {
                report.unchanged.push(domain);
                continue;
            }
            if source_rank(&existing.source) > source_rank(&d.source) {
                report.skipped_precedence.push(domain);
                continue;
            }
        }
        if dry_run {
            report.would_write.push((domain, d.organization.clone()));
        } else {
            kv.add_override_with_source(&domain, &d.organization, &d.source)?;
            report.written.push((domain, d.organization.clone()));
        }
    }
    Ok(report)
}

/// A single applied-decision record for the JSONL audit trail written beside the
/// override store. Persists WHY a mapping was accepted (the cited signals) so an
/// accepted `claude_verified` mapping stays auditable even after the transient
/// decisions file is gone.
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord<'a> {
    pub applied: &'a str,
    pub domain: String,
    pub organization: &'a str,
    pub source: &'a str,
    pub action: DecisionAction,
    pub signals: &'a [Signal],
    pub note: &'a str,
}

/// Build one JSONL audit line for an applied decision.
pub fn audit_line(d: &Decision, applied: &str) -> Result<String> {
    let rec = AuditRecord {
        applied,
        domain: d.domain.trim().to_lowercase(),
        organization: &d.organization,
        source: &d.source,
        action: d.action,
        signals: &d.signals,
        note: &d.note,
    };
    serde_json::to_string(&rec).context("serialize audit record")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn kv() -> (tempfile::TempDir, KnownVendors) {
        let dir = tempdir().unwrap();
        let base = dir.path().join("known_vendors.json");
        let ov = dir.path().join("known_vendors_local.json");
        let kv = KnownVendors::load_from_paths(&base, &ov).unwrap();
        (dir, kv)
    }

    fn sig(layer: &str, quote: &str) -> Signal {
        Signal {
            layer: layer.to_string(),
            tool: "test".to_string(),
            url: String::new(),
            quote: quote.to_string(),
        }
    }

    fn decision(domain: &str, org: &str, action: DecisionAction, signals: Vec<Signal>) -> Decision {
        Decision {
            decision_type: "domain_org".to_string(),
            domain: domain.to_string(),
            organization: org.to_string(),
            source: "claude_verified".to_string(),
            action,
            signals,
            note: String::new(),
            allow_infra_operator: false,
        }
    }

    fn good_signals() -> Vec<Signal> {
        vec![
            sig("registration", "Registrant Organization: Example, Inc."),
            sig("presentation", "© 2026 Example, Inc."),
        ]
    }

    #[test]
    fn build_export_maps_both_directions() {
        let pending = vec![PendingOrgMapping {
            org_name: "Acme Corp".to_string(),
            inferred_domain: "acmecorp.com".to_string(),
            source_domain: "vanta.com".to_string(),
        }];
        let unverified = vec![UnverifiedOrgMapping {
            domain: "sub.example.com".to_string(),
            inferred_org: "Sub".to_string(),
        }];
        let e = build_review_export(
            "vanta.com",
            &pending,
            &unverified,
            "/tmp/ov.json",
            "2026-07-05T00:00:00Z",
        );
        assert_eq!(e.schema, REVIEW_EXPORT_SCHEMA);
        assert_eq!(e.root_domain, "vanta.com");
        assert_eq!(e.resolved_overrides_path, "/tmp/ov.json");
        assert_eq!(e.unverified_orgs.len(), 1);
        assert_eq!(e.unverified_orgs[0].domain, "sub.example.com");
        assert_eq!(e.pending_mappings[0].org_name, "Acme Corp");
        assert!(e.instructions.contains("ABSTAIN"));
        // roundtrips through json
        let json = export_to_json(&e).unwrap();
        assert!(json.contains("\"nthpartyfinder.review/v1\""));
    }

    #[test]
    fn parse_decisions_roundtrip_with_defaults() {
        let json = r#"{"decisions":[{"domain":"x.com","organization":"X","signals":[]}]}"#;
        let df = parse_decisions(json).unwrap();
        assert_eq!(df.decisions.len(), 1);
        // defaults applied
        assert_eq!(df.decisions[0].decision_type, "domain_org");
        assert_eq!(df.decisions[0].source, "claude_verified");
        assert_eq!(df.decisions[0].action, DecisionAction::Accept);
    }

    #[test]
    fn parse_decisions_rejects_garbage() {
        assert!(parse_decisions("not json").is_err());
    }

    #[test]
    fn validate_passes_with_two_distinct_layers() {
        let d = decision(
            "x.com",
            "Example, Inc.",
            DecisionAction::Accept,
            good_signals(),
        );
        assert!(validate_provenance(&d).is_ok());
    }

    #[test]
    fn validate_rejects_single_layer_even_if_two_signals() {
        let d = decision(
            "x.com",
            "X",
            DecisionAction::Accept,
            vec![sig("registration", "a"), sig("registration", "b")],
        );
        assert!(validate_provenance(&d).is_err());
    }

    #[test]
    fn validate_rejects_empty_quote() {
        let d = decision(
            "x.com",
            "X",
            DecisionAction::Accept,
            vec![sig("registration", "a"), sig("presentation", "  ")],
        );
        assert!(validate_provenance(&d).is_err());
    }

    #[test]
    fn validate_rejects_unknown_layer() {
        let d = decision(
            "x.com",
            "X",
            DecisionAction::Accept,
            vec![sig("registration", "a"), sig("vibes", "b")],
        );
        assert!(validate_provenance(&d).is_err());
    }

    #[test]
    fn validate_rejects_empty_org_and_bad_type() {
        let mut d = decision("x.com", "  ", DecisionAction::Accept, good_signals());
        assert!(validate_provenance(&d).is_err());
        d.organization = "X".to_string();
        d.decision_type = "org_domain".to_string();
        assert!(validate_provenance(&d).is_err());
    }

    #[test]
    fn source_rank_orders_trust() {
        assert!(source_rank("user_confirmed") > source_rank("claude_verified"));
        assert_eq!(
            source_rank("whois_verified"),
            source_rank("claude_verified")
        );
        assert!(source_rank("claude_verified") > source_rank("inferred"));
    }

    #[test]
    fn apply_writes_accept_and_is_idempotent() {
        let (_d, kv) = kv();
        let df = DecisionsFile {
            schema: DECISIONS_SCHEMA.to_string(),
            decisions: vec![decision(
                "Example.com",
                "Example, Inc.",
                DecisionAction::Accept,
                good_signals(),
            )],
        };
        let r1 = apply_decisions(&kv, &df, false).unwrap();
        assert_eq!(r1.written.len(), 1);
        // lowercased on write
        let e = kv.override_entry("example.com").unwrap();
        assert_eq!(e.organization, "Example, Inc.");
        assert_eq!(e.source, "claude_verified");
        // second apply is a no-op
        let r2 = apply_decisions(&kv, &df, false).unwrap();
        assert_eq!(r2.written.len(), 0);
        assert_eq!(r2.unchanged.len(), 1);
    }

    #[test]
    fn apply_dry_run_writes_nothing() {
        let (_d, kv) = kv();
        let df = DecisionsFile {
            schema: String::new(),
            decisions: vec![decision(
                "x.com",
                "Example, Inc.",
                DecisionAction::Accept,
                good_signals(),
            )],
        };
        let r = apply_decisions(&kv, &df, true).unwrap();
        assert_eq!(r.would_write.len(), 1);
        assert!(kv.override_entry("x.com").is_none());
    }

    #[test]
    fn apply_respects_precedence_no_downgrade() {
        let (_d, kv) = kv();
        // A human confirmation exists.
        kv.add_override_with_source("x.com", "Human Co", "user_confirmed")
            .unwrap();
        let df = DecisionsFile {
            schema: String::new(),
            decisions: vec![decision(
                "x.com",
                "Example, Inc.",
                DecisionAction::Correct,
                good_signals(),
            )],
        };
        let r = apply_decisions(&kv, &df, false).unwrap();
        assert_eq!(r.skipped_precedence.len(), 1);
        // human value preserved
        assert_eq!(kv.override_entry("x.com").unwrap().organization, "Human Co");
    }

    #[test]
    fn apply_abstain_and_reject_do_not_write() {
        let (_d, kv) = kv();
        let df = DecisionsFile {
            schema: String::new(),
            decisions: vec![
                decision("a.com", "A", DecisionAction::Abstain, vec![]),
                decision(
                    "b.com",
                    "B",
                    DecisionAction::Accept,
                    vec![sig("registration", "only one")],
                ),
            ],
        };
        let r = apply_decisions(&kv, &df, false).unwrap();
        assert_eq!(r.abstained, vec!["a.com".to_string()]);
        assert_eq!(r.rejected.len(), 1);
        assert_eq!(r.rejected[0].0, "b.com");
        assert!(kv.override_entry("a.com").is_none());
        assert!(kv.override_entry("b.com").is_none());
    }

    #[test]
    fn apply_correct_overwrites_equal_or_lower_trust() {
        let (_d, kv) = kv();
        kv.add_override_with_source("x.com", "Old Guess", "claude_verified")
            .unwrap();
        let df = DecisionsFile {
            schema: String::new(),
            decisions: vec![decision(
                "x.com",
                "New Verified Co",
                DecisionAction::Correct,
                vec![
                    sig("registration", "Registrant Organization: New Verified Co"),
                    sig("presentation", "© 2026 New Verified Co"),
                ],
            )],
        };
        let r = apply_decisions(&kv, &df, false).unwrap();
        assert_eq!(r.written.len(), 1);
        assert_eq!(
            kv.override_entry("x.com").unwrap().organization,
            "New Verified Co"
        );
    }

    #[test]
    fn apply_report_summary_counts() {
        let mut r = ApplyReport::default();
        r.written.push(("a".into(), "A".into()));
        r.abstained.push("b".into());
        let s = r.summary();
        assert!(s.contains("1 written"));
        assert!(s.contains("1 abstained"));
    }

    #[test]
    fn audit_line_is_valid_jsonl_with_evidence() {
        let d = decision(
            "sendgrid.net",
            "Twilio SendGrid",
            DecisionAction::Correct,
            good_signals(),
        );
        let line = audit_line(&d, "2026-07-05T00:00:00Z").unwrap();
        assert!(!line.contains('\n'), "audit line must be single-line JSONL");
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["domain"], "sendgrid.net");
        assert_eq!(v["organization"], "Twilio SendGrid");
        assert_eq!(v["applied"], "2026-07-05T00:00:00Z");
        assert_eq!(v["signals"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn validate_rejects_non_machine_source() {
        // A decisions file cannot launder a human `user_confirmed` in.
        let mut d = decision(
            "x.com",
            "Example, Inc.",
            DecisionAction::Accept,
            good_signals(),
        );
        d.source = "user_confirmed".to_string();
        assert!(validate_provenance(&d).is_err());
    }

    #[test]
    fn validate_rejects_org_absent_from_quotes() {
        // "Acme Corp" appears in none of the Example quotes → unsupported attribution.
        let d = decision("x.com", "Acme Corp", DecisionAction::Accept, good_signals());
        assert!(validate_provenance(&d).is_err());
    }

    #[test]
    fn validate_rejects_org_named_in_only_one_layer() {
        // registration names Acme; presentation names a DIFFERENT entity. Only one
        // layer corroborates "Acme", so the layers do NOT agree — reject (the
        // finding-4 cross-layer-disagreement write-hole).
        let sigs = vec![
            sig("registration", "Registrant Organization: Acme Inc."),
            sig("presentation", "© 2026 Globex Corporation"),
        ];
        let d = decision("x.com", "Acme Inc.", DecisionAction::Accept, sigs);
        assert!(validate_provenance(&d).is_err());
    }

    #[test]
    fn validate_rejects_infra_org_unless_asserted() {
        let sigs = vec![
            sig("registration", "Registrant Organization: Cloudflare, Inc."),
            sig("presentation", "© Cloudflare, Inc."),
        ];
        let d = decision(
            "victim.com",
            "Cloudflare, Inc.",
            DecisionAction::Accept,
            sigs.clone(),
        );
        assert!(
            validate_provenance(&d).is_err(),
            "an infra org must be rejected by default (the BUG-006/011 FP class)"
        );
        let mut d2 = decision(
            "status.cloudflare.com",
            "Cloudflare, Inc.",
            DecisionAction::Accept,
            sigs,
        );
        d2.allow_infra_operator = true;
        assert!(
            validate_provenance(&d2).is_ok(),
            "explicit allow_infra_operator permits a genuine infra operator"
        );
    }
}
