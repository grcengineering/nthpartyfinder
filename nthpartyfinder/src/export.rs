use crate::vendor::{RecordType, VendorRelationship};
use anyhow::Result;
use askama::Template;
use chrono::Utc;
use csv::Writer;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use tracing::{debug, info};

/// One option in the HTML report's "Discovery Source" filter dropdown. `value`
/// is the hierarchy string (matching each row's `data-type`, so filtering works
/// 1:1); `label` is the human-friendly name shown in the dropdown.
struct DiscoverySourceOption {
    value: String,
    label: String,
}

/// Build the filter's option list from the discovery sources that actually
/// appear in this report, in canonical [`RecordType::all_variants`] order. The
/// filter therefore can never list a source that isn't present nor omit one that
/// is — the exact drift that previously hid trust-center subprocessors.
fn present_discovery_sources(relationships: &[VendorRelationship]) -> Vec<DiscoverySourceOption> {
    let present: HashSet<String> = relationships
        .iter()
        .map(|r| r.nth_party_record_type.as_hierarchy_string())
        .collect();
    RecordType::all_variants()
        .iter()
        .filter(|rt| present.contains(&rt.as_hierarchy_string()))
        .map(|rt| DiscoverySourceOption {
            value: rt.as_hierarchy_string(),
            label: rt.discovery_source_label().to_string(),
        })
        .collect()
}

/// JSON object mapping every discovery-source identifier — both the hierarchy
/// string (`TRUST_CENTER::API`) and the serde variant name (`TrustCenterApi`) —
/// to its friendly label. Injected into the report so the in-page JS that
/// renders badge text and the evidence modal draws labels from the same source
/// of truth as the filter, keeping every label complete and consistent.
fn record_type_label_map_json() -> String {
    let mut map = serde_json::Map::new();
    for rt in RecordType::all_variants() {
        let label = serde_json::Value::String(rt.discovery_source_label().to_string());
        map.insert(rt.as_hierarchy_string(), label.clone());
        map.insert(rt.variant_name().to_string(), label);
    }
    serde_json::to_string(&serde_json::Value::Object(map)).unwrap_or_else(|_| "{}".to_string())
}

/// Separator for the multi-source cells a merged edge produces. Matches the one
/// `deduplicate_results` already uses when it concatenates evidence, so a reader
/// (or a spreadsheet split) sees one convention across the whole report.
const EVIDENCE_JOIN: &str = " | ";

/// One discovery that produced an edge: which source found it and the raw record
/// it emitted. A merged edge carries a list of these rather than a winner —
/// collapsing rows is only allowed to cost the reader repetition, never
/// provenance, and "reported honestly" is the property this tool sells.
#[derive(Debug, Clone, PartialEq)]
pub struct EdgeEvidence {
    pub record_type: RecordType,
    pub record: String,
    pub evidence: String,
}

/// One parent→child relationship with every discovery that found it.
///
/// TF-EDGEDEDUP: DNS, web traffic and CT each emit their own row for the same
/// pair — `deduplicate_results` only collapses rows that also share a record
/// type, so a 2026-07-17 census still found 207 rows that were the same
/// relationship said three ways, and the 2026-08-15 scan shipped 22,482 rows.
/// The reader cannot tell "22,482 relationships" from "22,482 sightings".
#[derive(Debug, Clone, PartialEq)]
pub struct MergedEdge {
    pub nth_party_domain: String,
    pub nth_party_organization: String,
    pub nth_party_layer: u32,
    pub nth_party_customer_domain: String,
    pub nth_party_customer_organization: String,
    pub root_customer_domain: String,
    pub root_customer_organization: String,
    /// Every (source, raw record) that produced this edge, sorted canonically so
    /// two runs of the same scan render identical reports.
    pub evidence: Vec<EdgeEvidence>,
}

impl MergedEdge {
    /// The source to show where a surface has room for exactly one (the mermaid
    /// edge style, the table an edge is filed under). `evidence` is sorted in
    /// [`RecordType::all_variants`] order, so this is the same source every run
    /// even though discovery finishes in nondeterministic order.
    ///
    /// Indexing is safe: [`merge_edge_evidence`] seeds `evidence` with the row
    /// that created the edge, so it is never empty.
    pub fn primary_record_type(&self) -> &RecordType {
        &self.evidence[0].record_type
    }

    /// Hierarchy strings of every source that found this edge.
    pub fn joined_record_types(&self) -> String {
        self.join_field(|e| e.record_type.as_hierarchy_string())
    }

    /// Friendly source labels, for surfaces read by people rather than parsers.
    pub fn joined_source_labels(&self) -> String {
        self.join_field(|e| e.record_type.discovery_source_label().to_string())
    }

    /// Raw records, positionally aligned with [`Self::joined_record_types`] — the
    /// i-th record is what the i-th source emitted, which is what makes the
    /// single-row rendering lossless rather than merely shorter.
    pub fn joined_records(&self) -> String {
        self.join_field(|e| e.record.clone())
    }

    /// Evidence strings, positionally aligned with [`Self::joined_record_types`].
    pub fn joined_evidence(&self) -> String {
        self.join_field(|e| e.evidence.clone())
    }

    fn join_field(&self, f: impl Fn(&EdgeEvidence) -> String) -> String {
        self.evidence
            .iter()
            .map(f)
            .collect::<Vec<_>>()
            .join(EVIDENCE_JOIN)
    }
}

/// Position of a record type in the canonical variant order, so merged evidence
/// sorts the same way the report's discovery-source filter lists sources.
fn record_type_rank(record_type: &RecordType) -> usize {
    RecordType::all_variants()
        .iter()
        .position(|v| v == record_type)
        .unwrap_or(usize::MAX)
}

/// Collapse rows into one edge per (source domain, target domain), carrying every
/// contributing discovery.
///
/// Pure: no I/O, no clock, no globals — the report surfaces call it and render
/// what comes back, so the collapse rule is testable without writing a file.
///
/// Two rules are inherited rather than invented. The layer is the MINIMUM of the
/// inputs, matching `deduplicate_results`: an edge's honest layer is the
/// shallowest path that reaches it, and taking whichever arrived first was
/// nondeterministic across runs. The organization names are taken from the first
/// row seen because `finalize::reconcile_org_per_domain` has already forced one
/// name per domain across the whole report — if that ever stops being true, this
/// picks a name silently and needs revisiting.
pub fn merge_edge_evidence(relationships: &[VendorRelationship]) -> Vec<MergedEdge> {
    let mut index: HashMap<(String, String), usize> = HashMap::new();
    let mut merged: Vec<MergedEdge> = Vec::new();

    for r in relationships {
        // Case-fold the key: a domain echoed back as the page wrote it ("CDN.Example.com")
        // is the same edge as the lowercased one, and splitting them is precisely the
        // duplication this function exists to remove.
        let key = (
            r.nth_party_customer_domain.to_ascii_lowercase(),
            r.nth_party_domain.to_ascii_lowercase(),
        );
        let entry = EdgeEvidence {
            record_type: r.nth_party_record_type.clone(),
            record: r.nth_party_record.clone(),
            evidence: r.evidence.clone(),
        };

        if let Some(&i) = index.get(&key) {
            let edge = &mut merged[i];
            edge.nth_party_layer = edge.nth_party_layer.min(r.nth_party_layer);
            // Identical triples cannot survive `deduplicate_results`, but export is
            // also called on raw slices (tests, --no-dedup paths); an exact repeat is
            // a sighting we already recorded, not a second source.
            if !edge.evidence.contains(&entry) {
                edge.evidence.push(entry);
            }
        } else {
            index.insert(key, merged.len());
            merged.push(MergedEdge {
                nth_party_domain: r.nth_party_domain.clone(),
                nth_party_organization: r.nth_party_organization.clone(),
                nth_party_layer: r.nth_party_layer,
                nth_party_customer_domain: r.nth_party_customer_domain.clone(),
                nth_party_customer_organization: r.nth_party_customer_organization.clone(),
                root_customer_domain: r.root_customer_domain.clone(),
                root_customer_organization: r.root_customer_organization.clone(),
                evidence: vec![entry],
            });
        }
    }

    // Discovery runs concurrently, so the order rows arrive in is not stable between
    // two scans of the same target. Sort each edge's evidence on its own content so
    // the rendered report is diffable run over run.
    for edge in &mut merged {
        edge.evidence.sort_by_key(evidence_sort_key);
    }

    merged
}

/// Total order over evidence entries: canonical source order first, then the
/// record and evidence text so two entries from the same source still sort
/// deterministically.
fn evidence_sort_key(entry: &EdgeEvidence) -> (usize, String, String, String) {
    (
        record_type_rank(&entry.record_type),
        entry.record_type.as_hierarchy_string(),
        entry.record.clone(),
        entry.evidence.clone(),
    )
}

#[cfg_attr(coverage_nightly, coverage(off))]
pub fn export_csv(relationships: &[VendorRelationship], output_path: &str) -> Result<()> {
    debug!(
        "Exporting {} relationships to CSV: {}",
        relationships.len(),
        output_path
    );

    let file = File::create(output_path)?;
    let mut wtr = Writer::from_writer(file);

    // TF-EDGEDEDUP: one row per edge, not per sighting. The record/type/evidence
    // cells hold every contributing discovery, positionally aligned, so nothing
    // the per-sighting rows carried is dropped — the count column tells the reader
    // how many discoveries a row stands for.
    let merged = merge_edge_evidence(relationships);

    // Write CSV headers
    wtr.write_record([
        "Root Customer Domain",
        "Root Customer Organization",
        "Nth Party Domain",
        "Nth Party Organization",
        "Nth Party Layer",
        "Nth Party Customer Domain",
        "Nth Party Customer Organization",
        "Nth Party Record",
        "Nth Party Record Type",
        "Evidence",
        "Discovery Source Count",
    ])?;

    // Write data rows
    for edge in &merged {
        wtr.write_record([
            &edge.root_customer_domain,
            &edge.root_customer_organization,
            &edge.nth_party_domain,
            &edge.nth_party_organization,
            &edge.nth_party_layer.to_string(),
            &edge.nth_party_customer_domain,
            &edge.nth_party_customer_organization,
            &edge.joined_records(),
            &edge.joined_record_types(),
            &edge.joined_evidence(),
            &edge.evidence.len().to_string(),
        ])?;
    }

    wtr.flush()?;
    info!(
        "Successfully exported {} relationships ({} merged edges) to CSV: {}",
        relationships.len(),
        merged.len(),
        output_path
    );

    Ok(())
}

/// Deliberately NOT merged (TF-EDGEDEDUP): the JSON export is the machine-readable
/// artifact other tools diff and re-ingest, so it stays one object per discovery.
/// The collapse belongs to the surfaces a person reads.
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn export_json(relationships: &[VendorRelationship], output_path: &str) -> Result<()> {
    debug!(
        "Exporting {} relationships to JSON: {}",
        relationships.len(),
        output_path
    );

    let json_output = JsonExport {
        summary: ExportSummary {
            total_relationships: relationships.len(),
            max_depth: relationships
                .iter()
                .map(|r| r.nth_party_layer)
                .max()
                .unwrap_or(0),
            unique_domains: relationships
                .iter()
                .map(|r| r.nth_party_domain.clone())
                .collect::<std::collections::HashSet<_>>()
                .len(),
            unique_organizations: relationships
                .iter()
                .map(|r| r.nth_party_organization.clone())
                .collect::<std::collections::HashSet<_>>()
                .len(),
        },
        relationships: relationships.iter().map(JsonRelationship::from).collect(),
    };

    let json_string = serde_json::to_string_pretty(&json_output)?;

    let mut file = File::create(output_path)?;
    file.write_all(json_string.as_bytes())?;

    info!(
        "Successfully exported {} relationships to JSON: {}",
        relationships.len(),
        output_path
    );

    Ok(())
}

#[derive(serde::Serialize)]
struct JsonExport<'a> {
    summary: ExportSummary,
    relationships: Vec<JsonRelationship<'a>>,
}

/// JSON-export view of a relationship. Identical to [`VendorRelationship`] in
/// shape and field order, except `nth_party_record_type` is rendered as the
/// hierarchy string (`TRUST_CENTER::API`) instead of the serde variant name
/// (`TrustCenterApi`). This keeps the JSON export's discovery-source values 1:1
/// with the CSV, Markdown, and HTML reports (which all use the hierarchy string).
/// Export-only: the internal result sink serializes `VendorRelationship`
/// directly and round-trips it, so its variant-name form must stay unchanged.
#[derive(serde::Serialize)]
struct JsonRelationship<'a> {
    nth_party_domain: &'a str,
    nth_party_organization: &'a str,
    nth_party_layer: u32,
    nth_party_customer_domain: &'a str,
    nth_party_customer_organization: &'a str,
    nth_party_record: &'a str,
    nth_party_record_type: String,
    root_customer_domain: &'a str,
    root_customer_organization: &'a str,
    evidence: &'a str,
}

impl<'a> From<&'a VendorRelationship> for JsonRelationship<'a> {
    fn from(r: &'a VendorRelationship) -> Self {
        JsonRelationship {
            nth_party_domain: &r.nth_party_domain,
            nth_party_organization: &r.nth_party_organization,
            nth_party_layer: r.nth_party_layer,
            nth_party_customer_domain: &r.nth_party_customer_domain,
            nth_party_customer_organization: &r.nth_party_customer_organization,
            nth_party_record: &r.nth_party_record,
            nth_party_record_type: r.nth_party_record_type.as_hierarchy_string(),
            root_customer_domain: &r.root_customer_domain,
            root_customer_organization: &r.root_customer_organization,
            evidence: &r.evidence,
        }
    }
}

#[derive(serde::Serialize)]
struct ExportSummary {
    total_relationships: usize,
    max_depth: u32,
    unique_domains: usize,
    unique_organizations: usize,
}

/// P4.5: count DISTINCT vendor domains per layer, assigning each vendor to its
/// MINIMUM layer, so a vendor lands in exactly one band. The old per-layer stat
/// counted `(parent, child, source)` rows: a vendor discovered via three sources
/// counted 3×, and a vendor appearing at two layers counted in both bands. Returns
/// a Vec indexed by layer (1..=max), each entry the distinct-vendor count for that band.
pub fn count_vendors_by_min_layer(relationships: &[VendorRelationship]) -> Vec<(u32, usize)> {
    use std::collections::HashMap;
    // vendor domain -> minimum layer it appears at
    let mut min_layer: HashMap<&str, u32> = HashMap::new();
    for r in relationships {
        let e = min_layer
            .entry(r.nth_party_domain.as_str())
            .or_insert(r.nth_party_layer);
        if r.nth_party_layer < *e {
            *e = r.nth_party_layer;
        }
    }
    let max_layer = min_layer.values().copied().max().unwrap_or(0);
    let mut counts: HashMap<u32, usize> = HashMap::new();
    for layer in min_layer.values() {
        *counts.entry(*layer).or_insert(0) += 1;
    }
    (1..=max_layer)
        .filter_map(|l| counts.get(&l).map(|&c| (l, c)))
        .collect()
}

pub fn print_analysis_summary(relationships: &[VendorRelationship]) {
    if relationships.is_empty() {
        println!("No vendor relationships found.");
        return;
    }

    let max_depth = relationships
        .iter()
        .map(|r| r.nth_party_layer)
        .max()
        .unwrap_or(0);
    let unique_domains: std::collections::HashSet<_> = relationships
        .iter()
        .map(|r| r.nth_party_domain.clone())
        .collect();
    let unique_orgs: std::collections::HashSet<_> = relationships
        .iter()
        .map(|r| r.nth_party_organization.clone())
        .collect();

    println!("\n=== Analysis Summary ===");
    println!("Total vendor relationships found: {}", relationships.len());
    // TF-EDGEDEDUP: the raw count above is sightings. Say how many distinct
    // relationships that actually is, so the headline number is not read as
    // "this many vendors" when three sources found the same one.
    println!(
        "Distinct vendor edges (evidence merged): {}",
        merge_edge_evidence(relationships).len()
    );
    println!("Maximum depth reached: {} layers", max_depth);
    println!("Unique vendor domains: {}", unique_domains.len());
    println!("Unique vendor organizations: {}", unique_orgs.len());

    // Show breakdown by layer — distinct vendors per min-layer band (P4.5).
    for (layer, count) in count_vendors_by_min_layer(relationships) {
        println!("  Layer {} vendors: {}", layer, count);
    }

    println!("========================\n");
}

#[cfg_attr(coverage_nightly, coverage(off))]
pub fn export_markdown(relationships: &[VendorRelationship], output_path: &str) -> Result<()> {
    debug!(
        "Exporting {} relationships to Markdown: {}",
        relationships.len(),
        output_path
    );

    if relationships.is_empty() {
        let content = "# Nth Party Analysis Report\n\nNo vendor relationships found.\n";
        std::fs::write(output_path, content)?;
        info!(
            "Successfully exported empty report to Markdown: {}",
            output_path
        );
        return Ok(());
    }

    let mut content = String::new();

    // TF-EDGEDEDUP: every row-level section below renders MERGED edges — one row
    // per (customer domain, vendor domain), carrying each source that found it.
    // The summary counts stay on the raw rows so this report and the JSON export
    // still describe the same scan.
    let merged = merge_edge_evidence(relationships);

    // Get root domain for the report
    let root_domain = &relationships[0].root_customer_domain;
    let root_organization = &relationships[0].root_customer_organization;

    // Header
    content.push_str("# Nth Party Analysis Report\n\n");
    content.push_str(&format!("**Domain:** {}\n", root_domain));
    content.push_str(&format!("**Organization:** {}\n\n", root_organization));
    content.push_str(&format!(
        "*Generated on: {}*\n\n",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    ));

    // Summary statistics
    let max_depth = relationships
        .iter()
        .map(|r| r.nth_party_layer)
        .max()
        .unwrap_or(0);
    let unique_domains: HashSet<_> = relationships
        .iter()
        .map(|r| r.nth_party_domain.clone())
        .collect();
    let unique_orgs: HashSet<_> = relationships
        .iter()
        .map(|r| r.nth_party_organization.clone())
        .collect();

    // Count by record type
    let mut type_counts = HashMap::new();
    for rel in relationships {
        *type_counts
            .entry(rel.nth_party_record_type.as_hierarchy_string())
            .or_insert(0) += 1;
    }

    content.push_str("## Executive Summary\n\n");
    content.push_str(&format!(
        "- **Total vendor relationships found:** {}\n",
        relationships.len()
    ));
    content.push_str(&format!(
        "- **Distinct vendor edges (evidence merged):** {}\n",
        merged.len()
    ));
    content.push_str(&format!(
        "- **Maximum depth reached:** {} layers\n",
        max_depth
    ));
    content.push_str(&format!(
        "- **Unique vendor domains:** {}\n",
        unique_domains.len()
    ));
    content.push_str(&format!(
        "- **Unique vendor organizations:** {}\n\n",
        unique_orgs.len()
    ));

    // Breakdown by record type
    content.push_str("### Breakdown by Record Type\n\n");
    content.push_str(
        "Counts are discoveries, not edges — one relationship found by three sources counts three times here and appears once in the tables below.\n\n",
    );
    for (record_type, count) in &type_counts {
        content.push_str(&format!("- **{}:** {} relationships\n", record_type, count));
    }
    content.push('\n');

    // Breakdown by layer — distinct vendors per min-layer band (P4.5).
    content.push_str("### Breakdown by Layer\n\n");
    for (layer, count) in count_vendors_by_min_layer(relationships) {
        content.push_str(&format!("- **Layer {} vendors:** {}\n", layer, count));
    }
    content.push('\n');

    // Mermaid.js graph
    content.push_str("## Vendor Relationship Graph\n\n");
    content.push_str("The following diagram shows the relationships between your organization and third-party vendors:\n\n");
    content.push_str("```mermaid\n");
    content.push_str("graph TD\n");

    // Create nodes and edges for Mermaid
    let mut nodes = HashSet::new();
    let mut edges = Vec::new();

    // Add root node
    let root_node = sanitize_mermaid_id(root_domain);
    nodes.insert(root_node.clone());
    content.push_str(&format!(
        "    {}[\"{}<br/>({})\"]\\n",
        root_node, root_domain, root_organization
    ));

    // Process merged edges by layer. Drawing one arrow per sighting stacked three
    // identical arrows between the same two nodes; the graph is about who talks to
    // whom, so it draws the edge once and names its sources in the label.
    for layer in 1..=max_depth {
        let layer_edges: Vec<_> = merged
            .iter()
            .filter(|e| e.nth_party_layer == layer)
            .collect();

        for edge in layer_edges {
            let vendor_node = sanitize_mermaid_id(&edge.nth_party_domain);
            let customer_node = sanitize_mermaid_id(&edge.nth_party_customer_domain);

            // Add vendor node if not already added
            if !nodes.contains(&vendor_node) {
                nodes.insert(vendor_node.clone());
                let node_label = format!(
                    "{}<br/>({})",
                    edge.nth_party_domain, edge.nth_party_organization
                );
                content.push_str(&format!("    {}[\"{}\"]\\n", vendor_node, node_label));
            }

            // Add edge with record type styling
            let primary_type = edge.primary_record_type().as_hierarchy_string();
            let edge_style = match primary_type.as_str() {
                "DNS::TXT::SPF" => "-.->",
                "DNS::TXT::VERIFICATION" => "-->",
                "DNS::SUBDOMAIN" => "==>",
                "DISCOVERY::WEBPAGE_SOURCE" => "-..->",
                "DISCOVERY::WEBPAGE_NETWORK" => "-.->",
                _ => "-->",
            };

            let edge_label = format!("{}|{}", edge.joined_record_types(), edge.nth_party_layer);
            edges.push(format!(
                "    {} {} {}[\"{}\"]",
                customer_node, edge_style, vendor_node, edge_label
            ));
        }
    }

    // Add all edges
    for edge in edges {
        content.push_str(&format!("{}\\n", edge));
    }

    // Add styling
    content.push_str("\\n");
    content.push_str("    classDef spfNode fill:#e1f5fe,stroke:#01579b,stroke-width:2px\\n");
    content
        .push_str("    classDef verificationNode fill:#f3e5f5,stroke:#4a148c,stroke-width:2px\\n");
    content.push_str("    classDef rootNode fill:#e8f5e8,stroke:#2e7d32,stroke-width:3px\\n");
    content.push_str(&format!("    class {} rootNode\\n", root_node));

    content.push_str("```\n\n");

    // Legend
    content.push_str("### Legend\n\n");
    content.push_str(
        "- **Solid arrows (→):** Verification relationships (domain/site verification)\n",
    );
    content.push_str("- **Dashed arrows (⇢):** SPF relationships (email sending authorization)\n");
    content.push_str("- **Double arrows (⇒):** Subdomain relationships\n");
    content.push_str(
        "- **Dotted arrows (⇢⇢):** Webpage discovery (source references, network requests)\n",
    );
    content.push_str("- **Numbers on edges:** Layer depth and record type\n\n");

    // Detailed tables
    content.push_str("## Detailed Relationships\n\n");

    // Group merged edges by their PRIMARY source, so an edge appears in exactly one
    // table. Filing by every source would put a DNS+web-traffic edge in two tables
    // and re-create the repetition the merge just removed; the "Sources" column
    // carries the rest.
    let mut spf_edges = Vec::new();
    let mut verification_edges = Vec::new();
    let mut web_traffic_edges = Vec::new();
    let mut other_edges = Vec::new();

    for edge in &merged {
        match edge.primary_record_type().as_hierarchy_string().as_str() {
            "DNS::TXT::SPF" => spf_edges.push(edge),
            "DNS::TXT::VERIFICATION" => verification_edges.push(edge),
            "DISCOVERY::WEBPAGE_SOURCE" | "DISCOVERY::WEBPAGE_NETWORK" => {
                web_traffic_edges.push(edge)
            }
            _ => other_edges.push(edge),
        }
    }

    // SPF Relationships table
    if !spf_edges.is_empty() {
        content.push_str("### Email Service Providers (SPF)\n\n");
        content.push_str("These vendors can send emails on behalf of your domain:\n\n");
        content.push_str("| Vendor | Organization | Layer | Customer | SPF Record | Sources |\n");
        content.push_str("|--------|--------------|-------|----------|------------|---------|\n");

        for edge in &spf_edges {
            content.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                escape_markdown(&edge.nth_party_domain),
                escape_markdown(&edge.nth_party_organization),
                edge.nth_party_layer,
                escape_markdown(&edge.nth_party_customer_domain),
                escape_markdown(&edge.joined_records()),
                escape_markdown(&edge.joined_source_labels())
            ));
        }
        content.push('\n');
    }

    // Verification Relationships table
    if !verification_edges.is_empty() {
        content.push_str("### Integrated Services (Domain Verification)\n\n");
        content.push_str(
            "These vendors have verified domain ownership and likely have integrations:\n\n",
        );
        content.push_str(
            "| Vendor | Organization | Layer | Customer | Verification Record | Sources |\n",
        );
        content.push_str(
            "|--------|--------------|-------|----------|--------------------|---------|\n",
        );

        for edge in &verification_edges {
            content.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                escape_markdown(&edge.nth_party_domain),
                escape_markdown(&edge.nth_party_organization),
                edge.nth_party_layer,
                escape_markdown(&edge.nth_party_customer_domain),
                escape_markdown(&edge.joined_records()),
                escape_markdown(&edge.joined_source_labels())
            ));
        }
        content.push('\n');
    }

    // Webpage discovery relationships table
    if !web_traffic_edges.is_empty() {
        content.push_str("### Webpage Discovery\n\n");
        content.push_str("These vendors were discovered through webpage source analysis or runtime network request capture:\n\n");
        content.push_str(
            "| Vendor | Organization | Layer | Discovery Method | Customer | Evidence | Sources |\n",
        );
        content.push_str(
            "|--------|--------------|-------|-----------------|----------|----------|---------|\n",
        );

        for edge in &web_traffic_edges {
            let primary = edge.primary_record_type().as_hierarchy_string();
            let method = if primary == "DISCOVERY::WEBPAGE_SOURCE" {
                "Webpage Source"
            } else {
                "Webpage Network Requests"
            };
            content.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                escape_markdown(&edge.nth_party_domain),
                escape_markdown(&edge.nth_party_organization),
                edge.nth_party_layer,
                method,
                escape_markdown(&edge.nth_party_customer_domain),
                escape_markdown(&edge.joined_records()),
                escape_markdown(&edge.joined_source_labels())
            ));
        }
        content.push('\n');
    }

    // Other relationships
    if !other_edges.is_empty() {
        content.push_str("### Other Relationships\n\n");
        content.push_str("| Vendor | Organization | Layer | Type | Customer | Record |\n");
        content.push_str("|--------|--------------|-------|------|----------|--------|\n");

        for edge in &other_edges {
            content.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                escape_markdown(&edge.nth_party_domain),
                escape_markdown(&edge.nth_party_organization),
                edge.nth_party_layer,
                escape_markdown(&edge.joined_record_types()),
                escape_markdown(&edge.nth_party_customer_domain),
                escape_markdown(&edge.joined_records())
            ));
        }
        content.push('\n');
    }

    // Risk assessment section
    content.push_str("## Risk Assessment\n\n");
    content.push_str("### High-Risk Considerations\n\n");
    content.push_str("- **Email providers (SPF)** can send emails as your organization\n");
    content.push_str("- **Verification services** have confirmed domain ownership and likely access to sensitive data\n");
    content.push_str("- **Webpage components** load external scripts, send data to third-party servers, or phone home to vendor APIs — potential data exfiltration vectors\n");
    content.push_str("- **Multi-layer relationships** may create complex dependency chains\n\n");

    content.push_str("### Recommendations\n\n");
    content.push_str(
        "1. **Review each verified service** to ensure they still provide business value\n",
    );
    content.push_str("2. **Audit email providers** to prevent unauthorized email sending\n");
    content.push_str("3. **Monitor for new relationships** by running this analysis regularly\n");
    content.push_str("4. **Document business justification** for each vendor relationship\n\n");

    // Footer
    content.push_str("---\n\n");
    content.push_str("*Report generated by [nthpartyfinder](https://github.com/grcengineering/nthpartyfinder) - A tool for discovering third-party vendor relationships through DNS analysis.*\n");

    // Write to file
    std::fs::write(output_path, content)?;
    info!(
        "Successfully exported {} relationships ({} merged edges) to Markdown: {}",
        relationships.len(),
        merged.len(),
        output_path
    );

    Ok(())
}

fn sanitize_mermaid_id(domain: &str) -> String {
    // L008 fix: ensure IDs are valid Mermaid identifiers (alphanumeric + underscore, no leading digit)
    let id: String = domain
        .replace(['.', '-'], "_")
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    // Prefix with 'n' if ID starts with a digit (Mermaid doesn't allow numeric-start IDs)
    if id.starts_with(|c: char| c.is_ascii_digit()) {
        format!("n{}", id)
    } else if id.is_empty() {
        "unknown".to_string()
    } else {
        id
    }
}

fn escape_markdown(text: &str) -> String {
    text.replace("|", "\\|")
        .replace("*", "\\*")
        .replace("_", "\\_")
}

// XYFlow Svelte vendor graph bundle - embedded at compile time
const VENDOR_GRAPH_JS: &str = include_str!("../static/vendor-graph.js");
const VENDOR_GRAPH_CSS: &str = include_str!("../static/vendor-graph.css");

// GRC Engineering Design System — self-contained tokens + base64-embedded fonts.
// Generated by scripts/build-design-system-css.ts from grcengineering/grce-design-system.
const DESIGN_SYSTEM_CSS: &str = include_str!("../static/design-system.css");

#[cfg_attr(coverage_nightly, coverage(off))]
mod html_report_template {
    use super::*;
    use askama::Template;

    #[derive(Template)]
    #[template(path = "report.html")]
    pub(super) struct HtmlReportTemplate {
        pub(super) summary: HtmlSummary,
        pub(super) relationships: Vec<VendorRelationship>,
        pub(super) relationships_json: String,
        pub(super) summary_json: String,
        pub(super) discovery_sources: Vec<DiscoverySourceOption>,
        pub(super) record_type_labels_json: String,
        pub(super) vendor_graph_js: &'static str,
        pub(super) vendor_graph_css: &'static str,
        pub(super) design_system_css: &'static str,
        /// Compact `ScanSummary::to_embed_json()` payload (`</` pre-escaped). Empty string =
        /// no diagnostics; the template renders its `<script id="scan-summary">` only when
        /// non-empty.
        pub(super) scan_summary_json: String,
    }
}
use html_report_template::HtmlReportTemplate;

#[derive(serde::Serialize)]
struct HtmlSummary {
    root_domain: String,
    root_organization: String,
    total_relationships: usize,
    max_depth: u32,
    unique_domains: usize,
    unique_organizations: usize,
    generated_at: String,
}

/// Deliberately NOT merged yet (TF-EDGEDEDUP). The HTML table and the embedded
/// `relationships_json` are coupled BY INDEX — `report.html` renders rows with
/// `openEvidenceModal({{ loop.index0 }})` and the modal reads
/// `window.graphData.relationships[i]`. Handing the table a merged list while the
/// JSON stays per-sighting silently shifts every evidence modal onto the wrong
/// record, and merging the JSON instead would change the array the Svelte graph
/// bundle consumes and give each row a single `data-type` when several sources
/// found it — re-opening the discovery-source filter drift that `present_discovery_sources`
/// exists to prevent. Collapsing this surface needs the template change described
/// alongside this work; it cannot be done from the exporter alone.
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn export_html(relationships: &[VendorRelationship], output_path: &str) -> Result<()> {
    export_html_with_diagnostics(relationships, output_path, None)
}

/// `export_html` plus an optional embedded scan-diagnostics payload
/// (`ScanSummary::to_embed_json()`), rendered into a `<script type="application/json"
/// id="scan-summary">` element so the report is self-describing about how its scan ran.
/// `None` renders byte-identically to the pre-diagnostics report (no script tag, no footer
/// line) — which is why `export_html` can delegate here without disturbing its callers.
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn export_html_with_diagnostics(
    relationships: &[VendorRelationship],
    output_path: &str,
    diagnostics_json: Option<&str>,
) -> Result<()> {
    let scan_summary_json = diagnostics_json.unwrap_or_default().to_string();
    debug!(
        "Exporting {} relationships to HTML: {}",
        relationships.len(),
        output_path
    );

    if relationships.is_empty() {
        let empty_template = HtmlReportTemplate {
            summary: HtmlSummary {
                root_domain: "Unknown".to_string(),
                root_organization: "Unknown".to_string(),
                total_relationships: 0,
                max_depth: 0,
                unique_domains: 0,
                unique_organizations: 0,
                generated_at: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            },
            relationships: Vec::new(),
            relationships_json: "[]".to_string(),
            summary_json: "{}".to_string(),
            discovery_sources: Vec::new(),
            record_type_labels_json: record_type_label_map_json(),
            vendor_graph_js: VENDOR_GRAPH_JS,
            vendor_graph_css: VENDOR_GRAPH_CSS,
            design_system_css: DESIGN_SYSTEM_CSS,
            scan_summary_json,
        };

        let html_content = empty_template.render()?;
        std::fs::write(output_path, html_content)?;
        info!(
            "Successfully exported empty report to HTML: {}",
            output_path
        );
        return Ok(());
    }

    let root_domain = &relationships[0].root_customer_domain;
    let root_organization = &relationships[0].root_customer_organization;

    let max_depth = relationships
        .iter()
        .map(|r| r.nth_party_layer)
        .max()
        .unwrap_or(0);
    let unique_domains: HashSet<_> = relationships
        .iter()
        .map(|r| r.nth_party_domain.clone())
        .collect();
    let unique_orgs: HashSet<_> = relationships
        .iter()
        .map(|r| r.nth_party_organization.clone())
        .collect();

    let summary = HtmlSummary {
        root_domain: root_domain.clone(),
        root_organization: root_organization.clone(),
        total_relationships: relationships.len(),
        max_depth,
        unique_domains: unique_domains.len(),
        unique_organizations: unique_orgs.len(),
        generated_at: Utc::now().format("%Y-%m-%d %H:%M:%S UTC").to_string(),
    };

    let relationships_json = serde_json::to_string(relationships)?;
    let summary_json = serde_json::to_string(&summary)?;

    let template = HtmlReportTemplate {
        summary,
        relationships: relationships.to_vec(),
        relationships_json,
        summary_json,
        discovery_sources: present_discovery_sources(relationships),
        record_type_labels_json: record_type_label_map_json(),
        vendor_graph_js: VENDOR_GRAPH_JS,
        vendor_graph_css: VENDOR_GRAPH_CSS,
        design_system_css: DESIGN_SYSTEM_CSS,
        scan_summary_json,
    };

    let html_content = template.render()?;
    std::fs::write(output_path, html_content)?;

    info!(
        "Successfully exported {} relationships to HTML: {}",
        relationships.len(),
        output_path
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::{RecordType, VendorRelationship};
    use rstest::rstest;
    use tempfile::TempDir;

    fn make_vendor(domain: &str, org: &str, layer: u32, rt: RecordType) -> VendorRelationship {
        VendorRelationship::new(
            domain.to_string(),
            org.to_string(),
            layer,
            "customer.com".to_string(),
            "Customer Inc".to_string(),
            format!("v=spf1 include:{}", domain),
            rt,
            "root.com".to_string(),
            "Root Inc".to_string(),
            "test evidence".to_string(),
        )
    }

    fn sample_relationships() -> Vec<VendorRelationship> {
        vec![
            make_vendor("google.com", "Google", 3, RecordType::DnsTxtSpf),
            make_vendor(
                "sendgrid.net",
                "SendGrid",
                3,
                RecordType::DnsTxtVerification,
            ),
            make_vendor("cloudflare.com", "Cloudflare", 4, RecordType::DnsSubdomain),
            make_vendor(
                "cdn.example.com",
                "ExampleCDN",
                3,
                RecordType::WebTrafficSource,
            ),
            make_vendor(
                "analytics.test.com",
                "Analytics",
                3,
                RecordType::WebTrafficNetwork,
            ),
        ]
    }

    #[rstest]
    #[case("example.com", "example_com")]
    #[case("sub.domain.co.uk", "sub_domain_co_uk")]
    #[case("test-site.org", "test_site_org")]
    #[case("123.456.com", "n123_456_com")]
    #[case("", "unknown")]
    fn test_sanitize_mermaid_id(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(sanitize_mermaid_id(input), expected);
    }

    #[rstest]
    #[case("hello", "hello")]
    #[case("pipe|char", "pipe\\|char")]
    #[case("*bold*", "\\*bold\\*")]
    #[case("under_score", "under\\_score")]
    #[case("a|b*c_d", "a\\|b\\*c\\_d")]
    fn test_escape_markdown(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(escape_markdown(input), expected);
    }

    #[test]
    fn test_export_csv_with_data() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.csv");
        let path_str = path.to_str().unwrap();
        let rels = sample_relationships();

        export_csv(&rels, path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("Root Customer Domain"));
        assert!(content.contains("google.com"));
        assert!(content.contains("SendGrid"));
        assert!(content.contains("DNS::TXT::SPF"));
    }

    #[test]
    fn test_export_csv_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.csv");
        let path_str = path.to_str().unwrap();

        export_csv(&[], path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("Root Customer Domain"));
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 1);
    }

    #[test]
    fn test_export_json_with_data() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.json");
        let path_str = path.to_str().unwrap();
        let rels = sample_relationships();

        export_json(&rels, path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["summary"]["total_relationships"], 5);
        assert!(parsed["summary"]["max_depth"].as_u64().unwrap() >= 3);
        assert!(parsed["relationships"].is_array());
        assert_eq!(parsed["relationships"].as_array().unwrap().len(), 5);
    }

    #[test]
    fn test_export_json_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.json");
        let path_str = path.to_str().unwrap();

        export_json(&[], path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["summary"]["total_relationships"], 0);
    }

    #[test]
    fn test_export_markdown_with_data() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.md");
        let path_str = path.to_str().unwrap();
        let rels = sample_relationships();

        export_markdown(&rels, path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("# Nth Party Analysis Report"));
        assert!(content.contains("Executive Summary"));
        assert!(content.contains("google.com"));
        assert!(content.contains("Email Service Providers"));
        assert!(content.contains("Integrated Services"));
        assert!(content.contains("Webpage Discovery"));
        assert!(content.contains("Risk Assessment"));
        assert!(content.contains("mermaid"));
    }

    #[test]
    fn test_export_markdown_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.md");
        let path_str = path.to_str().unwrap();

        export_markdown(&[], path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("No vendor relationships found"));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_export_html_with_data() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.html");
        let path_str = path.to_str().unwrap();
        let rels = sample_relationships();

        export_html(&rels, path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("<html") || content.contains("<!DOCTYPE"));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_export_html_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("empty.html");
        let path_str = path.to_str().unwrap();

        export_html(&[], path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("<html") || content.contains("<!DOCTYPE"));
    }

    #[test]
    fn test_print_analysis_summary_empty() {
        print_analysis_summary(&[]);
    }

    #[test]
    fn test_print_analysis_summary_with_data() {
        let rels = sample_relationships();
        print_analysis_summary(&rels);
    }

    #[test]
    fn test_export_markdown_other_record_types() {
        let rels = vec![
            make_vendor("api.example.com", "ApiCo", 3, RecordType::HttpSubprocessor),
            make_vendor(
                "trust.example.com",
                "TrustCo",
                3,
                RecordType::TrustCenterApi,
            ),
        ];
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("other.md");
        let path_str = path.to_str().unwrap();

        export_markdown(&rels, path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("Other Relationships"));
    }

    // ── Additional coverage tests ────────────────────────────────────

    #[test]
    fn test_export_markdown_multi_layer() {
        // Tests the layer breakdown loop with multiple layers
        let rels = vec![
            make_vendor("a.com", "A", 3, RecordType::DnsTxtSpf),
            make_vendor("b.com", "B", 4, RecordType::DnsTxtSpf),
            make_vendor("c.com", "C", 5, RecordType::DnsTxtVerification),
        ];
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("multi_layer.md");
        let path_str = path.to_str().unwrap();

        export_markdown(&rels, path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("Layer 3"));
        assert!(content.contains("Layer 4"));
        assert!(content.contains("Layer 5"));
    }

    #[test]
    fn test_print_analysis_summary_multi_layer() {
        let rels = vec![
            make_vendor("a.com", "A", 3, RecordType::DnsTxtSpf),
            make_vendor("b.com", "B", 4, RecordType::DnsTxtSpf),
            make_vendor("c.com", "C", 3, RecordType::DnsTxtVerification),
        ];
        // Just verify it doesn't panic and prints layer breakdown
        print_analysis_summary(&rels);
    }

    // P4.5: distinct vendors per min-layer band, not (parent,child,source) rows.
    #[test]
    fn test_count_vendors_by_min_layer_counts_distinct_vendors() {
        let rels = vec![
            // one vendor, three source rows at layer 2 -> counts ONCE in layer 2
            make_vendor("a.com", "A", 2, RecordType::DnsTxtSpf),
            make_vendor("a.com", "A", 2, RecordType::DnsTxtDmarc),
            make_vendor("a.com", "A", 2, RecordType::DnsTxtVerification),
            // one vendor at layers 3 and 2 -> counts ONCE, in its MIN band (2)
            make_vendor("b.com", "B", 3, RecordType::DnsTxtSpf),
            make_vendor("b.com", "B", 2, RecordType::DnsTxtSpf),
            // a genuine layer-3 vendor
            make_vendor("c.com", "C", 3, RecordType::DnsTxtSpf),
        ];
        let counts = count_vendors_by_min_layer(&rels);
        // layer 2: a.com + b.com = 2 distinct; layer 3: c.com = 1 distinct.
        assert_eq!(counts, vec![(2, 2), (3, 1)]);
        // Old (wrong) row-count would have been layer2=4, layer3=2.
    }

    #[test]
    fn test_count_vendors_by_min_layer_empty() {
        assert!(count_vendors_by_min_layer(&[]).is_empty());
    }

    #[test]
    fn test_export_markdown_mermaid_edge_styles() {
        // Exercise all mermaid edge_style branches
        let rels = vec![
            make_vendor("spf.com", "SPF", 3, RecordType::DnsTxtSpf),
            make_vendor("verify.com", "Verify", 3, RecordType::DnsTxtVerification),
            make_vendor("sub.com", "Sub", 3, RecordType::DnsSubdomain),
            make_vendor("src.com", "Src", 3, RecordType::WebTrafficSource),
            make_vendor("net.com", "Net", 3, RecordType::WebTrafficNetwork),
            make_vendor("other.com", "Other", 3, RecordType::HttpSubprocessor),
        ];
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("edges.md");
        let path_str = path.to_str().unwrap();

        export_markdown(&rels, path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("mermaid"));
        assert!(content.contains("graph TD"));
    }

    #[test]
    fn test_export_markdown_webpage_discovery_methods() {
        // Test both webpage source and network discovery method labels
        let rels = vec![
            make_vendor("src.com", "SrcCo", 3, RecordType::WebTrafficSource),
            make_vendor("net.com", "NetCo", 3, RecordType::WebTrafficNetwork),
        ];
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("web_discovery.md");
        let path_str = path.to_str().unwrap();

        export_markdown(&rels, path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("Webpage Source"));
        assert!(content.contains("Webpage Network Requests"));
    }

    #[test]
    fn test_export_csv_special_chars() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("special.csv");
        let path_str = path.to_str().unwrap();
        let rels = vec![make_vendor(
            "pipe|star*under_score.com",
            "Pipe|Star*Under_Score",
            3,
            RecordType::DnsTxtSpf,
        )];

        export_csv(&rels, path_str).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("pipe|star*under_score.com"));
    }

    #[test]
    fn test_export_json_summary_fields() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("summary.json");
        let path_str = path.to_str().unwrap();
        let rels = vec![
            make_vendor("a.com", "A", 3, RecordType::DnsTxtSpf),
            make_vendor("a.com", "A", 4, RecordType::DnsTxtVerification),
            make_vendor("b.com", "B", 3, RecordType::DnsTxtSpf),
        ];

        export_json(&rels, path_str).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["summary"]["total_relationships"], 3);
        assert_eq!(parsed["summary"]["max_depth"], 4);
        assert_eq!(parsed["summary"]["unique_domains"], 2);
        // unique_organizations: A and B
        assert_eq!(parsed["summary"]["unique_organizations"], 2);
    }

    // --- Additional tests for uncovered branches ---

    #[test]
    fn test_export_markdown_duplicate_vendor_domains() {
        // Tests the mermaid node deduplication: same domain in multiple relationships
        // should only create one node but multiple edges
        let rels = vec![
            make_vendor("google.com", "Google", 3, RecordType::DnsTxtSpf),
            make_vendor("google.com", "Google", 4, RecordType::DnsTxtVerification),
        ];
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("dedup.md");
        let path_str = path.to_str().unwrap();

        export_markdown(&rels, path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("mermaid"));
        assert!(content.contains("google_com"));
    }

    #[test]
    fn test_export_markdown_only_verification_relationships() {
        let rels = vec![
            make_vendor("verify1.com", "Verify1", 3, RecordType::DnsTxtVerification),
            make_vendor("verify2.com", "Verify2", 3, RecordType::DnsTxtVerification),
        ];
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("verify_only.md");
        let path_str = path.to_str().unwrap();

        export_markdown(&rels, path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("Integrated Services"));
        // Should NOT contain SPF or Webpage sections
        assert!(!content.contains("Email Service Providers"));
        assert!(!content.contains("Webpage Discovery"));
    }

    #[test]
    fn test_export_markdown_only_other_relationships() {
        let rels = vec![make_vendor("api.com", "ApiCo", 3, RecordType::DnsMx)];
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("other_only.md");
        let path_str = path.to_str().unwrap();

        export_markdown(&rels, path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("Other Relationships"));
        assert!(!content.contains("Email Service Providers"));
    }

    #[test]
    fn test_export_csv_all_record_types() {
        let rels = vec![
            make_vendor("a.com", "A", 3, RecordType::DnsTxtSpf),
            make_vendor("b.com", "B", 3, RecordType::DnsTxtVerification),
            make_vendor("c.com", "C", 3, RecordType::DnsSubdomain),
            make_vendor("d.com", "D", 3, RecordType::WebTrafficSource),
            make_vendor("e.com", "E", 3, RecordType::WebTrafficNetwork),
            make_vendor("f.com", "F", 3, RecordType::HttpSubprocessor),
            make_vendor("g.com", "G", 3, RecordType::TrustCenterApi),
        ];
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("all_types.csv");
        let path_str = path.to_str().unwrap();

        export_csv(&rels, path_str).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("DNS::TXT::SPF"));
        assert!(content.contains("DNS::TXT::VERIFICATION"));
        assert!(content.contains("DNS::SUBDOMAIN"));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_export_html_with_multiple_layers() {
        let rels = vec![
            make_vendor("a.com", "A", 3, RecordType::DnsTxtSpf),
            make_vendor("b.com", "B", 4, RecordType::DnsTxtVerification),
            make_vendor("c.com", "C", 5, RecordType::WebTrafficSource),
        ];
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("multi.html");
        let path_str = path.to_str().unwrap();

        export_html(&rels, path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("<html") || content.contains("<!DOCTYPE"));
        // Verify JSON data is embedded
        assert!(content.contains("a.com"));
    }

    #[test]
    fn test_print_analysis_summary_single_layer() {
        let rels = vec![
            make_vendor("a.com", "A", 3, RecordType::DnsTxtSpf),
            make_vendor("b.com", "B", 3, RecordType::DnsTxtSpf),
        ];
        print_analysis_summary(&rels);
        // Just verify no panic
    }

    #[test]
    fn test_sanitize_mermaid_id_special_chars() {
        // Test with chars that are neither alphanumeric, '.', nor '-'
        assert_eq!(sanitize_mermaid_id("test@domain#com"), "testdomaincom");
    }

    #[test]
    fn test_escape_markdown_no_special() {
        assert_eq!(escape_markdown("plain text"), "plain text");
    }

    #[test]
    fn test_html_report_template_render_into_string() {
        // Exercise the askama-generated render_into::<String> monomorphization
        use askama::Template;
        let template = HtmlReportTemplate {
            summary: HtmlSummary {
                root_domain: "test.com".to_string(),
                root_organization: "Test Org".to_string(),
                total_relationships: 0,
                max_depth: 0,
                unique_domains: 0,
                unique_organizations: 0,
                generated_at: "2024-01-01".to_string(),
            },
            relationships: Vec::new(),
            relationships_json: "[]".to_string(),
            summary_json: "{}".to_string(),
            discovery_sources: Vec::new(),
            record_type_labels_json: record_type_label_map_json(),
            vendor_graph_js: "",
            vendor_graph_css: "",
            design_system_css: "",
            scan_summary_json: String::new(),
        };
        let mut buf = String::new();
        template
            .render_into(&mut buf)
            .expect("render_into should succeed");
        assert!(
            buf.contains("test.com"),
            "Rendered HTML should contain root domain"
        );
        assert!(
            buf.contains("Test Org"),
            "Rendered HTML should contain organization name"
        );
    }

    #[test]
    fn test_present_discovery_sources_matches_records_present() {
        // The filter must list exactly the sources present — no more, no less.
        let rels = vec![
            make_vendor("a.com", "A", 3, RecordType::HttpSubprocessor),
            make_vendor("b.com", "B", 3, RecordType::TrustCenterApi),
            make_vendor("c.com", "C", 3, RecordType::DnsTxtSpf),
            // Duplicate source must collapse to a single option.
            make_vendor("d.com", "D", 3, RecordType::TrustCenterApi),
        ];
        let opts = present_discovery_sources(&rels);
        let values: Vec<&str> = opts.iter().map(|o| o.value.as_str()).collect();

        // Exactly the three distinct sources present, in canonical order
        // (HttpSubprocessor before TrustCenterApi per all_variants(); SPF first).
        assert_eq!(
            values,
            vec!["DNS::TXT::SPF", "HTTP::SUBPROCESSOR", "TRUST_CENTER::API"]
        );
        // The trust-center option (previously absent → subprocessors unfilterable)
        // carries its friendly label.
        let trust = opts
            .iter()
            .find(|o| o.value == "TRUST_CENTER::API")
            .expect("trust center option present");
        assert_eq!(trust.label, "Trust Center");
        // A source NOT present must not appear as an option.
        assert!(!values.contains(&"DISCOVERY::SAAS_TENANT"));
    }

    #[test]
    fn test_html_report_filter_options_cover_every_present_source() {
        // End-to-end: every record type's hierarchy string that appears in the
        // rendered table (data-type=...) must have a matching <option value=...> in
        // the Discovery Source filter, and a label in the injected label map.
        use askama::Template;
        let rels = vec![
            make_vendor("a.com", "A", 3, RecordType::HttpSubprocessor),
            make_vendor("b.com", "B", 3, RecordType::TrustCenterApi),
            make_vendor("c.com", "C", 3, RecordType::DnsTxtSpf),
        ];
        let template = HtmlReportTemplate {
            summary: HtmlSummary {
                root_domain: "root.com".to_string(),
                root_organization: "Root".to_string(),
                total_relationships: rels.len(),
                max_depth: 4,
                unique_domains: rels.len(),
                unique_organizations: rels.len(),
                generated_at: "2024-01-01".to_string(),
            },
            relationships: rels.clone(),
            relationships_json: serde_json::to_string(&rels).unwrap(),
            summary_json: "{}".to_string(),
            discovery_sources: present_discovery_sources(&rels),
            record_type_labels_json: record_type_label_map_json(),
            vendor_graph_js: "",
            vendor_graph_css: "",
            design_system_css: "",
            scan_summary_json: String::new(),
        };
        let html = template.render().expect("render");

        for rel in &rels {
            let hierarchy = rel.nth_party_record_type.as_hierarchy_string();
            // A filter option whose value matches the row's data-type.
            assert!(
                html.contains(&format!("<option value=\"{hierarchy}\">")),
                "filter is missing an option for present source {hierarchy}"
            );
            // The row itself carries that data-type, so the filter matches 1:1.
            assert!(
                html.contains(&format!("data-type=\"{hierarchy}\"")),
                "no table row carries data-type {hierarchy}"
            );
            // The injected label map covers it (no raw code leaks into the badge).
            assert!(
                html.contains(&format!("\"{hierarchy}\":")),
                "label map is missing {hierarchy}"
            );
        }
        // The previously-missing trust-center label is present and friendly.
        assert!(html.contains(">Trust Center</option>"));
    }

    #[test]
    fn test_json_export_uses_hierarchy_string_for_record_type() {
        // The JSON export's discovery-source value must match the CSV/Markdown/HTML
        // reports (hierarchy string), not the internal serde variant name — so all
        // report types are 1:1. Trust-center subprocessors are the regression case.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("rels.json");
        let path_str = path.to_str().unwrap();
        let rels = vec![
            make_vendor("a.com", "A", 3, RecordType::TrustCenterApi),
            make_vendor("b.com", "B", 3, RecordType::HttpSubprocessor),
        ];
        export_json(&rels, path_str).unwrap();
        let body = std::fs::read_to_string(path_str).unwrap();

        // Hierarchy strings present...
        assert!(body.contains("\"nth_party_record_type\": \"TRUST_CENTER::API\""));
        assert!(body.contains("\"nth_party_record_type\": \"HTTP::SUBPROCESSOR\""));
        // ...and the internal variant names must NOT leak into the export.
        assert!(!body.contains("\"TrustCenterApi\""));
        assert!(!body.contains("\"HttpSubprocessor\""));

        // The export still parses as well-formed JSON with the expected shape.
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["relationships"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["relationships"][0]["nth_party_domain"], "a.com");
    }

    // ====================================================================
    // Tests for functions that previously had coverage(off)
    // ====================================================================

    #[test]
    fn test_export_csv_writes_correct_headers_and_row_count() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("headers.csv");
        let path_str = path.to_str().unwrap();
        let rels = sample_relationships();
        let count = rels.len();

        export_csv(&rels, path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        // Header + data rows
        assert_eq!(lines.len(), count + 1);
        assert!(lines[0].contains("Root Customer Domain"));
        assert!(lines[0].contains("Nth Party Record Type"));
    }

    #[test]
    fn test_export_json_summary_accuracy() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("accurate.json");
        let path_str = path.to_str().unwrap();
        let rels = sample_relationships();

        export_json(&rels, path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();

        assert_eq!(
            parsed["summary"]["total_relationships"].as_u64().unwrap(),
            rels.len() as u64
        );
        let max_depth = rels.iter().map(|r| r.nth_party_layer).max().unwrap();
        assert_eq!(
            parsed["summary"]["max_depth"].as_u64().unwrap(),
            max_depth as u64
        );
        let unique_domains: std::collections::HashSet<_> =
            rels.iter().map(|r| &r.nth_party_domain).collect();
        assert_eq!(
            parsed["summary"]["unique_domains"].as_u64().unwrap(),
            unique_domains.len() as u64
        );
    }

    #[test]
    fn test_print_analysis_summary_computes_correct_stats() {
        let rels = vec![
            make_vendor("a.com", "A Corp", 3, RecordType::DnsTxtSpf),
            make_vendor("b.com", "B Corp", 4, RecordType::DnsTxtSpf),
            make_vendor("a.com", "A Corp", 5, RecordType::DnsTxtVerification),
        ];

        let max_depth = rels.iter().map(|r| r.nth_party_layer).max().unwrap_or(0);
        assert_eq!(max_depth, 5);

        let unique_domains: std::collections::HashSet<_> =
            rels.iter().map(|r| r.nth_party_domain.clone()).collect();
        assert_eq!(unique_domains.len(), 2);

        let unique_orgs: std::collections::HashSet<_> = rels
            .iter()
            .map(|r| r.nth_party_organization.clone())
            .collect();
        assert_eq!(unique_orgs.len(), 2);

        let layer_3_count = rels.iter().filter(|r| r.nth_party_layer == 3).count();
        assert_eq!(layer_3_count, 1);

        let layer_4_count = rels.iter().filter(|r| r.nth_party_layer == 4).count();
        assert_eq!(layer_4_count, 1);

        let layer_5_count = rels.iter().filter(|r| r.nth_party_layer == 5).count();
        assert_eq!(layer_5_count, 1);

        // Calling print_analysis_summary should exercise the same logic without panic
        print_analysis_summary(&rels);
    }

    #[test]
    fn test_export_markdown_contains_root_domain_and_org() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("root_check.md");
        let path_str = path.to_str().unwrap();
        let rels = sample_relationships();

        export_markdown(&rels, path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains(&rels[0].root_customer_domain));
        assert!(content.contains(&rels[0].root_customer_organization));
        assert!(content.contains("Generated on:"));
    }

    /// The report is handed to auditors and opened offline; it must not reach out to the network.
    /// A dead `initializeGraph()` used to sit in the template carrying three hardcoded CDN URLs
    /// for vis.js plus a message claiming the graph "requires an internet connection" — none of
    /// which was true, since the graph is rendered by the embedded Svelte bundle. It was never
    /// called, so nothing failed and nothing caught it.
    #[test]
    fn test_export_html_has_no_external_subresources() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("selfcontained.html");
        let path_str = path.to_str().unwrap();

        export_html(&sample_relationships(), path_str).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();

        for host in [
            "cdn.jsdelivr.net",
            "cdnjs.cloudflare.com",
            "unpkg.com",
            "fonts.googleapis.com",
        ] {
            assert!(
                !content.contains(host),
                "report references external host {host}; it must be fully self-contained"
            );
        }
        // Match the code, not the word: the template carries a comment explaining why the dead
        // bootstrap was removed, and a bare substring check would fire on that explanation.
        assert!(
            !content.contains("function initializeGraph"),
            "dead vis.js bootstrap function is back in the template"
        );
        assert!(
            !content.contains("initializeGraph()"),
            "something calls the removed vis.js bootstrap"
        );
    }

    /// Guards the contract that produced the worst reported defect in this report: pagination
    /// gates on `data-filtered-out`, and `applyFilters` must SET it. When only the reader existed,
    /// pagination re-showed rows by index and silently undid the filter — searching then paging
    /// forward showed rows that did not match, while the search box still displayed the term.
    /// One reader with no writer is invisible to every other kind of test, so assert both halves.
    #[test]
    fn test_html_filter_and_pagination_share_the_same_contract() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("filter_contract.html");
        let path_str = path.to_str().unwrap();

        export_html(&sample_relationships(), path_str).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();

        assert!(
            content.contains("setAttribute('data-filtered-out'"),
            "applyFilters must record its verdict where applyPagination reads it"
        );
        assert!(
            content.contains("getAttribute('data-filtered-out')"),
            "applyPagination must honor the filter verdict"
        );
        assert!(
            content.contains("state.totalRows = visible.length"),
            "pagination must count the filtered set, not every row in the table"
        );
    }

    #[test]
    fn test_export_html_embeds_json_data() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("data_check.html");
        let path_str = path.to_str().unwrap();
        let rels = sample_relationships();

        export_html(&rels, path_str).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        // HTML report should embed the relationships as JSON
        assert!(content.contains(&rels[0].root_customer_domain));
        let unique_domains: HashSet<_> = rels.iter().map(|r| r.nth_party_domain.clone()).collect();
        let unique_orgs: HashSet<_> = rels
            .iter()
            .map(|r| r.nth_party_organization.clone())
            .collect();
        // Summary stats should be embedded
        assert!(content.contains(&format!("{}", rels.len())));
        assert!(content.contains(&format!("{}", unique_domains.len())));
        assert!(content.contains(&format!("{}", unique_orgs.len())));
    }

    #[test]
    fn test_html_template_trait_constants() {
        use askama::Template;
        // askama 0.13+ removed the generated `EXTENSION` / `MIME_TYPE` associated
        // constants from the `Template` impl; `SIZE_HINT` remains. We preserve this
        // test's intent ("this template emits an HTML document") by rendering it and
        // asserting the output is a `<!DOCTYPE html>` document rather than reading
        // metadata constants the library no longer provides.
        let _ = HtmlReportTemplate::SIZE_HINT;
        let template = HtmlReportTemplate {
            summary: HtmlSummary {
                root_domain: "test.com".to_string(),
                root_organization: "Test Org".to_string(),
                total_relationships: 0,
                max_depth: 0,
                unique_domains: 0,
                unique_organizations: 0,
                generated_at: "2024-01-01".to_string(),
            },
            relationships: Vec::new(),
            relationships_json: "[]".to_string(),
            summary_json: "{}".to_string(),
            discovery_sources: Vec::new(),
            record_type_labels_json: record_type_label_map_json(),
            vendor_graph_js: VENDOR_GRAPH_JS,
            vendor_graph_css: VENDOR_GRAPH_CSS,
            design_system_css: DESIGN_SYSTEM_CSS,
            scan_summary_json: String::new(),
        };
        let html = template
            .render()
            .expect("HTML report template should render");
        assert!(
            html.contains("<!DOCTYPE html>"),
            "rendered report should be an HTML document"
        );
        assert!(html.contains("text/html") || html.contains("<html"));
    }

    #[test]
    fn test_html_template_render_into_directly() {
        use askama::Template;
        let template = HtmlReportTemplate {
            summary: HtmlSummary {
                root_domain: "test.com".to_string(),
                root_organization: "Test Org".to_string(),
                total_relationships: 0,
                max_depth: 0,
                unique_domains: 0,
                unique_organizations: 0,
                generated_at: "2024-01-01".to_string(),
            },
            relationships: Vec::new(),
            relationships_json: "[]".to_string(),
            summary_json: "{}".to_string(),
            discovery_sources: Vec::new(),
            record_type_labels_json: record_type_label_map_json(),
            vendor_graph_js: VENDOR_GRAPH_JS,
            vendor_graph_css: VENDOR_GRAPH_CSS,
            design_system_css: DESIGN_SYSTEM_CSS,
            scan_summary_json: String::new(),
        };
        let mut buf = String::new();
        template.render_into(&mut buf).unwrap();
        assert!(buf.contains("<html"));
    }

    #[test]
    fn test_export_all_formats_with_tracing_enabled() {
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(std::io::sink)
                .finish(),
        );
        let dir = TempDir::new().unwrap();
        let rels = sample_relationships();

        let csv_path = dir.path().join("traced.csv");
        export_csv(&rels, csv_path.to_str().unwrap()).unwrap();

        let json_path = dir.path().join("traced.json");
        export_json(&rels, json_path.to_str().unwrap()).unwrap();

        let md_path = dir.path().join("traced.md");
        export_markdown(&rels, md_path.to_str().unwrap()).unwrap();

        let html_path = dir.path().join("traced.html");
        export_html(&rels, html_path.to_str().unwrap()).unwrap();

        assert!(csv_path.exists());
        assert!(json_path.exists());
        assert!(md_path.exists());
        assert!(html_path.exists());
    }

    // ── TF-EDGEDEDUP: merging duplicate edge evidence at export ──────────

    /// Full control over both endpoints and the per-sighting payload, which
    /// `make_vendor` (fixed customer, derived record) cannot express.
    fn sighting(
        customer: &str,
        vendor: &str,
        layer: u32,
        rt: RecordType,
        record: &str,
        evidence: &str,
    ) -> VendorRelationship {
        VendorRelationship::new(
            vendor.to_string(),
            format!("{} Inc", vendor),
            layer,
            customer.to_string(),
            format!("{} Inc", customer),
            record.to_string(),
            rt,
            "root.com".to_string(),
            "Root Inc".to_string(),
            evidence.to_string(),
        )
    }

    /// The headline case: DNS, web traffic and a CT log each found the same
    /// parent→child pair, and the report used to say it three times.
    #[test]
    fn merge_edge_evidence_collapses_one_edge_found_by_three_sources() {
        let rels = vec![
            sighting(
                "acme.com",
                "vendor.com",
                2,
                RecordType::DnsTxtSpf,
                "v=spf1 include:vendor.com",
                "spf lookup",
            ),
            sighting(
                "acme.com",
                "vendor.com",
                2,
                RecordType::WebTrafficNetwork,
                "https://vendor.com/tag.js",
                "network request",
            ),
            sighting(
                "acme.com",
                "vendor.com",
                2,
                RecordType::CtLogDiscovery,
                "cert CN=vendor.com",
                "crt.sh entry",
            ),
        ];

        let merged = merge_edge_evidence(&rels);

        assert_eq!(merged.len(), 1, "one relationship must render as one edge");
        assert_eq!(merged[0].evidence.len(), 3, "all three sources survive");
        assert_eq!(merged[0].nth_party_domain, "vendor.com");
        assert_eq!(merged[0].nth_party_customer_domain, "acme.com");
    }

    /// Merging is only acceptable if it is lossless: every (source, record,
    /// evidence) triple that went in must come back out, unchanged.
    #[test]
    fn merge_edge_evidence_preserves_every_source_record_and_evidence() {
        let rels = vec![
            sighting(
                "acme.com",
                "vendor.com",
                2,
                RecordType::DnsTxtSpf,
                "spf-record",
                "spf evidence",
            ),
            sighting(
                "acme.com",
                "vendor.com",
                2,
                RecordType::TrustCenterApi,
                "trust-record",
                "trust evidence",
            ),
            sighting(
                "acme.com",
                "other.com",
                3,
                RecordType::DnsMx,
                "mx-record",
                "mx evidence",
            ),
        ];

        let merged = merge_edge_evidence(&rels);

        let mut got: Vec<(String, String, String)> = merged
            .iter()
            .flat_map(|e| {
                e.evidence.iter().map(|ev| {
                    (
                        ev.record_type.as_hierarchy_string(),
                        ev.record.clone(),
                        ev.evidence.clone(),
                    )
                })
            })
            .collect();
        let mut want: Vec<(String, String, String)> = rels
            .iter()
            .map(|r| {
                (
                    r.nth_party_record_type.as_hierarchy_string(),
                    r.nth_party_record.clone(),
                    r.evidence.clone(),
                )
            })
            .collect();
        got.sort();
        want.sort();
        assert_eq!(got, want, "no discovery may be dropped by the merge");
    }

    #[test]
    fn merge_edge_evidence_keeps_distinct_edges_apart() {
        let rels = vec![
            // Same vendor, different parents — two genuinely different edges.
            sighting("a.com", "vendor.com", 2, RecordType::DnsTxtSpf, "r1", "e1"),
            sighting("b.com", "vendor.com", 2, RecordType::DnsTxtSpf, "r2", "e2"),
            // Same parent, different vendors — also two edges.
            sighting("a.com", "other.com", 2, RecordType::DnsTxtSpf, "r3", "e3"),
        ];

        let merged = merge_edge_evidence(&rels);

        assert_eq!(merged.len(), 3);
        assert!(
            merged.iter().all(|e| e.evidence.len() == 1),
            "distinct edges must not pool each other's evidence"
        );
    }

    /// Same rule `deduplicate_results` already established: an edge's honest layer
    /// is the shallowest path that reaches it, not whichever row arrived first.
    #[test]
    fn merge_edge_evidence_keeps_minimum_layer() {
        let deep_first = vec![
            sighting("a.com", "v.com", 5, RecordType::DnsTxtSpf, "r1", "e1"),
            sighting("a.com", "v.com", 2, RecordType::CtLogDiscovery, "r2", "e2"),
        ];
        let shallow_first = vec![
            sighting("a.com", "v.com", 2, RecordType::CtLogDiscovery, "r2", "e2"),
            sighting("a.com", "v.com", 5, RecordType::DnsTxtSpf, "r1", "e1"),
        ];

        assert_eq!(merge_edge_evidence(&deep_first)[0].nth_party_layer, 2);
        assert_eq!(merge_edge_evidence(&shallow_first)[0].nth_party_layer, 2);
    }

    /// Discovery finishes in nondeterministic order, so the same scan must not
    /// produce two different-looking reports.
    #[test]
    fn merge_edge_evidence_is_independent_of_input_order() {
        let a = sighting(
            "a.com",
            "v.com",
            2,
            RecordType::WebTrafficNetwork,
            "r-net",
            "e-net",
        );
        let b = sighting("a.com", "v.com", 2, RecordType::DnsTxtSpf, "r-spf", "e-spf");
        let c = sighting(
            "a.com",
            "v.com",
            2,
            RecordType::CtLogDiscovery,
            "r-ct",
            "e-ct",
        );

        let one = merge_edge_evidence(&[a.clone(), b.clone(), c.clone()]);
        let two = merge_edge_evidence(&[c, a, b]);

        assert_eq!(one[0].evidence, two[0].evidence);
        // Canonical `all_variants` order: SPF (DNS) before CT log before web traffic.
        let order: Vec<String> = one[0]
            .evidence
            .iter()
            .map(|e| e.record_type.as_hierarchy_string())
            .collect();
        assert_eq!(
            order,
            vec![
                "DNS::TXT::SPF",
                "DISCOVERY::CT_LOG",
                "DISCOVERY::WEBPAGE_NETWORK",
            ]
        );
    }

    /// The one source a surface shows when it has room for one must be stable and
    /// canonical, not "whichever thread finished first".
    #[test]
    fn merge_edge_evidence_primary_source_is_canonically_first() {
        let rels = vec![
            sighting(
                "a.com",
                "v.com",
                2,
                RecordType::WebTrafficSource,
                "r-src",
                "e-src",
            ),
            sighting("a.com", "v.com", 2, RecordType::DnsTxtSpf, "r-spf", "e-spf"),
        ];
        let merged = merge_edge_evidence(&rels);
        assert_eq!(
            merged[0].primary_record_type().as_hierarchy_string(),
            "DNS::TXT::SPF"
        );
    }

    /// A domain echoed back with the casing a page used is the same edge; splitting
    /// on case would re-create the duplicate rows this function removes.
    #[test]
    fn merge_edge_evidence_folds_case_variant_domains() {
        let rels = vec![
            sighting(
                "Acme.com",
                "Vendor.COM",
                2,
                RecordType::DnsTxtSpf,
                "r1",
                "e1",
            ),
            sighting(
                "acme.com",
                "vendor.com",
                2,
                RecordType::CtLogDiscovery,
                "r2",
                "e2",
            ),
        ];
        let merged = merge_edge_evidence(&rels);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].evidence.len(), 2);
        // The first spelling seen is what the report shows; only the key is folded.
        assert_eq!(merged[0].nth_party_domain, "Vendor.COM");
    }

    /// An exact repeat is a sighting already recorded, not a second source — it
    /// must not inflate the evidence list a reader is asked to trust.
    #[test]
    fn merge_edge_evidence_ignores_exact_duplicate_sightings() {
        let one = sighting("a.com", "v.com", 2, RecordType::DnsTxtSpf, "r1", "e1");
        let merged = merge_edge_evidence(&[one.clone(), one]);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].evidence.len(), 1);
    }

    #[test]
    fn merge_edge_evidence_empty_input() {
        assert!(merge_edge_evidence(&[]).is_empty());
    }

    #[test]
    fn merged_edge_joined_fields_align_positionally() {
        let rels = vec![
            sighting("a.com", "v.com", 2, RecordType::DnsTxtSpf, "r-spf", "e-spf"),
            sighting(
                "a.com",
                "v.com",
                2,
                RecordType::CtLogDiscovery,
                "r-ct",
                "e-ct",
            ),
        ];
        let edge = &merge_edge_evidence(&rels)[0];

        // The i-th type, record and evidence describe the same discovery — that
        // alignment is what makes a one-row rendering lossless.
        assert_eq!(
            edge.joined_record_types(),
            "DNS::TXT::SPF | DISCOVERY::CT_LOG"
        );
        assert_eq!(edge.joined_records(), "r-spf | r-ct");
        assert_eq!(edge.joined_evidence(), "e-spf | e-ct");
        assert_eq!(
            edge.joined_source_labels(),
            "Email Provider (SPF) | Certificate Transparency Log"
        );
    }

    /// The reader-facing payoff: one CSV row per relationship, still carrying every
    /// source that found it.
    #[test]
    fn test_export_csv_writes_one_row_per_edge_with_all_sources() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("merged.csv");
        let rels = vec![
            sighting(
                "acme.com",
                "dup.com",
                2,
                RecordType::DnsTxtSpf,
                "r-spf",
                "e-spf",
            ),
            sighting(
                "acme.com",
                "dup.com",
                3,
                RecordType::WebTrafficNetwork,
                "r-net",
                "e-net",
            ),
            sighting(
                "acme.com",
                "dup.com",
                2,
                RecordType::CtLogDiscovery,
                "r-ct",
                "e-ct",
            ),
            sighting("acme.com", "solo.com", 2, RecordType::DnsMx, "r-mx", "e-mx"),
        ];

        export_csv(&rels, path.to_str().unwrap()).unwrap();

        let mut rdr = csv::Reader::from_path(&path).unwrap();
        let rows: Vec<csv::StringRecord> = rdr.records().map(|r| r.unwrap()).collect();
        assert_eq!(rows.len(), 2, "three sightings of one edge must be one row");

        let dup = rows
            .iter()
            .find(|r| &r[2] == "dup.com")
            .expect("merged edge present");
        assert_eq!(&dup[4], "2", "merged row keeps the minimum layer");
        assert_eq!(
            &dup[8],
            "DNS::TXT::SPF | DISCOVERY::CT_LOG | DISCOVERY::WEBPAGE_NETWORK"
        );
        assert_eq!(&dup[7], "r-spf | r-ct | r-net");
        assert_eq!(&dup[9], "e-spf | e-ct | e-net");
        assert_eq!(
            &dup[10], "3",
            "the row says how many discoveries it stands for"
        );

        let solo = rows
            .iter()
            .find(|r| &r[2] == "solo.com")
            .expect("unmerged edge present");
        assert_eq!(&solo[10], "1");
    }

    /// The Markdown tables are the other surface a person reads; the same edge must
    /// appear on exactly one line there, with its other sources named.
    #[test]
    fn test_export_markdown_renders_a_merged_edge_once() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("merged.md");
        let rels = vec![
            sighting(
                "acme.com",
                "dup.com",
                2,
                RecordType::DnsTxtSpf,
                "r-spf",
                "e-spf",
            ),
            sighting(
                "acme.com",
                "dup.com",
                2,
                RecordType::CtLogDiscovery,
                "r-ct",
                "e-ct",
            ),
        ];

        export_markdown(&rels, path.to_str().unwrap()).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();

        assert_eq!(
            content.matches("| dup.com |").count(),
            1,
            "a merged edge must occupy exactly one table row"
        );
        // Filed under its primary (SPF) source, with the CT sighting still named.
        assert!(content.contains("Email Service Providers"));
        assert!(content.contains("Certificate Transparency Log"));
        // Both raw records survive in the one row (the pipe is markdown-escaped).
        assert!(content.contains("r-spf \\| r-ct"));
        assert!(content.contains("**Distinct vendor edges (evidence merged):** 1"));
        assert!(content.contains("**Total vendor relationships found:** 2"));
    }

    /// The JSON export is the machine-readable artifact; the merge must NOT reach
    /// it, or diffing two scans stops being possible at sighting granularity.
    #[test]
    fn test_export_json_is_not_merged() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("unmerged.json");
        let rels = vec![
            sighting(
                "acme.com",
                "dup.com",
                2,
                RecordType::DnsTxtSpf,
                "r-spf",
                "e-spf",
            ),
            sighting(
                "acme.com",
                "dup.com",
                2,
                RecordType::CtLogDiscovery,
                "r-ct",
                "e-ct",
            ),
        ];

        export_json(&rels, path.to_str().unwrap()).unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();

        assert_eq!(parsed["relationships"].as_array().unwrap().len(), 2);
        assert_eq!(parsed["summary"]["total_relationships"], 2);
    }

    /// The embedded JSON the Svelte graph bundle reads (`window.graphData.relationships`)
    /// is index-coupled to the table rows via `openEvidenceModal(loop.index0)`. Merging
    /// one side and not the other points every evidence modal at the wrong record, so
    /// this asserts the HTML surface still emits one entry per sighting until the
    /// template is changed to consume a merged array.
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_export_html_json_still_matches_table_row_count() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("coupled.html");
        let rels = vec![
            sighting(
                "acme.com",
                "dup.com",
                2,
                RecordType::DnsTxtSpf,
                "r-spf",
                "e-spf",
            ),
            sighting(
                "acme.com",
                "dup.com",
                2,
                RecordType::CtLogDiscovery,
                "r-ct",
                "e-ct",
            ),
        ];

        export_html(&rels, path.to_str().unwrap()).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();

        // One table row per sighting, indices 0..n-1, matching the embedded array.
        assert!(content.contains("openEvidenceModal(0)"));
        assert!(content.contains("openEvidenceModal(1)"));
        assert!(!content.contains("openEvidenceModal(2)"));
        assert!(content.contains("\"r-spf\""));
        assert!(content.contains("\"r-ct\""));
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_export_html_with_diagnostics_embeds_payload_and_none_omits_it() {
        let dir = TempDir::new().unwrap();
        let rels = vec![make_vendor("a.com", "A Org", 1, RecordType::DnsTxtSpf)];
        let payload = r#"{"schema_version":1,"probe":"embedded-diagnostics-probe"}"#;

        // Some(json): the payload lands in the typed JSON script element + a footer note.
        let with_path = dir.path().join("with.html");
        export_html_with_diagnostics(&rels, with_path.to_str().unwrap(), Some(payload)).unwrap();
        let html = std::fs::read_to_string(&with_path).unwrap();
        assert!(
            html.contains(r#"<script type="application/json" id="scan-summary">"#),
            "diagnostics script element missing"
        );
        assert!(
            html.contains("embedded-diagnostics-probe"),
            "payload not embedded"
        );
        assert!(
            html.contains("scan-summary.json alongside this report"),
            "footer note missing"
        );

        // export_html (delegates with None): no script element, no footer note — the
        // pre-diagnostics surface its 22 existing test call sites rely on.
        let without_path = dir.path().join("without.html");
        export_html(&rels, without_path.to_str().unwrap()).unwrap();
        let html = std::fs::read_to_string(&without_path).unwrap();
        assert!(!html.contains(r#"id="scan-summary""#));
        assert!(!html.contains("scan-summary.json alongside this report"));

        // The empty-relationships template branch honors the payload too — a failed scan's
        // empty report still explains itself.
        let empty_path = dir.path().join("empty.html");
        export_html_with_diagnostics(&[], empty_path.to_str().unwrap(), Some(payload)).unwrap();
        let html = std::fs::read_to_string(&empty_path).unwrap();
        assert!(html.contains(r#"id="scan-summary""#));
        assert!(html.contains("embedded-diagnostics-probe"));
    }
}
