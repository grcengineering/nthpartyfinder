use crate::vendor::VendorRelationship;
use anyhow::Result;
use askama::Template;
use chrono::Utc;
use csv::Writer;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Write;
use tracing::{debug, info};

#[cfg_attr(coverage_nightly, coverage(off))]
pub fn export_csv(relationships: &[VendorRelationship], output_path: &str) -> Result<()> {
    debug!(
        "Exporting {} relationships to CSV: {}",
        relationships.len(),
        output_path
    );

    let file = File::create(output_path)?;
    let mut wtr = Writer::from_writer(file);

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
    ])?;

    // Write data rows
    for relationship in relationships {
        wtr.write_record([
            &relationship.root_customer_domain,
            &relationship.root_customer_organization,
            &relationship.nth_party_domain,
            &relationship.nth_party_organization,
            &relationship.nth_party_layer.to_string(),
            &relationship.nth_party_customer_domain,
            &relationship.nth_party_customer_organization,
            &relationship.nth_party_record,
            &relationship.nth_party_record_type.as_hierarchy_string(),
            &relationship.evidence,
        ])?;
    }

    wtr.flush()?;
    info!(
        "Successfully exported {} relationships to CSV: {}",
        relationships.len(),
        output_path
    );

    Ok(())
}

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
        relationships: relationships.to_vec(),
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
struct JsonExport {
    summary: ExportSummary,
    relationships: Vec<VendorRelationship>,
}

#[derive(serde::Serialize)]
struct ExportSummary {
    total_relationships: usize,
    max_depth: u32,
    unique_domains: usize,
    unique_organizations: usize,
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
    println!("Maximum depth reached: {} layers", max_depth);
    println!("Unique vendor domains: {}", unique_domains.len());
    println!("Unique vendor organizations: {}", unique_orgs.len());

    // Show breakdown by layer
    for layer in 1..=max_depth {
        let layer_count = relationships
            .iter()
            .filter(|r| r.nth_party_layer == layer)
            .count();

        if layer_count > 0 {
            println!("  Layer {} vendors: {}", layer, layer_count);
        }
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
    for (record_type, count) in &type_counts {
        content.push_str(&format!("- **{}:** {} relationships\n", record_type, count));
    }
    content.push('\n');

    // Breakdown by layer
    content.push_str("### Breakdown by Layer\n\n");
    for layer in 1..=max_depth {
        let layer_count = relationships
            .iter()
            .filter(|r| r.nth_party_layer == layer)
            .count();
        if layer_count > 0 {
            content.push_str(&format!("- **Layer {} vendors:** {}\n", layer, layer_count));
        }
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

    // Process relationships by layer
    for layer in 1..=max_depth {
        let layer_relationships: Vec<_> = relationships
            .iter()
            .filter(|r| r.nth_party_layer == layer)
            .collect();

        for rel in layer_relationships {
            let vendor_node = sanitize_mermaid_id(&rel.nth_party_domain);
            let customer_node = sanitize_mermaid_id(&rel.nth_party_customer_domain);

            // Add vendor node if not already added
            if !nodes.contains(&vendor_node) {
                nodes.insert(vendor_node.clone());
                let node_label = format!(
                    "{}<br/>({})",
                    rel.nth_party_domain, rel.nth_party_organization
                );
                content.push_str(&format!("    {}[\"{}\"]\\n", vendor_node, node_label));
            }

            // Add edge with record type styling
            let edge_style = match rel.nth_party_record_type.as_hierarchy_string().as_str() {
                "DNS::TXT::SPF" => "-.->",
                "DNS::TXT::VERIFICATION" => "-->",
                "DNS::SUBDOMAIN" => "==>",
                "DISCOVERY::WEBPAGE_SOURCE" => "-..->",
                "DISCOVERY::WEBPAGE_NETWORK" => "-.->",
                _ => "-->",
            };

            let edge_label = format!(
                "{}|{}",
                rel.nth_party_record_type.as_hierarchy_string(),
                rel.nth_party_layer
            );
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

    // Group by record type
    let mut spf_relationships = Vec::new();
    let mut verification_relationships = Vec::new();
    let mut web_traffic_relationships = Vec::new();
    let mut other_relationships = Vec::new();

    for rel in relationships {
        match rel.nth_party_record_type.as_hierarchy_string().as_str() {
            "DNS::TXT::SPF" => spf_relationships.push(rel),
            "DNS::TXT::VERIFICATION" => verification_relationships.push(rel),
            "DISCOVERY::WEBPAGE_SOURCE" | "DISCOVERY::WEBPAGE_NETWORK" => {
                web_traffic_relationships.push(rel)
            }
            _ => other_relationships.push(rel),
        }
    }

    // SPF Relationships table
    if !spf_relationships.is_empty() {
        content.push_str("### Email Service Providers (SPF)\n\n");
        content.push_str("These vendors can send emails on behalf of your domain:\n\n");
        content.push_str("| Vendor | Organization | Layer | Customer | SPF Record |\n");
        content.push_str("|--------|--------------|-------|----------|------------|\n");

        for rel in &spf_relationships {
            content.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                escape_markdown(&rel.nth_party_domain),
                escape_markdown(&rel.nth_party_organization),
                rel.nth_party_layer,
                escape_markdown(&rel.nth_party_customer_domain),
                escape_markdown(&rel.nth_party_record)
            ));
        }
        content.push('\n');
    }

    // Verification Relationships table
    if !verification_relationships.is_empty() {
        content.push_str("### Integrated Services (Domain Verification)\n\n");
        content.push_str(
            "These vendors have verified domain ownership and likely have integrations:\n\n",
        );
        content.push_str("| Vendor | Organization | Layer | Customer | Verification Record |\n");
        content.push_str("|--------|--------------|-------|----------|--------------------|\n");

        for rel in &verification_relationships {
            content.push_str(&format!(
                "| {} | {} | {} | {} | {} |\n",
                escape_markdown(&rel.nth_party_domain),
                escape_markdown(&rel.nth_party_organization),
                rel.nth_party_layer,
                escape_markdown(&rel.nth_party_customer_domain),
                escape_markdown(&rel.nth_party_record)
            ));
        }
        content.push('\n');
    }

    // Webpage discovery relationships table
    if !web_traffic_relationships.is_empty() {
        content.push_str("### Webpage Discovery\n\n");
        content.push_str("These vendors were discovered through webpage source analysis or runtime network request capture:\n\n");
        content.push_str(
            "| Vendor | Organization | Layer | Discovery Method | Customer | Evidence |\n",
        );
        content.push_str(
            "|--------|--------------|-------|-----------------|----------|----------|\n",
        );

        for rel in &web_traffic_relationships {
            let method =
                if rel.nth_party_record_type.as_hierarchy_string() == "DISCOVERY::WEBPAGE_SOURCE" {
                    "Webpage Source"
                } else {
                    "Webpage Network Requests"
                };
            content.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                escape_markdown(&rel.nth_party_domain),
                escape_markdown(&rel.nth_party_organization),
                rel.nth_party_layer,
                method,
                escape_markdown(&rel.nth_party_customer_domain),
                escape_markdown(&rel.nth_party_record)
            ));
        }
        content.push('\n');
    }

    // Other relationships
    if !other_relationships.is_empty() {
        content.push_str("### Other Relationships\n\n");
        content.push_str("| Vendor | Organization | Layer | Type | Customer | Record |\n");
        content.push_str("|--------|--------------|-------|------|----------|--------|\n");

        for rel in &other_relationships {
            content.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                escape_markdown(&rel.nth_party_domain),
                escape_markdown(&rel.nth_party_organization),
                rel.nth_party_layer,
                escape_markdown(&rel.nth_party_record_type.as_hierarchy_string()),
                escape_markdown(&rel.nth_party_customer_domain),
                escape_markdown(&rel.nth_party_record)
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
        "Successfully exported {} relationships to Markdown: {}",
        relationships.len(),
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
        pub(super) vendor_graph_js: &'static str,
        pub(super) vendor_graph_css: &'static str,
        pub(super) design_system_css: &'static str,
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

#[cfg_attr(coverage_nightly, coverage(off))]
pub fn export_html(relationships: &[VendorRelationship], output_path: &str) -> Result<()> {
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
            vendor_graph_js: VENDOR_GRAPH_JS,
            vendor_graph_css: VENDOR_GRAPH_CSS,
            design_system_css: DESIGN_SYSTEM_CSS,
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
        vendor_graph_js: VENDOR_GRAPH_JS,
        vendor_graph_css: VENDOR_GRAPH_CSS,
        design_system_css: DESIGN_SYSTEM_CSS,
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
            vendor_graph_js: "",
            vendor_graph_css: "",
            design_system_css: "",
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
            vendor_graph_js: VENDOR_GRAPH_JS,
            vendor_graph_css: VENDOR_GRAPH_CSS,
            design_system_css: DESIGN_SYSTEM_CSS,
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
            vendor_graph_js: VENDOR_GRAPH_JS,
            vendor_graph_css: VENDOR_GRAPH_CSS,
            design_system_css: DESIGN_SYSTEM_CSS,
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
}
