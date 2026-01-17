use crate::vendor::VendorRelationship;
use anyhow::Result;
use csv::Writer;
use serde_json;
use std::fs::File;
use std::io::Write;
use std::collections::{HashMap, HashSet};
use tracing::{info, debug};
use askama::Template;
use chrono::Utc;

pub fn export_csv(relationships: &[VendorRelationship], output_path: &str) -> Result<()> {
    debug!("Exporting {} relationships to CSV: {}", relationships.len(), output_path);
    
    let file = File::create(output_path)?;
    let mut wtr = Writer::from_writer(file);
    
    // Write CSV headers
    wtr.write_record(&[
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
        wtr.write_record(&[
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
    info!("Successfully exported {} relationships to CSV: {}", relationships.len(), output_path);
    
    Ok(())
}

pub fn export_json(relationships: &[VendorRelationship], output_path: &str) -> Result<()> {
    debug!("Exporting {} relationships to JSON: {}", relationships.len(), output_path);
    
    let json_output = JsonExport {
        summary: ExportSummary {
            total_relationships: relationships.len(),
            max_depth: relationships.iter().map(|r| r.nth_party_layer).max().unwrap_or(0),
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
    
    info!("Successfully exported {} relationships to JSON: {}", relationships.len(), output_path);
    
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
    
    let max_depth = relationships.iter().map(|r| r.nth_party_layer).max().unwrap_or(0);
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

pub fn export_markdown(relationships: &[VendorRelationship], output_path: &str) -> Result<()> {
    debug!("Exporting {} relationships to Markdown: {}", relationships.len(), output_path);
    
    if relationships.is_empty() {
        let content = "# Nth Party Analysis Report\n\nNo vendor relationships found.\n";
        std::fs::write(output_path, content)?;
        info!("Successfully exported empty report to Markdown: {}", output_path);
        return Ok(());
    }
    
    let mut content = String::new();
    
    // Get root domain for the report
    let root_domain = &relationships[0].root_customer_domain;
    let root_organization = &relationships[0].root_customer_organization;
    
    // Header
    content.push_str(&format!("# Nth Party Analysis Report\n\n"));
    content.push_str(&format!("**Domain:** {}\n", root_domain));
    content.push_str(&format!("**Organization:** {}\n\n", root_organization));
    content.push_str(&format!("*Generated on: {}*\n\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
    
    // Summary statistics
    let max_depth = relationships.iter().map(|r| r.nth_party_layer).max().unwrap_or(0);
    let unique_domains: HashSet<_> = relationships.iter().map(|r| r.nth_party_domain.clone()).collect();
    let unique_orgs: HashSet<_> = relationships.iter().map(|r| r.nth_party_organization.clone()).collect();
    
    // Count by record type
    let mut type_counts = HashMap::new();
    for rel in relationships {
        *type_counts.entry(rel.nth_party_record_type.as_hierarchy_string()).or_insert(0) += 1;
    }
    
    content.push_str("## Executive Summary\n\n");
    content.push_str(&format!("- **Total vendor relationships found:** {}\n", relationships.len()));
    content.push_str(&format!("- **Maximum depth reached:** {} layers\n", max_depth));
    content.push_str(&format!("- **Unique vendor domains:** {}\n", unique_domains.len()));
    content.push_str(&format!("- **Unique vendor organizations:** {}\n\n", unique_orgs.len()));
    
    // Breakdown by record type
    content.push_str("### Breakdown by Record Type\n\n");
    for (record_type, count) in &type_counts {
        content.push_str(&format!("- **{}:** {} relationships\n", record_type, count));
    }
    content.push_str("\n");
    
    // Breakdown by layer
    content.push_str("### Breakdown by Layer\n\n");
    for layer in 1..=max_depth {
        let layer_count = relationships.iter().filter(|r| r.nth_party_layer == layer).count();
        if layer_count > 0 {
            content.push_str(&format!("- **Layer {} vendors:** {}\n", layer, layer_count));
        }
    }
    content.push_str("\n");
    
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
    content.push_str(&format!("    {}[\"{}<br/>({})\"]\\n", root_node, root_domain, root_organization));
    
    // Process relationships by layer
    for layer in 1..=max_depth {
        let layer_relationships: Vec<_> = relationships.iter().filter(|r| r.nth_party_layer == layer).collect();
        
        for rel in layer_relationships {
            let vendor_node = sanitize_mermaid_id(&rel.nth_party_domain);
            let customer_node = sanitize_mermaid_id(&rel.nth_party_customer_domain);
            
            // Add vendor node if not already added
            if !nodes.contains(&vendor_node) {
                nodes.insert(vendor_node.clone());
                let node_label = format!("{}<br/>({})", rel.nth_party_domain, rel.nth_party_organization);
                content.push_str(&format!("    {}[\"{}\"]\\n", vendor_node, node_label));
            }
            
            // Add edge with record type styling
            let edge_style = match rel.nth_party_record_type.as_hierarchy_string().as_str() {
                "DNS::TXT::SPF" => "-.->",
                "DNS::TXT::VERIFICATION" => "-->", 
                "DNS::SUBDOMAIN" => "==>",
                _ => "-->"
            };
            
            let edge_label = format!("{}|{}", rel.nth_party_record_type.as_hierarchy_string(), rel.nth_party_layer);
            edges.push(format!("    {} {} {}[\"{}\"]", customer_node, edge_style, vendor_node, edge_label));
        }
    }
    
    // Add all edges
    for edge in edges {
        content.push_str(&format!("{}\\n", edge));
    }
    
    // Add styling
    content.push_str("\\n");
    content.push_str("    classDef spfNode fill:#e1f5fe,stroke:#01579b,stroke-width:2px\\n");
    content.push_str("    classDef verificationNode fill:#f3e5f5,stroke:#4a148c,stroke-width:2px\\n");
    content.push_str("    classDef rootNode fill:#e8f5e8,stroke:#2e7d32,stroke-width:3px\\n");
    content.push_str(&format!("    class {} rootNode\\n", root_node));
    
    content.push_str("```\n\n");
    
    // Legend
    content.push_str("### Legend\n\n");
    content.push_str("- **Solid arrows (→):** Verification relationships (domain/site verification)\n");
    content.push_str("- **Dashed arrows (⇢):** SPF relationships (email sending authorization)\n");
    content.push_str("- **Double arrows (⇒):** Subdomain relationships\n");
    content.push_str("- **Numbers on edges:** Layer depth and record type\n\n");
    
    // Detailed tables
    content.push_str("## Detailed Relationships\n\n");
    
    // Group by record type
    let mut spf_relationships = Vec::new();
    let mut verification_relationships = Vec::new();
    let mut other_relationships = Vec::new();
    
    for rel in relationships {
        match rel.nth_party_record_type.as_hierarchy_string().as_str() {
            "DNS::TXT::SPF" => spf_relationships.push(rel),
            "DNS::TXT::VERIFICATION" => verification_relationships.push(rel),
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
            content.push_str(&format!("| {} | {} | {} | {} | {} |\n",
                escape_markdown(&rel.nth_party_domain),
                escape_markdown(&rel.nth_party_organization),
                rel.nth_party_layer,
                escape_markdown(&rel.nth_party_customer_domain),
                escape_markdown(&rel.nth_party_record)
            ));
        }
        content.push_str("\n");
    }
    
    // Verification Relationships table
    if !verification_relationships.is_empty() {
        content.push_str("### Integrated Services (Domain Verification)\n\n");
        content.push_str("These vendors have verified domain ownership and likely have integrations:\n\n");
        content.push_str("| Vendor | Organization | Layer | Customer | Verification Record |\n");
        content.push_str("|--------|--------------|-------|----------|--------------------|\n");
        
        for rel in &verification_relationships {
            content.push_str(&format!("| {} | {} | {} | {} | {} |\n",
                escape_markdown(&rel.nth_party_domain),
                escape_markdown(&rel.nth_party_organization),
                rel.nth_party_layer,
                escape_markdown(&rel.nth_party_customer_domain),
                escape_markdown(&rel.nth_party_record)
            ));
        }
        content.push_str("\n");
    }
    
    // Other relationships
    if !other_relationships.is_empty() {
        content.push_str("### Other Relationships\n\n");
        content.push_str("| Vendor | Organization | Layer | Type | Customer | Record |\n");
        content.push_str("|--------|--------------|-------|------|----------|--------|\n");
        
        for rel in &other_relationships {
            content.push_str(&format!("| {} | {} | {} | {} | {} | {} |\n",
                escape_markdown(&rel.nth_party_domain),
                escape_markdown(&rel.nth_party_organization),
                rel.nth_party_layer,
                escape_markdown(&rel.nth_party_record_type.as_hierarchy_string()),
                escape_markdown(&rel.nth_party_customer_domain),
                escape_markdown(&rel.nth_party_record)
            ));
        }
        content.push_str("\n");
    }
    
    // Risk assessment section
    content.push_str("## Risk Assessment\n\n");
    content.push_str("### High-Risk Considerations\n\n");
    content.push_str("- **Email providers (SPF)** can send emails as your organization\n");
    content.push_str("- **Verification services** have confirmed domain ownership and likely access to sensitive data\n");
    content.push_str("- **Multi-layer relationships** may create complex dependency chains\n\n");
    
    content.push_str("### Recommendations\n\n");
    content.push_str("1. **Review each verified service** to ensure they still provide business value\n");
    content.push_str("2. **Audit email providers** to prevent unauthorized email sending\n");
    content.push_str("3. **Monitor for new relationships** by running this analysis regularly\n");
    content.push_str("4. **Document business justification** for each vendor relationship\n\n");
    
    // Footer
    content.push_str("---\n\n");
    content.push_str("*Report generated by [nthpartyfinder](https://github.com/your-org/nthpartyfinder) - A tool for discovering third-party vendor relationships through DNS analysis.*\n");
    
    // Write to file
    std::fs::write(output_path, content)?;
    info!("Successfully exported {} relationships to Markdown: {}", relationships.len(), output_path);
    
    Ok(())
}

fn sanitize_mermaid_id(domain: &str) -> String {
    domain.replace(".", "_").replace("-", "_").chars().filter(|c| c.is_alphanumeric() || *c == '_').collect()
}

fn escape_markdown(text: &str) -> String {
    text.replace("|", "\\|").replace("*", "\\*").replace("_", "\\_")
}

#[derive(Template)]
#[template(path = "report.html")]
struct HtmlReportTemplate {
    summary: HtmlSummary,
    relationships: Vec<VendorRelationship>,
    relationships_json: String,
    summary_json: String,
}

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

pub fn export_html(relationships: &[VendorRelationship], output_path: &str) -> Result<()> {
    debug!("Exporting {} relationships to HTML: {}", relationships.len(), output_path);
    
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
        };
        
        let html_content = empty_template.render()?;
        std::fs::write(output_path, html_content)?;
        info!("Successfully exported empty report to HTML: {}", output_path);
        return Ok(());
    }
    
    let root_domain = &relationships[0].root_customer_domain;
    let root_organization = &relationships[0].root_customer_organization;
    
    let max_depth = relationships.iter().map(|r| r.nth_party_layer).max().unwrap_or(0);
    let unique_domains: HashSet<_> = relationships.iter().map(|r| r.nth_party_domain.clone()).collect();
    let unique_orgs: HashSet<_> = relationships.iter().map(|r| r.nth_party_organization.clone()).collect();
    
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
    };
    
    let html_content = template.render()?;
    std::fs::write(output_path, html_content)?;
    
    info!("Successfully exported {} relationships to HTML: {}", relationships.len(), output_path);
    
    Ok(())
}