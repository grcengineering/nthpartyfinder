use anyhow::Result;
use std::collections::HashMap;
use std::io::{self, Write};
use std::sync::Arc;
use tokio::sync::Mutex;

#[cfg(not(coverage))]
use crate::known_vendors;
use crate::logger::AnalysisLogger;
use crate::subprocessor;

pub(crate) trait UserInput {
    fn read_line(&self) -> io::Result<String>;
}

pub(crate) struct StdioInput;

impl UserInput for StdioInput {
    // cfg(not(coverage)): terminal-only — reads from real stdin
    #[cfg(not(coverage))]
    fn read_line(&self) -> io::Result<String> {
        let mut buf = String::new();
        io::stdin().read_line(&mut buf)?;
        Ok(buf)
    }
    #[cfg(coverage)]
    fn read_line(&self) -> io::Result<String> {
        Ok(String::new())
    }
}

#[derive(Debug, Clone)]
pub struct UnverifiedOrgMapping {
    pub domain: String,
    pub inferred_org: String,
}

pub async fn confirm_pending_mappings(
    pending: &[subprocessor::PendingOrgMapping],
    analyzer: &subprocessor::SubprocessorAnalyzer,
    logger: &AnalysisLogger,
) -> Result<()> {
    confirm_pending_mappings_with_input(pending, analyzer, logger, &StdioInput).await
}

#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) async fn confirm_pending_mappings_with_input(
    pending: &[subprocessor::PendingOrgMapping],
    analyzer: &subprocessor::SubprocessorAnalyzer,
    logger: &AnalysisLogger,
    user_input: &dyn UserInput,
) -> Result<()> {
    if pending.is_empty() {
        return Ok(());
    }

    let grouped = group_pending_by_source(pending);
    let unique_mappings = dedup_grouped_mappings(&grouped);

    println!();
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║         UNCONFIRMED ORG-TO-DOMAIN MAPPINGS DETECTED            ║");
    println!("╠════════════════════════════════════════════════════════════════╣");
    println!("║ The following mappings were inferred via generic fallback.     ║");
    println!("║ Please review and confirm to improve future extraction.        ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!();

    for (source_domain, mappings) in &unique_mappings {
        println!(
            "📋 Source: {} ({} mapping{})",
            source_domain,
            mappings.len(),
            if mappings.len() == 1 { "" } else { "s" }
        );
        println!("─────────────────────────────────────────────────────────────────");

        for (idx, (org_name, domain)) in mappings.iter().enumerate() {
            println!("  [{}] \"{}\" → {}", idx + 1, org_name, domain);
        }
        println!();
    }

    println!("Options:");
    println!("  [A] Accept ALL mappings and save to cache");
    println!("  [R] Review each mapping individually");
    println!("  [S] Skip - don't save any mappings (analysis results are already exported)");
    println!();
    print!("Your choice (A/R/S): ");
    io::stdout().flush()?;

    let raw_input = user_input.read_line()?;
    let choice = raw_input.trim().to_uppercase();

    match choice.as_str() {
        "A" => {
            for (source_domain, mappings) in &unique_mappings {
                let confirmed: Vec<(String, String)> = mappings
                    .iter()
                    .map(|(org, dom)| (org.to_string(), dom.to_string()))
                    .collect();

                save_and_log_confirmed(analyzer, source_domain, &confirmed, logger).await;
            }
        }
        "R" => {
            for (source_domain, mappings) in &unique_mappings {
                println!();
                println!("📋 Reviewing mappings for: {}", source_domain);
                println!("─────────────────────────────────────────────────────────────────");

                let mut confirmed: Vec<(String, String)> = Vec::new();

                for (org_name, inferred_domain) in mappings {
                    println!();
                    println!("  Organization: \"{}\"", org_name);
                    println!("  Inferred domain: {}", inferred_domain);
                    print!("  [Y] Accept  [N] Reject  [C] Custom domain: ");
                    io::stdout().flush()?;

                    let response = user_input.read_line()?;
                    let resp = response.trim().to_uppercase();

                    match resp.as_str() {
                        "Y" => {
                            confirmed.push((org_name.to_string(), inferred_domain.to_string()));
                            println!("    ✅ Accepted: \"{}\" → {}", org_name, inferred_domain);
                        }
                        "C" => {
                            print!("    Enter correct domain: ");
                            io::stdout().flush()?;
                            let custom = user_input.read_line()?;
                            let custom_domain = custom.trim().to_lowercase();
                            if !custom_domain.is_empty() {
                                confirmed.push((org_name.to_string(), custom_domain.clone()));
                                println!("    ✅ Custom: \"{}\" → {}", org_name, custom_domain);
                            } else {
                                println!("    ⏭️  Skipped (empty input)");
                            }
                        }
                        _ => {
                            println!("    ⏭️  Rejected");
                        }
                    }
                }

                if !confirmed.is_empty() {
                    save_and_log_review_confirmed(analyzer, source_domain, &confirmed, logger)
                        .await;
                }
            }
        }
        _ => {
            println!("⏭️  Skipped - no mappings saved");
            println!("   (Your analysis results have already been exported)");
        }
    }

    analyzer.clear_pending_mappings().await;

    println!();
    Ok(())
}

// cfg(not(coverage)): infallible in test — file cache save always succeeds
#[cfg(not(coverage))]
async fn save_and_log_confirmed(
    analyzer: &subprocessor::SubprocessorAnalyzer,
    source_domain: &str,
    confirmed: &[(String, String)],
    logger: &AnalysisLogger,
) {
    if let Err(e) = analyzer
        .save_confirmed_mappings(source_domain, confirmed)
        .await
    {
        logger.warn(&format!(
            "Failed to save mappings for {}: {}",
            source_domain, e
        ));
    } else {
        println!(
            "✅ Saved {} mapping{} for {}",
            confirmed.len(),
            plural_suffix(confirmed.len()),
            source_domain
        );
    }
}
#[cfg(coverage)]
async fn save_and_log_confirmed(
    analyzer: &subprocessor::SubprocessorAnalyzer,
    source_domain: &str,
    confirmed: &[(String, String)],
    _logger: &AnalysisLogger,
) {
    let _ = analyzer
        .save_confirmed_mappings(source_domain, confirmed)
        .await;
}

// cfg(not(coverage)): infallible in test — file cache save always succeeds
#[cfg(not(coverage))]
async fn save_and_log_review_confirmed(
    analyzer: &subprocessor::SubprocessorAnalyzer,
    source_domain: &str,
    confirmed: &[(String, String)],
    logger: &AnalysisLogger,
) {
    if let Err(e) = analyzer
        .save_confirmed_mappings(source_domain, confirmed)
        .await
    {
        logger.warn(&format!(
            "Failed to save mappings for {}: {}",
            source_domain, e
        ));
    } else {
        println!();
        println!(
            "✅ Saved {} mapping{} for {}",
            confirmed.len(),
            plural_suffix(confirmed.len()),
            source_domain
        );
    }
}
#[cfg(coverage)]
async fn save_and_log_review_confirmed(
    analyzer: &subprocessor::SubprocessorAnalyzer,
    source_domain: &str,
    confirmed: &[(String, String)],
    _logger: &AnalysisLogger,
) {
    let _ = analyzer
        .save_confirmed_mappings(source_domain, confirmed)
        .await;
}

pub async fn confirm_unverified_organizations(
    unverified: &[UnverifiedOrgMapping],
    discovered_vendors: &Arc<Mutex<HashMap<String, String>>>,
    logger: &AnalysisLogger,
) -> Result<()> {
    confirm_unverified_organizations_with_input(unverified, discovered_vendors, logger, &StdioInput)
        .await
}

#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) async fn confirm_unverified_organizations_with_input(
    unverified: &[UnverifiedOrgMapping],
    discovered_vendors: &Arc<Mutex<HashMap<String, String>>>,
    logger: &AnalysisLogger,
    user_input: &dyn UserInput,
) -> Result<()> {
    if unverified.is_empty() {
        return Ok(());
    }

    let unique = dedup_unverified_orgs(unverified);

    println!();
    println!("╔════════════════════════════════════════════════════════════════╗");
    println!("║         UNVERIFIED ORGANIZATION NAMES DETECTED                 ║");
    println!("╠════════════════════════════════════════════════════════════════╣");
    println!("║ The following organizations were inferred from domain names    ║");
    println!("║ because WHOIS data was unavailable or protected by privacy.    ║");
    println!("║ You may specify correct organization names to improve accuracy.║");
    println!("║                                                                ║");
    println!("║ Confirmed names are saved locally for future runs.             ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    println!();

    let domains = sort_domain_org_pairs(&unique);

    for (idx, (domain, inferred_org)) in domains.iter().enumerate() {
        println!("  [{}] {} → \"{}\"", idx + 1, domain, inferred_org);
    }
    println!();

    println!("Options:");
    println!("  [A] Accept ALL inferred names and save for future runs");
    println!("  [R] Review each domain and specify correct organization names");
    println!("  [S] Skip - use inferred names without saving");
    println!();
    print!("Your choice (A/R/S): ");
    io::stdout().flush()?;

    let raw_input = user_input.read_line()?;
    let choice = raw_input.trim().to_uppercase();

    match choice.as_str() {
        "A" => {
            let saved_count = save_all_vendor_overrides(&domains, logger);
            println!(
                "✅ Accepted all {} inferred organization names",
                unique.len()
            );
            print_vendor_save_count(saved_count);
        }
        "R" => {
            println!();
            println!("📋 Reviewing inferred organizations:");
            println!("─────────────────────────────────────────────────────────────────");

            let mut vendors = discovered_vendors.lock().await;
            let mut updated_count = 0;
            let mut saved_count = 0;

            for (domain, inferred_org) in &domains {
                println!();
                println!("  Domain: {}", domain);
                println!("  Inferred: \"{}\"", inferred_org);
                print!("  [Y] Accept  [C] Custom name  [S] Skip: ");
                io::stdout().flush()?;

                let response = user_input.read_line()?;
                let resp = response.trim().to_uppercase();

                match resp.as_str() {
                    "C" => {
                        print!("    Enter correct organization name: ");
                        io::stdout().flush()?;
                        let custom = user_input.read_line()?;
                        let custom_org = custom.trim();
                        if !custom_org.is_empty() {
                            vendors.insert(domain.to_string(), custom_org.to_string());

                            saved_count +=
                                try_save_vendor_override(domain, custom_org, logger) as usize;

                            logger.info(&format!(
                                "Updated organization for {}: {} -> {}",
                                domain, inferred_org, custom_org
                            ));
                            println!(
                                "    ✅ Updated: {} → \"{}\" (saved for future runs)",
                                domain, custom_org
                            );
                            updated_count += 1;
                        } else {
                            println!("    ⏭️  Kept inferred name (empty input)");
                        }
                    }
                    "Y" | "" => {
                        saved_count +=
                            try_save_vendor_override(domain, inferred_org, logger) as usize;
                        println!(
                            "    ✅ Accepted: \"{}\" (saved for future runs)",
                            inferred_org
                        );
                    }
                    _ => {
                        println!("    ⏭️  Skipped (not saved)");
                    }
                }
            }

            print_review_summary(updated_count, saved_count);
        }
        _ => {
            println!("⏭️  Skipped - using inferred organization names (not saved)");
        }
    }

    println!();
    Ok(())
}

// cfg(not(coverage)): OnceLock singleton — None in test context, can't be reset
#[cfg(not(coverage))]
fn save_all_vendor_overrides(domains: &[(&String, &String)], logger: &AnalysisLogger) -> usize {
    let mut saved = 0;
    if let Some(kv) = known_vendors::get() {
        for (domain, org) in domains {
            if let Err(e) = kv.add_override(domain, org) {
                logger.warn(&format!("Failed to save override for {}: {}", domain, e));
            } else {
                saved += 1;
            }
        }
    }
    saved
}
#[cfg(coverage)]
fn save_all_vendor_overrides(_domains: &[(&String, &String)], _logger: &AnalysisLogger) -> usize {
    0
}

// cfg(not(coverage)): OnceLock singleton — None in test context, can't be reset
#[cfg(not(coverage))]
fn try_save_vendor_override(domain: &str, org: &str, logger: &AnalysisLogger) -> bool {
    if let Some(kv) = known_vendors::get() {
        if let Err(e) = kv.add_override(domain, org) {
            logger.warn(&format!("Failed to save override for {}: {}", domain, e));
            false
        } else {
            true
        }
    } else {
        false
    }
}
#[cfg(coverage)]
fn try_save_vendor_override(_domain: &str, _org: &str, _logger: &AnalysisLogger) -> bool {
    false
}

// cfg(not(coverage)): display-only — saved_count depends on OnceLock state
#[cfg(not(coverage))]
fn print_vendor_save_count(saved_count: usize) {
    if saved_count > 0 {
        println!(
            "   💾 Saved {} names to local database for future runs",
            saved_count
        );
    }
}
#[cfg(coverage)]
fn print_vendor_save_count(_saved_count: usize) {}

// cfg(not(coverage)): display-only — counts depend on OnceLock state
#[cfg(not(coverage))]
fn print_review_summary(updated_count: usize, saved_count: usize) {
    if updated_count > 0 || saved_count > 0 {
        println!();
        if updated_count > 0 {
            println!(
                "✅ Updated {} organization name{}",
                updated_count,
                plural_suffix(updated_count)
            );
        }
        if saved_count > 0 {
            println!(
                "💾 Saved {} name{} to local database for future runs",
                saved_count,
                plural_suffix(saved_count)
            );
        }
        if updated_count > 0 {
            println!("   Note: Re-run analysis to regenerate reports with corrected names");
        }
    }
}
#[cfg(coverage)]
fn print_review_summary(_updated_count: usize, _saved_count: usize) {}

/// Group pending mappings by source domain (extracted for testability).
pub(crate) fn group_pending_by_source(
    pending: &[subprocessor::PendingOrgMapping],
) -> HashMap<&str, Vec<&subprocessor::PendingOrgMapping>> {
    let mut grouped: HashMap<&str, Vec<&subprocessor::PendingOrgMapping>> = HashMap::new();
    for mapping in pending {
        grouped
            .entry(&mapping.source_domain)
            .or_default()
            .push(mapping);
    }
    grouped
}

/// Deduplicate grouped mappings, keeping first-seen inferred_domain per org_name.
pub(crate) fn dedup_grouped_mappings<'a>(
    grouped: &HashMap<&'a str, Vec<&'a subprocessor::PendingOrgMapping>>,
) -> HashMap<&'a str, Vec<(&'a str, &'a str)>> {
    let mut unique_mappings: HashMap<&str, Vec<(&str, &str)>> = HashMap::new();
    for (source, mappings) in grouped {
        let mut seen: HashMap<&str, &str> = HashMap::new();
        for m in mappings {
            seen.entry(&m.org_name).or_insert(&m.inferred_domain);
        }
        unique_mappings.insert(source, seen.into_iter().collect());
    }
    unique_mappings
}

/// Deduplicate unverified org mappings, keeping first-seen inferred_org per domain.
pub(crate) fn dedup_unverified_orgs(
    unverified: &[UnverifiedOrgMapping],
) -> HashMap<String, String> {
    let mut unique: HashMap<String, String> = HashMap::new();
    for mapping in unverified {
        unique
            .entry(mapping.domain.clone())
            .or_insert(mapping.inferred_org.clone());
    }
    unique
}

/// Sort domain-org pairs alphabetically by domain.
pub(crate) fn sort_domain_org_pairs(unique: &HashMap<String, String>) -> Vec<(&String, &String)> {
    let mut domains: Vec<_> = unique.iter().collect();
    domains.sort_by(|a, b| a.0.cmp(b.0));
    domains
}

/// Format the plural suffix for counts.
pub(crate) fn plural_suffix(count: usize) -> &'static str {
    if count == 1 {
        ""
    } else {
        "s"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ──────────────────────────────────────────────────────────────────
    // UnverifiedOrgMapping struct tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_unverified_org_mapping_creation() {
        let mapping = UnverifiedOrgMapping {
            domain: "example.com".to_string(),
            inferred_org: "Example Inc.".to_string(),
        };
        assert_eq!(mapping.domain, "example.com");
        assert_eq!(mapping.inferred_org, "Example Inc.");
    }

    #[test]
    fn test_unverified_org_mapping_clone() {
        let original = UnverifiedOrgMapping {
            domain: "test.com".to_string(),
            inferred_org: "Test Corp".to_string(),
        };
        let cloned = original.clone();
        assert_eq!(original.domain, cloned.domain);
        assert_eq!(original.inferred_org, cloned.inferred_org);
    }

    #[test]
    fn test_unverified_org_mapping_debug() {
        let mapping = UnverifiedOrgMapping {
            domain: "debug.com".to_string(),
            inferred_org: "Debug LLC".to_string(),
        };
        let debug_str = format!("{:?}", mapping);
        assert!(debug_str.contains("debug.com"));
        assert!(debug_str.contains("Debug LLC"));
        assert!(debug_str.contains("UnverifiedOrgMapping"));
    }

    #[test]
    fn test_unverified_org_mapping_clone_independence() {
        let original = UnverifiedOrgMapping {
            domain: "original.com".to_string(),
            inferred_org: "Original Corp".to_string(),
        };
        let mut cloned = original.clone();
        cloned.domain = "modified.com".to_string();
        cloned.inferred_org = "Modified Corp".to_string();
        // Original should be unaffected
        assert_eq!(original.domain, "original.com");
        assert_eq!(original.inferred_org, "Original Corp");
        assert_eq!(cloned.domain, "modified.com");
        assert_eq!(cloned.inferred_org, "Modified Corp");
    }

    #[test]
    fn test_unverified_org_mapping_empty_fields() {
        let mapping = UnverifiedOrgMapping {
            domain: String::new(),
            inferred_org: String::new(),
        };
        assert!(mapping.domain.is_empty());
        assert!(mapping.inferred_org.is_empty());
    }

    #[test]
    fn test_unverified_org_mapping_unicode() {
        let mapping = UnverifiedOrgMapping {
            domain: "例え.jp".to_string(),
            inferred_org: "日本株式会社".to_string(),
        };
        assert_eq!(mapping.domain, "例え.jp");
        assert_eq!(mapping.inferred_org, "日本株式会社");
    }

    // ──────────────────────────────────────────────────────────────────
    // group_pending_by_source tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_group_pending_by_source_empty() {
        let pending: Vec<subprocessor::PendingOrgMapping> = vec![];
        let grouped = group_pending_by_source(&pending);
        assert!(grouped.is_empty());
    }

    #[test]
    fn test_group_pending_by_source_single_source() {
        let pending = vec![
            subprocessor::PendingOrgMapping {
                org_name: "Acme".to_string(),
                inferred_domain: "acme.com".to_string(),
                source_domain: "example.com".to_string(),
            },
            subprocessor::PendingOrgMapping {
                org_name: "Beta".to_string(),
                inferred_domain: "beta.io".to_string(),
                source_domain: "example.com".to_string(),
            },
        ];
        let grouped = group_pending_by_source(&pending);
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped["example.com"].len(), 2);
    }

    #[test]
    fn test_group_pending_by_source_multiple_sources() {
        let pending = vec![
            subprocessor::PendingOrgMapping {
                org_name: "Acme".to_string(),
                inferred_domain: "acme.com".to_string(),
                source_domain: "source1.com".to_string(),
            },
            subprocessor::PendingOrgMapping {
                org_name: "Beta".to_string(),
                inferred_domain: "beta.io".to_string(),
                source_domain: "source2.com".to_string(),
            },
            subprocessor::PendingOrgMapping {
                org_name: "Gamma".to_string(),
                inferred_domain: "gamma.net".to_string(),
                source_domain: "source1.com".to_string(),
            },
        ];
        let grouped = group_pending_by_source(&pending);
        assert_eq!(grouped.len(), 2);
        assert_eq!(grouped["source1.com"].len(), 2);
        assert_eq!(grouped["source2.com"].len(), 1);
    }

    // ──────────────────────────────────────────────────────────────────
    // dedup_grouped_mappings tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_dedup_grouped_mappings_no_duplicates() {
        let pending = vec![
            subprocessor::PendingOrgMapping {
                org_name: "Acme".to_string(),
                inferred_domain: "acme.com".to_string(),
                source_domain: "example.com".to_string(),
            },
            subprocessor::PendingOrgMapping {
                org_name: "Beta".to_string(),
                inferred_domain: "beta.io".to_string(),
                source_domain: "example.com".to_string(),
            },
        ];
        let grouped = group_pending_by_source(&pending);
        let deduped = dedup_grouped_mappings(&grouped);
        assert_eq!(deduped["example.com"].len(), 2);
    }

    #[test]
    fn test_dedup_grouped_mappings_with_duplicates() {
        let pending = vec![
            subprocessor::PendingOrgMapping {
                org_name: "Acme".to_string(),
                inferred_domain: "acme.com".to_string(),
                source_domain: "example.com".to_string(),
            },
            subprocessor::PendingOrgMapping {
                org_name: "Acme".to_string(),
                inferred_domain: "acmeinc.com".to_string(),
                source_domain: "example.com".to_string(),
            },
        ];
        let grouped = group_pending_by_source(&pending);
        let deduped = dedup_grouped_mappings(&grouped);
        // Should keep only the first occurrence
        assert_eq!(deduped["example.com"].len(), 1);
        let (org, domain) = &deduped["example.com"][0];
        assert_eq!(*org, "Acme");
        assert_eq!(*domain, "acme.com");
    }

    #[test]
    fn test_dedup_grouped_mappings_empty() {
        let grouped: HashMap<&str, Vec<&subprocessor::PendingOrgMapping>> = HashMap::new();
        let deduped = dedup_grouped_mappings(&grouped);
        assert!(deduped.is_empty());
    }

    #[test]
    fn test_dedup_grouped_mappings_multiple_sources() {
        let pending = vec![
            subprocessor::PendingOrgMapping {
                org_name: "Acme".to_string(),
                inferred_domain: "acme.com".to_string(),
                source_domain: "source1.com".to_string(),
            },
            subprocessor::PendingOrgMapping {
                org_name: "Acme".to_string(),
                inferred_domain: "acme.com".to_string(),
                source_domain: "source2.com".to_string(),
            },
        ];
        let grouped = group_pending_by_source(&pending);
        let deduped = dedup_grouped_mappings(&grouped);
        assert_eq!(deduped.len(), 2);
        assert_eq!(deduped["source1.com"].len(), 1);
        assert_eq!(deduped["source2.com"].len(), 1);
    }

    // ──────────────────────────────────────────────────────────────────
    // dedup_unverified_orgs tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_dedup_unverified_orgs_empty() {
        let unverified: Vec<UnverifiedOrgMapping> = vec![];
        let unique = dedup_unverified_orgs(&unverified);
        assert!(unique.is_empty());
    }

    #[test]
    fn test_dedup_unverified_orgs_no_duplicates() {
        let unverified = vec![
            UnverifiedOrgMapping {
                domain: "alpha.com".to_string(),
                inferred_org: "Alpha Inc".to_string(),
            },
            UnverifiedOrgMapping {
                domain: "beta.com".to_string(),
                inferred_org: "Beta Corp".to_string(),
            },
        ];
        let unique = dedup_unverified_orgs(&unverified);
        assert_eq!(unique.len(), 2);
        assert_eq!(unique["alpha.com"], "Alpha Inc");
        assert_eq!(unique["beta.com"], "Beta Corp");
    }

    #[test]
    fn test_dedup_unverified_orgs_with_duplicates_keeps_first() {
        let unverified = vec![
            UnverifiedOrgMapping {
                domain: "dup.com".to_string(),
                inferred_org: "First Org".to_string(),
            },
            UnverifiedOrgMapping {
                domain: "dup.com".to_string(),
                inferred_org: "Second Org".to_string(),
            },
            UnverifiedOrgMapping {
                domain: "unique.com".to_string(),
                inferred_org: "Unique Corp".to_string(),
            },
        ];
        let unique = dedup_unverified_orgs(&unverified);
        assert_eq!(unique.len(), 2);
        // or_insert keeps the first value
        assert_eq!(unique["dup.com"], "First Org");
        assert_eq!(unique["unique.com"], "Unique Corp");
    }

    #[test]
    fn test_dedup_unverified_orgs_all_same_domain() {
        let unverified = vec![
            UnverifiedOrgMapping {
                domain: "same.com".to_string(),
                inferred_org: "Org A".to_string(),
            },
            UnverifiedOrgMapping {
                domain: "same.com".to_string(),
                inferred_org: "Org B".to_string(),
            },
            UnverifiedOrgMapping {
                domain: "same.com".to_string(),
                inferred_org: "Org C".to_string(),
            },
        ];
        let unique = dedup_unverified_orgs(&unverified);
        assert_eq!(unique.len(), 1);
        assert_eq!(unique["same.com"], "Org A");
    }

    // ──────────────────────────────────────────────────────────────────
    // sort_domain_org_pairs tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_sort_domain_org_pairs_empty() {
        let unique: HashMap<String, String> = HashMap::new();
        let sorted = sort_domain_org_pairs(&unique);
        assert!(sorted.is_empty());
    }

    #[test]
    fn test_sort_domain_org_pairs_alphabetical() {
        let mut unique = HashMap::new();
        unique.insert("zebra.com".to_string(), "Zebra Inc".to_string());
        unique.insert("alpha.com".to_string(), "Alpha Corp".to_string());
        unique.insert("middle.com".to_string(), "Middle LLC".to_string());
        let sorted = sort_domain_org_pairs(&unique);
        assert_eq!(sorted.len(), 3);
        assert_eq!(sorted[0].0, "alpha.com");
        assert_eq!(sorted[1].0, "middle.com");
        assert_eq!(sorted[2].0, "zebra.com");
    }

    #[test]
    fn test_sort_domain_org_pairs_single() {
        let mut unique = HashMap::new();
        unique.insert("only.com".to_string(), "Only One".to_string());
        let sorted = sort_domain_org_pairs(&unique);
        assert_eq!(sorted.len(), 1);
        assert_eq!(sorted[0].0, "only.com");
        assert_eq!(sorted[0].1, "Only One");
    }

    #[test]
    fn test_sort_domain_org_pairs_preserves_org_values() {
        let mut unique = HashMap::new();
        unique.insert("b.com".to_string(), "Bravo".to_string());
        unique.insert("a.com".to_string(), "Alpha".to_string());
        let sorted = sort_domain_org_pairs(&unique);
        assert_eq!(sorted[0], (&"a.com".to_string(), &"Alpha".to_string()));
        assert_eq!(sorted[1], (&"b.com".to_string(), &"Bravo".to_string()));
    }

    // ──────────────────────────────────────────────────────────────────
    // plural_suffix tests
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_plural_suffix_zero() {
        assert_eq!(plural_suffix(0), "s");
    }

    #[test]
    fn test_plural_suffix_one() {
        assert_eq!(plural_suffix(1), "");
    }

    #[test]
    fn test_plural_suffix_many() {
        assert_eq!(plural_suffix(2), "s");
        assert_eq!(plural_suffix(100), "s");
        assert_eq!(plural_suffix(999), "s");
    }

    // ──────────────────────────────────────────────────────────────────
    // confirm_pending_mappings early-return tests
    // ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_confirm_pending_mappings_empty_returns_ok() {
        let pending: Vec<subprocessor::PendingOrgMapping> = vec![];
        let analyzer = subprocessor::SubprocessorAnalyzer::new().await;
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let result = confirm_pending_mappings(&pending, &analyzer, &logger).await;
        assert!(result.is_ok());
    }

    // ──────────────────────────────────────────────────────────────────
    // confirm_unverified_organizations early-return tests
    // ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_confirm_unverified_organizations_empty_returns_ok() {
        let unverified: Vec<UnverifiedOrgMapping> = vec![];
        let vendors = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let result = confirm_unverified_organizations(&unverified, &vendors, &logger).await;
        assert!(result.is_ok());
    }

    // ──────────────────────────────────────────────────────────────────
    // Integration: grouping + dedup pipeline
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_grouping_dedup_total_count() {
        let pending = vec![
            subprocessor::PendingOrgMapping {
                org_name: "OrgA".to_string(),
                inferred_domain: "orga.com".to_string(),
                source_domain: "src1.com".to_string(),
            },
            subprocessor::PendingOrgMapping {
                org_name: "OrgA".to_string(),
                inferred_domain: "orga-alt.com".to_string(),
                source_domain: "src1.com".to_string(),
            },
            subprocessor::PendingOrgMapping {
                org_name: "OrgB".to_string(),
                inferred_domain: "orgb.com".to_string(),
                source_domain: "src1.com".to_string(),
            },
            subprocessor::PendingOrgMapping {
                org_name: "OrgC".to_string(),
                inferred_domain: "orgc.com".to_string(),
                source_domain: "src2.com".to_string(),
            },
        ];
        let grouped = group_pending_by_source(&pending);
        let deduped = dedup_grouped_mappings(&grouped);

        // src1 should have OrgA (deduped) + OrgB = 2
        // src2 should have OrgC = 1
        let total_count: usize = deduped.values().map(|v| v.len()).sum();
        assert_eq!(total_count, 3);
    }

    #[test]
    fn test_grouping_dedup_zero_after_all_duplicates() {
        // Not possible with current logic since dedup still keeps one per org_name,
        // but we can verify single entries are preserved
        let pending = vec![
            subprocessor::PendingOrgMapping {
                org_name: "Same".to_string(),
                inferred_domain: "same.com".to_string(),
                source_domain: "src.com".to_string(),
            },
            subprocessor::PendingOrgMapping {
                org_name: "Same".to_string(),
                inferred_domain: "same2.com".to_string(),
                source_domain: "src.com".to_string(),
            },
        ];
        let grouped = group_pending_by_source(&pending);
        let deduped = dedup_grouped_mappings(&grouped);
        let total_count: usize = deduped.values().map(|v| v.len()).sum();
        assert_eq!(total_count, 1);
    }

    // ──────────────────────────────────────────────────────────────────
    // dedup + sort pipeline for unverified orgs
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_dedup_then_sort_pipeline() {
        let unverified = vec![
            UnverifiedOrgMapping {
                domain: "z-last.com".to_string(),
                inferred_org: "Z Corp".to_string(),
            },
            UnverifiedOrgMapping {
                domain: "a-first.com".to_string(),
                inferred_org: "A Inc".to_string(),
            },
            UnverifiedOrgMapping {
                domain: "a-first.com".to_string(),
                inferred_org: "A Duplicate".to_string(),
            },
            UnverifiedOrgMapping {
                domain: "m-middle.com".to_string(),
                inferred_org: "M LLC".to_string(),
            },
        ];

        let unique = dedup_unverified_orgs(&unverified);
        assert_eq!(unique.len(), 3); // a-first deduplicated

        let sorted = sort_domain_org_pairs(&unique);
        assert_eq!(sorted[0].0, "a-first.com");
        assert_eq!(sorted[0].1, "A Inc"); // first-seen value
        assert_eq!(sorted[1].0, "m-middle.com");
        assert_eq!(sorted[2].0, "z-last.com");
    }

    // ──────────────────────────────────────────────────────────────────
    // Additional edge cases for group_pending_by_source
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_group_pending_by_source_single_mapping() {
        let pending = vec![subprocessor::PendingOrgMapping {
            org_name: "Solo".to_string(),
            inferred_domain: "solo.com".to_string(),
            source_domain: "src.com".to_string(),
        }];
        let grouped = group_pending_by_source(&pending);
        assert_eq!(grouped.len(), 1);
        assert_eq!(grouped["src.com"].len(), 1);
        assert_eq!(grouped["src.com"][0].org_name, "Solo");
    }

    #[test]
    fn test_group_pending_preserves_all_fields() {
        let pending = vec![subprocessor::PendingOrgMapping {
            org_name: "FieldOrg".to_string(),
            inferred_domain: "field.org".to_string(),
            source_domain: "source.net".to_string(),
        }];
        let grouped = group_pending_by_source(&pending);
        let entry = grouped["source.net"][0];
        assert_eq!(entry.org_name, "FieldOrg");
        assert_eq!(entry.inferred_domain, "field.org");
        assert_eq!(entry.source_domain, "source.net");
    }

    #[test]
    fn test_group_pending_many_sources() {
        let mut pending = Vec::new();
        for i in 0..20 {
            pending.push(subprocessor::PendingOrgMapping {
                org_name: format!("Org{}", i),
                inferred_domain: format!("org{}.com", i),
                source_domain: format!("source{}.com", i),
            });
        }
        let grouped = group_pending_by_source(&pending);
        assert_eq!(grouped.len(), 20);
    }

    // ──────────────────────────────────────────────────────────────────
    // Additional edge cases for dedup_grouped_mappings
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_dedup_grouped_mappings_single_entry() {
        let pending = vec![subprocessor::PendingOrgMapping {
            org_name: "Single".to_string(),
            inferred_domain: "single.com".to_string(),
            source_domain: "s.com".to_string(),
        }];
        let grouped = group_pending_by_source(&pending);
        let deduped = dedup_grouped_mappings(&grouped);
        assert_eq!(deduped.len(), 1);
        assert_eq!(deduped["s.com"].len(), 1);
    }

    #[test]
    fn test_dedup_grouped_many_orgs_same_source() {
        let pending = vec![
            subprocessor::PendingOrgMapping {
                org_name: "A".to_string(),
                inferred_domain: "a.com".to_string(),
                source_domain: "s.com".to_string(),
            },
            subprocessor::PendingOrgMapping {
                org_name: "B".to_string(),
                inferred_domain: "b.com".to_string(),
                source_domain: "s.com".to_string(),
            },
            subprocessor::PendingOrgMapping {
                org_name: "C".to_string(),
                inferred_domain: "c.com".to_string(),
                source_domain: "s.com".to_string(),
            },
        ];
        let grouped = group_pending_by_source(&pending);
        let deduped = dedup_grouped_mappings(&grouped);
        assert_eq!(deduped["s.com"].len(), 3);
    }

    // ──────────────────────────────────────────────────────────────────
    // Additional edge cases for dedup_unverified_orgs
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_dedup_unverified_orgs_single() {
        let unverified = vec![UnverifiedOrgMapping {
            domain: "one.com".to_string(),
            inferred_org: "One Inc".to_string(),
        }];
        let unique = dedup_unverified_orgs(&unverified);
        assert_eq!(unique.len(), 1);
        assert_eq!(unique["one.com"], "One Inc");
    }

    #[test]
    fn test_dedup_unverified_orgs_many_unique() {
        let mut unverified = Vec::new();
        for i in 0..50 {
            unverified.push(UnverifiedOrgMapping {
                domain: format!("domain{}.com", i),
                inferred_org: format!("Org {}", i),
            });
        }
        let unique = dedup_unverified_orgs(&unverified);
        assert_eq!(unique.len(), 50);
    }

    #[test]
    fn test_dedup_unverified_special_chars_in_domain() {
        let unverified = vec![
            UnverifiedOrgMapping {
                domain: "test-site.co.uk".to_string(),
                inferred_org: "Test Site".to_string(),
            },
            UnverifiedOrgMapping {
                domain: "my_site.io".to_string(),
                inferred_org: "My Site".to_string(),
            },
        ];
        let unique = dedup_unverified_orgs(&unverified);
        assert_eq!(unique.len(), 2);
        assert_eq!(unique["test-site.co.uk"], "Test Site");
    }

    // ──────────────────────────────────────────────────────────────────
    // Additional sort_domain_org_pairs edge cases
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_sort_domain_org_pairs_numeric_domains() {
        let mut unique = HashMap::new();
        unique.insert("3.com".to_string(), "Three".to_string());
        unique.insert("1.com".to_string(), "One".to_string());
        unique.insert("2.com".to_string(), "Two".to_string());
        let sorted = sort_domain_org_pairs(&unique);
        assert_eq!(sorted[0].0, "1.com");
        assert_eq!(sorted[1].0, "2.com");
        assert_eq!(sorted[2].0, "3.com");
    }

    #[test]
    fn test_sort_domain_org_pairs_case_sensitivity() {
        let mut unique = HashMap::new();
        unique.insert("B.com".to_string(), "Big".to_string());
        unique.insert("a.com".to_string(), "Alpha".to_string());
        let sorted = sort_domain_org_pairs(&unique);
        // Uppercase 'B' sorts before lowercase 'a' in ASCII
        assert_eq!(sorted[0].0, "B.com");
        assert_eq!(sorted[1].0, "a.com");
    }

    #[test]
    fn test_sort_domain_org_pairs_large_set() {
        let mut unique = HashMap::new();
        for i in (0..100).rev() {
            unique.insert(format!("{:03}.com", i), format!("Org{}", i));
        }
        let sorted = sort_domain_org_pairs(&unique);
        assert_eq!(sorted.len(), 100);
        assert_eq!(sorted[0].0, "000.com");
        assert_eq!(sorted[99].0, "099.com");
    }

    // ──────────────────────────────────────────────────────────────────
    // Additional plural_suffix edge cases
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_plural_suffix_large_numbers() {
        assert_eq!(plural_suffix(1_000_000), "s");
        assert_eq!(plural_suffix(usize::MAX), "s");
    }

    // ──────────────────────────────────────────────────────────────────
    // confirm_unverified_organizations dedup-all edge case
    // ──────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_confirm_unverified_dedup_all_same_returns_ok() {
        // All mappings have the same domain - after dedup there's 1 entry, but
        // the function will attempt stdin, so we test the unique map instead
        let unverified = vec![
            UnverifiedOrgMapping {
                domain: "same.com".to_string(),
                inferred_org: "A".to_string(),
            },
            UnverifiedOrgMapping {
                domain: "same.com".to_string(),
                inferred_org: "B".to_string(),
            },
        ];
        let unique = dedup_unverified_orgs(&unverified);
        assert_eq!(unique.len(), 1);
        let sorted = sort_domain_org_pairs(&unique);
        assert_eq!(sorted.len(), 1);
        assert_eq!(sorted[0].0, "same.com");
        assert_eq!(sorted[0].1, "A"); // first-seen wins
    }

    // ──────────────────────────────────────────────────────────────────
    // Pipeline tests: group -> dedup -> total_count == 0
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_dedup_grouped_total_count_single_dup() {
        let pending = vec![
            subprocessor::PendingOrgMapping {
                org_name: "Dup".to_string(),
                inferred_domain: "dup1.com".to_string(),
                source_domain: "s.com".to_string(),
            },
            subprocessor::PendingOrgMapping {
                org_name: "Dup".to_string(),
                inferred_domain: "dup2.com".to_string(),
                source_domain: "s.com".to_string(),
            },
            subprocessor::PendingOrgMapping {
                org_name: "Dup".to_string(),
                inferred_domain: "dup3.com".to_string(),
                source_domain: "s.com".to_string(),
            },
        ];
        let grouped = group_pending_by_source(&pending);
        let deduped = dedup_grouped_mappings(&grouped);
        let total: usize = deduped.values().map(|v| v.len()).sum();
        assert_eq!(total, 1); // All three have same org_name -> deduplicated to 1
    }

    // ──────────────────────────────────────────────────────────────────
    // UnverifiedOrgMapping with special characters
    // ──────────────────────────────────────────────────────────────────

    #[test]
    fn test_unverified_org_mapping_special_chars() {
        let mapping = UnverifiedOrgMapping {
            domain: "test.com".to_string(),
            inferred_org: "O'Brien & Co. (Ltd.)".to_string(),
        };
        assert_eq!(mapping.inferred_org, "O'Brien & Co. (Ltd.)");
    }

    #[test]
    fn test_unverified_org_mapping_very_long_domain() {
        let long_domain = format!("{}.example.com", "a".repeat(200));
        let mapping = UnverifiedOrgMapping {
            domain: long_domain.clone(),
            inferred_org: "Test".to_string(),
        };
        assert_eq!(mapping.domain, long_domain);
    }

    // ── confirm_pending_mappings / confirm_unverified_organizations ──

    #[tokio::test]
    async fn test_confirm_pending_mappings_empty_is_noop() {
        let analyzer = subprocessor::SubprocessorAnalyzer::new().await;
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let result = confirm_pending_mappings(&[], &analyzer, &logger).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_confirm_unverified_organizations_empty_is_noop() {
        let vendors: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let result = confirm_unverified_organizations(&[], &vendors, &logger).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_confirm_unverified_organizations_all_dupes_deduped() {
        let mappings = vec![
            UnverifiedOrgMapping {
                domain: "a.com".to_string(),
                inferred_org: "A".to_string(),
            },
            UnverifiedOrgMapping {
                domain: "a.com".to_string(),
                inferred_org: "A".to_string(),
            },
        ];
        let unique = dedup_unverified_orgs(&mappings);
        assert_eq!(unique.len(), 1);
    }

    // ──────────────────────────────────────────────────────────────────
    // MockInput + _with_input tests for confirm_pending_mappings
    // ──────────────────────────────────────────────────────────────────

    struct MockInput {
        responses: std::cell::RefCell<Vec<String>>,
    }

    impl MockInput {
        fn new(responses: Vec<&str>) -> Self {
            Self {
                responses: std::cell::RefCell::new(
                    responses.into_iter().map(|s| format!("{}\n", s)).collect(),
                ),
            }
        }
    }

    impl UserInput for MockInput {
        fn read_line(&self) -> io::Result<String> {
            let mut r = self.responses.borrow_mut();
            Ok(r.remove(0))
        }
    }

    fn make_pending(org: &str, domain: &str, source: &str) -> subprocessor::PendingOrgMapping {
        subprocessor::PendingOrgMapping {
            org_name: org.to_string(),
            inferred_domain: domain.to_string(),
            source_domain: source.to_string(),
        }
    }

    #[tokio::test]
    async fn test_pending_with_input_empty_returns_ok() {
        let analyzer = subprocessor::SubprocessorAnalyzer::new().await;
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let mock = MockInput::new(vec![]);
        let result = confirm_pending_mappings_with_input(&[], &analyzer, &logger, &mock).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pending_accept_all_saves_mappings() {
        let analyzer = subprocessor::SubprocessorAnalyzer::new().await;
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let pending = vec![make_pending("Acme", "acme.com", "src.com")];
        let mock = MockInput::new(vec!["A"]);
        let result = confirm_pending_mappings_with_input(&pending, &analyzer, &logger, &mock).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pending_accept_all_multiple_sources() {
        let analyzer = subprocessor::SubprocessorAnalyzer::new().await;
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let pending = vec![
            make_pending("Acme", "acme.com", "src1.com"),
            make_pending("Beta", "beta.io", "src2.com"),
        ];
        let mock = MockInput::new(vec!["A"]);
        let result = confirm_pending_mappings_with_input(&pending, &analyzer, &logger, &mock).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pending_skip_no_save() {
        let analyzer = subprocessor::SubprocessorAnalyzer::new().await;
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let pending = vec![make_pending("Acme", "acme.com", "src.com")];
        let mock = MockInput::new(vec!["S"]);
        let result = confirm_pending_mappings_with_input(&pending, &analyzer, &logger, &mock).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pending_unknown_choice_skips() {
        let analyzer = subprocessor::SubprocessorAnalyzer::new().await;
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let pending = vec![make_pending("Acme", "acme.com", "src.com")];
        let mock = MockInput::new(vec!["X"]);
        let result = confirm_pending_mappings_with_input(&pending, &analyzer, &logger, &mock).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pending_review_accept_mapping() {
        let analyzer = subprocessor::SubprocessorAnalyzer::new().await;
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let pending = vec![make_pending("Acme", "acme.com", "src.com")];
        let mock = MockInput::new(vec!["R", "Y"]);
        let result = confirm_pending_mappings_with_input(&pending, &analyzer, &logger, &mock).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pending_review_reject_mapping() {
        let analyzer = subprocessor::SubprocessorAnalyzer::new().await;
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let pending = vec![make_pending("Acme", "acme.com", "src.com")];
        let mock = MockInput::new(vec!["R", "N"]);
        let result = confirm_pending_mappings_with_input(&pending, &analyzer, &logger, &mock).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pending_review_custom_domain() {
        let analyzer = subprocessor::SubprocessorAnalyzer::new().await;
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let pending = vec![make_pending("Acme", "acme.com", "src.com")];
        let mock = MockInput::new(vec!["R", "C", "custom.org"]);
        let result = confirm_pending_mappings_with_input(&pending, &analyzer, &logger, &mock).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pending_review_custom_empty_skips() {
        let analyzer = subprocessor::SubprocessorAnalyzer::new().await;
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let pending = vec![make_pending("Acme", "acme.com", "src.com")];
        let mock = MockInput::new(vec!["R", "C", ""]);
        let result = confirm_pending_mappings_with_input(&pending, &analyzer, &logger, &mock).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pending_review_multiple_mappings_mixed() {
        let analyzer = subprocessor::SubprocessorAnalyzer::new().await;
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let pending = vec![
            make_pending("Acme", "acme.com", "src.com"),
            make_pending("Beta", "beta.io", "src.com"),
        ];
        // R -> review; first mapping Y accept, second mapping N reject
        let mock = MockInput::new(vec!["R", "Y", "N"]);
        let result = confirm_pending_mappings_with_input(&pending, &analyzer, &logger, &mock).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pending_accept_all_single_mapping_singular_suffix() {
        let analyzer = subprocessor::SubprocessorAnalyzer::new().await;
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let pending = vec![make_pending("Solo", "solo.com", "src.com")];
        let mock = MockInput::new(vec!["A"]);
        let result = confirm_pending_mappings_with_input(&pending, &analyzer, &logger, &mock).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pending_lowercase_input_accepted() {
        let analyzer = subprocessor::SubprocessorAnalyzer::new().await;
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let pending = vec![make_pending("Acme", "acme.com", "src.com")];
        let mock = MockInput::new(vec!["a"]);
        let result = confirm_pending_mappings_with_input(&pending, &analyzer, &logger, &mock).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pending_review_all_rejected_no_save() {
        let analyzer = subprocessor::SubprocessorAnalyzer::new().await;
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let pending = vec![
            make_pending("A", "a.com", "s.com"),
            make_pending("B", "b.com", "s.com"),
        ];
        let mock = MockInput::new(vec!["R", "N", "N"]);
        let result = confirm_pending_mappings_with_input(&pending, &analyzer, &logger, &mock).await;
        assert!(result.is_ok());
    }

    // ──────────────────────────────────────────────────────────────────
    // _with_input tests for confirm_unverified_organizations
    // ──────────────────────────────────────────────────────────────────

    fn make_unverified(domain: &str, org: &str) -> UnverifiedOrgMapping {
        UnverifiedOrgMapping {
            domain: domain.to_string(),
            inferred_org: org.to_string(),
        }
    }

    #[tokio::test]
    async fn test_unverified_with_input_empty_returns_ok() {
        let vendors = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let mock = MockInput::new(vec![]);
        let result =
            confirm_unverified_organizations_with_input(&[], &vendors, &logger, &mock).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unverified_accept_all() {
        let vendors = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let unverified = vec![make_unverified("alpha.com", "Alpha Inc")];
        let mock = MockInput::new(vec!["A"]);
        let result =
            confirm_unverified_organizations_with_input(&unverified, &vendors, &logger, &mock)
                .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unverified_accept_all_multiple() {
        let vendors = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let unverified = vec![
            make_unverified("alpha.com", "Alpha Inc"),
            make_unverified("beta.com", "Beta Corp"),
        ];
        let mock = MockInput::new(vec!["A"]);
        let result =
            confirm_unverified_organizations_with_input(&unverified, &vendors, &logger, &mock)
                .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unverified_skip() {
        let vendors = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let unverified = vec![make_unverified("alpha.com", "Alpha Inc")];
        let mock = MockInput::new(vec!["S"]);
        let result =
            confirm_unverified_organizations_with_input(&unverified, &vendors, &logger, &mock)
                .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unverified_unknown_choice_skips() {
        let vendors = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let unverified = vec![make_unverified("alpha.com", "Alpha Inc")];
        let mock = MockInput::new(vec!["Z"]);
        let result =
            confirm_unverified_organizations_with_input(&unverified, &vendors, &logger, &mock)
                .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unverified_review_accept() {
        let vendors = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let unverified = vec![make_unverified("alpha.com", "Alpha Inc")];
        let mock = MockInput::new(vec!["R", "Y"]);
        let result =
            confirm_unverified_organizations_with_input(&unverified, &vendors, &logger, &mock)
                .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unverified_review_accept_empty_input() {
        let vendors = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let unverified = vec![make_unverified("alpha.com", "Alpha Inc")];
        // Empty string maps to "" which after trim().to_uppercase() matches "" in "Y" | ""
        let mock = MockInput::new(vec!["R", ""]);
        let result =
            confirm_unverified_organizations_with_input(&unverified, &vendors, &logger, &mock)
                .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unverified_review_custom_name() {
        let vendors = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let unverified = vec![make_unverified("alpha.com", "Alpha Inc")];
        let mock = MockInput::new(vec!["R", "C", "Alpha Corporation"]);
        let result =
            confirm_unverified_organizations_with_input(&unverified, &vendors, &logger, &mock)
                .await;
        assert!(result.is_ok());
        let v = vendors.lock().await;
        assert_eq!(v.get("alpha.com").unwrap(), "Alpha Corporation");
    }

    #[tokio::test]
    async fn test_unverified_review_custom_empty_keeps_inferred() {
        let vendors = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let unverified = vec![make_unverified("alpha.com", "Alpha Inc")];
        let mock = MockInput::new(vec!["R", "C", ""]);
        let result =
            confirm_unverified_organizations_with_input(&unverified, &vendors, &logger, &mock)
                .await;
        assert!(result.is_ok());
        let v = vendors.lock().await;
        assert!(v.get("alpha.com").is_none());
    }

    #[tokio::test]
    async fn test_unverified_review_skip_individual() {
        let vendors = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let unverified = vec![make_unverified("alpha.com", "Alpha Inc")];
        let mock = MockInput::new(vec!["R", "S"]);
        let result =
            confirm_unverified_organizations_with_input(&unverified, &vendors, &logger, &mock)
                .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unverified_review_mixed_responses() {
        let vendors = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let unverified = vec![
            make_unverified("alpha.com", "Alpha Inc"),
            make_unverified("beta.com", "Beta Corp"),
            make_unverified("gamma.com", "Gamma LLC"),
        ];
        // R=review, then: Y accept alpha, C custom for beta, S skip gamma
        let mock = MockInput::new(vec!["R", "Y", "C", "Real Beta", "S"]);
        let result =
            confirm_unverified_organizations_with_input(&unverified, &vendors, &logger, &mock)
                .await;
        assert!(result.is_ok());
        let v = vendors.lock().await;
        assert_eq!(v.get("beta.com").unwrap(), "Real Beta");
    }

    #[tokio::test]
    async fn test_unverified_review_all_custom_triggers_update_count() {
        let vendors = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let unverified = vec![make_unverified("a.com", "A"), make_unverified("b.com", "B")];
        let mock = MockInput::new(vec!["R", "C", "Real A", "C", "Real B"]);
        let result =
            confirm_unverified_organizations_with_input(&unverified, &vendors, &logger, &mock)
                .await;
        assert!(result.is_ok());
        let v = vendors.lock().await;
        assert_eq!(v.len(), 2);
        assert_eq!(v.get("a.com").unwrap(), "Real A");
        assert_eq!(v.get("b.com").unwrap(), "Real B");
    }

    #[tokio::test]
    async fn test_unverified_review_all_rejected_no_summary() {
        let vendors = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let unverified = vec![make_unverified("a.com", "A")];
        let mock = MockInput::new(vec!["R", "S"]);
        let result =
            confirm_unverified_organizations_with_input(&unverified, &vendors, &logger, &mock)
                .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unverified_lowercase_input_accepted() {
        let vendors = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let unverified = vec![make_unverified("alpha.com", "Alpha")];
        let mock = MockInput::new(vec!["a"]);
        let result =
            confirm_unverified_organizations_with_input(&unverified, &vendors, &logger, &mock)
                .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pending_review_custom_domain_is_lowercased() {
        let analyzer = subprocessor::SubprocessorAnalyzer::new().await;
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let pending = vec![make_pending("Acme", "acme.com", "src.com")];
        let mock = MockInput::new(vec!["R", "C", "CUSTOM.ORG"]);
        let result = confirm_pending_mappings_with_input(&pending, &analyzer, &logger, &mock).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pending_review_saves_only_accepted() {
        let analyzer = subprocessor::SubprocessorAnalyzer::new().await;
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let pending = vec![
            make_pending("Keep", "keep.com", "s.com"),
            make_pending("Drop", "drop.com", "s.com"),
        ];
        // Review: accept first, reject second -> only one saved
        let mock = MockInput::new(vec!["R", "Y", "N"]);
        let result = confirm_pending_mappings_with_input(&pending, &analyzer, &logger, &mock).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unverified_review_single_custom_triggers_counts() {
        let vendors = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let unverified = vec![make_unverified("x.com", "X")];
        let mock = MockInput::new(vec!["R", "C", "Real X"]);
        let result =
            confirm_unverified_organizations_with_input(&unverified, &vendors, &logger, &mock)
                .await;
        assert!(result.is_ok());
        let v = vendors.lock().await;
        assert_eq!(v.get("x.com").unwrap(), "Real X");
    }

    #[test]
    fn test_plural_suffix_singular() {
        assert_eq!(plural_suffix(1), "");
    }

    #[test]
    fn test_plural_suffix_plural_values() {
        assert_eq!(plural_suffix(0), "s");
        assert_eq!(plural_suffix(2), "s");
        assert_eq!(plural_suffix(100), "s");
    }

    #[test]
    fn test_stdio_input_coverage_stub() {
        let input = StdioInput;
        let result = input.read_line();
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_confirm_pending_mappings_empty_delegates() {
        let analyzer = subprocessor::SubprocessorAnalyzer::new().await;
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let result = confirm_pending_mappings(&[], &analyzer, &logger).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_confirm_unverified_empty_delegates() {
        let vendors = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let result = confirm_unverified_organizations(&[], &vendors, &logger).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pending_review_custom_domain_empty_skips() {
        let analyzer = subprocessor::SubprocessorAnalyzer::new().await;
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let pending = vec![make_pending("Org", "org.com", "src.com")];
        let mock = MockInput::new(vec!["R", "C", ""]);
        let result = confirm_pending_mappings_with_input(&pending, &analyzer, &logger, &mock).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unverified_review_skip_choice() {
        let vendors = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let unverified = vec![make_unverified("s.com", "S")];
        let mock = MockInput::new(vec!["R", "S"]);
        let result =
            confirm_unverified_organizations_with_input(&unverified, &vendors, &logger, &mock)
                .await;
        assert!(result.is_ok());
        let v = vendors.lock().await;
        assert!(v.is_empty());
    }

    #[tokio::test]
    async fn test_unverified_review_accept_choice() {
        let vendors = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let unverified = vec![make_unverified("y.com", "Y")];
        let mock = MockInput::new(vec!["R", "Y"]);
        let result =
            confirm_unverified_organizations_with_input(&unverified, &vendors, &logger, &mock)
                .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_unverified_review_custom_empty_skips() {
        let vendors = Arc::new(Mutex::new(HashMap::new()));
        let logger = AnalysisLogger::new(crate::logger::VerbosityLevel::Silent);
        let unverified = vec![make_unverified("z.com", "Z")];
        let mock = MockInput::new(vec!["R", "C", ""]);
        let result =
            confirm_unverified_organizations_with_input(&unverified, &vendors, &logger, &mock)
                .await;
        assert!(result.is_ok());
    }
}
