//! Embedded domain → organization dataset (CC BY-SA 4.0, AdGuard companiesdb).
//!
//! This is the widest attribution tier the scanner can consult without a network
//! call. It sits BELOW every curated/user tier (local overrides, known_vendors,
//! vendor_registry) and ABOVE every inference tier (web scrape, WHOIS, NER), which is
//! exactly where its reliability sits: an independently-maintained public dataset is
//! more trustworthy than anything we scrape off the vendor's own page, and less
//! trustworthy than a human-confirmed mapping.
//!
//! # Licensing
//!
//! `data/companies.tsv` is derived from AdGuard companiesdb and is licensed **CC BY-SA
//! 4.0**, not MIT. It is loaded here as a standalone artifact and is never merged into
//! the MIT-licensed curated vendor data. See `data/README.md`.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::domain_utils;

/// The raw dataset, embedded at compile time so a default scan needs no network and no
/// config. ~5.1k domains, ~135 KB.
const COMPANIES_TSV: &str = include_str!("../data/companies.tsv");

/// Parsed dataset: `domain -> organization`, plus the upstream snapshot version.
#[derive(Debug)]
pub struct OrgDataset {
    by_domain: HashMap<String, String>,
    version: String,
}

impl OrgDataset {
    /// Parse the embedded TSV. Comment lines (`#`) carry provenance; the
    /// `# dataset_version:` line is the upstream snapshot timestamp.
    fn parse(tsv: &str) -> Self {
        let mut by_domain = HashMap::new();
        let mut version = String::from("unknown");

        for line in tsv.lines() {
            if let Some(rest) = line.strip_prefix('#') {
                if let Some(v) = rest.trim().strip_prefix("dataset_version:") {
                    version = v.trim().to_string();
                }
                continue;
            }
            let Some((domain, org)) = line.split_once('\t') else {
                continue;
            };
            let domain = domain.trim().to_lowercase();
            let org = org.trim();
            if domain.is_empty() || org.is_empty() {
                continue;
            }
            by_domain.insert(domain, org.to_string());
        }

        Self { by_domain, version }
    }

    /// Number of domain → organization mappings loaded.
    pub fn len(&self) -> usize {
        self.by_domain.len()
    }

    /// Whether the dataset failed to load any mappings (a build/packaging error).
    pub fn is_empty(&self) -> bool {
        self.by_domain.is_empty()
    }

    /// Upstream snapshot version, so a stale mapping is auditable rather than silently
    /// asserted as current truth.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Look up a domain, then its registrable base domain.
    ///
    /// The two-step matches how the dataset is keyed: it lists both exact tracker hosts
    /// (`analytics.163.com`) and registrable domains (`doubleclick.net`), so an exact hit
    /// is more specific and is preferred, with the eTLD+1 as the fallback.
    pub fn lookup(&self, domain: &str) -> Option<&str> {
        let domain = domain.trim().trim_end_matches('.').to_lowercase();
        if domain.is_empty() {
            return None;
        }
        if let Some(org) = self.by_domain.get(&domain) {
            return Some(org.as_str());
        }
        let base = domain_utils::extract_base_domain(&domain);
        if base != domain {
            if let Some(org) = self.by_domain.get(&base) {
                return Some(org.as_str());
            }
        }
        None
    }
}

static DATASET: OnceLock<OrgDataset> = OnceLock::new();

/// The process-wide embedded dataset, parsed once on first use.
pub fn dataset() -> &'static OrgDataset {
    DATASET.get_or_init(|| OrgDataset::parse(COMPANIES_TSV))
}

/// Look up a domain's organization in the embedded dataset.
pub fn lookup(domain: &str) -> Option<&'static str> {
    dataset().lookup(domain)
}

/// Upstream snapshot version of the embedded dataset.
pub fn version() -> &'static str {
    dataset().version()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_dataset_loads_a_substantial_number_of_domains() {
        // Guards against a packaging error silently shipping an empty tier. The upstream
        // snapshot had 5,125 rows; allow shrinkage but not collapse.
        assert!(
            dataset().len() >= 4_500,
            "embedded dataset only loaded {} domains",
            dataset().len()
        );
    }

    #[test]
    fn dataset_version_is_recorded() {
        assert_ne!(version(), "unknown");
        assert!(version().starts_with("20"), "version: {}", version());
    }

    #[test]
    fn looks_up_well_known_tracker_domains() {
        // Spot-checks across distinct owners — these are the domains a real scan trips
        // over constantly and which the curated 280-entry tier never covered.
        assert_eq!(lookup("doubleclick.net"), Some("Google"));
        assert_eq!(lookup("google-analytics.com"), Some("Google"));
    }

    #[test]
    fn falls_back_to_the_registrable_base_domain() {
        // An arbitrary host under a listed registrable domain still attributes.
        let direct = lookup("doubleclick.net").expect("base domain is listed");
        assert_eq!(lookup("stats.g.doubleclick.net"), Some(direct));
    }

    #[test]
    fn unknown_domains_return_none_rather_than_guessing() {
        assert_eq!(
            lookup("this-domain-is-not-in-the-dataset-xyzzy.example"),
            None
        );
        assert_eq!(lookup(""), None);
    }

    #[test]
    fn lookup_is_case_and_trailing_dot_insensitive() {
        let expected = lookup("doubleclick.net");
        assert!(expected.is_some());
        assert_eq!(lookup("DoubleClick.NET"), expected);
        assert_eq!(lookup("doubleclick.net."), expected);
    }

    #[test]
    fn no_mapping_has_an_empty_organization() {
        // A blank org would render as an attributed-but-nameless vendor.
        assert!(dataset().by_domain.values().all(|o| !o.trim().is_empty()));
    }
}
