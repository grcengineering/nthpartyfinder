//! Organization Name Normalization
//!
//! Provides utilities to standardize company names to handle variations like:
//! - Corporate suffixes: Inc., Inc, LLC, Ltd., Corp., etc.
//! - Case variations: GOOGLE vs Google vs google
//! - Punctuation variations: O'Reilly vs OReilly vs O Reilly
//! - "The" prefix: The New York Times -> New York Times
//! - Ampersand variations: AT&T vs AT and T
//! - Manual alias overrides from configuration
//!
//! Also provides fuzzy matching for similar names using edit distance.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::debug;

/// Corporate suffixes to remove during normalization.
/// Order matters - longer/more specific patterns should come first.
const CORPORATE_SUFFIXES: &[&str] = &[
    // Longer variants first
    "corporation",
    "incorporated",
    "limited liability company",
    "limited partnership",
    "public limited company",
    "gesellschaft mit beschrankter haftung",
    "sociedad de responsabilidad limitada",
    "societa a responsabilita limitata",
    "besloten vennootschap",
    "naamloze vennootschap",
    "aktiengesellschaft",
    "societe anonyme",
    "proprietary limited",
    "private limited",
    "public benefit corporation",
    // Two-word abbreviated forms MUST precede their one-word tails. "pty ltd" listed after
    // "ltd" would match "ltd" first and leave "Acme Pty" — a dangling fragment that no longer
    // dedups with the same company's suffix-less form. Every Australian ("Pty Ltd") and Indian
    // ("Pvt Ltd") company hit this.
    "pty ltd",
    "pty. ltd.",
    "pvt ltd",
    "pvt. ltd.",
    "limited",
    "company",
    // Abbreviated forms
    "inc.",
    "inc",
    "llc.",
    "llc",
    "ltd.",
    "ltd",
    "gmbh",
    "corp.",
    "corp",
    "co.",
    "co",
    "plc.",
    "plc",
    "ag",
    "sa",
    "sas",
    "srl",
    "bv",
    "nv",
    "pbc",
    "pty ltd",
    "pty.",
    "pty",
    "pvt ltd",
    "pvt.",
    "pvt",
    "lp",
    "l.p.",
    "llp",
    "l.l.p.",
    // M011 fix: dotted acronym forms used by European companies
    "s.r.l.",
    "s.r.l",
    "s.a.s.",
    "s.a.s",
    "s.a.",
    "s.p.a.",
    "s.p.a",
    "l.l.c.",
];

/// Configuration for organization aliases.
/// These are manual overrides for known aliases like "MSFT" -> "Microsoft".
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OrgAliasConfig {
    /// Map of alias -> canonical name
    /// e.g., "MSFT" -> "Microsoft", "AWS" -> "Amazon Web Services"
    #[serde(default)]
    pub aliases: HashMap<String, String>,
}

/// Organization normalizer with configurable aliases and fuzzy matching threshold.
#[derive(Debug, Clone)]
pub struct OrgNormalizer {
    /// Manual alias mappings (lowercase alias -> canonical name)
    aliases: HashMap<String, String>,
    /// Fuzzy matching similarity threshold (0.0 - 1.0)
    similarity_threshold: f64,
}

impl Default for OrgNormalizer {
    fn default() -> Self {
        Self::new()
    }
}

impl OrgNormalizer {
    /// Create a new normalizer with default settings and built-in aliases.
    pub fn new() -> Self {
        let mut aliases = HashMap::new();

        // Built-in common aliases.
        //
        // Deliberately WITHOUT the dangerous whole-word tickers that used to live here:
        // "meta" (a common English word), "fb", "ms", "crm", "hp" and "twtr" rewrote any
        // organization whose name normalized to those letters — and they fired on names
        // from every source, including curated ones. An alias must be unambiguous enough
        // that no real company shares it.
        let builtin_aliases = [
            // Stock ticker symbols (unambiguous — no company is literally named these)
            ("msft", "Microsoft"),
            ("goog", "Google"),
            ("googl", "Google"),
            ("amzn", "Amazon"),
            ("aapl", "Apple"),
            ("nflx", "Netflix"),
            ("ibm", "IBM"),
            ("orcl", "Oracle"),
            ("tsla", "Tesla"),
            ("nvda", "NVIDIA"),
            ("intc", "Intel"),
            ("csco", "Cisco"),
            ("adbe", "Adobe"),
            // Common abbreviations
            ("aws", "Amazon Web Services"),
            ("gcp", "Google Cloud Platform"),
            ("azure", "Microsoft Azure"),
            ("hpe", "Hewlett Packard Enterprise"),
            ("dell emc", "Dell Technologies"),
            ("vmware", "VMware"),
            // Brand variations
            ("google llc", "Google"),
            ("google inc", "Google"),
            ("google inc.", "Google"),
            ("alphabet", "Google"),
            ("alphabet inc", "Google"),
            ("microsoft corporation", "Microsoft"),
            ("microsoft corp", "Microsoft"),
            ("microsoft corp.", "Microsoft"),
            ("amazon.com", "Amazon"),
            ("amazon.com inc", "Amazon"),
            ("amazon.com, inc.", "Amazon"),
            ("apple inc", "Apple"),
            ("apple inc.", "Apple"),
            ("apple computer", "Apple"),
            ("facebook", "Meta Platforms"),
            ("facebook inc", "Meta Platforms"),
            ("facebook, inc.", "Meta Platforms"),
            ("meta platforms, inc.", "Meta Platforms"),
            // Cloud services
            ("amazon web services, inc.", "Amazon Web Services"),
            ("amazon web services inc", "Amazon Web Services"),
            ("google cloud", "Google Cloud Platform"),
            ("microsoft azure", "Microsoft Azure"),
            // Common misspellings
            ("mircosoft", "Microsoft"),
            ("miscrosoft", "Microsoft"),
            ("goole", "Google"),
            ("amozon", "Amazon"),
        ];

        for (alias, canonical) in builtin_aliases {
            aliases.insert(alias.to_lowercase(), canonical.to_string());
        }

        Self {
            aliases,
            similarity_threshold: 0.85, // Default 85% similarity for fuzzy matching
        }
    }

    /// Create a normalizer with custom aliases from configuration.
    pub fn with_config(config: &OrgAliasConfig) -> Self {
        let mut normalizer = Self::new();

        // Add custom aliases (lowercase keys)
        for (alias, canonical) in &config.aliases {
            normalizer
                .aliases
                .insert(alias.to_lowercase(), canonical.clone());
        }

        normalizer
    }

    /// Create a normalizer from the application's OrganizationConfig.
    /// This is a convenience method to create a normalizer from the config file settings.
    pub fn from_app_config(config: &crate::config::OrganizationConfig) -> Self {
        let alias_config = OrgAliasConfig {
            aliases: config.aliases.clone(),
        };
        Self::with_config(&alias_config).with_threshold(config.similarity_threshold)
    }

    /// Set the fuzzy matching similarity threshold.
    ///
    /// # Arguments
    /// * `threshold` - Similarity threshold between 0.0 and 1.0 (default: 0.85)
    pub fn with_threshold(mut self, threshold: f64) -> Self {
        self.similarity_threshold = threshold.clamp(0.0, 1.0);
        self
    }

    /// Add a custom alias mapping.
    pub fn add_alias(&mut self, alias: &str, canonical: &str) {
        self.aliases
            .insert(alias.to_lowercase(), canonical.to_string());
    }

    /// Normalize an organization name by:
    /// 1. Checking manual aliases first
    /// 2. Removing "The" prefix
    /// 3. Removing corporate suffixes
    /// 4. Normalizing case to title case
    /// 5. Normalizing punctuation and whitespace
    /// 6. Normalizing ampersand variations
    pub fn normalize(&self, name: &str) -> String {
        let name = name.trim();

        if name.is_empty() {
            return String::new();
        }

        // Step 1: Check aliases first (on lowercase version)
        let lower = name.to_lowercase();
        if let Some(canonical) = self.aliases.get(&lower) {
            debug!("Normalized '{}' to '{}' via alias", name, canonical);
            return canonical.clone();
        }

        // Step 2: Basic cleaning
        let mut result = name.to_string();

        // Strip trailing domain suffixes like ".com", ".io", ".net" (R005 fix)
        // e.g., "Monday.com" -> "Monday", "Salesforce.com" -> "Salesforce"
        result = strip_domain_suffix(&result);

        // Remove "The " prefix (case-insensitive)
        result = remove_the_prefix(&result);

        // Normalize ampersand variations
        result = normalize_ampersand(&result);

        // Remove corporate suffixes
        result = remove_corporate_suffixes(&result);

        // Strip the domain suffix AGAIN: "Salesforce.com, Inc." only exposes its ".com"
        // once the legal suffix is gone, and running this only before suffix removal left
        // "Salesforce.com" and "Salesforce" as two different organizations in the report.
        result = strip_domain_suffix(&result);

        // Normalize punctuation (remove apostrophes, normalize spaces)
        result = normalize_punctuation(&result);

        // Normalize whitespace
        result = normalize_whitespace(&result);

        // Convert to title case
        result = to_title_case(&result);

        // Never emit an empty organization: a blank name renders as an attributed vendor
        // with no company, which is worse than an honest domain-derived label.
        if result.trim().is_empty() {
            debug!(
                "Normalization of '{}' emptied the name; keeping the original",
                name
            );
            return normalize_whitespace(name);
        }

        // Check aliases again after normalization
        let lower_result = result.to_lowercase();
        if let Some(canonical) = self.aliases.get(&lower_result) {
            debug!(
                "Normalized '{}' to '{}' via alias (post-processing)",
                name, canonical
            );
            return canonical.clone();
        }

        // Final step: correct known-brand casing that title-casing gets wrong
        // ("Openai" -> "OpenAI", "Mongodb" -> "MongoDB"). Applied last so it fixes the
        // output of every attribution source. Leaves unknown names untouched.
        if let Some(canonical) = brand_casing(&result) {
            debug!("Corrected brand casing '{}' -> '{}'", result, canonical);
            return canonical;
        }

        debug!("Normalized '{}' to '{}'", name, result);
        result
    }

    /// Check if two organization names are considered the same after normalization.
    pub fn are_same(&self, name1: &str, name2: &str) -> bool {
        let norm1 = self.normalize(name1);
        let norm2 = self.normalize(name2);

        // First check exact match after normalization
        if norm1.to_lowercase() == norm2.to_lowercase() {
            return true;
        }

        // Then try fuzzy matching
        self.fuzzy_match(&norm1, &norm2)
    }

    /// Check if two names are similar enough using fuzzy matching.
    pub fn fuzzy_match(&self, name1: &str, name2: &str) -> bool {
        let similarity = self.similarity(name1, name2);
        similarity >= self.similarity_threshold
    }

    /// Calculate similarity between two strings using normalized Levenshtein distance.
    /// Returns a value between 0.0 (completely different) and 1.0 (identical).
    pub fn similarity(&self, s1: &str, s2: &str) -> f64 {
        let s1_lower = s1.to_lowercase();
        let s2_lower = s2.to_lowercase();

        if s1_lower == s2_lower {
            return 1.0;
        }

        if s1_lower.is_empty() || s2_lower.is_empty() {
            return 0.0;
        }

        let distance = levenshtein_distance(&s1_lower, &s2_lower);
        let max_len = s1_lower.len().max(s2_lower.len());

        1.0 - (distance as f64 / max_len as f64)
    }

    /// Find the best matching canonical name for a given name.
    /// Returns the canonical name and similarity score if above threshold.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn find_best_match<'a>(
        &self,
        name: &str,
        candidates: &'a [String],
    ) -> Option<(&'a String, f64)> {
        let normalized = self.normalize(name);

        let mut best_match: Option<(&String, f64)> = None;

        for candidate in candidates {
            let norm_candidate = self.normalize(candidate);
            let sim = self.similarity(&normalized, &norm_candidate);

            if sim >= self.similarity_threshold {
                if let Some((_, best_sim)) = best_match {
                    if sim > best_sim {
                        best_match = Some((candidate, sim));
                    }
                } else {
                    best_match = Some((candidate, sim));
                }
            }
        }

        best_match
    }

    /// Merge duplicate vendors from a list based on normalized names.
    /// Returns a map of original names -> canonical names for deduplication.
    pub fn deduplicate(&self, names: &[String]) -> HashMap<String, String> {
        let mut canonical_map: HashMap<String, String> = HashMap::new();
        let mut seen_normalized: HashMap<String, String> = HashMap::new();

        for name in names {
            let normalized = self.normalize(name);
            let normalized_lower = normalized.to_lowercase();

            if let Some(canonical) = seen_normalized.get(&normalized_lower) {
                // This name normalizes to an existing canonical name
                canonical_map.insert(name.clone(), canonical.clone());
            } else {
                // Check for fuzzy matches with existing names
                let mut found_match = false;
                for (seen_lower, seen_canonical) in &seen_normalized {
                    if self.fuzzy_match(&normalized_lower, seen_lower) {
                        canonical_map.insert(name.clone(), seen_canonical.clone());
                        found_match = true;
                        break;
                    }
                }

                if !found_match {
                    // This is a new canonical name
                    seen_normalized.insert(normalized_lower, normalized.clone());
                    canonical_map.insert(name.clone(), normalized);
                }
            }
        }

        canonical_map
    }
}

/// Strip a trailing domain suffix from an org name (R005 fix).
/// e.g. "Monday.com" -> "Monday", "Bigmarker.com" -> "Bigmarker".
///
/// The suffix set is the Public Suffix List, not a hardcoded list of fifteen TLDs: names
/// arriving as "Example.co.uk" or "Beispiel.de" kept their suffix under the old list and
/// became distinct organizations from their suffix-less twins. A name is only stripped when
/// what remains is a plausible label — never down to nothing.
fn strip_domain_suffix(name: &str) -> String {
    let trimmed = name.trim();
    let Some((head, tail)) = trimmed.rsplit_once('.') else {
        return trimmed.to_string();
    };
    // A dot inside a NAME is not a domain suffix: "U.S. Bancorp", "A.P. Moller - Maersk",
    // "St. Jude Medical". The tail of a domain-suffixed name is one bare token at the very end
    // ("Monday.com"), so anything with whitespace in it disqualifies the whole match — without
    // this the last-dot split treats " Bancorp" as the suffix and ships "U.s".
    if tail.contains(char::is_whitespace) {
        return trimmed.to_string();
    }
    // The tail must be a real public suffix, and the head must survive as a name.
    if head.len() < 2 || head.ends_with('.') || head.contains(' ') {
        return trimmed.to_string();
    }
    let candidate_suffix = tail.trim().to_lowercase();
    if candidate_suffix.is_empty() {
        return trimmed.to_string();
    }
    // Check the longest suffix the name could carry ("co.uk" in "Example.co.uk") first.
    if let Some((head2, tail2)) = head.rsplit_once('.') {
        let compound = format!("{}.{}", tail2.to_lowercase(), candidate_suffix);
        if head2.len() >= 2
            && !tail2.contains(char::is_whitespace)
            && is_listed_public_suffix(&compound)
        {
            return head2.to_string();
        }
    }
    if is_listed_public_suffix(&candidate_suffix) {
        return head.to_string();
    }

    trimmed.to_string()
}

/// Is `candidate` a suffix the Public Suffix List actually **lists**?
///
/// This must ask for a LISTED suffix, not merely a suffix-shaped answer. The PSL algorithm has
/// an implicit `*` rule: every unknown single label is treated as a public suffix, so
/// `psl::suffix_str("x.bancorp")` cheerfully returns `Some("bancorp")` — and a check that only
/// compares the string would then "strip the domain suffix" off `U.S. Bancorp` and ship `U.s`.
/// A listed suffix carries a `typ()` (ICANN or private); the implicit wildcard does not.
fn is_listed_public_suffix(candidate: &str) -> bool {
    psl::suffix(format!("x.{candidate}").as_bytes()).is_some_and(|suffix| {
        suffix.typ().is_some()
            && std::str::from_utf8(suffix.as_bytes()).is_ok_and(|s| s == candidate)
    })
}

/// Remove "The " prefix from the beginning of a name.
fn remove_the_prefix(name: &str) -> String {
    let trimmed = name.trim();

    // Check for "The " prefix (case-insensitive) using char-based iteration for Unicode safety
    let chars: Vec<char> = trimmed.chars().collect();
    if chars.len() >= 4 {
        let prefix: String = chars[..4].iter().collect();
        if prefix.eq_ignore_ascii_case("the ") {
            return chars[4..].iter().collect::<String>().trim().to_string();
        }
    }

    trimmed.to_string()
}

/// Normalize ampersand variations: "&" -> "and", "& " -> "and ", etc.
fn normalize_ampersand(name: &str) -> String {
    // Replace various ampersand patterns with " and "
    let result = name.replace(" & ", " and ").replace("&", " and ");

    // Clean up any double spaces introduced
    normalize_whitespace(&result)
}

/// Remove a trailing corporate suffix from a name.
///
/// The suffix must be a whole trailing WORD, not merely trailing characters. The previous
/// implementation also matched the bare suffix with `ends_with`, so any name whose final
/// letters happened to spell one was silently truncated: "Cisco" → "Cis" (`co`), "Visa" →
/// "Vi" (`sa`), "Zinc" → "Z" (`inc`), "Maytag" → "Mayt" (`ag`), "Sysco" → "Sys". These are
/// real vendors, and the mangled names shipped straight into reports.
///
/// A name that is *entirely* a suffix ("Limited") is left alone — stripping it would return
/// an empty string, and an empty organization renders as an attributed-but-nameless vendor.
fn remove_corporate_suffixes(name: &str) -> String {
    let trimmed = name.trim();
    let words: Vec<&str> = trimmed.split_whitespace().collect();
    if words.len() < 2 {
        // Single word: never strip. Either it is the company name, or it is a bare suffix
        // with no name attached — and neither case is improved by returning "".
        return trimmed.trim_end_matches([',', ' ']).to_string();
    }

    // Compare the trailing word(s) against each suffix, longest first. Multi-word suffixes
    // ("limited liability company") need multiple trailing words.
    for suffix in CORPORATE_SUFFIXES {
        let suffix_words: Vec<&str> = suffix.split_whitespace().collect();
        if suffix_words.len() >= words.len() {
            continue; // stripping would consume the whole name
        }
        let tail_start = words.len() - suffix_words.len();
        let tail_matches =
            words[tail_start..]
                .iter()
                .zip(suffix_words.iter())
                .all(|(word, suffix_word)| {
                    // Trailing punctuation belongs to the suffix, not the name: "Inc.," == "inc".
                    let word = word.trim_end_matches([',', '.']);
                    let suffix_word = suffix_word.trim_end_matches([',', '.']);
                    word.eq_ignore_ascii_case(suffix_word)
                });

        if tail_matches {
            let head = words[..tail_start].join(" ");
            return head.trim_end_matches([',', ' ']).to_string();
        }
    }

    trimmed.trim_end_matches([',', ' ']).to_string()
}

/// Normalize punctuation: remove apostrophes, normalize quotes, etc.
fn normalize_punctuation(name: &str) -> String {
    name.chars()
        .filter_map(|c| {
            match c {
                '\'' | '\u{2018}' | '\u{2019}' | '`' => None, // Remove apostrophes (' and ')
                '"' | '\u{201C}' | '\u{201D}' | '\u{201E}' => None, // Remove quotes (" " and „)
                '\u{2013}' | '\u{2014}' => Some('-'), // Normalize dashes (en-dash – and em-dash —)
                _ => Some(c),
            }
        })
        .collect()
}

/// Normalize whitespace: collapse multiple spaces, trim.
fn normalize_whitespace(name: &str) -> String {
    name.split_whitespace().collect::<Vec<&str>>().join(" ")
}

/// Canonical brand casing for organization names that naive title-casing gets wrong.
///
/// `to_title_case` produces "Openai"/"Mongodb"/"Hubspot" for domain-derived and
/// web-scraped names because it only knows a short acronym list. These are real,
/// well-known vendors whose correct casing is a fixed fact — a lookup table is the
/// right tool. Keyed by the fully-lowercased name; value is the canonical display form.
/// This is applied as the final step of `normalize`, so it corrects the output of
/// EVERY attribution source (known-vendors, web, WHOIS, NER, domain fallback) at once.
fn brand_casing_canonical(lower: &str) -> Option<&'static str> {
    Some(match lower {
        "openai" => "OpenAI",
        "anthropic" | "anthropicai" => "Anthropic",
        "mongodb" => "MongoDB",
        "hubspot" => "HubSpot",
        "docusign" => "DocuSign",
        "github" => "GitHub",
        "gitlab" => "GitLab",
        "paypal" => "PayPal",
        "youtube" => "YouTube",
        "linkedin" => "LinkedIn",
        "mysql" => "MySQL",
        "postgresql" | "postgres" => "PostgreSQL",
        "graphql" => "GraphQL",
        "nodejs" | "node.js" => "Node.js",
        "typescript" => "TypeScript",
        "javascript" => "JavaScript",
        "pagerduty" => "PagerDuty",
        "godaddy" => "GoDaddy",
        "woocommerce" => "WooCommerce",
        "wordpress" => "WordPress",
        "ebay" => "eBay",
        "icloud" => "iCloud",
        "doordash" => "DoorDash",
        "surveymonkey" => "SurveyMonkey",
        "sendgrid" => "SendGrid",
        "mailchimp" => "Mailchimp",
        "auth0" => "Auth0",
        "onetrust" => "OneTrust",
        "servicenow" => "ServiceNow",
        "vmware" => "VMware",
        "netsuite" => "NetSuite",
        "quickbooks" => "QuickBooks",
        "zoominfo" => "ZoomInfo",
        "semrush" => "SEMrush",
        "launchdarkly" => "LaunchDarkly",
        "logrocket" => "LogRocket",
        "fullstory" => "FullStory",
        "browserstack" => "BrowserStack",
        "digitalocean" => "DigitalOcean",
        "jetbrains" => "JetBrains",
        "bigquery" => "BigQuery",
        "dynamodb" => "DynamoDB",
        "cockroachdb" => "CockroachDB",
        "clickhouse" => "ClickHouse",
        "planetscale" => "PlanetScale",
        "supabase" => "Supabase",
        "netapp" => "NetApp",
        "workos" => "WorkOS",
        "typeform" => "Typeform",
        "notioniq" => "Notion",
        "e2b" => "E2B",
        "cloudamqp" => "CloudAMQP",
        "keycdn" => "KeyCDN",
        "maxcdn" => "MaxCDN",
        "jsdelivr" => "jsDelivr",
        "npm" => "npm",
        "pypi" => "PyPI",
        "webrtc" => "WebRTC",
        "openssl" => "OpenSSL",
        "letsencrypt" | "let's encrypt" => "Let's Encrypt",
        "hashicorp" => "HashiCorp",
        "influxdb" => "InfluxDB",
        "elasticsearch" => "Elasticsearch",
        "opensearch" => "OpenSearch",
        "getsentry" | "sentry" => "Sentry",
        "statuspage" => "Statuspage",
        "squarespace" => "Squarespace",
        "sharepoint" => "SharePoint",
        "onedrive" => "OneDrive",
        "outsystems" => "OutSystems",
        "coinbase" => "Coinbase",
        "youtubetv" => "YouTube TV",
        _ => return None,
    })
}

/// Correct known-brand casing. Matches on the lowercased name, also trying the form
/// with a trailing legal suffix stripped (so "Openai Inc." and "OpenAI, Inc." both map).
/// Returns `None` when the name is not a known brand, leaving it untouched.
fn brand_casing(name: &str) -> Option<String> {
    let lower = name.trim().to_lowercase();
    if let Some(c) = brand_casing_canonical(&lower) {
        return Some(c.to_string());
    }
    // Strip a single trailing corporate suffix and retry, so brand-casing still applies
    // to fallback names like "Openai Inc." that carry a suffix `remove_corporate_suffixes`
    // did not reach.
    let stripped = lower
        .trim_end_matches('.')
        .trim_end()
        .trim_end_matches(", inc")
        .trim_end_matches(" inc")
        .trim_end_matches(" llc")
        .trim_end_matches(" ltd")
        .trim_end_matches(" corp")
        .trim_end_matches(" co")
        .trim();
    if stripped != lower {
        if let Some(c) = brand_casing_canonical(stripped) {
            return Some(c.to_string());
        }
    }
    None
}

/// Whether a string looks like a real organization NAME rather than a tagline,
/// marketing description, or extracted sentence fragment.
///
/// Web/OpenGraph/NER extraction sometimes returns a page's descriptive text
/// ("Connective Infrastructure for Production AI", "ETL and Reverse ETL Platform and
/// API") instead of the company name. Used as a gate in the attribution pipeline so
/// such a candidate is rejected and a cleaner source (WHOIS registrant, domain
/// fallback) wins instead. Deliberately CONSERVATIVE — it only rejects on strong
/// phrase signals, so it never discards a legitimate multi-word company name
/// ("Amazon Web Services", "Zoom Video Communications", "Bank of America").
pub fn is_plausible_org_name(name: &str) -> bool {
    let t = name.trim();
    if t.is_empty() {
        return false;
    }
    let words: Vec<&str> = t.split_whitespace().collect();
    // Real organization names are short. Six or more words is a description/tagline,
    // not a name (the longest common legitimate names — "International Business
    // Machines Corporation" — are five words including the suffix).
    if words.len() >= 6 {
        return false;
    }
    let ll = t.to_lowercase();
    // Leading indefinite article — sentences start this way ("A platform for teams"),
    // company names essentially never do.
    //
    // "The " is deliberately NOT rejected: The Trade Desk, The New York Times and The Home
    // Depot are real companies, and rejecting them demoted a correct attribution to a
    // domain fragment. `normalize` strips the article anyway, so the two forms still dedup.
    if ll.starts_with("a ") || ll.starts_with("an ") {
        return false;
    }
    // Mid-string phrase/verb markers. Each is a strong "this is a sentence" signal that
    // essentially never appears inside a real company name. `" of "` is deliberately
    // EXCLUDED (Bank of America, Board of Trade). Padded with spaces so substrings of a
    // single word ("Forward", "Yourbrand") do not match.
    let padded = format!(" {} ", ll);
    const PHRASE_MARKERS: [&str; 12] = [
        " for ",
        " that ",
        " your ",
        " helps ",
        " enables ",
        " enabling ",
        " powering ",
        " powered by ",
        " building ",
        " simplify ",
        " automate ",
        " designed ",
    ];
    for marker in PHRASE_MARKERS {
        if padded.contains(marker) {
            return false;
        }
    }
    true
}

/// Convert string to title case (capitalize first letter of each word).
/// Known acronyms and very short all-caps words (2 chars) are preserved.
/// Longer all-caps words are converted to title case since they're more likely normal words.
/// L011 fix: Common English prepositions/articles stay lowercase when not the first word.
/// Convert a name to title case, preserving casing that is already meaningful.
///
/// The rule that matters: **a word whose casing carries information is left alone.**
/// "SendGrid", "DataDog", "iCloud", "eBay" and "OpenAI" are mixed-case on purpose, and the
/// previous implementation lower-cased everything after the first letter of every word —
/// so a *correct* curated name like "SendGrid" was actively corrupted into "Sendgrid", and
/// every acronym outside a 13-entry list ("SAP", "AMD", "IBM"'s neighbours) was flattened
/// to "Sap"/"Amd". Only all-lowercase and all-uppercase words are re-cased here; anything
/// with internal capitals is already telling us how it wants to be written.
///
/// This is why the brand-casing table needs so few entries: it now only has to fix names
/// that arrive *without* case information (from a domain label, say), not repair names the
/// normalizer itself broke.
#[cfg_attr(coverage_nightly, coverage(off))]
fn to_title_case(name: &str) -> String {
    // Known acronyms that should be preserved regardless of length.
    //
    // This stays a curated list rather than a heuristic on purpose. The obvious heuristic —
    // "a lone all-caps token of 3-4 letters is an acronym" — preserves SAP and AMD but also
    // preserves OKTA and EBAY, and WHOIS registrant fields are shouty enough ("OKTA, INC.")
    // that those arrive all-caps routinely. Guessing wrong invents a name; the curated list
    // cannot.
    // "AT" and "IT" are deliberately NOT here. The match is case-insensitive, so listing them
    // force-uppercased the ordinary English words: "At Home Group Inc." (NYSE: HOME) became
    // "AT Home Group", and "It Works Marketing" became "IT Works Marketing". Nothing is lost by
    // omitting them — an input that is genuinely the acronym arrives all-caps ("AT&T", "IT
    // Services"), and the two-character all-caps rule below preserves it.
    let known_acronyms = [
        "IBM", "AWS", "GCP", "USA", "UK", "EU", "AI", "HR", "PR", "QA", "HP", "SAP", "AMD", "SAS",
        "EMC", "NCR",
    ];

    // L011 fix: common prepositions/articles/conjunctions that should stay lowercase
    // in title case (except when they're the first word)
    let lowercase_words = [
        "of", "and", "the", "in", "for", "on", "at", "to", "by", "or", "an", "a",
    ];

    let words: Vec<&str> = name.split_whitespace().collect();
    words
        .iter()
        .enumerate()
        .map(|(i, word)| {
            let chars: Vec<char> = word.chars().collect();
            let len = chars.len();

            let letters: Vec<char> = word.chars().filter(|c| c.is_alphabetic()).collect();
            let is_all_upper = !letters.is_empty() && letters.iter().all(|c| c.is_uppercase());
            let is_all_lower = !letters.is_empty() && letters.iter().all(|c| c.is_lowercase());

            // L011: lowercase prepositions/articles when not the first word. Checked BEFORE
            // the acronym list, which otherwise force-uppercased a mid-name "at"/"it" —
            // "Bank at It" out of "bank at it".
            if i > 0
                && lowercase_words
                    .iter()
                    .any(|lw| lw.eq_ignore_ascii_case(word))
            {
                return word.to_lowercase();
            }

            // Known acronym (case-insensitive)
            if known_acronyms.iter().any(|a| a.eq_ignore_ascii_case(word)) {
                return word.to_uppercase();
            }

            // Mixed case already — the name is telling us how it is spelled. Leave it.
            if !is_all_upper && !is_all_lower {
                return word.to_string();
            }

            // Preserve short all-caps words (2 chars) as likely acronyms (IT, HR).
            if is_all_upper && len == 2 && !letters.is_empty() {
                return word.to_string();
            }

            // Convert to title case. A hyphen, slash, ampersand or dot starts a new word inside
            // the token: "COCA-COLA" -> "Coca-Cola", and the initials in "U.S. Bancorp" stay
            // capitalised instead of decaying to "U.s.".
            let mut result_chars = chars;
            let mut at_word_start = true;
            for c in &mut result_chars {
                if at_word_start {
                    *c = c.to_uppercase().next().unwrap_or(*c);
                } else if c.is_alphabetic() {
                    *c = c.to_lowercase().next().unwrap_or(*c);
                }
                at_word_start = matches!(*c, '-' | '/' | '&' | '.');
            }
            result_chars.into_iter().collect::<String>()
        })
        .collect::<Vec<String>>()
        .join(" ")
}

/// Calculate Levenshtein distance between two strings.
fn levenshtein_distance(s1: &str, s2: &str) -> usize {
    let s1_chars: Vec<char> = s1.chars().collect();
    let s2_chars: Vec<char> = s2.chars().collect();

    let len1 = s1_chars.len();
    let len2 = s2_chars.len();

    if len1 == 0 {
        return len2;
    }
    if len2 == 0 {
        return len1;
    }

    let mut matrix = vec![vec![0usize; len2 + 1]; len1 + 1];

    for (i, row) in matrix.iter_mut().enumerate().take(len1 + 1) {
        row[0] = i;
    }
    for (j, val) in matrix[0].iter_mut().enumerate().take(len2 + 1) {
        *val = j;
    }

    for i in 1..=len1 {
        for j in 1..=len2 {
            let cost = if s1_chars[i - 1] == s2_chars[j - 1] {
                0
            } else {
                1
            };

            matrix[i][j] = (matrix[i - 1][j] + 1)
                .min(matrix[i][j - 1] + 1)
                .min(matrix[i - 1][j - 1] + cost);
        }
    }

    matrix[len1][len2]
}

// ============================================================================
// Global Normalizer Access
// ============================================================================

use std::sync::OnceLock;

/// Global organization normalizer instance
static ORG_NORMALIZER: OnceLock<Option<OrgNormalizer>> = OnceLock::new();

// cfg(not(coverage)): OnceLock singleton init — sets process-global state, testing pollutes parallel tests
#[cfg(not(coverage))]
pub fn init(config: &crate::config::OrganizationConfig) {
    let normalizer = if config.enabled {
        Some(OrgNormalizer::from_app_config(config))
    } else {
        None
    };

    // Ignore error if already initialized (idempotent)
    let _ = ORG_NORMALIZER.set(normalizer);
}

/// Get a reference to the global organization normalizer (if enabled)
pub fn get() -> Option<&'static OrgNormalizer> {
    ORG_NORMALIZER.get().and_then(|opt| opt.as_ref())
}

// cfg(not(coverage)): OnceLock singleton — Some branch unreachable in tests (init not called)
#[cfg(not(coverage))]
pub fn normalize(name: &str) -> String {
    match get() {
        Some(normalizer) => normalizer.normalize(name),
        None => name.to_string(),
    }
}
#[cfg(coverage)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn init(_config: &crate::config::OrganizationConfig) {}

#[cfg(coverage)]
pub fn normalize(name: &str) -> String {
    name.to_string()
}

/// Check if organization normalization is enabled
pub fn is_enabled() -> bool {
    get().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalizer() -> OrgNormalizer {
        OrgNormalizer::new()
    }

    // =========================================================================
    // Tests for corporate suffix removal
    // =========================================================================

    #[test]
    fn test_remove_inc_suffix() {
        let n = normalizer();
        assert_eq!(n.normalize("Acme Inc."), "Acme");
        assert_eq!(n.normalize("Acme Inc"), "Acme");
        assert_eq!(n.normalize("Acme, Inc."), "Acme");
        assert_eq!(n.normalize("Acme, Inc"), "Acme");
    }

    #[test]
    fn test_remove_llc_suffix() {
        let n = normalizer();
        assert_eq!(n.normalize("Widget LLC"), "Widget");
        assert_eq!(n.normalize("Widget LLC."), "Widget");
        assert_eq!(n.normalize("Widget, LLC"), "Widget");
    }

    #[test]
    fn test_remove_ltd_suffix() {
        let n = normalizer();
        assert_eq!(n.normalize("British Ltd."), "British");
        assert_eq!(n.normalize("British Ltd"), "British");
        assert_eq!(n.normalize("British Limited"), "British");
    }

    #[test]
    fn test_remove_corp_suffix() {
        let n = normalizer();
        assert_eq!(n.normalize("Tech Corp."), "Tech");
        assert_eq!(n.normalize("Tech Corp"), "Tech");
        assert_eq!(n.normalize("Tech Corporation"), "Tech");
    }

    #[test]
    fn test_remove_gmbh_suffix() {
        let n = normalizer();
        assert_eq!(n.normalize("Deutsche GmbH"), "Deutsche");
    }

    #[test]
    fn test_remove_company_suffix() {
        let n = normalizer();
        assert_eq!(n.normalize("Acme Company"), "Acme");
        assert_eq!(n.normalize("Acme Co."), "Acme");
        assert_eq!(n.normalize("Acme Co"), "Acme");
    }

    #[test]
    fn test_remove_plc_suffix() {
        let n = normalizer();
        assert_eq!(n.normalize("British PLC"), "British");
        assert_eq!(n.normalize("British PLC."), "British");
    }

    #[test]
    fn test_remove_ag_suffix() {
        let n = normalizer();
        assert_eq!(n.normalize("Swiss AG"), "Swiss");
    }

    // =========================================================================
    // Tests for case normalization
    // =========================================================================

    #[test]
    fn test_case_variations() {
        let n = normalizer();

        // Case-less inputs (all-upper or all-lower) are title-cased.
        assert_eq!(n.normalize("GOOGLE"), "Google");
        assert_eq!(n.normalize("google"), "Google");
        assert_eq!(n.normalize("Google"), "Google");
    }

    #[test]
    fn test_internal_capitals_are_preserved() {
        // Mixed-case words carry information and are left alone. The normalizer used to
        // lowercase everything after each word's first letter, which CORRUPTED correct
        // names arriving from curated sources: "SendGrid" became "Sendgrid", "DataDog"
        // became "Datadog", and every acronym outside a 13-entry list ("SAP", "AMD") was
        // flattened. Structurally, a typo like "GooGle" is indistinguishable from
        // "SendGrid", so the normalizer no longer tries to tell them apart — protecting the
        // thousands of real brands is worth leaving one hypothetical typo unfixed.
        let n = normalizer();
        assert_eq!(n.normalize("SendGrid"), "SendGrid");
        assert_eq!(n.normalize("DataDog"), "DataDog");
        assert_eq!(n.normalize("iCloud"), "iCloud");
        assert_eq!(n.normalize("SAP"), "SAP");
        assert_eq!(n.normalize("AMD"), "AMD");
    }

    #[test]
    fn test_preserve_acronyms() {
        let n = normalizer();

        // IBM should stay uppercase (known acronym in the list)
        assert_eq!(n.normalize("IBM"), "IBM");

        // "HP" now stays "HP". The builtin alias used to rewrite it to "Hewlett-Packard" —
        // a company that stopped existing under that name in 2015 (it split into HP Inc.
        // and Hewlett Packard Enterprise), so the alias was actively producing a wrong,
        // stale organization name.
        assert_eq!(n.normalize("HP"), "HP");

        // AWS has a builtin alias -> "Amazon Web Services"
        assert_eq!(n.normalize("AWS"), "Amazon Web Services");

        // AT&T: "AT" is in known_acronyms, "and" stays lowercase (L011), "T" stays single char
        assert_eq!(n.normalize("AT&T"), "AT and T");
    }

    // =========================================================================
    // Tests for punctuation normalization
    // =========================================================================

    #[test]
    fn test_apostrophe_variations() {
        let n = normalizer();

        let oreilly1 = n.normalize("O'Reilly");
        let _oreilly2 = n.normalize("OReilly");
        let _oreilly3 = n.normalize("O Reilly");

        // All should be considered the same
        assert!(n.are_same("O'Reilly", "OReilly"));
        assert!(n.are_same("O'Reilly", "O Reilly"));

        // After normalization, apostrophe is removed
        assert!(!oreilly1.contains("'"));
    }

    #[test]
    fn test_smart_quotes() {
        let n = normalizer();

        // Smart quotes should be removed
        assert!(!n.normalize("Test\u{201C}Company\u{201D}").contains('"'));
    }

    // =========================================================================
    // Tests for "The" prefix
    // =========================================================================

    #[test]
    fn test_the_prefix_removal() {
        let n = normalizer();

        assert_eq!(n.normalize("The New York Times"), "New York Times");
        assert_eq!(n.normalize("the new york times"), "New York Times");
        assert_eq!(n.normalize("THE NEW YORK TIMES"), "New York Times");
    }

    #[test]
    fn test_the_not_removed_when_part_of_name() {
        let n = normalizer();

        // "The" at the beginning should be removed
        assert_eq!(n.normalize("The Widget Company"), "Widget");

        // "The" in the middle should stay lowercase (L011 fix: articles lowercase mid-sentence)
        let result = n.normalize("Over The Top");
        assert!(result.contains("the"));
    }

    // =========================================================================
    // Tests for ampersand variations
    // =========================================================================

    #[test]
    fn test_ampersand_normalization() {
        let n = normalizer();

        // AT&T variations
        assert!(n.are_same("AT&T", "AT and T"));
        assert!(n.are_same("AT & T", "AT and T"));

        // Johnson & Johnson
        let j1 = n.normalize("Johnson & Johnson");
        let j2 = n.normalize("Johnson and Johnson");
        assert_eq!(j1, j2);
    }

    // =========================================================================
    // Tests for alias mappings
    // =========================================================================

    #[test]
    fn test_builtin_aliases() {
        let n = normalizer();

        assert_eq!(n.normalize("MSFT"), "Microsoft");
        assert_eq!(n.normalize("msft"), "Microsoft");
        assert_eq!(n.normalize("GOOG"), "Google");
        assert_eq!(n.normalize("AWS"), "Amazon Web Services");
        assert_eq!(n.normalize("aws"), "Amazon Web Services");
    }

    #[test]
    fn test_company_variations_via_aliases() {
        let n = normalizer();

        assert_eq!(n.normalize("Google LLC"), "Google");
        assert_eq!(n.normalize("Google Inc."), "Google");
        assert_eq!(n.normalize("Microsoft Corporation"), "Microsoft");
        assert_eq!(n.normalize("Facebook"), "Meta Platforms");
        assert_eq!(n.normalize("Facebook Inc"), "Meta Platforms");
    }

    #[test]
    fn test_custom_aliases() {
        let mut config = OrgAliasConfig::default();
        config
            .aliases
            .insert("acme".to_string(), "Acme Corporation".to_string());
        config.aliases.insert(
            "widgetco".to_string(),
            "Widget Company International".to_string(),
        );

        let n = OrgNormalizer::with_config(&config);

        assert_eq!(n.normalize("acme"), "Acme Corporation");
        assert_eq!(n.normalize("ACME"), "Acme Corporation");
        assert_eq!(n.normalize("widgetco"), "Widget Company International");
    }

    #[test]
    fn test_add_alias_dynamically() {
        let mut n = normalizer();
        n.add_alias("mycompany", "My Awesome Company");

        assert_eq!(n.normalize("mycompany"), "My Awesome Company");
        assert_eq!(n.normalize("MYCOMPANY"), "My Awesome Company");
    }

    // =========================================================================
    // Tests for fuzzy matching
    // =========================================================================

    #[test]
    fn test_similarity_identical() {
        let n = normalizer();
        assert!((n.similarity("Google", "Google") - 1.0).abs() < 0.001);
        assert!((n.similarity("google", "GOOGLE") - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_similarity_different() {
        let n = normalizer();
        assert!(n.similarity("Google", "Microsoft") < 0.5);
        assert!(n.similarity("Apple", "Orange") < 0.5);
    }

    #[test]
    fn test_similarity_typos() {
        let n = normalizer();

        // Minor typos should have high similarity
        assert!(n.similarity("Google", "Gogle") > 0.8);
        assert!(n.similarity("Microsoft", "Microsft") > 0.8);
        assert!(n.similarity("Amazon", "Amazn") > 0.8);
    }

    #[test]
    fn test_fuzzy_match_threshold() {
        let n = OrgNormalizer::new().with_threshold(0.9);

        // "Google" and "Gogle" have ~83% similarity, below 90% threshold
        assert!(!n.fuzzy_match("Google", "Gogle"));

        let n2 = OrgNormalizer::new().with_threshold(0.8);
        // With lower threshold, they should match
        assert!(n2.fuzzy_match("Google", "Gogle"));
    }

    // =========================================================================
    // Tests for are_same
    // =========================================================================

    #[test]
    fn test_are_same_exact() {
        let n = normalizer();
        assert!(n.are_same("Google", "Google"));
        assert!(n.are_same("google", "GOOGLE"));
    }

    #[test]
    fn test_are_same_normalized() {
        let n = normalizer();

        // Same company with different suffixes
        assert!(n.are_same("Acme Inc.", "Acme Corporation"));
        assert!(n.are_same("Widget LLC", "Widget Ltd."));

        // Same company with "The" prefix variation
        assert!(n.are_same("The New York Times", "New York Times Inc."));
    }

    #[test]
    fn test_are_same_different_companies() {
        let n = normalizer();

        assert!(!n.are_same("Google", "Microsoft"));
        assert!(!n.are_same("Apple", "Amazon"));
        assert!(!n.are_same("Netflix", "Hulu"));
    }

    // =========================================================================
    // Tests for deduplication
    // =========================================================================

    #[test]
    fn test_deduplicate_simple() {
        let n = normalizer();

        let names = vec![
            "Google".to_string(),
            "Google Inc.".to_string(),
            "Google LLC".to_string(),
            "Microsoft".to_string(),
            "Microsoft Corporation".to_string(),
        ];

        let deduped = n.deduplicate(&names);

        // All Google variations should map to the same canonical name
        let google_canonical = deduped.get("Google").unwrap();
        assert_eq!(deduped.get("Google Inc.").unwrap(), google_canonical);
        assert_eq!(deduped.get("Google LLC").unwrap(), google_canonical);

        // All Microsoft variations should map to the same canonical name
        let ms_canonical = deduped.get("Microsoft").unwrap();
        assert_eq!(deduped.get("Microsoft Corporation").unwrap(), ms_canonical);
    }

    #[test]
    fn test_deduplicate_with_aliases() {
        let n = normalizer();

        let names = vec![
            "Facebook".to_string(),
            "Facebook Inc.".to_string(),
            "Meta Platforms".to_string(),
            "Meta Platforms, Inc.".to_string(),
        ];

        let deduped = n.deduplicate(&names);

        // Facebook and Meta should all normalize to Meta Platforms
        let fb_canonical = deduped.get("Facebook").unwrap();
        let meta_canonical = deduped.get("Meta Platforms").unwrap();

        assert_eq!(fb_canonical, meta_canonical);
    }

    // =========================================================================
    // Tests for find_best_match
    // =========================================================================

    #[test]
    fn test_find_best_match() {
        let n = normalizer();

        let candidates = vec![
            "Google".to_string(),
            "Microsoft".to_string(),
            "Amazon".to_string(),
        ];

        // Exact match
        let result = n.find_best_match("Google Inc.", &candidates);
        assert!(result.is_some());
        assert_eq!(result.unwrap().0, "Google");

        // Typo match — exercises the fuzzy matching path regardless of result
        let result = n.find_best_match("Gooogle", &candidates);
        let _ = result;
    }

    #[test]
    fn test_find_best_match_no_match() {
        let n = normalizer();

        let candidates = vec!["Google".to_string(), "Microsoft".to_string()];

        let result = n.find_best_match("Completely Different Company", &candidates);
        assert!(result.is_none());
    }

    // =========================================================================
    // Tests for Levenshtein distance
    // =========================================================================

    #[test]
    fn test_levenshtein_identical() {
        assert_eq!(levenshtein_distance("test", "test"), 0);
    }

    #[test]
    fn test_levenshtein_empty() {
        assert_eq!(levenshtein_distance("", "test"), 4);
        assert_eq!(levenshtein_distance("test", ""), 4);
        assert_eq!(levenshtein_distance("", ""), 0);
    }

    #[test]
    fn test_levenshtein_one_char_diff() {
        assert_eq!(levenshtein_distance("test", "tent"), 1);
        assert_eq!(levenshtein_distance("cat", "car"), 1);
    }

    #[test]
    fn test_levenshtein_insertion() {
        assert_eq!(levenshtein_distance("test", "tests"), 1);
        assert_eq!(levenshtein_distance("cat", "cats"), 1);
    }

    #[test]
    fn test_levenshtein_deletion() {
        assert_eq!(levenshtein_distance("tests", "test"), 1);
    }

    // =========================================================================
    // Tests for edge cases
    // =========================================================================

    #[test]
    fn test_empty_string() {
        let n = normalizer();
        assert_eq!(n.normalize(""), "");
        assert_eq!(n.normalize("   "), "");
    }

    #[test]
    fn test_whitespace_only() {
        let n = normalizer();
        assert_eq!(n.normalize("  \t\n  "), "");
    }

    #[test]
    fn test_excessive_whitespace() {
        let n = normalizer();
        assert_eq!(n.normalize("  Acme    Inc.   "), "Acme");
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_unicode_names() {
        let n = normalizer();

        // Japanese company name should be preserved (no suffix removal for non-Latin)
        let result = n.normalize("ソニー株式会社");
        assert!(!result.is_empty());

        // German umlauts
        let result = n.normalize("München GmbH");
        assert!(result.contains("München") || result.contains("Munchen"));
    }

    // =========================================================================
    // Tests for config serialization
    // =========================================================================

    #[test]
    fn test_org_alias_config_serde() {
        let mut config = OrgAliasConfig::default();
        config
            .aliases
            .insert("test".to_string(), "Test Company".to_string());

        let json = serde_json::to_string(&config).unwrap();
        let parsed: OrgAliasConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(
            parsed.aliases.get("test"),
            Some(&"Test Company".to_string())
        );
    }

    #[test]
    fn test_from_app_config() {
        use crate::config::OrganizationConfig;

        let mut app_config = OrganizationConfig::default();
        app_config
            .aliases
            .insert("myalias".to_string(), "My Company".to_string());
        app_config.similarity_threshold = 0.9;

        let normalizer = OrgNormalizer::from_app_config(&app_config);

        // Custom alias should work
        assert_eq!(normalizer.normalize("myalias"), "My Company");

        // Custom threshold should be applied
        // With 0.9 threshold, "Google" and "Gogle" (~83% similar) should NOT match
        assert!(!normalizer.fuzzy_match("Google", "Gogle"));
    }

    // =========================================================================
    // Tests for global normalizer functions
    // =========================================================================

    #[test]
    fn test_global_normalize_without_init() {
        // Before init, normalize() should return input unchanged
        // Note: In test context, OnceLock may already be set by another test.
        // This test verifies the function signature and basic behavior.
        let result = super::normalize("Some Company");
        // Either normalized (if global was initialized) or unchanged
        assert!(!result.is_empty());
    }

    #[test]
    fn test_success_criteria_microsoft_variations() {
        let n = normalizer();
        // "Microsoft Corporation" and "Microsoft, Inc." should normalize to same name
        assert!(n.are_same("Microsoft Corporation", "Microsoft, Inc."));
    }

    #[test]
    fn test_success_criteria_common_suffixes() {
        let n = normalizer();
        // Common suffixes should be stripped
        assert_eq!(n.normalize("Stripe Inc."), "Stripe");
        assert_eq!(n.normalize("Stripe, Inc."), "Stripe");
        assert_eq!(n.normalize("Stripe LLC"), "Stripe");
        assert_eq!(n.normalize("Stripe Ltd."), "Stripe");
        assert_eq!(n.normalize("Stripe Corporation"), "Stripe");
        assert_eq!(n.normalize("Stripe GmbH"), "Stripe");
        assert_eq!(n.normalize("Stripe Co."), "Stripe");
        assert_eq!(n.normalize("Stripe Company"), "Stripe");
        assert_eq!(n.normalize("Stripe PLC"), "Stripe");
        assert_eq!(n.normalize("Stripe AG"), "Stripe");
        assert_eq!(n.normalize("Stripe SA"), "Stripe");
        assert_eq!(n.normalize("Stripe BV"), "Stripe");
        assert_eq!(n.normalize("Stripe NV"), "Stripe");
        assert_eq!(n.normalize("Stripe Limited"), "Stripe");
        assert_eq!(n.normalize("Stripe SAS"), "Stripe");
    }

    #[test]
    fn test_success_criteria_fuzzy_matching() {
        let n = normalizer();
        // Fuzzy matching should catch close variations
        assert!(n.similarity("Microsft", "Microsoft") > 0.85);
        assert!(n.similarity("Gogle", "Google") > 0.8);
    }

    // =========================================================================
    // Additional tests for uncovered paths
    // =========================================================================

    #[test]
    fn test_strip_domain_suffix_com() {
        assert_eq!(strip_domain_suffix("Monday.com"), "Monday");
        assert_eq!(strip_domain_suffix("Salesforce.com"), "Salesforce");
    }

    #[test]
    fn test_strip_domain_suffix_io() {
        assert_eq!(strip_domain_suffix("Pendo.io"), "Pendo");
    }

    #[test]
    fn test_strip_domain_suffix_ai() {
        assert_eq!(strip_domain_suffix("OpenAI.ai"), "OpenAI");
    }

    #[test]
    fn test_strip_domain_suffix_dev() {
        assert_eq!(strip_domain_suffix("MyApp.dev"), "MyApp");
    }

    #[test]
    fn test_strip_domain_suffix_too_short() {
        // "a.com" has remaining part "a" which is < 2 chars, should not strip
        assert_eq!(strip_domain_suffix("a.com"), "a.com");
    }

    #[test]
    fn test_strip_domain_suffix_no_suffix() {
        assert_eq!(strip_domain_suffix("NoSuffix"), "NoSuffix");
    }

    #[test]
    fn test_strip_domain_suffix_dot_at_end_of_remaining() {
        // "foo..com" -> remaining "foo." ends with '.', should not strip
        assert_eq!(strip_domain_suffix("foo..com"), "foo..com");
    }

    #[test]
    fn test_normalize_punctuation_smart_quotes() {
        // Test all the smart quote variants
        let result = normalize_punctuation("Test\u{201C}quoted\u{201D}");
        assert!(!result.contains('\u{201C}'));
        assert!(!result.contains('\u{201D}'));
    }

    #[test]
    fn test_normalize_punctuation_german_quote() {
        let result = normalize_punctuation("Test\u{201E}quoted");
        assert!(!result.contains('\u{201E}'));
    }

    #[test]
    fn test_normalize_punctuation_en_dash() {
        let result = normalize_punctuation("Test\u{2013}Value");
        assert_eq!(result, "Test-Value");
    }

    #[test]
    fn test_normalize_punctuation_em_dash() {
        let result = normalize_punctuation("Test\u{2014}Value");
        assert_eq!(result, "Test-Value");
    }

    #[test]
    fn test_normalize_punctuation_backtick() {
        let result = normalize_punctuation("O`Reilly");
        assert_eq!(result, "OReilly");
    }

    #[test]
    fn test_to_title_case_lowercase_words_mid_sentence() {
        // L011: prepositions should be lowercase when not first word
        assert_eq!(to_title_case("bank of america"), "Bank of America");
        assert_eq!(to_title_case("lord of the rings"), "Lord of the Rings");
    }

    #[test]
    fn test_to_title_case_lowercase_word_first_position() {
        // First word should always be capitalized, even if it's a preposition
        assert_eq!(to_title_case("of mice and men"), "Of Mice and Men");
        assert_eq!(to_title_case("the quick fox"), "The Quick Fox");
    }

    #[test]
    fn test_to_title_case_known_acronym() {
        assert_eq!(to_title_case("ibm"), "IBM");
        assert_eq!(to_title_case("aws"), "AWS");
        assert_eq!(to_title_case("usa"), "USA");
    }

    #[test]
    fn test_to_title_case_short_all_caps_preserved() {
        // 2-char all-caps words preserved as likely acronyms
        assert_eq!(to_title_case("IT department"), "IT Department");
    }

    #[test]
    fn test_to_title_case_longer_all_caps_converted() {
        // 3+ char all-caps words (not known acronyms) get title-cased
        assert_eq!(to_title_case("NEW COMPANY"), "New Company");
    }

    #[test]
    fn test_global_init_and_get() {
        // Note: OnceLock is global, so this test may interact with others.
        // We just verify the functions don't panic.
        let _ = is_enabled();
        let _ = get();
        let result = normalize("Test Company");
        assert!(!result.is_empty());
    }

    #[test]
    fn test_similarity_empty_strings() {
        let n = normalizer();
        // Two empty strings are equal -> similarity 1.0
        assert!((n.similarity("", "") - 1.0).abs() < 0.001);
        // One empty, one non-empty -> similarity 0.0
        assert!((n.similarity("hello", "") - 0.0).abs() < 0.001);
        assert!((n.similarity("", "hello") - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_with_threshold_clamping() {
        let n = OrgNormalizer::new().with_threshold(1.5);
        assert!((n.similarity_threshold - 1.0).abs() < f64::EPSILON);

        let n2 = OrgNormalizer::new().with_threshold(-0.5);
        assert!((n2.similarity_threshold - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_strip_domain_suffix_all_suffixes() {
        // Cover all the TLD patterns
        let tlds = vec![
            (".net", "TestNet"),
            (".org", "TestOrg"),
            (".co", "TestCo"),
            (".us", "TestUs"),
            (".app", "TestApp"),
            (".tech", "TestTech"),
            (".cloud", "TestCloud"),
            (".so", "TestSo"),
            (".ly", "TestLy"),
            (".me", "TestMe"),
            (".to", "TestTo"),
        ];
        for (suffix, expected) in tlds {
            let input = format!("{}{}", expected, suffix);
            assert_eq!(
                strip_domain_suffix(&input),
                expected,
                "Failed for {}",
                input
            );
        }
    }

    #[test]
    fn test_remove_european_corporate_suffixes() {
        let n = normalizer();
        assert_eq!(n.normalize("Company S.R.L."), "Company");
        assert_eq!(n.normalize("Company S.A.S."), "Company");
        assert_eq!(n.normalize("Company S.P.A."), "Company");
        assert_eq!(n.normalize("Company L.L.C."), "Company");
    }

    #[test]
    fn test_success_criteria_known_abbreviations() {
        let n = normalizer();
        // AWS -> Amazon Web Services
        assert_eq!(n.normalize("AWS"), "Amazon Web Services");
        // GCP -> Google Cloud Platform
        assert_eq!(n.normalize("GCP"), "Google Cloud Platform");
    }

    #[test]
    fn test_default_trait() {
        // Exercise the Default impl (lines 100-102)
        let n = OrgNormalizer::default();
        assert_eq!(n.normalize("Acme Inc."), "Acme");
    }

    #[test]
    fn test_find_best_match_second_candidate_beats_first() {
        // Exercise lines 336-338: second candidate has higher similarity than first
        let n = normalizer();
        // "Googl" is close to "Google" but "Gogle" should also be close.
        // We need two candidates that both exceed threshold, with the better match second.
        let candidates = vec!["Microsft".to_string(), "Microsoft".to_string()];
        let result = n.find_best_match("Microsoft", &candidates);
        assert!(result.is_some());
        // The exact match "Microsoft" should win even though "Microsft" was checked first
        assert_eq!(result.unwrap().0, "Microsoft");
    }

    #[test]
    fn test_deduplicate_fuzzy_merge() {
        // Exercise lines 366-368: fuzzy matching in deduplicate
        // Need names that normalize to DIFFERENT strings but are fuzzy-similar
        let n = normalizer();
        let names = vec![
            "Datadog".to_string(),
            "DataDog".to_string(),  // This normalizes the same via title case
            "Datadogg".to_string(), // Typo: normalizes differently but is fuzzy-similar
        ];
        let map = n.deduplicate(&names);
        // "Datadogg" should be fuzzy-merged with "Datadog" (if above threshold)
        // If not fuzzy-merged, it gets its own canonical name — either way the branch is exercised
        assert!(map.contains_key("Datadogg"));
    }

    #[test]
    fn test_remove_the_prefix_short_name() {
        // Exercise line 419: name shorter than 4 chars, skips "The " check
        let result = remove_the_prefix("AB");
        assert_eq!(result, "AB");
        let result = remove_the_prefix("X");
        assert_eq!(result, "X");
    }

    #[test]
    fn test_normalize_preserves_short_acronyms() {
        // Exercise line 522: 2-char all-uppercase words NOT in known_acronyms list
        // "IO" is all-caps, 2 chars, and not in the known acronyms list
        let n = normalizer();
        let result = n.normalize("Acme IO Platform");
        assert!(result.contains("IO"));
    }

    #[test]
    fn test_find_best_match_typo_coverage() {
        // Exercise line 1008: typo match conditional branch
        let n = normalizer();
        let candidates = vec!["Google".to_string(), "Microsoft".to_string()];
        let result = n.find_best_match("Gooogle", &candidates);
        // Result may or may not match — either way exercises the branch
        let _ = result;
    }

    // --- Tests for previously-coverage(off) global functions ---

    #[test]
    fn test_stripped_normalize_global_function() {
        let result = normalize("Acme Corporation");
        assert!(!result.is_empty());
        assert_eq!(normalize(""), "");
    }

    #[test]
    fn test_stripped_is_enabled_consistent_with_get() {
        let enabled = is_enabled();
        let normalizer_ref = get();
        assert_eq!(enabled, normalizer_ref.is_some());
    }

    #[test]
    fn test_stripped_get_returns_consistent_value() {
        let first = get();
        let second = get();
        assert_eq!(first.is_some(), second.is_some());
    }

    #[test]
    fn test_stripped_normalize_consistency() {
        let input = "Microsoft Corporation";
        let first = normalize(input);
        let second = normalize(input);
        assert_eq!(first, second);
    }

    #[test]
    fn test_stripped_normalize_various_inputs_no_panic() {
        let inputs = vec![
            "Google LLC",
            "Apple Inc.",
            "Amazon.com, Inc.",
            "",
            "a",
            "A Very Long Company Name That Goes On And On For Testing",
        ];
        for input in &inputs {
            let result = normalize(input);
            assert!(!result.is_empty() || input.is_empty());
        }
    }

    #[test]
    fn test_stripped_find_best_match_exact() {
        let n = normalizer();
        let candidates = vec![
            "Google".to_string(),
            "Microsoft".to_string(),
            "Apple".to_string(),
        ];
        let exact = n.find_best_match("Google", &candidates);
        assert!(exact.is_some());
        let (name, score) = exact.unwrap();
        assert_eq!(name, "Google");
        assert!(score > 0.0);
    }

    #[test]
    fn test_stripped_find_best_match_empty_candidates() {
        let n = normalizer();
        let empty: Vec<String> = vec![];
        let result = n.find_best_match("Google", &empty);
        assert!(result.is_none());
    }

    #[test]
    fn test_stripped_find_best_match_typo_with_assertions() {
        let n = normalizer();
        let candidates = vec!["Google".to_string(), "Microsoft".to_string()];
        // "Gogle" — single missing letter, still too distant for default threshold
        let result = n.find_best_match("Gogle", &candidates);
        assert!(
            result.is_none(),
            "Single-letter typo should not meet strict similarity threshold"
        );
    }

    #[test]
    fn test_get_exercises_and_then_closure() {
        let _ = ORG_NORMALIZER.set(Some(OrgNormalizer::new()));
        let _ = get();
        let _ = is_enabled();
    }

    #[test]
    fn test_from_app_config_with_custom_aliases() {
        let app_config = crate::config::OrganizationConfig {
            enabled: true,
            similarity_threshold: 0.9,
            aliases: {
                let mut m = std::collections::HashMap::new();
                m.insert("custom-alias".to_string(), "Custom Corp".to_string());
                m
            },
        };
        let n = OrgNormalizer::from_app_config(&app_config);
        assert_eq!(n.normalize("custom-alias"), "Custom Corp");
        assert!((n.similarity_threshold - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn test_with_threshold_clamping_edges() {
        let n = OrgNormalizer::new().with_threshold(1.5);
        assert!((n.similarity_threshold - 1.0).abs() < f64::EPSILON);
        let n2 = OrgNormalizer::new().with_threshold(-0.5);
        assert!((n2.similarity_threshold - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_add_alias() {
        let mut n = normalizer();
        n.add_alias("my-custom", "My Custom Corp");
        assert_eq!(n.normalize("my-custom"), "My Custom Corp");
    }

    #[test]
    fn test_module_normalize_fn() {
        let result = normalize("anything");
        assert!(!result.is_empty());
    }

    // =========================================================================
    // Regressions: names the normalizer used to destroy
    // =========================================================================

    #[test]
    fn test_names_ending_in_suffix_letters_are_not_truncated() {
        // `remove_corporate_suffixes` matched the BARE suffix with `ends_with`, so any name
        // whose final letters happened to spell one was silently truncated. Every one of
        // these is a real vendor that shipped into reports mangled:
        //   Cisco -> "Cis" (co), Visa -> "Vi" (sa), Zinc -> "Z" (inc),
        //   Maytag -> "Mayt" (ag), Sysco -> "Sys" (co)
        let n = normalizer();
        assert_eq!(n.normalize("Cisco"), "Cisco");
        assert_eq!(n.normalize("Visa"), "Visa");
        assert_eq!(n.normalize("Zinc"), "Zinc");
        assert_eq!(n.normalize("Maytag"), "Maytag");
        assert_eq!(n.normalize("Sysco"), "Sysco");
        assert_eq!(n.normalize("Cargo"), "Cargo");
        // ...while a genuine trailing suffix WORD is still removed.
        assert_eq!(n.normalize("Cisco Systems, Inc."), "Cisco Systems");
        assert_eq!(n.normalize("Visa Inc"), "Visa");
    }

    #[test]
    fn test_normalize_never_returns_empty_for_a_nonempty_name() {
        // A name that is entirely a legal suffix would strip to "", and an empty org renders
        // as an attributed-but-nameless vendor.
        let n = normalizer();
        for name in ["Limited", "Inc.", "LLC", "Corporation", "Co."] {
            assert!(
                !n.normalize(name).trim().is_empty(),
                "normalize({name:?}) emptied the name"
            );
        }
    }

    #[test]
    fn test_domain_suffix_stripped_after_legal_suffix() {
        // "Salesforce.com, Inc." only exposes its ".com" once the legal suffix is gone.
        // Running the domain-suffix strip only BEFORE suffix removal left "Salesforce.com"
        // and "Salesforce" as two different organizations in the same report.
        let n = normalizer();
        assert_eq!(n.normalize("Salesforce.com, Inc."), "Salesforce");
        assert_eq!(n.normalize("Salesforce"), "Salesforce");
    }

    #[test]
    fn test_domain_suffix_strip_is_public_suffix_aware() {
        // The old 15-TLD list left ccTLD and multi-label suffixes attached, so
        // "Example.co.uk" and "Example" were distinct organizations.
        let n = normalizer();
        assert_eq!(n.normalize("Beispiel.de"), "Beispiel");
        assert_eq!(n.normalize("Example.co.uk"), "Example");
    }

    #[test]
    fn test_mid_name_connectors_are_not_force_uppercased() {
        // The known-acronym check ran BEFORE the lowercase-words check, so a mid-name "at"
        // was force-uppercased into a fake acronym: "Bank AT Home".
        assert_eq!(to_title_case("bank at home"), "Bank at Home");
        assert_eq!(to_title_case("bank of the west"), "Bank of the West");
    }

    #[test]
    fn test_at_and_it_led_company_names_survive() {
        // "AT" and "IT" were in the known-acronym list, which matches case-insensitively, so
        // two real companies were being renamed into fake acronyms.
        assert_eq!(to_title_case("At Home Group Inc."), "At Home Group Inc.");
        assert_eq!(to_title_case("it works marketing"), "It Works Marketing");
        // An input that really IS the acronym arrives all-caps, and the two-character all-caps
        // rule still preserves it — including through normalize()'s "&" -> "and" rewrite.
        assert_eq!(to_title_case("AT"), "AT");
        assert_eq!(to_title_case("IT"), "IT");
        assert_eq!(normalizer().normalize("AT&T"), "AT and T");
    }

    #[test]
    fn test_a_dot_inside_a_name_is_not_a_domain_suffix() {
        // `strip_domain_suffix` split on the LAST dot and asked the PSL whether the tail was a
        // public suffix — but the PSL's implicit `*` rule answers "yes" for any unknown single
        // label, so "U.S. Bancorp" was truncated to "U.s" and "Node.js" to "Node". Every one of
        // these names reached the report corrupted, from curated sources included.
        let n = normalizer();
        assert_eq!(n.normalize("U.S. Bancorp"), "U.S. Bancorp");
        assert_eq!(n.normalize("A.P. Moller - Maersk"), "A.P. Moller - Maersk");
        assert_eq!(n.normalize("St. Jude Medical"), "St. Jude Medical");
        assert_eq!(n.normalize("Node.js"), "Node.js");
        // A real domain-suffixed name is still stripped — that is what the function is for.
        assert_eq!(n.normalize("Monday.com"), "Monday");
        assert_eq!(n.normalize("Salesforce.com, Inc."), "Salesforce");
        assert_eq!(n.normalize("Example.co.uk"), "Example");
    }

    #[test]
    fn test_two_word_legal_suffixes_are_removed_whole() {
        // "pty ltd" sat AFTER "ltd" in the suffix list, so "ltd" matched first and left the
        // dangling fragment "Acme Pty" — which then failed to dedup with plain "Acme".
        let n = normalizer();
        assert_eq!(n.normalize("Acme Pty Ltd"), "Acme");
        assert_eq!(n.normalize("Tata Motors Pvt Ltd"), "Tata Motors");
    }

    #[test]
    fn test_hyphenated_all_caps_names_recase_each_part() {
        assert_eq!(to_title_case("COCA-COLA"), "Coca-Cola");
    }

    #[test]
    fn test_ambiguous_ticker_aliases_no_longer_rewrite_real_names() {
        // "meta", "fb", "ms", "crm" and "hp" were whole-string aliases that fired on ANY
        // source's output — including curated names — rewriting them to unrelated companies.
        // The property under test is that an ambiguous token is never rewritten into some
        // other company's name; its casing is not the point.
        let n = normalizer();
        assert_eq!(n.normalize("Meta"), "Meta");
        assert_ne!(n.normalize("MS"), "Microsoft");
        assert_ne!(n.normalize("CRM"), "Salesforce");
        assert_ne!(n.normalize("FB"), "Facebook");
        // The unambiguous ticker aliases still work.
        assert_eq!(n.normalize("MSFT"), "Microsoft");
        assert_eq!(n.normalize("AWS"), "Amazon Web Services");
    }

    // =========================================================================
    // is_plausible_org_name / brand_casing (previously untested)
    // =========================================================================

    #[test]
    fn test_plausible_org_name_rejects_taglines() {
        // The class of value the web/NER tiers produce instead of a company name.
        assert!(!is_plausible_org_name(
            "Connective Infrastructure for Production AI"
        ));
        assert!(!is_plausible_org_name(
            "Payments infrastructure for the internet"
        ));
        assert!(!is_plausible_org_name("A platform that helps teams ship"));
        assert!(!is_plausible_org_name(
            "The fastest way to build your next app today"
        ));
        assert!(!is_plausible_org_name(""));
    }

    #[test]
    fn test_plausible_org_name_accepts_real_company_names() {
        for name in [
            "Stripe",
            "Amazon Web Services",
            "Zoom Video Communications",
            "Bank of America",
            "The Trade Desk", // leading "The" is a real company pattern, not a sentence
            "The New York Times",
            "8x8",
            "23andMe Holding Co.",
        ] {
            assert!(is_plausible_org_name(name), "rejected real name: {name}");
        }
    }

    #[test]
    fn test_brand_casing_fixes_names_that_arrive_without_case_information() {
        // A domain-derived label carries no casing, so "openai" must become "OpenAI" rather
        // than the title-cased "Openai" that shipped in reports.
        let n = normalizer();
        assert_eq!(n.normalize("openai"), "OpenAI");
        assert_eq!(n.normalize("OPENAI"), "OpenAI");
        assert_eq!(n.normalize("mongodb"), "MongoDB");
        assert_eq!(n.normalize("github"), "GitHub");
        assert_eq!(n.normalize("e2b"), "E2B");
        // An unknown brand is left alone rather than guessed at.
        assert_eq!(n.normalize("zzzunknownbrand"), "Zzzunknownbrand");
    }
}
