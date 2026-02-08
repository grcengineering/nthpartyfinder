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

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
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

        // Built-in common aliases
        let builtin_aliases = [
            // Stock ticker symbols
            ("msft", "Microsoft"),
            ("goog", "Google"),
            ("googl", "Google"),
            ("amzn", "Amazon"),
            ("aapl", "Apple"),
            ("meta", "Meta Platforms"),
            ("fb", "Meta Platforms"),
            ("nflx", "Netflix"),
            ("ibm", "IBM"),
            ("orcl", "Oracle"),
            ("crm", "Salesforce"),
            ("twtr", "Twitter"),
            ("tsla", "Tesla"),
            ("nvda", "NVIDIA"),
            ("intc", "Intel"),
            ("csco", "Cisco"),
            ("adbe", "Adobe"),

            // Common abbreviations
            ("aws", "Amazon Web Services"),
            ("gcp", "Google Cloud Platform"),
            ("azure", "Microsoft Azure"),
            ("ms", "Microsoft"),
            ("ibm", "IBM"),
            ("hp", "Hewlett-Packard"),
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
            normalizer.aliases.insert(alias.to_lowercase(), canonical.clone());
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
        self.aliases.insert(alias.to_lowercase(), canonical.to_string());
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

        // Normalize punctuation (remove apostrophes, normalize spaces)
        result = normalize_punctuation(&result);

        // Normalize whitespace
        result = normalize_whitespace(&result);

        // Convert to title case
        result = to_title_case(&result);

        // Check aliases again after normalization
        let lower_result = result.to_lowercase();
        if let Some(canonical) = self.aliases.get(&lower_result) {
            debug!("Normalized '{}' to '{}' via alias (post-processing)", name, canonical);
            return canonical.clone();
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
    pub fn find_best_match<'a>(&self, name: &str, candidates: &'a [String]) -> Option<(&'a String, f64)> {
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

/// Strip trailing domain suffixes from org names (R005 fix).
/// e.g., "Monday.com" -> "Monday", "Bigmarker.com" -> "Bigmarker"
/// Only strips if the name ends with a known TLD suffix preceded by a dot.
fn strip_domain_suffix(name: &str) -> String {
    let domain_suffixes = [
        ".com", ".io", ".net", ".org", ".co", ".us", ".ai", ".dev",
        ".app", ".tech", ".cloud", ".so", ".ly", ".me", ".to",
    ];

    let lower = name.to_lowercase();
    for suffix in &domain_suffixes {
        if lower.ends_with(suffix) {
            let stripped = &name[..name.len() - suffix.len()];
            // Only strip if the remaining part is non-empty and looks like a name
            // (not something like just ".com" or "a.com")
            if stripped.len() >= 2 && !stripped.ends_with('.') {
                return stripped.to_string();
            }
        }
    }

    name.to_string()
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
    let result = name
        .replace(" & ", " and ")
        .replace("&", " and ");

    // Clean up any double spaces introduced
    normalize_whitespace(&result)
}

/// Remove corporate suffixes from a name.
fn remove_corporate_suffixes(name: &str) -> String {
    let mut result = name.to_string();
    let lower = name.to_lowercase();

    // Try each suffix (order matters - longer ones first)
    for suffix in CORPORATE_SUFFIXES {
        // Check for suffix at the end, optionally preceded by comma or space
        let patterns = [
            format!(", {}", suffix),
            format!(" {}", suffix),
            suffix.to_string(),
        ];

        for pattern in &patterns {
            let pattern_lower = pattern.to_lowercase();
            if lower.ends_with(&pattern_lower) {
                let end_pos = result.len() - pattern.len();
                result = result[..end_pos].trim().to_string();
                break;
            }
        }

        // Check if we've modified the result
        if result.len() < name.len() {
            break;
        }
    }

    // Also remove trailing punctuation like commas, periods
    result = result.trim_end_matches(&[',', '.', ' ']).to_string();

    result
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
    name.split_whitespace()
        .collect::<Vec<&str>>()
        .join(" ")
}

/// Convert string to title case (capitalize first letter of each word).
/// Known acronyms and very short all-caps words (2 chars) are preserved.
/// Longer all-caps words are converted to title case since they're more likely normal words.
/// L011 fix: Common English prepositions/articles stay lowercase when not the first word.
fn to_title_case(name: &str) -> String {
    // Known acronyms that should be preserved regardless of length
    let known_acronyms = ["IBM", "AT", "AWS", "GCP", "USA", "UK", "EU", "AI", "IT", "HR", "PR", "QA", "HP"];

    // L011 fix: common prepositions/articles/conjunctions that should stay lowercase
    // in title case (except when they're the first word)
    let lowercase_words = ["of", "and", "the", "in", "for", "on", "at", "to", "by", "or", "an", "a"];

    let words: Vec<&str> = name.split_whitespace().collect();
    words.iter()
        .enumerate()
        .map(|(i, word)| {
            let chars: Vec<char> = word.chars().collect();
            let len = chars.len();

            // Check if word is all uppercase
            let is_all_upper = word.chars().all(|c| c.is_uppercase() || !c.is_alphabetic());

            // Check if it's a known acronym (case-insensitive)
            if known_acronyms.iter().any(|a| a.eq_ignore_ascii_case(word)) {
                return word.to_uppercase();
            }

            // Preserve only very short all-caps words (2 chars) as likely acronyms
            // e.g., IT, HR, etc. Words like NEW, THE are too common as normal words
            if is_all_upper && len == 2 && chars.iter().any(|c| c.is_alphabetic()) {
                return word.to_string();
            }

            // L011: lowercase prepositions/articles when not the first word
            if i > 0 && lowercase_words.iter().any(|lw| lw.eq_ignore_ascii_case(word)) {
                return word.to_lowercase();
            }

            // Convert to title case
            let mut result_chars = chars;
            if let Some(first) = result_chars.first_mut() {
                *first = first.to_uppercase().next().unwrap_or(*first);
            }
            for c in &mut result_chars[1..] {
                if c.is_alphabetic() {
                    *c = c.to_lowercase().next().unwrap_or(*c);
                }
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

    for i in 0..=len1 {
        matrix[i][0] = i;
    }
    for j in 0..=len2 {
        matrix[0][j] = j;
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

/// Initialize the global organization normalizer from configuration
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

/// Normalize an organization name using the global normalizer
/// If normalization is disabled or not initialized, returns the input unchanged
pub fn normalize(name: &str) -> String {
    match get() {
        Some(normalizer) => normalizer.normalize(name),
        None => name.to_string(),
    }
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

        // All should normalize to "Google"
        assert_eq!(n.normalize("GOOGLE"), "Google");
        assert_eq!(n.normalize("google"), "Google");
        assert_eq!(n.normalize("Google"), "Google");
        assert_eq!(n.normalize("GooGle"), "Google");
    }

    #[test]
    fn test_preserve_acronyms() {
        let n = normalizer();

        // IBM should stay uppercase (known acronym in the list)
        assert_eq!(n.normalize("IBM"), "IBM");

        // HP has a builtin alias -> "Hewlett-Packard"
        assert_eq!(n.normalize("HP"), "Hewlett-Packard");

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
        config.aliases.insert("acme".to_string(), "Acme Corporation".to_string());
        config.aliases.insert("widgetco".to_string(), "Widget Company International".to_string());

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

        // Typo match
        let result = n.find_best_match("Gooogle", &candidates);
        // May or may not match depending on threshold
        if let Some((match_name, sim)) = result {
            assert_eq!(match_name, "Google");
            assert!(sim >= 0.85);
        }
    }

    #[test]
    fn test_find_best_match_no_match() {
        let n = normalizer();

        let candidates = vec![
            "Google".to_string(),
            "Microsoft".to_string(),
        ];

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
        config.aliases.insert("test".to_string(), "Test Company".to_string());

        let json = serde_json::to_string(&config).unwrap();
        let parsed: OrgAliasConfig = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.aliases.get("test"), Some(&"Test Company".to_string()));
    }

    #[test]
    fn test_from_app_config() {
        use crate::config::OrganizationConfig;

        let mut app_config = OrganizationConfig::default();
        app_config.aliases.insert("myalias".to_string(), "My Company".to_string());
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

    #[test]
    fn test_success_criteria_known_abbreviations() {
        let n = normalizer();
        // AWS -> Amazon Web Services
        assert_eq!(n.normalize("AWS"), "Amazon Web Services");
        // GCP -> Google Cloud Platform
        assert_eq!(n.normalize("GCP"), "Google Cloud Platform");
    }
}
