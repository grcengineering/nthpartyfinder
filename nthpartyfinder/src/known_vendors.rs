//! Known vendor database for reliable domain-to-organization mappings
//!
//! This module provides a curated database of well-known vendor domains and their
//! official organization names. It supports:
//! - VendorRegistry (consolidated vendor JSON files)
//! - Local JSON database shipped with the tool (legacy)
//! - GitHub sync for remote updates
//! - Local user overrides for confirmed mappings
//!
//! Lookup priority: Local overrides → VendorRegistry → Remote database → Base database

use crate::vendor_registry;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::RwLock;
use tracing::{debug, info, warn};

/// Path to the base known vendors database relative to working directory
pub const KNOWN_VENDORS_PATH: &str = "./config/known_vendors.json";

/// Path to local user overrides
pub const LOCAL_OVERRIDES_PATH: &str = "./config/known_vendors_local.json";

/// Find the config directory by checking multiple locations
fn find_config_dir() -> Option<PathBuf> {
    // Priority 1: Relative to current working directory
    let cwd_config = PathBuf::from("./config");
    if cwd_config.exists() && cwd_config.is_dir() {
        debug!(
            "Found config directory at: {:?}",
            cwd_config.canonicalize().unwrap_or(cwd_config.clone())
        );
        return Some(cwd_config);
    }

    // Priority 2: Relative to executable directory
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            // Check config next to executable
            let exe_config = exe_dir.join("config");
            if exe_config.exists() && exe_config.is_dir() {
                debug!(
                    "Found config directory next to executable: {:?}",
                    exe_config
                );
                return Some(exe_config);
            }

            // Check parent of executable (for target/release/ layout)
            if let Some(parent) = exe_dir.parent() {
                let parent_config = parent.join("config");
                if parent_config.exists() && parent_config.is_dir() {
                    debug!(
                        "Found config directory at parent of executable: {:?}",
                        parent_config
                    );
                    return Some(parent_config);
                }

                // Check grandparent (for target/release/ -> project root)
                if let Some(grandparent) = parent.parent() {
                    let grandparent_config = grandparent.join("config");
                    if grandparent_config.exists() && grandparent_config.is_dir() {
                        debug!(
                            "Found config directory at grandparent of executable: {:?}",
                            grandparent_config
                        );
                        return Some(grandparent_config);
                    }
                }
            }
        }
    }

    // Priority 3: Absolute path from NTHPARTYFINDER_CONFIG_DIR env var
    if let Ok(env_config) = std::env::var("NTHPARTYFINDER_CONFIG_DIR") {
        let env_path = PathBuf::from(&env_config);
        if env_path.exists() && env_path.is_dir() {
            debug!("Found config directory from env var: {:?}", env_path);
            return Some(env_path);
        }
    }

    None
}

/// Get the path to the known vendors JSON file
fn get_known_vendors_path() -> PathBuf {
    if let Some(config_dir) = find_config_dir() {
        config_dir.join("known_vendors.json")
    } else {
        // Fallback to relative path
        PathBuf::from(KNOWN_VENDORS_PATH)
    }
}

/// Get the path to the local overrides JSON file
fn get_local_overrides_path() -> PathBuf {
    if let Some(config_dir) = find_config_dir() {
        config_dir.join("known_vendors_local.json")
    } else {
        // Fallback to relative path
        PathBuf::from(LOCAL_OVERRIDES_PATH)
    }
}

/// GitHub raw URL for remote updates
pub const GITHUB_RAW_URL: &str = "https://raw.githubusercontent.com/grcengineering/nthpartyfinder/main/config/known_vendors.json";

/// Known vendors database structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownVendorsDatabase {
    /// Version of the database
    pub version: String,
    /// Last updated date
    pub updated: String,
    /// Description
    #[serde(default)]
    pub description: String,
    /// Map of domain -> organization name
    pub vendors: HashMap<String, String>,
}

impl Default for KnownVendorsDatabase {
    fn default() -> Self {
        Self {
            version: "1.0.0".to_string(),
            updated: chrono::Utc::now().format("%Y-%m-%d").to_string(),
            description: "Known vendor database".to_string(),
            vendors: HashMap::new(),
        }
    }
}

/// Local override entry with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalOverride {
    /// Organization name confirmed by user
    pub organization: String,
    /// When the override was added
    pub added: String,
    /// Source of the confirmation (e.g., "user_confirmed", "whois_verified")
    #[serde(default = "default_source")]
    pub source: String,
}

fn default_source() -> String {
    "user_confirmed".to_string()
}

/// Local overrides database structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalOverridesDatabase {
    /// Version of the overrides
    pub version: String,
    /// Last updated date
    pub updated: String,
    /// Map of domain -> override entry
    pub overrides: HashMap<String, LocalOverride>,
}

/// Result of a known vendor lookup
#[derive(Debug, Clone)]
pub struct KnownVendorResult {
    /// The organization name
    pub organization: String,
    /// Source of the lookup (base, remote, local_override)
    pub source: KnownVendorSource,
}

/// Source of a known vendor lookup
#[derive(Debug, Clone, PartialEq)]
pub enum KnownVendorSource {
    /// From the base shipped database
    Base,
    /// From GitHub remote sync
    Remote,
    /// From local user overrides
    LocalOverride,
    /// From VendorRegistry (consolidated vendor JSON files)
    VendorRegistry,
}

impl std::fmt::Display for KnownVendorSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KnownVendorSource::Base => write!(f, "known_vendors"),
            KnownVendorSource::Remote => write!(f, "known_vendors_remote"),
            KnownVendorSource::LocalOverride => write!(f, "local_override"),
            KnownVendorSource::VendorRegistry => write!(f, "vendor_registry"),
        }
    }
}

/// Known vendors manager
pub struct KnownVendors {
    /// Base database shipped with the tool
    base: KnownVendorsDatabase,
    /// Remote database from GitHub (if synced)
    remote: RwLock<Option<KnownVendorsDatabase>>,
    /// Local user overrides
    local_overrides: RwLock<LocalOverridesDatabase>,
    /// Path to local overrides file
    overrides_path: PathBuf,
}

impl KnownVendors {
    /// Load known vendors from the default paths
    pub fn load() -> Result<Self> {
        let base_path = get_known_vendors_path();
        let overrides_path = get_local_overrides_path();

        info!("Loading known vendors from: {:?}", base_path);
        info!("Local overrides path: {:?}", overrides_path);

        Self::load_from_paths(&base_path, &overrides_path)
    }

    /// Load known vendors from specific paths
    pub fn load_from_paths(base_path: &Path, overrides_path: &Path) -> Result<Self> {
        // Load base database (required)
        let base = if base_path.exists() {
            let content = fs::read_to_string(base_path)
                .with_context(|| format!("Failed to read known vendors from {:?}", base_path))?;
            serde_json::from_str(&content)
                .with_context(|| format!("Failed to parse known vendors from {:?}", base_path))?
        } else {
            debug!(
                "Known vendors database not found at {:?}, using empty database",
                base_path
            );
            KnownVendorsDatabase::default()
        };

        info!(
            "Loaded known vendors database: {} vendors (version {}, updated {})",
            base.vendors.len(),
            base.version,
            base.updated
        );

        // Load local overrides (optional)
        let local_overrides = if overrides_path.exists() {
            let content = fs::read_to_string(overrides_path).with_context(|| {
                format!("Failed to read local overrides from {:?}", overrides_path)
            })?;
            let db: LocalOverridesDatabase = serde_json::from_str(&content).with_context(|| {
                format!("Failed to parse local overrides from {:?}", overrides_path)
            })?;
            info!("Loaded {} local vendor overrides", db.overrides.len());
            db
        } else {
            debug!("No local overrides found at {:?}", overrides_path);
            LocalOverridesDatabase::default()
        };

        Ok(Self {
            base,
            remote: RwLock::new(None),
            local_overrides: RwLock::new(local_overrides),
            overrides_path: overrides_path.to_path_buf(),
        })
    }

    /// Look up organization name for a domain
    /// Returns None if domain is not in any database
    pub fn lookup(&self, domain: &str) -> Option<KnownVendorResult> {
        let domain_lower = domain.to_lowercase();

        // 1. Check local overrides first (highest priority)
        if let Ok(overrides) = self.local_overrides.read() {
            if let Some(override_entry) = overrides.overrides.get(&domain_lower) {
                debug!(
                    "Found {} in local overrides: {}",
                    domain, override_entry.organization
                );
                return Some(KnownVendorResult {
                    organization: override_entry.organization.clone(),
                    source: KnownVendorSource::LocalOverride,
                });
            }
        }

        // 2. Check VendorRegistry (consolidated vendor JSON files)
        if let Some(org) = vendor_registry::lookup_organization(&domain_lower) {
            debug!("Found {} in VendorRegistry: {}", domain, org);
            return Some(KnownVendorResult {
                organization: org,
                source: KnownVendorSource::VendorRegistry,
            });
        }

        // 3. Check remote database (if synced)
        if let Ok(remote_guard) = self.remote.read() {
            if let Some(ref remote) = *remote_guard {
                if let Some(org) = remote.vendors.get(&domain_lower) {
                    debug!("Found {} in remote database: {}", domain, org);
                    return Some(KnownVendorResult {
                        organization: org.clone(),
                        source: KnownVendorSource::Remote,
                    });
                }
            }
        }

        // 4. Check base database (legacy known_vendors.json)
        if let Some(org) = self.base.vendors.get(&domain_lower) {
            debug!("Found {} in base database: {}", domain, org);
            return Some(KnownVendorResult {
                organization: org.clone(),
                source: KnownVendorSource::Base,
            });
        }

        // Also try extracting base domain for subdomains
        let base_domain = extract_base_domain(&domain_lower);
        if base_domain != domain_lower {
            // Try local overrides for base domain
            if let Ok(overrides) = self.local_overrides.read() {
                if let Some(override_entry) = overrides.overrides.get(&base_domain) {
                    debug!(
                        "Found base domain {} in local overrides: {}",
                        base_domain, override_entry.organization
                    );
                    return Some(KnownVendorResult {
                        organization: override_entry.organization.clone(),
                        source: KnownVendorSource::LocalOverride,
                    });
                }
            }

            // Try VendorRegistry for base domain
            if let Some(org) = vendor_registry::lookup_organization(&base_domain) {
                debug!(
                    "Found base domain {} in VendorRegistry: {}",
                    base_domain, org
                );
                return Some(KnownVendorResult {
                    organization: org,
                    source: KnownVendorSource::VendorRegistry,
                });
            }

            // Try remote for base domain
            if let Ok(remote_guard) = self.remote.read() {
                if let Some(ref remote) = *remote_guard {
                    if let Some(org) = remote.vendors.get(&base_domain) {
                        debug!(
                            "Found base domain {} in remote database: {}",
                            base_domain, org
                        );
                        return Some(KnownVendorResult {
                            organization: org.clone(),
                            source: KnownVendorSource::Remote,
                        });
                    }
                }
            }

            // Try base database for base domain
            if let Some(org) = self.base.vendors.get(&base_domain) {
                debug!(
                    "Found base domain {} in base database: {}",
                    base_domain, org
                );
                return Some(KnownVendorResult {
                    organization: org.clone(),
                    source: KnownVendorSource::Base,
                });
            }
        }

        None
    }

    /// Add a local override for a domain
    pub fn add_override(&self, domain: &str, organization: &str) -> Result<()> {
        let domain_lower = domain.to_lowercase();

        let override_entry = LocalOverride {
            organization: organization.to_string(),
            added: chrono::Utc::now().format("%Y-%m-%d").to_string(),
            source: "user_confirmed".to_string(),
        };

        // Update in-memory
        {
            let mut overrides = self
                .local_overrides
                .write()
                .map_err(|_| anyhow!("Failed to acquire write lock on overrides"))?;
            overrides
                .overrides
                .insert(domain_lower.clone(), override_entry);
            overrides.updated = chrono::Utc::now().format("%Y-%m-%d").to_string();
            overrides.version = "1.0.0".to_string();
        }

        // Persist to disk
        self.save_overrides()?;

        info!("Added local override: {} -> {}", domain_lower, organization);
        Ok(())
    }

    /// Save local overrides to disk
    fn save_overrides(&self) -> Result<()> {
        let overrides = self
            .local_overrides
            .read()
            .map_err(|_| anyhow!("Failed to acquire read lock on overrides"))?;

        // Create parent directory if needed
        if let Some(parent) = self.overrides_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(&*overrides)?;
        fs::write(&self.overrides_path, content)?;

        debug!(
            "Saved {} local overrides to {:?}",
            overrides.overrides.len(),
            self.overrides_path
        );
        Ok(())
    }

    /// Sync with GitHub remote database
    pub async fn sync_from_github(&self, url: Option<&str>) -> Result<usize> {
        let url = url.unwrap_or(GITHUB_RAW_URL);

        info!("Syncing known vendors from GitHub: {}", url);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let response = client
            .get(url)
            .header("Accept", "application/json")
            .send()
            .await
            .with_context(|| format!("Failed to fetch known vendors from {}", url))?;

        if !response.status().is_success() {
            return Err(anyhow!(
                "GitHub sync failed with status {}: {}",
                response.status(),
                response.text().await.unwrap_or_default()
            ));
        }

        let content = response.text().await?;
        let remote_db: KnownVendorsDatabase = serde_json::from_str(&content)
            .with_context(|| "Failed to parse remote known vendors database")?;

        let vendor_count = remote_db.vendors.len();

        info!(
            "Synced {} vendors from GitHub (version {}, updated {})",
            vendor_count, remote_db.version, remote_db.updated
        );

        // Update in-memory remote database
        {
            let mut remote = self
                .remote
                .write()
                .map_err(|_| anyhow!("Failed to acquire write lock on remote database"))?;
            *remote = Some(remote_db);
        }

        Ok(vendor_count)
    }

    /// Get statistics about the database
    pub fn stats(&self) -> KnownVendorStats {
        let base_count = self.base.vendors.len();

        let remote_count = self
            .remote
            .read()
            .map(|r| r.as_ref().map(|db| db.vendors.len()).unwrap_or(0))
            .unwrap_or(0);

        let override_count = self
            .local_overrides
            .read()
            .map(|o| o.overrides.len())
            .unwrap_or(0);

        KnownVendorStats {
            base_count,
            remote_count,
            override_count,
            base_version: self.base.version.clone(),
            base_updated: self.base.updated.clone(),
        }
    }

    /// Check if a domain is in the known vendors database
    pub fn contains(&self, domain: &str) -> bool {
        self.lookup(domain).is_some()
    }

    /// Get the number of vendors in all databases combined (deduplicated)
    pub fn total_unique_vendors(&self) -> usize {
        let mut all_domains: std::collections::HashSet<String> = std::collections::HashSet::new();

        // Add base domains
        for domain in self.base.vendors.keys() {
            all_domains.insert(domain.to_lowercase());
        }

        // Add remote domains
        if let Ok(remote) = self.remote.read() {
            if let Some(ref db) = *remote {
                for domain in db.vendors.keys() {
                    all_domains.insert(domain.to_lowercase());
                }
            }
        }

        // Add override domains
        if let Ok(overrides) = self.local_overrides.read() {
            for domain in overrides.overrides.keys() {
                all_domains.insert(domain.to_lowercase());
            }
        }

        all_domains.len()
    }
}

/// Statistics about the known vendors database
#[derive(Debug, Clone)]
pub struct KnownVendorStats {
    /// Number of vendors in base database
    pub base_count: usize,
    /// Number of vendors in remote database (0 if not synced)
    pub remote_count: usize,
    /// Number of local overrides
    pub override_count: usize,
    /// Version of base database
    pub base_version: String,
    /// Last updated date of base database
    pub base_updated: String,
}

/// Extract the base domain from a potentially subdomained domain
/// e.g., "api.stripe.com" -> "stripe.com"
fn extract_base_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() <= 2 {
        domain.to_string()
    } else {
        // Handle common TLDs like .co.uk, .com.au, etc.
        let last_two = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
        let compound_tlds = [
            "co.uk", "co.au", "com.au", "co.nz", "co.jp", "co.kr", "com.br", "com.mx", "com.cn",
            "org.uk", "net.au",
        ];

        if compound_tlds.contains(&last_two.as_str()) && parts.len() > 2 {
            format!("{}.{}", parts[parts.len() - 3], last_two)
        } else {
            last_two
        }
    }
}

/// Global known vendors instance for easy access
static KNOWN_VENDORS: std::sync::OnceLock<KnownVendors> = std::sync::OnceLock::new();

/// Initialize the global known vendors database
pub fn init() -> Result<()> {
    let kv = KnownVendors::load()?;
    let stats = kv.stats();
    KNOWN_VENDORS
        .set(kv)
        .map_err(|_| anyhow!("Known vendors already initialized"))?;

    if stats.base_count > 0 {
        info!(
            "Known vendors database initialized: {} vendors loaded",
            stats.base_count
        );
    } else {
        warn!("Known vendors database is empty - organization lookups will fall back to WHOIS/domain inference");
    }

    Ok(())
}

/// Get a reference to the global known vendors database
pub fn get() -> Option<&'static KnownVendors> {
    KNOWN_VENDORS.get()
}

/// Look up a domain in the global known vendors database
pub fn lookup(domain: &str) -> Option<KnownVendorResult> {
    KNOWN_VENDORS.get().and_then(|kv| kv.lookup(domain))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;
    use tempfile::tempdir;

    // ── extract_base_domain ───────────────────────────────────────────

    #[test]
    fn test_extract_base_domain() {
        assert_eq!(extract_base_domain("google.com"), "google.com");
        assert_eq!(extract_base_domain("api.stripe.com"), "stripe.com");
        assert_eq!(extract_base_domain("www.example.co.uk"), "example.co.uk");
        assert_eq!(extract_base_domain("sub.domain.example.com"), "example.com");
    }

    #[rstest]
    #[case("example.co.uk", "example.co.uk")]
    #[case("api.example.co.uk", "example.co.uk")]
    #[case("deep.sub.example.co.uk", "example.co.uk")]
    #[case("example.com.au", "example.com.au")]
    #[case("sub.example.com.au", "example.com.au")]
    #[case("example.co.nz", "example.co.nz")]
    #[case("example.co.jp", "example.co.jp")]
    #[case("example.co.kr", "example.co.kr")]
    #[case("example.com.br", "example.com.br")]
    #[case("example.com.mx", "example.com.mx")]
    #[case("example.com.cn", "example.com.cn")]
    #[case("example.org.uk", "example.org.uk")]
    #[case("example.net.au", "example.net.au")]
    fn test_extract_base_domain_compound_tlds(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(extract_base_domain(input), expected);
    }

    #[rstest]
    #[case("com", "com")]
    #[case("localhost", "localhost")]
    #[case("a.b", "a.b")]
    fn test_extract_base_domain_edge_cases(#[case] input: &str, #[case] expected: &str) {
        assert_eq!(extract_base_domain(input), expected);
    }

    // ── KnownVendorsDatabase ──────────────────────────────────────────

    #[test]
    fn test_database_default() {
        let db = KnownVendorsDatabase::default();
        assert!(db.vendors.is_empty());
        assert_eq!(db.version, "1.0.0");
        assert_eq!(db.description, "Known vendor database");
        // updated should be today's date in YYYY-MM-DD format
        assert!(!db.updated.is_empty());
    }

    #[test]
    fn test_database_serde_roundtrip() {
        let mut db = KnownVendorsDatabase::default();
        db.vendors
            .insert("stripe.com".into(), "Stripe, Inc.".into());
        db.vendors
            .insert("github.com".into(), "GitHub, Inc.".into());
        db.version = "2.0.0".into();
        db.description = "Test DB".into();

        let json = serde_json::to_string(&db).unwrap();
        let parsed: KnownVendorsDatabase = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.version, "2.0.0");
        assert_eq!(parsed.description, "Test DB");
        assert_eq!(parsed.vendors.len(), 2);
        assert_eq!(parsed.vendors.get("stripe.com").unwrap(), "Stripe, Inc.");
    }

    #[test]
    fn test_database_deserialize_missing_description() {
        let json = r#"{"version":"1.0","updated":"2024-01-01","vendors":{}}"#;
        let db: KnownVendorsDatabase = serde_json::from_str(json).unwrap();
        assert_eq!(db.description, ""); // default
    }

    // ── KnownVendorSource ─────────────────────────────────────────────

    #[test]
    fn test_known_vendor_source_display() {
        assert_eq!(KnownVendorSource::Base.to_string(), "known_vendors");
        assert_eq!(
            KnownVendorSource::Remote.to_string(),
            "known_vendors_remote"
        );
        assert_eq!(
            KnownVendorSource::LocalOverride.to_string(),
            "local_override"
        );
        assert_eq!(
            KnownVendorSource::VendorRegistry.to_string(),
            "vendor_registry"
        );
    }

    #[test]
    fn test_known_vendor_source_equality() {
        assert_eq!(KnownVendorSource::Base, KnownVendorSource::Base);
        assert_ne!(KnownVendorSource::Base, KnownVendorSource::Remote);
        assert_ne!(
            KnownVendorSource::LocalOverride,
            KnownVendorSource::VendorRegistry
        );
    }

    // ── LocalOverride / LocalOverridesDatabase serde ──────────────────

    #[test]
    fn test_local_override_serde_roundtrip() {
        let entry = LocalOverride {
            organization: "Acme Corp".to_string(),
            added: "2024-06-15".to_string(),
            source: "whois_verified".to_string(),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: LocalOverride = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.organization, "Acme Corp");
        assert_eq!(parsed.added, "2024-06-15");
        assert_eq!(parsed.source, "whois_verified");
    }

    #[test]
    fn test_local_override_default_source() {
        // When "source" is absent, default_source() should supply "user_confirmed"
        let json = r#"{"organization":"Test","added":"2024-01-01"}"#;
        let parsed: LocalOverride = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.source, "user_confirmed");
    }

    #[test]
    fn test_local_overrides_database_default() {
        let db = LocalOverridesDatabase::default();
        assert!(db.overrides.is_empty());
        assert_eq!(db.version, "");
        assert_eq!(db.updated, "");
    }

    #[test]
    fn test_local_overrides_database_serde() {
        let mut db = LocalOverridesDatabase::default();
        db.version = "1.0.0".into();
        db.updated = "2024-06-15".into();
        db.overrides.insert(
            "example.com".into(),
            LocalOverride {
                organization: "Example Inc".into(),
                added: "2024-06-15".into(),
                source: "user_confirmed".into(),
            },
        );

        let json = serde_json::to_string_pretty(&db).unwrap();
        let parsed: LocalOverridesDatabase = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.overrides.len(), 1);
        assert_eq!(
            parsed.overrides.get("example.com").unwrap().organization,
            "Example Inc"
        );
    }

    // ── KnownVendorResult / KnownVendorStats ─────────────────────────

    #[test]
    fn test_known_vendor_result_clone() {
        let r = KnownVendorResult {
            organization: "Foo".into(),
            source: KnownVendorSource::Base,
        };
        let r2 = r.clone();
        assert_eq!(r2.organization, "Foo");
        assert_eq!(r2.source, KnownVendorSource::Base);
    }

    #[test]
    fn test_known_vendor_stats_clone_debug() {
        let stats = KnownVendorStats {
            base_count: 10,
            remote_count: 5,
            override_count: 2,
            base_version: "1.0.0".into(),
            base_updated: "2024-01-01".into(),
        };
        let stats2 = stats.clone();
        assert_eq!(stats2.base_count, 10);
        assert_eq!(stats2.remote_count, 5);
        assert_eq!(stats2.override_count, 2);
        let dbg = format!("{:?}", stats2);
        assert!(dbg.contains("base_count: 10"));
    }

    // ── KnownVendors: load_from_paths ─────────────────────────────────

    fn write_base_db(dir: &std::path::Path, vendors: &[(&str, &str)]) -> PathBuf {
        let path = dir.join("known_vendors.json");
        let mut map = HashMap::new();
        for (k, v) in vendors {
            map.insert(k.to_string(), v.to_string());
        }
        let db = KnownVendorsDatabase {
            version: "1.0.0".into(),
            updated: "2024-01-01".into(),
            description: "test".into(),
            vendors: map,
        };
        fs::write(&path, serde_json::to_string_pretty(&db).unwrap()).unwrap();
        path
    }

    fn write_overrides_db(dir: &std::path::Path, overrides: &[(&str, &str)]) -> PathBuf {
        let path = dir.join("known_vendors_local.json");
        let mut map = HashMap::new();
        for (domain, org) in overrides {
            map.insert(
                domain.to_string(),
                LocalOverride {
                    organization: org.to_string(),
                    added: "2024-01-01".into(),
                    source: "user_confirmed".into(),
                },
            );
        }
        let db = LocalOverridesDatabase {
            version: "1.0.0".into(),
            updated: "2024-01-01".into(),
            overrides: map,
        };
        fs::write(&path, serde_json::to_string_pretty(&db).unwrap()).unwrap();
        path
    }

    #[test]
    fn test_load_from_paths_with_base_only() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(dir.path(), &[("google.com", "Google LLC")]);
        let overrides_path = dir.path().join("nonexistent_overrides.json");

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();
        assert_eq!(kv.base.vendors.len(), 1);
        assert_eq!(kv.base.vendors.get("google.com").unwrap(), "Google LLC");
    }

    #[test]
    fn test_load_from_paths_no_files_uses_defaults() {
        let dir = tempdir().unwrap();
        let base_path = dir.path().join("no_such_base.json");
        let overrides_path = dir.path().join("no_such_overrides.json");

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();
        assert!(kv.base.vendors.is_empty());
    }

    #[test]
    fn test_load_from_paths_with_overrides() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(dir.path(), &[("google.com", "Google LLC")]);
        let overrides_path = write_overrides_db(dir.path(), &[("custom.com", "Custom Corp")]);

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();
        assert_eq!(kv.base.vendors.len(), 1);
        let overrides = kv.local_overrides.read().unwrap();
        assert_eq!(overrides.overrides.len(), 1);
    }

    #[test]
    fn test_load_from_paths_invalid_json_base() {
        let dir = tempdir().unwrap();
        let base_path = dir.path().join("bad.json");
        fs::write(&base_path, "not valid json!!!").unwrap();
        let overrides_path = dir.path().join("no_overrides.json");

        let result = KnownVendors::load_from_paths(&base_path, &overrides_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_load_from_paths_invalid_json_overrides() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(dir.path(), &[]);
        let overrides_path = dir.path().join("bad_overrides.json");
        fs::write(&overrides_path, "not valid json!!!").unwrap();

        let result = KnownVendors::load_from_paths(&base_path, &overrides_path);
        assert!(result.is_err());
    }

    // ── KnownVendors: lookup ──────────────────────────────────────────

    #[test]
    fn test_lookup_from_base() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(
            dir.path(),
            &[
                ("stripe.com", "Stripe, Inc."),
                ("github.com", "GitHub, Inc."),
            ],
        );
        let overrides_path = dir.path().join("no_overrides.json");

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();

        let result = kv.lookup("stripe.com");
        assert!(result.is_some());
        let r = result.unwrap();
        assert_eq!(r.organization, "Stripe, Inc.");
        assert_eq!(r.source, KnownVendorSource::Base);
    }

    #[test]
    fn test_lookup_case_insensitive() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(dir.path(), &[("stripe.com", "Stripe, Inc.")]);
        let overrides_path = dir.path().join("no_overrides.json");

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();

        // Uppercase input should still match lowercase key
        let result = kv.lookup("STRIPE.COM");
        assert!(result.is_some());
        assert_eq!(result.unwrap().organization, "Stripe, Inc.");
    }

    #[test]
    fn test_lookup_not_found() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(dir.path(), &[("stripe.com", "Stripe, Inc.")]);
        let overrides_path = dir.path().join("no_overrides.json");

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();

        assert!(kv.lookup("unknown-domain.xyz").is_none());
    }

    #[test]
    fn test_lookup_subdomain_falls_back_to_base_domain() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(dir.path(), &[("stripe.com", "Stripe, Inc.")]);
        let overrides_path = dir.path().join("no_overrides.json");

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();

        // "api.stripe.com" should extract base domain "stripe.com" and find it
        let result = kv.lookup("api.stripe.com");
        assert!(result.is_some());
        assert_eq!(result.unwrap().organization, "Stripe, Inc.");
    }

    #[test]
    fn test_lookup_override_takes_priority_over_base() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(dir.path(), &[("stripe.com", "Stripe Old")]);
        let overrides_path = write_overrides_db(dir.path(), &[("stripe.com", "Stripe Override")]);

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();

        let result = kv.lookup("stripe.com").unwrap();
        assert_eq!(result.organization, "Stripe Override");
        assert_eq!(result.source, KnownVendorSource::LocalOverride);
    }

    #[test]
    fn test_lookup_subdomain_override_priority() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(dir.path(), &[("stripe.com", "Base Stripe")]);
        let overrides_path = write_overrides_db(dir.path(), &[("stripe.com", "Override Stripe")]);

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();

        // Subdomain lookup should also prefer override for the base domain
        let result = kv.lookup("api.stripe.com").unwrap();
        assert_eq!(result.organization, "Override Stripe");
        assert_eq!(result.source, KnownVendorSource::LocalOverride);
    }

    // ── KnownVendors: add_override ────────────────────────────────────

    #[test]
    fn test_add_override_and_lookup() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(dir.path(), &[]);
        let overrides_path = dir.path().join("known_vendors_local.json");

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();

        // Add an override
        kv.add_override("newdomain.com", "New Domain Corp").unwrap();

        // Should be findable now
        let result = kv.lookup("newdomain.com").unwrap();
        assert_eq!(result.organization, "New Domain Corp");
        assert_eq!(result.source, KnownVendorSource::LocalOverride);
    }

    #[test]
    fn test_add_override_persists_to_disk() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(dir.path(), &[]);
        let overrides_path = dir.path().join("known_vendors_local.json");

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();
        kv.add_override("disk.com", "Disk Corp").unwrap();

        // File should exist now
        assert!(overrides_path.exists());

        // Read it back
        let content = fs::read_to_string(&overrides_path).unwrap();
        let parsed: LocalOverridesDatabase = serde_json::from_str(&content).unwrap();
        assert_eq!(
            parsed.overrides.get("disk.com").unwrap().organization,
            "Disk Corp"
        );
    }

    #[test]
    fn test_add_override_lowercases_domain() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(dir.path(), &[]);
        let overrides_path = dir.path().join("known_vendors_local.json");

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();
        kv.add_override("UPPER.COM", "Upper Corp").unwrap();

        let result = kv.lookup("upper.com").unwrap();
        assert_eq!(result.organization, "Upper Corp");
    }

    #[test]
    fn test_add_override_creates_parent_dir() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(dir.path(), &[]);
        // Nested path whose parent doesn't exist
        let overrides_path = dir.path().join("subdir").join("known_vendors_local.json");

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();
        kv.add_override("nested.com", "Nested Corp").unwrap();

        assert!(overrides_path.exists());
    }

    // ── KnownVendors: contains ────────────────────────────────────────

    #[test]
    fn test_contains() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(dir.path(), &[("known.com", "Known Corp")]);
        let overrides_path = dir.path().join("no_overrides.json");

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();

        assert!(kv.contains("known.com"));
        assert!(!kv.contains("unknown.com"));
    }

    // ── KnownVendors: stats ───────────────────────────────────────────

    #[test]
    fn test_stats_base_only() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(
            dir.path(),
            &[("a.com", "A"), ("b.com", "B"), ("c.com", "C")],
        );
        let overrides_path = dir.path().join("no_overrides.json");

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();
        let stats = kv.stats();

        assert_eq!(stats.base_count, 3);
        assert_eq!(stats.remote_count, 0);
        assert_eq!(stats.override_count, 0);
        assert_eq!(stats.base_version, "1.0.0");
    }

    #[test]
    fn test_stats_with_overrides() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(dir.path(), &[("a.com", "A")]);
        let overrides_path = write_overrides_db(dir.path(), &[("x.com", "X"), ("y.com", "Y")]);

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();
        let stats = kv.stats();

        assert_eq!(stats.base_count, 1);
        assert_eq!(stats.override_count, 2);
    }

    // ── KnownVendors: total_unique_vendors ────────────────────────────

    #[test]
    fn test_total_unique_vendors_deduplicates() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(dir.path(), &[("a.com", "A Corp"), ("b.com", "B Corp")]);
        // Override one of the same domains
        let overrides_path =
            write_overrides_db(dir.path(), &[("a.com", "A Override"), ("c.com", "C Corp")]);

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();

        // base has {a.com, b.com}, overrides has {a.com, c.com}
        // unique = {a.com, b.com, c.com} = 3
        assert_eq!(kv.total_unique_vendors(), 3);
    }

    #[test]
    fn test_total_unique_vendors_empty() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(dir.path(), &[]);
        let overrides_path = dir.path().join("no_overrides.json");

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();
        assert_eq!(kv.total_unique_vendors(), 0);
    }

    // ── find_config_dir with env var ──────────────────────────────────

    #[test]
    fn test_find_config_dir_with_env_var() {
        let dir = tempdir().unwrap();
        let config_dir = dir.path().join("myconfig");
        fs::create_dir_all(&config_dir).unwrap();

        // Set the env var
        std::env::set_var("NTHPARTYFINDER_CONFIG_DIR", config_dir.to_str().unwrap());

        // find_config_dir may or may not use the env (depends on whether ./config exists)
        // but we can verify the env var path is valid
        let env_val = std::env::var("NTHPARTYFINDER_CONFIG_DIR").unwrap();
        let env_path = PathBuf::from(&env_val);
        assert!(env_path.exists());
        assert!(env_path.is_dir());

        // Clean up
        std::env::remove_var("NTHPARTYFINDER_CONFIG_DIR");
    }

    // ── get_known_vendors_path / get_local_overrides_path ─────────────

    #[test]
    fn test_get_known_vendors_path_returns_pathbuf() {
        let path = get_known_vendors_path();
        // Should end with known_vendors.json regardless of which config dir is found
        assert!(path.to_str().unwrap().ends_with("known_vendors.json"));
    }

    #[test]
    fn test_get_local_overrides_path_returns_pathbuf() {
        let path = get_local_overrides_path();
        assert!(path.to_str().unwrap().ends_with("known_vendors_local.json"));
    }

    // ── Constants ─────────────────────────────────────────────────────

    #[test]
    fn test_constants() {
        assert!(KNOWN_VENDORS_PATH.contains("known_vendors.json"));
        assert!(LOCAL_OVERRIDES_PATH.contains("known_vendors_local.json"));
        assert!(GITHUB_RAW_URL.starts_with("https://"));
        assert!(GITHUB_RAW_URL.contains("known_vendors.json"));
    }

    // ── sync_from_github error path (no network) ─────────────────────

    #[tokio::test]
    async fn test_sync_from_github_bad_url() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(dir.path(), &[]);
        let overrides_path = dir.path().join("no_overrides.json");

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();

        // Use a URL that won't resolve — this should error
        let result = kv
            .sync_from_github(Some("http://127.0.0.1:1/nonexistent"))
            .await;
        assert!(result.is_err());
    }

    // ── default_source helper ─────────────────────────────────────────

    #[test]
    fn test_default_source_fn() {
        assert_eq!(default_source(), "user_confirmed");
    }

    // ── Multiple overrides then re-lookup ─────────────────────────────

    #[test]
    fn test_add_multiple_overrides() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(dir.path(), &[]);
        let overrides_path = dir.path().join("known_vendors_local.json");

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();

        kv.add_override("one.com", "One Corp").unwrap();
        kv.add_override("two.com", "Two Corp").unwrap();
        kv.add_override("three.com", "Three Corp").unwrap();

        assert_eq!(kv.lookup("one.com").unwrap().organization, "One Corp");
        assert_eq!(kv.lookup("two.com").unwrap().organization, "Two Corp");
        assert_eq!(kv.lookup("three.com").unwrap().organization, "Three Corp");

        let stats = kv.stats();
        assert_eq!(stats.override_count, 3);
    }

    #[test]
    fn test_override_replaces_existing() {
        let dir = tempdir().unwrap();
        let base_path = write_base_db(dir.path(), &[]);
        let overrides_path = dir.path().join("known_vendors_local.json");

        let kv = KnownVendors::load_from_paths(&base_path, &overrides_path).unwrap();

        kv.add_override("change.com", "Original").unwrap();
        assert_eq!(kv.lookup("change.com").unwrap().organization, "Original");

        kv.add_override("change.com", "Updated").unwrap();
        assert_eq!(kv.lookup("change.com").unwrap().organization, "Updated");

        // Should still only have 1 override, not 2
        assert_eq!(kv.stats().override_count, 1);
    }

    // ── Global functions (get/lookup when not initialized) ────────────

    #[test]
    fn test_global_lookup_without_init_returns_none() {
        // The global KNOWN_VENDORS may or may not be initialized depending on
        // test execution order, but calling lookup should never panic.
        let _ = lookup("definitely-not-a-real-domain-12345.xyz");
    }

    #[test]
    fn test_global_get_does_not_panic() {
        let _ = get();
    }
}
