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
use anyhow::{Result, anyhow, Context};
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
        debug!("Found config directory at: {:?}", cwd_config.canonicalize().unwrap_or(cwd_config.clone()));
        return Some(cwd_config);
    }

    // Priority 2: Relative to executable directory
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            // Check config next to executable
            let exe_config = exe_dir.join("config");
            if exe_config.exists() && exe_config.is_dir() {
                debug!("Found config directory next to executable: {:?}", exe_config);
                return Some(exe_config);
            }

            // Check parent of executable (for target/release/ layout)
            if let Some(parent) = exe_dir.parent() {
                let parent_config = parent.join("config");
                if parent_config.exists() && parent_config.is_dir() {
                    debug!("Found config directory at parent of executable: {:?}", parent_config);
                    return Some(parent_config);
                }

                // Check grandparent (for target/release/ -> project root)
                if let Some(grandparent) = parent.parent() {
                    let grandparent_config = grandparent.join("config");
                    if grandparent_config.exists() && grandparent_config.is_dir() {
                        debug!("Found config directory at grandparent of executable: {:?}", grandparent_config);
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
pub const GITHUB_RAW_URL: &str = "https://raw.githubusercontent.com/your-org/nthpartyfinder/main/config/known_vendors.json";

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
            debug!("Known vendors database not found at {:?}, using empty database", base_path);
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
            let content = fs::read_to_string(overrides_path)
                .with_context(|| format!("Failed to read local overrides from {:?}", overrides_path))?;
            let db: LocalOverridesDatabase = serde_json::from_str(&content)
                .with_context(|| format!("Failed to parse local overrides from {:?}", overrides_path))?;
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
                debug!("Found {} in local overrides: {}", domain, override_entry.organization);
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
                    debug!("Found base domain {} in local overrides: {}", base_domain, override_entry.organization);
                    return Some(KnownVendorResult {
                        organization: override_entry.organization.clone(),
                        source: KnownVendorSource::LocalOverride,
                    });
                }
            }

            // Try VendorRegistry for base domain
            if let Some(org) = vendor_registry::lookup_organization(&base_domain) {
                debug!("Found base domain {} in VendorRegistry: {}", base_domain, org);
                return Some(KnownVendorResult {
                    organization: org,
                    source: KnownVendorSource::VendorRegistry,
                });
            }

            // Try remote for base domain
            if let Ok(remote_guard) = self.remote.read() {
                if let Some(ref remote) = *remote_guard {
                    if let Some(org) = remote.vendors.get(&base_domain) {
                        debug!("Found base domain {} in remote database: {}", base_domain, org);
                        return Some(KnownVendorResult {
                            organization: org.clone(),
                            source: KnownVendorSource::Remote,
                        });
                    }
                }
            }

            // Try base database for base domain
            if let Some(org) = self.base.vendors.get(&base_domain) {
                debug!("Found base domain {} in base database: {}", base_domain, org);
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
            let mut overrides = self.local_overrides.write()
                .map_err(|_| anyhow!("Failed to acquire write lock on overrides"))?;
            overrides.overrides.insert(domain_lower.clone(), override_entry);
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
        let overrides = self.local_overrides.read()
            .map_err(|_| anyhow!("Failed to acquire read lock on overrides"))?;

        // Create parent directory if needed
        if let Some(parent) = self.overrides_path.parent() {
            fs::create_dir_all(parent)?;
        }

        let content = serde_json::to_string_pretty(&*overrides)?;
        fs::write(&self.overrides_path, content)?;

        debug!("Saved {} local overrides to {:?}", overrides.overrides.len(), self.overrides_path);
        Ok(())
    }

    /// Sync with GitHub remote database
    pub async fn sync_from_github(&self, url: Option<&str>) -> Result<usize> {
        let url = url.unwrap_or(GITHUB_RAW_URL);

        info!("Syncing known vendors from GitHub: {}", url);

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()?;

        let response = client.get(url)
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
            vendor_count,
            remote_db.version,
            remote_db.updated
        );

        // Update in-memory remote database
        {
            let mut remote = self.remote.write()
                .map_err(|_| anyhow!("Failed to acquire write lock on remote database"))?;
            *remote = Some(remote_db);
        }

        Ok(vendor_count)
    }

    /// Get statistics about the database
    pub fn stats(&self) -> KnownVendorStats {
        let base_count = self.base.vendors.len();

        let remote_count = self.remote.read()
            .map(|r| r.as_ref().map(|db| db.vendors.len()).unwrap_or(0))
            .unwrap_or(0);

        let override_count = self.local_overrides.read()
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
        let compound_tlds = ["co.uk", "co.au", "com.au", "co.nz", "co.jp", "co.kr",
                            "com.br", "com.mx", "com.cn", "org.uk", "net.au"];

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
    KNOWN_VENDORS.set(kv)
        .map_err(|_| anyhow!("Known vendors already initialized"))?;

    if stats.base_count > 0 {
        info!("Known vendors database initialized: {} vendors loaded", stats.base_count);
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

    #[test]
    fn test_extract_base_domain() {
        assert_eq!(extract_base_domain("google.com"), "google.com");
        assert_eq!(extract_base_domain("api.stripe.com"), "stripe.com");
        assert_eq!(extract_base_domain("www.example.co.uk"), "example.co.uk");
        assert_eq!(extract_base_domain("sub.domain.example.com"), "example.com");
    }

    #[test]
    fn test_database_default() {
        let db = KnownVendorsDatabase::default();
        assert!(db.vendors.is_empty());
        assert_eq!(db.version, "1.0.0");
    }

    #[test]
    fn test_known_vendor_source_display() {
        assert_eq!(KnownVendorSource::Base.to_string(), "known_vendors");
        assert_eq!(KnownVendorSource::Remote.to_string(), "known_vendors_remote");
        assert_eq!(KnownVendorSource::LocalOverride.to_string(), "local_override");
        assert_eq!(KnownVendorSource::VendorRegistry.to_string(), "vendor_registry");
    }
}
