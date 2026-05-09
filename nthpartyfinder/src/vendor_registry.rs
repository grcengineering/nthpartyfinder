//! Vendor Registry - Consolidated vendor configuration management

use anyhow::{Context, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum DomainType {
    Primary,
    Service,
    Api,
    Cdn,
    Acquired,
    Alias,
    Email,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum RiskCategory {
    Platform,
    Infrastructure,
    Tracking,
    Advertising,
    Security,
    Payment,
    Communication,
    Storage,
    Development,
    Monitoring,
    Media,
    Support,
    Analytics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainMetadata {
    #[serde(rename = "type")]
    pub domain_type: Option<DomainType>,
    pub category: Option<RiskCategory>,
    pub description: Option<String>,
    pub acquired_year: Option<u16>,
    pub vendor_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantDetection {
    pub success_indicators: Option<Vec<String>>,
    pub failure_indicators: Option<Vec<String>>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaasTenant {
    pub name: String,
    pub patterns: Vec<String>,
    pub detection: Option<TenantDetection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorConfig {
    #[serde(rename = "$schema")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub id: String,
    pub organization: String,
    pub primary_domain: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_vendor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub acquired_year: Option<u16>,
    #[serde(default)]
    pub domains: HashMap<String, DomainMetadata>,
    #[serde(default)]
    pub verification_patterns: Vec<String>,
    #[serde(default)]
    pub provider_aliases: Vec<String>,
    #[serde(default)]
    pub saas_tenants: Vec<SaasTenant>,
}

#[derive(Debug)]
pub struct VendorRegistry {
    vendors: HashMap<String, Arc<VendorConfig>>,
    domain_to_vendor: HashMap<String, String>,
    alias_to_vendor: HashMap<String, String>,
    verification_patterns: Vec<(String, String)>,
    config_dir: PathBuf,
}

/// Filter directory entries to valid vendor JSON file paths.
fn filter_vendor_path(entry: std::io::Result<std::fs::DirEntry>) -> Option<PathBuf> {
    let entry = entry.ok()?;
    let path = entry.path();
    if path.extension().is_none_or(|e| e != "json") {
        return None;
    }
    if path.file_name().is_some_and(|n| n == "_schema.json") {
        return None;
    }
    Some(path)
}

impl VendorRegistry {
    pub fn new() -> Self {
        Self {
            vendors: HashMap::new(),
            domain_to_vendor: HashMap::new(),
            alias_to_vendor: HashMap::new(),
            verification_patterns: Vec::new(),
            config_dir: PathBuf::new(),
        }
    }

    pub fn load_from_directory(config_dir: &Path) -> Result<Self> {
        let vendors_dir = config_dir.join("vendors");
        if !vendors_dir.exists() {
            warn!("Vendors directory not found: {:?}", vendors_dir);
            return Ok(Self::new());
        }
        let mut registry = Self::new();
        registry.config_dir = config_dir.to_path_buf();

        // Collect all JSON file paths first
        let json_files: Vec<PathBuf> = std::fs::read_dir(&vendors_dir)
            .with_context(|| format!("Failed to read: {:?}", vendors_dir))?
            .filter_map(filter_vendor_path)
            .collect();

        // Read and parse all files in parallel using rayon
        let parsed_configs: Vec<Result<VendorConfig>> = json_files
            .par_iter()
            .map(|path| {
                let content = std::fs::read_to_string(path)
                    .with_context(|| format!("Failed to read: {:?}", path))?;
                let config: VendorConfig = serde_json::from_str(&content)
                    .with_context(|| format!("Failed to parse: {:?}", path))?;
                Ok(config)
            })
            .collect();

        // Merge results into registry (single-threaded, fast)
        for result in parsed_configs {
            match result {
                Ok(config) => {
                    let vendor_id = config.id.clone();
                    let config = Arc::new(config);
                    for domain in config.domains.keys() {
                        registry
                            .domain_to_vendor
                            .insert(domain.to_lowercase(), vendor_id.clone());
                    }
                    let primary = config.primary_domain.to_lowercase();
                    registry
                        .domain_to_vendor
                        .entry(primary)
                        .or_insert_with(|| vendor_id.clone());
                    for alias in &config.provider_aliases {
                        registry
                            .alias_to_vendor
                            .insert(alias.to_lowercase(), vendor_id.clone());
                    }
                    for pattern in &config.verification_patterns {
                        registry
                            .verification_patterns
                            .push((pattern.clone(), vendor_id.clone()));
                    }
                    debug!(
                        "Loaded vendor: {} with {} domains",
                        config.id,
                        config.domains.len()
                    );
                    registry.vendors.insert(vendor_id, config);
                }
                Err(e) => warn!("Failed to load vendor: {}", e),
            }
        }
        info!("Loaded {} vendors", registry.vendors.len());
        Ok(registry)
    }

    fn load_vendor_file(&mut self, path: &Path) -> Result<Arc<VendorConfig>> {
        let content =
            std::fs::read_to_string(path).with_context(|| format!("Failed to read: {:?}", path))?;
        let config: VendorConfig = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse: {:?}", path))?;
        let vendor_id = config.id.clone();
        let config = Arc::new(config);

        for domain in config.domains.keys() {
            self.domain_to_vendor
                .insert(domain.to_lowercase(), vendor_id.clone());
        }
        let primary = config.primary_domain.to_lowercase();
        self.domain_to_vendor
            .entry(primary)
            .or_insert_with(|| vendor_id.clone());
        for alias in &config.provider_aliases {
            self.alias_to_vendor
                .insert(alias.to_lowercase(), vendor_id.clone());
        }
        for pattern in &config.verification_patterns {
            self.verification_patterns
                .push((pattern.clone(), vendor_id.clone()));
        }
        self.vendors.insert(vendor_id, config.clone());
        Ok(config)
    }

    pub fn get_vendor_by_domain(&self, domain: &str) -> Option<Arc<VendorConfig>> {
        let d = domain.to_lowercase();
        if let Some(id) = self.domain_to_vendor.get(&d) {
            return self.vendors.get(id).cloned();
        }
        let parts: Vec<&str> = d.split('.').collect();
        if parts.len() > 2 {
            let base = parts[parts.len() - 2..].join(".");
            if let Some(id) = self.domain_to_vendor.get(&base) {
                return self.vendors.get(id).cloned();
            }
        }
        None
    }

    pub fn get_vendor_by_alias(&self, alias: &str) -> Option<Arc<VendorConfig>> {
        self.alias_to_vendor
            .get(&alias.to_lowercase())
            .and_then(|id| self.vendors.get(id).cloned())
    }

    pub fn get_vendor(&self, id: &str) -> Option<Arc<VendorConfig>> {
        self.vendors.get(id).cloned()
    }

    pub fn get_organization(&self, domain: &str) -> Option<String> {
        self.get_vendor_by_domain(domain)
            .map(|v| v.organization.clone())
    }

    pub fn find_vendor_by_verification(&self, txt: &str) -> Option<Arc<VendorConfig>> {
        let txt_lower = txt.to_lowercase();
        for (pattern, id) in &self.verification_patterns {
            if txt_lower.contains(&pattern.to_lowercase()) {
                return self.vendors.get(id).cloned();
            }
        }
        None
    }

    pub fn get_all_saas_tenants(&self) -> Vec<(String, SaasTenant)> {
        let mut tenants = Vec::new();
        for (id, config) in &self.vendors {
            for t in &config.saas_tenants {
                tenants.push((id.clone(), t.clone()));
            }
        }
        tenants
    }

    pub fn is_known_domain(&self, domain: &str) -> bool {
        self.domain_to_vendor.contains_key(&domain.to_lowercase())
    }

    pub fn vendor_count(&self) -> usize {
        self.vendors.len()
    }
    pub fn domain_count(&self) -> usize {
        self.domain_to_vendor.len()
    }

    pub fn get_all_domain_mappings(&self) -> HashMap<String, String> {
        let mut m = HashMap::new();
        for (d, id) in &self.domain_to_vendor {
            if let Some(v) = self.vendors.get(id) {
                m.insert(d.clone(), v.organization.clone());
            }
        }
        m
    }
}

impl Default for VendorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Global Registry Access
// ============================================================================

use std::sync::OnceLock;

/// Global vendor registry instance
static VENDOR_REGISTRY: OnceLock<VendorRegistry> = OnceLock::new();

/// Testable core of config-directory search. Accepts pre-resolved inputs
/// so tests can exercise every branch without filesystem or env-var side effects.
fn find_config_dir_inner(
    cwd_config: &Path,
    exe_path: Option<PathBuf>,
    env_config: Option<String>,
) -> Option<PathBuf> {
    // Priority 1: Relative to current working directory
    if cwd_config.exists() && cwd_config.is_dir() && cwd_config.join("vendors").exists() {
        debug!(
            "Found config directory at: {:?}",
            cwd_config
                .canonicalize()
                .unwrap_or(cwd_config.to_path_buf())
        );
        return Some(cwd_config.to_path_buf());
    }

    // Priority 2: Relative to executable directory
    if let Some(exe_path) = exe_path {
        if let Some(exe_dir) = exe_path.parent() {
            let exe_config = exe_dir.join("config");
            if exe_config.exists() && exe_config.join("vendors").exists() {
                debug!(
                    "Found config directory next to executable: {:?}",
                    exe_config
                );
                return Some(exe_config);
            }
            if let Some(parent) = exe_dir.parent() {
                let parent_config = parent.join("config");
                if parent_config.exists() && parent_config.join("vendors").exists() {
                    return Some(parent_config);
                }
                if let Some(grandparent) = parent.parent() {
                    let grandparent_config = grandparent.join("config");
                    if grandparent_config.exists() && grandparent_config.join("vendors").exists() {
                        return Some(grandparent_config);
                    }
                }
            }
        }
    }

    // Priority 3: Env var
    if let Some(env_config) = env_config {
        let env_path = PathBuf::from(&env_config);
        if env_path.exists() && env_path.join("vendors").exists() {
            return Some(env_path);
        }
    }

    None
}

// coverage(off): thin wrapper gathering real env/filesystem inputs — all logic tested via find_config_dir_inner
#[cfg_attr(coverage_nightly, coverage(off))]
fn find_config_dir() -> Option<PathBuf> {
    find_config_dir_inner(
        &PathBuf::from("./config"),
        std::env::current_exe().ok(),
        std::env::var("NTHPARTYFINDER_CONFIG_DIR").ok(),
    )
}

// coverage(off): global OnceLock initializer — can only run once per process; all logic
// (load_from_directory, find_config_dir_inner) is tested independently
#[cfg_attr(coverage_nightly, coverage(off))]
pub fn init() -> Result<()> {
    let config_dir = find_config_dir();

    let registry = if let Some(ref dir) = config_dir {
        VendorRegistry::load_from_directory(dir)?
    } else {
        warn!("No config/vendors directory found, using empty registry");
        VendorRegistry::new()
    };

    let vendor_count = registry.vendor_count();
    let domain_count = registry.domain_count();

    VENDOR_REGISTRY
        .set(registry)
        .map_err(|_| anyhow::anyhow!("Vendor registry already initialized"))?;

    if vendor_count > 0 {
        info!(
            "Vendor registry initialized: {} vendors, {} domains",
            vendor_count, domain_count
        );
    }

    Ok(())
}

/// Get a reference to the global vendor registry
pub fn get() -> Option<&'static VendorRegistry> {
    VENDOR_REGISTRY.get()
}

/// Look up organization name for a domain using the global registry
pub fn lookup_organization(domain: &str) -> Option<String> {
    get().and_then(|r| r.get_organization(domain))
}

/// Check if a domain is known in the global registry
pub fn is_known_domain(domain: &str) -> bool {
    get().is_some_and(|r| r.is_known_domain(domain))
}

/// Get vendor by domain from global registry
pub fn get_vendor_by_domain(domain: &str) -> Option<Arc<VendorConfig>> {
    get().and_then(|r| r.get_vendor_by_domain(domain))
}

/// Find vendor by verification pattern from global registry
pub fn find_vendor_by_verification(txt: &str) -> Option<Arc<VendorConfig>> {
    get().and_then(|r| r.find_vendor_by_verification(txt))
}

/// Get all SaaS tenants from global registry
pub fn get_all_saas_tenants() -> Vec<(String, SaasTenant)> {
    get().map_or(Vec::new(), |r| r.get_all_saas_tenants())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn sample_vendor_json() -> &'static str {
        r#"{
            "id": "acme",
            "organization": "Acme Corp",
            "primary_domain": "acme.com",
            "domains": {
                "acme.com": {
                    "type": "primary",
                    "category": "platform",
                    "description": "Main website"
                },
                "acme-cdn.com": {
                    "type": "cdn",
                    "category": "infrastructure",
                    "description": "CDN domain"
                },
                "acme-api.io": {
                    "type": "api",
                    "category": "development"
                }
            },
            "verification_patterns": ["acme-verify", "acme-site-verification"],
            "provider_aliases": ["acme", "acme-corp", "acme_inc"],
            "saas_tenants": [
                {
                    "name": "Acme Workspace",
                    "patterns": ["{tenant}.acme.com", "{tenant}.acme-app.com"],
                    "detection": {
                        "success_indicators": ["Welcome to Acme"],
                        "failure_indicators": ["not found"],
                        "notes": "Check for 200 response"
                    }
                }
            ]
        }"#
    }

    fn sample_vendor2_json() -> &'static str {
        r#"{
            "id": "globex",
            "organization": "Globex Inc",
            "primary_domain": "globex.net",
            "parent_vendor": "mega-corp",
            "acquired_year": 2020,
            "domains": {
                "globex.net": {
                    "type": "primary",
                    "category": "platform"
                },
                "globex-mail.com": {
                    "type": "email",
                    "category": "communication"
                }
            },
            "verification_patterns": ["globex-verify"],
            "provider_aliases": ["globex"],
            "saas_tenants": []
        }"#
    }

    fn setup_vendor_dir() -> tempfile::TempDir {
        let dir = tempdir().unwrap();
        let vendors_dir = dir.path().join("vendors");
        fs::create_dir_all(&vendors_dir).unwrap();
        fs::write(vendors_dir.join("acme.json"), sample_vendor_json()).unwrap();
        fs::write(vendors_dir.join("globex.json"), sample_vendor2_json()).unwrap();
        dir
    }

    // ---- VendorRegistry::new ----

    #[test]
    fn new_creates_empty_registry() {
        let reg = VendorRegistry::new();
        assert_eq!(reg.vendor_count(), 0);
        assert_eq!(reg.domain_count(), 0);
    }

    #[test]
    fn default_creates_empty_registry() {
        let reg = VendorRegistry::default();
        assert_eq!(reg.vendor_count(), 0);
        assert_eq!(reg.domain_count(), 0);
    }

    // ---- load_from_directory ----

    #[test]
    fn load_from_directory_loads_vendors() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();
        assert_eq!(reg.vendor_count(), 2);
        // acme has 3 domains + primary_domain (already in domains), globex has 2 + primary
        assert!(reg.domain_count() >= 5);
    }

    #[test]
    fn load_from_directory_missing_dir_returns_empty() {
        let dir = tempdir().unwrap();
        // No "vendors" subdirectory
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();
        assert_eq!(reg.vendor_count(), 0);
    }

    #[test]
    fn load_from_directory_skips_schema_json() {
        let dir = tempdir().unwrap();
        let vendors_dir = dir.path().join("vendors");
        fs::create_dir_all(&vendors_dir).unwrap();
        fs::write(vendors_dir.join("_schema.json"), r#"{"type": "object"}"#).unwrap();
        fs::write(vendors_dir.join("acme.json"), sample_vendor_json()).unwrap();

        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();
        assert_eq!(reg.vendor_count(), 1);
    }

    #[test]
    fn load_from_directory_skips_non_json_files() {
        let dir = tempdir().unwrap();
        let vendors_dir = dir.path().join("vendors");
        fs::create_dir_all(&vendors_dir).unwrap();
        fs::write(vendors_dir.join("readme.txt"), "not json").unwrap();
        fs::write(vendors_dir.join("acme.json"), sample_vendor_json()).unwrap();

        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();
        assert_eq!(reg.vendor_count(), 1);
    }

    #[test]
    fn load_from_directory_handles_invalid_json() {
        let dir = tempdir().unwrap();
        let vendors_dir = dir.path().join("vendors");
        fs::create_dir_all(&vendors_dir).unwrap();
        fs::write(vendors_dir.join("bad.json"), "not valid json!").unwrap();
        fs::write(vendors_dir.join("acme.json"), sample_vendor_json()).unwrap();

        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();
        // bad.json should be skipped with a warning, acme.json should load
        assert_eq!(reg.vendor_count(), 1);
    }

    // ---- load_vendor_file ----

    #[test]
    fn load_vendor_file_adds_to_registry() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("acme.json");
        fs::write(&path, sample_vendor_json()).unwrap();

        let mut reg = VendorRegistry::new();
        let config = reg.load_vendor_file(&path).unwrap();
        assert_eq!(config.id, "acme");
        assert_eq!(config.organization, "Acme Corp");
        assert_eq!(reg.vendor_count(), 1);
    }

    #[test]
    fn load_vendor_file_registers_domains() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("acme.json");
        fs::write(&path, sample_vendor_json()).unwrap();

        let mut reg = VendorRegistry::new();
        reg.load_vendor_file(&path).unwrap();

        assert!(reg.is_known_domain("acme.com"));
        assert!(reg.is_known_domain("acme-cdn.com"));
        assert!(reg.is_known_domain("acme-api.io"));
    }

    #[test]
    fn load_vendor_file_registers_aliases() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("acme.json");
        fs::write(&path, sample_vendor_json()).unwrap();

        let mut reg = VendorRegistry::new();
        reg.load_vendor_file(&path).unwrap();

        assert!(reg.get_vendor_by_alias("acme").is_some());
        assert!(reg.get_vendor_by_alias("acme-corp").is_some());
        assert!(reg.get_vendor_by_alias("acme_inc").is_some());
    }

    #[test]
    fn load_vendor_file_registers_verification_patterns() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("acme.json");
        fs::write(&path, sample_vendor_json()).unwrap();

        let mut reg = VendorRegistry::new();
        reg.load_vendor_file(&path).unwrap();

        let found = reg.find_vendor_by_verification("acme-verify=abc123");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, "acme");
    }

    #[test]
    fn load_vendor_file_invalid_path_returns_error() {
        let mut reg = VendorRegistry::new();
        let result = reg.load_vendor_file(Path::new("/nonexistent/path.json"));
        assert!(result.is_err());
    }

    // ---- get_vendor_by_domain ----

    #[test]
    fn get_vendor_by_domain_exact_match() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        let vendor = reg.get_vendor_by_domain("acme.com");
        assert!(vendor.is_some());
        assert_eq!(vendor.unwrap().organization, "Acme Corp");
    }

    #[test]
    fn get_vendor_by_domain_case_insensitive() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        let vendor = reg.get_vendor_by_domain("ACME.COM");
        assert!(vendor.is_some());
        assert_eq!(vendor.unwrap().id, "acme");
    }

    #[test]
    fn get_vendor_by_domain_subdomain_fallback() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        // sub.acme.com should fall back to acme.com
        let vendor = reg.get_vendor_by_domain("sub.acme.com");
        assert!(vendor.is_some());
        assert_eq!(vendor.unwrap().id, "acme");
    }

    #[test]
    fn get_vendor_by_domain_unknown_returns_none() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        assert!(reg.get_vendor_by_domain("unknown-domain.com").is_none());
    }

    // ---- get_vendor_by_alias ----

    #[test]
    fn get_vendor_by_alias_exact() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        let vendor = reg.get_vendor_by_alias("acme");
        assert!(vendor.is_some());
        assert_eq!(vendor.unwrap().id, "acme");
    }

    #[test]
    fn get_vendor_by_alias_case_insensitive() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        let vendor = reg.get_vendor_by_alias("ACME-CORP");
        assert!(vendor.is_some());
        assert_eq!(vendor.unwrap().id, "acme");
    }

    #[test]
    fn get_vendor_by_alias_unknown_returns_none() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        assert!(reg.get_vendor_by_alias("nonexistent").is_none());
    }

    // ---- get_vendor ----

    #[test]
    fn get_vendor_by_id() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        let vendor = reg.get_vendor("acme");
        assert!(vendor.is_some());
        assert_eq!(vendor.unwrap().primary_domain, "acme.com");
    }

    #[test]
    fn get_vendor_unknown_id_returns_none() {
        let reg = VendorRegistry::new();
        assert!(reg.get_vendor("nonexistent").is_none());
    }

    // ---- get_organization ----

    #[test]
    fn get_organization_returns_name() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        assert_eq!(
            reg.get_organization("acme.com"),
            Some("Acme Corp".to_string())
        );
        assert_eq!(
            reg.get_organization("globex.net"),
            Some("Globex Inc".to_string())
        );
    }

    #[test]
    fn get_organization_unknown_returns_none() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        assert_eq!(reg.get_organization("nope.com"), None);
    }

    // ---- find_vendor_by_verification ----

    #[test]
    fn find_vendor_by_verification_match() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        let vendor = reg.find_vendor_by_verification("acme-site-verification=1234");
        assert!(vendor.is_some());
        assert_eq!(vendor.unwrap().id, "acme");
    }

    #[test]
    fn find_vendor_by_verification_case_insensitive() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        let vendor = reg.find_vendor_by_verification("GLOBEX-VERIFY=token");
        assert!(vendor.is_some());
        assert_eq!(vendor.unwrap().id, "globex");
    }

    #[test]
    fn find_vendor_by_verification_no_match() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        assert!(reg.find_vendor_by_verification("unknown-pattern").is_none());
    }

    // ---- get_all_saas_tenants ----

    #[test]
    fn get_all_saas_tenants_returns_tenants() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        let tenants = reg.get_all_saas_tenants();
        assert_eq!(tenants.len(), 1); // only acme has saas_tenants
        let (vendor_id, tenant) = &tenants[0];
        assert_eq!(vendor_id, "acme");
        assert_eq!(tenant.name, "Acme Workspace");
        assert_eq!(tenant.patterns.len(), 2);
    }

    #[test]
    fn get_all_saas_tenants_empty_registry() {
        let reg = VendorRegistry::new();
        assert!(reg.get_all_saas_tenants().is_empty());
    }

    // ---- is_known_domain ----

    #[test]
    fn is_known_domain_true_for_registered() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        assert!(reg.is_known_domain("acme.com"));
        assert!(reg.is_known_domain("ACME.COM"));
        assert!(reg.is_known_domain("globex-mail.com"));
    }

    #[test]
    fn is_known_domain_false_for_unknown() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        assert!(!reg.is_known_domain("unknown.com"));
    }

    // ---- vendor_count / domain_count ----

    #[test]
    fn vendor_and_domain_counts() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        assert_eq!(reg.vendor_count(), 2);
        // acme: acme.com, acme-cdn.com, acme-api.io (3 from domains map + primary already included)
        // globex: globex.net, globex-mail.com (2 from domains map + primary already included)
        assert!(reg.domain_count() >= 5);
    }

    // ---- get_all_domain_mappings ----

    #[test]
    fn get_all_domain_mappings_returns_map() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        let mappings = reg.get_all_domain_mappings();
        assert_eq!(mappings.get("acme.com"), Some(&"Acme Corp".to_string()));
        assert_eq!(mappings.get("globex.net"), Some(&"Globex Inc".to_string()));
        assert_eq!(mappings.get("acme-cdn.com"), Some(&"Acme Corp".to_string()));
    }

    #[test]
    fn get_all_domain_mappings_empty_registry() {
        let reg = VendorRegistry::new();
        assert!(reg.get_all_domain_mappings().is_empty());
    }

    // ---- VendorConfig serialization/deserialization ----

    #[test]
    fn vendor_config_deserialize() {
        let config: VendorConfig = serde_json::from_str(sample_vendor_json()).unwrap();
        assert_eq!(config.id, "acme");
        assert_eq!(config.organization, "Acme Corp");
        assert_eq!(config.primary_domain, "acme.com");
        assert!(config.parent_vendor.is_none());
        assert!(config.acquired_year.is_none());
        assert_eq!(config.domains.len(), 3);
        assert_eq!(config.verification_patterns.len(), 2);
        assert_eq!(config.provider_aliases.len(), 3);
        assert_eq!(config.saas_tenants.len(), 1);
    }

    #[test]
    fn vendor_config_with_parent_and_acquired() {
        let config: VendorConfig = serde_json::from_str(sample_vendor2_json()).unwrap();
        assert_eq!(config.parent_vendor, Some("mega-corp".to_string()));
        assert_eq!(config.acquired_year, Some(2020));
    }

    #[test]
    fn vendor_config_roundtrip() {
        let config: VendorConfig = serde_json::from_str(sample_vendor_json()).unwrap();
        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: VendorConfig = serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized.id, config.id);
        assert_eq!(deserialized.organization, config.organization);
        assert_eq!(deserialized.primary_domain, config.primary_domain);
        assert_eq!(deserialized.domains.len(), config.domains.len());
    }

    #[test]
    fn vendor_config_minimal() {
        let json = r#"{
            "id": "minimal",
            "organization": "Min Corp",
            "primary_domain": "min.com"
        }"#;
        let config: VendorConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.id, "minimal");
        assert!(config.domains.is_empty());
        assert!(config.verification_patterns.is_empty());
        assert!(config.provider_aliases.is_empty());
        assert!(config.saas_tenants.is_empty());
        assert!(config.parent_vendor.is_none());
        assert!(config.acquired_year.is_none());
        assert!(config.schema.is_none());
    }

    #[test]
    fn vendor_config_with_schema() {
        let json = r#"{
            "$schema": "vendor-schema.json",
            "id": "withschema",
            "organization": "Schema Corp",
            "primary_domain": "schema.com"
        }"#;
        let config: VendorConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.schema, Some("vendor-schema.json".to_string()));
    }

    // ---- DomainType enum ----

    #[test]
    fn domain_type_deserialize_all_variants() {
        let variants = vec![
            ("\"primary\"", DomainType::Primary),
            ("\"service\"", DomainType::Service),
            ("\"api\"", DomainType::Api),
            ("\"cdn\"", DomainType::Cdn),
            ("\"acquired\"", DomainType::Acquired),
            ("\"alias\"", DomainType::Alias),
            ("\"email\"", DomainType::Email),
        ];
        for (json, expected) in variants {
            let dt: DomainType = serde_json::from_str(json).unwrap();
            assert_eq!(dt, expected);
        }
    }

    #[test]
    fn domain_type_serialize() {
        let dt = DomainType::Primary;
        let s = serde_json::to_string(&dt).unwrap();
        assert_eq!(s, "\"primary\"");
    }

    // ---- RiskCategory enum ----

    #[test]
    fn risk_category_deserialize_all_variants() {
        let variants = vec![
            ("\"platform\"", RiskCategory::Platform),
            ("\"infrastructure\"", RiskCategory::Infrastructure),
            ("\"tracking\"", RiskCategory::Tracking),
            ("\"advertising\"", RiskCategory::Advertising),
            ("\"security\"", RiskCategory::Security),
            ("\"payment\"", RiskCategory::Payment),
            ("\"communication\"", RiskCategory::Communication),
            ("\"storage\"", RiskCategory::Storage),
            ("\"development\"", RiskCategory::Development),
            ("\"monitoring\"", RiskCategory::Monitoring),
            ("\"media\"", RiskCategory::Media),
            ("\"support\"", RiskCategory::Support),
            ("\"analytics\"", RiskCategory::Analytics),
        ];
        for (json, expected) in variants {
            let rc: RiskCategory = serde_json::from_str(json).unwrap();
            assert_eq!(rc, expected);
        }
    }

    #[test]
    fn risk_category_serialize() {
        let rc = RiskCategory::Infrastructure;
        let s = serde_json::to_string(&rc).unwrap();
        assert_eq!(s, "\"infrastructure\"");
    }

    // ---- DomainMetadata ----

    #[test]
    fn domain_metadata_deserialize() {
        let json = r#"{
            "type": "service",
            "category": "analytics",
            "description": "Analytics service",
            "acquired_year": 2019,
            "vendor_ref": "parent-vendor"
        }"#;
        let meta: DomainMetadata = serde_json::from_str(json).unwrap();
        assert_eq!(meta.domain_type, Some(DomainType::Service));
        assert_eq!(meta.category, Some(RiskCategory::Analytics));
        assert_eq!(meta.description, Some("Analytics service".to_string()));
        assert_eq!(meta.acquired_year, Some(2019));
        assert_eq!(meta.vendor_ref, Some("parent-vendor".to_string()));
    }

    #[test]
    fn domain_metadata_all_optional() {
        let json = r#"{}"#;
        let meta: DomainMetadata = serde_json::from_str(json).unwrap();
        assert!(meta.domain_type.is_none());
        assert!(meta.category.is_none());
        assert!(meta.description.is_none());
        assert!(meta.acquired_year.is_none());
        assert!(meta.vendor_ref.is_none());
    }

    // ---- TenantDetection ----

    #[test]
    fn tenant_detection_deserialize() {
        let json = r#"{
            "success_indicators": ["Welcome"],
            "failure_indicators": ["404"],
            "notes": "test note"
        }"#;
        let td: TenantDetection = serde_json::from_str(json).unwrap();
        assert_eq!(td.success_indicators, Some(vec!["Welcome".to_string()]));
        assert_eq!(td.failure_indicators, Some(vec!["404".to_string()]));
        assert_eq!(td.notes, Some("test note".to_string()));
    }

    #[test]
    fn tenant_detection_all_optional() {
        let json = r#"{}"#;
        let td: TenantDetection = serde_json::from_str(json).unwrap();
        assert!(td.success_indicators.is_none());
        assert!(td.failure_indicators.is_none());
        assert!(td.notes.is_none());
    }

    // ---- SaasTenant ----

    #[test]
    fn saas_tenant_deserialize() {
        let json = r#"{
            "name": "Test Tenant",
            "patterns": ["{tenant}.example.com"],
            "detection": {
                "success_indicators": ["OK"],
                "failure_indicators": [],
                "notes": null
            }
        }"#;
        let st: SaasTenant = serde_json::from_str(json).unwrap();
        assert_eq!(st.name, "Test Tenant");
        assert_eq!(st.patterns, vec!["{tenant}.example.com"]);
        assert!(st.detection.is_some());
    }

    #[test]
    fn saas_tenant_without_detection() {
        let json = r#"{
            "name": "Simple",
            "patterns": ["a.com", "b.com"]
        }"#;
        let st: SaasTenant = serde_json::from_str(json).unwrap();
        assert_eq!(st.name, "Simple");
        assert_eq!(st.patterns.len(), 2);
        assert!(st.detection.is_none());
    }

    // ---- primary_domain as implicit domain entry ----

    #[test]
    fn primary_domain_registered_even_without_domains_entry() {
        let json = r#"{
            "id": "simple",
            "organization": "Simple Corp",
            "primary_domain": "simple.io"
        }"#;
        let dir = tempdir().unwrap();
        let path = dir.path().join("simple.json");
        fs::write(&path, json).unwrap();

        let mut reg = VendorRegistry::new();
        reg.load_vendor_file(&path).unwrap();

        assert!(reg.is_known_domain("simple.io"));
        assert_eq!(
            reg.get_organization("simple.io"),
            Some("Simple Corp".to_string())
        );
    }

    // ---- subdomain lookup with deeply nested subdomain ----

    #[test]
    fn get_vendor_by_domain_deeply_nested_subdomain() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        // deep.sub.acme.com should still resolve to acme via base domain fallback
        let vendor = reg.get_vendor_by_domain("deep.sub.acme.com");
        assert!(vendor.is_some());
        assert_eq!(vendor.unwrap().id, "acme");
    }

    // ---- two-part domain (no subdomain fallback) ----

    #[test]
    fn get_vendor_by_domain_two_part_no_fallback() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        // unknown two-part domain should return None (no subdomain stripping for 2-part)
        assert!(reg.get_vendor_by_domain("unknown.com").is_none());
    }

    // ---- subdomain of unknown domain (3+ parts, base domain also not found) ----

    #[test]
    fn get_vendor_by_domain_subdomain_unknown_base() {
        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();

        // sub.unknown.com has 3 parts, so it tries base domain "unknown.com" but still not found
        assert!(reg.get_vendor_by_domain("sub.unknown.com").is_none());
    }

    // ---- load_from_directory with debug tracing enabled ----

    #[test]
    fn load_from_directory_with_debug_tracing() {
        // Install a tracing subscriber at debug level to exercise debug! formatting code
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(std::io::sink)
                .finish(),
        );

        let dir = setup_vendor_dir();
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();
        assert_eq!(reg.vendor_count(), 2);
    }

    // ---- or_insert_with closure: primary_domain NOT in domains map ----

    #[test]
    fn load_from_directory_primary_domain_not_in_domains_map() {
        // When primary_domain is absent from the "domains" map, the
        // or_insert_with closure fires to register it as a new entry.
        let dir = tempdir().unwrap();
        let vendors_dir = dir.path().join("vendors");
        fs::create_dir_all(&vendors_dir).unwrap();

        let json = r#"{
            "id": "separate",
            "organization": "Separate Corp",
            "primary_domain": "separate.io",
            "domains": {
                "other.com": {
                    "type": "service",
                    "category": "platform"
                }
            }
        }"#;
        fs::write(vendors_dir.join("separate.json"), json).unwrap();

        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();
        assert_eq!(reg.vendor_count(), 1);
        // "separate.io" should be registered via or_insert_with
        assert!(reg.is_known_domain("separate.io"));
        // "other.com" should also be registered from the domains map
        assert!(reg.is_known_domain("other.com"));
        assert_eq!(
            reg.get_organization("separate.io"),
            Some("Separate Corp".to_string())
        );
    }

    // ---- load_vendor_file parse-error closure (line 188) ----

    #[test]
    fn load_vendor_file_invalid_json_returns_parse_error() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad.json");
        // Valid file that can be read but contains invalid JSON for VendorConfig
        fs::write(&path, r#"{"not_a_vendor": true}"#).unwrap();

        let mut reg = VendorRegistry::new();
        let result = reg.load_vendor_file(&path);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Failed to parse"),
            "Expected parse error, got: {}",
            err_msg
        );
    }

    // ---- load_from_directory with unreadable vendors dir (line 118) ----

    #[cfg(unix)]
    #[test]
    fn load_from_directory_unreadable_vendors_dir() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let vendors_dir = dir.path().join("vendors");
        fs::create_dir_all(&vendors_dir).unwrap();
        // Make the vendors dir unreadable
        fs::set_permissions(&vendors_dir, fs::Permissions::from_mode(0o000)).unwrap();

        let result = VendorRegistry::load_from_directory(dir.path());
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("Failed to read"),
            "Expected read error, got: {}",
            err_msg
        );

        // Restore permissions for cleanup
        fs::set_permissions(&vendors_dir, fs::Permissions::from_mode(0o755)).unwrap();
    }

    // ---- load_from_directory with unreadable file in vendors dir (line 137) ----

    #[cfg(unix)]
    #[test]
    fn load_from_directory_unreadable_file_in_vendors_dir() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let vendors_dir = dir.path().join("vendors");
        fs::create_dir_all(&vendors_dir).unwrap();

        // Write a valid vendor
        fs::write(vendors_dir.join("acme.json"), sample_vendor_json()).unwrap();

        // Write an unreadable file
        let unreadable_path = vendors_dir.join("unreadable.json");
        fs::write(&unreadable_path, "irrelevant").unwrap();
        fs::set_permissions(&unreadable_path, fs::Permissions::from_mode(0o000)).unwrap();

        // load_from_directory should succeed but skip the unreadable file
        let reg = VendorRegistry::load_from_directory(dir.path()).unwrap();
        // acme.json should still load, unreadable.json is skipped with a warning
        assert_eq!(reg.vendor_count(), 1);
        assert!(reg.is_known_domain("acme.com"));

        // Restore permissions for cleanup
        fs::set_permissions(&unreadable_path, fs::Permissions::from_mode(0o644)).unwrap();
    }

    // ---- load_vendor_file primary_domain not in domains (or_insert_with) ----

    #[test]
    fn load_vendor_file_primary_not_in_domains_triggers_or_insert() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("simple.json");
        // primary_domain "simple.io" is NOT in the domains map
        let json = r#"{
            "id": "simple",
            "organization": "Simple Corp",
            "primary_domain": "simple.io",
            "domains": {
                "other-simple.com": {
                    "type": "service",
                    "category": "platform"
                }
            },
            "provider_aliases": ["simple-alias"],
            "verification_patterns": ["simple-verify"]
        }"#;
        fs::write(&path, json).unwrap();

        let mut reg = VendorRegistry::new();
        let config = reg.load_vendor_file(&path).unwrap();
        assert_eq!(config.id, "simple");

        // primary_domain should be registered via or_insert_with
        assert!(reg.is_known_domain("simple.io"));
        assert!(reg.is_known_domain("other-simple.com"));
        assert_eq!(
            reg.get_organization("simple.io"),
            Some("Simple Corp".to_string())
        );
    }

    // ====================================================================
    // Tests for global functions that previously had coverage(off)
    // ====================================================================

    #[test]
    fn test_global_get_returns_option() {
        let _result = get();
    }

    #[test]
    fn test_global_lookup_organization_returns_none_for_unknown() {
        // Domain never registered, so None regardless of init state
        let result = lookup_organization("nonexistent.example.com");
        assert_eq!(result, None);
    }

    #[test]
    fn test_global_is_known_domain_returns_false_for_unknown() {
        let result = is_known_domain("nonexistent.example.com");
        assert!(!result);
    }

    #[test]
    fn test_global_get_vendor_by_domain_returns_none_for_unknown() {
        let result = get_vendor_by_domain("nonexistent.example.com");
        assert!(result.is_none());
    }

    #[test]
    fn test_global_find_vendor_by_verification_returns_none_for_unknown() {
        let result = find_vendor_by_verification("nonexistent-pattern-xyz");
        assert!(result.is_none());
    }

    #[test]
    fn test_global_get_all_saas_tenants_does_not_panic() {
        let _result = get_all_saas_tenants();
    }

    // ---- find_config_dir_inner ----

    #[test]
    fn find_config_dir_inner_cwd_config_found() {
        let dir = tempdir().unwrap();
        let cwd_config = dir.path().join("config");
        fs::create_dir_all(cwd_config.join("vendors")).unwrap();

        let result = find_config_dir_inner(&cwd_config, None, None);
        assert_eq!(result, Some(cwd_config));
    }

    #[test]
    fn find_config_dir_inner_cwd_no_vendors_subdir() {
        let dir = tempdir().unwrap();
        let cwd_config = dir.path().join("config");
        fs::create_dir_all(&cwd_config).unwrap();
        // config/ exists but has no vendors/ subdirectory

        let result = find_config_dir_inner(&cwd_config, None, None);
        assert!(result.is_none());
    }

    #[test]
    fn find_config_dir_inner_cwd_is_file_not_dir() {
        let dir = tempdir().unwrap();
        let cwd_config = dir.path().join("config");
        fs::write(&cwd_config, "not a directory").unwrap();

        let result = find_config_dir_inner(&cwd_config, None, None);
        assert!(result.is_none());
    }

    #[test]
    fn find_config_dir_inner_exe_dir_config() {
        let dir = tempdir().unwrap();
        // Simulate exe at dir/bin/exe — config should be dir/bin/config/vendors
        let bin_dir = dir.path().join("bin");
        fs::create_dir_all(bin_dir.join("config").join("vendors")).unwrap();
        let exe_path = bin_dir.join("myexe");

        let result = find_config_dir_inner(Path::new("/nonexistent"), Some(exe_path), None);
        assert!(result.is_some());
        assert!(result.unwrap().join("vendors").exists());
    }

    #[test]
    fn find_config_dir_inner_exe_parent_config() {
        let dir = tempdir().unwrap();
        // exe at dir/target/debug/exe — config at dir/target/config/vendors
        let debug_dir = dir.path().join("target").join("debug");
        fs::create_dir_all(&debug_dir).unwrap();
        let target_dir = dir.path().join("target");
        fs::create_dir_all(target_dir.join("config").join("vendors")).unwrap();
        let exe_path = debug_dir.join("myexe");

        let result = find_config_dir_inner(Path::new("/nonexistent"), Some(exe_path), None);
        assert!(result.is_some());
    }

    #[test]
    fn find_config_dir_inner_exe_grandparent_config() {
        let dir = tempdir().unwrap();
        // exe at dir/a/b/c/exe — config at dir/a/config/vendors
        let c_dir = dir.path().join("a").join("b").join("c");
        fs::create_dir_all(&c_dir).unwrap();
        fs::create_dir_all(dir.path().join("a").join("config").join("vendors")).unwrap();
        let exe_path = c_dir.join("myexe");

        let result = find_config_dir_inner(Path::new("/nonexistent"), Some(exe_path), None);
        assert!(result.is_some());
    }

    #[test]
    fn find_config_dir_inner_exe_no_config_anywhere() {
        let dir = tempdir().unwrap();
        let exe_path = dir.path().join("myexe");

        let result = find_config_dir_inner(Path::new("/nonexistent"), Some(exe_path), None);
        assert!(result.is_none());
    }

    #[test]
    fn find_config_dir_inner_env_var_found() {
        let dir = tempdir().unwrap();
        fs::create_dir_all(dir.path().join("vendors")).unwrap();

        let result = find_config_dir_inner(
            Path::new("/nonexistent"),
            None,
            Some(dir.path().to_str().unwrap().to_string()),
        );
        assert!(result.is_some());
        assert_eq!(result.unwrap(), dir.path());
    }

    #[test]
    fn find_config_dir_inner_env_var_nonexistent() {
        let result = find_config_dir_inner(
            Path::new("/nonexistent"),
            None,
            Some("/nonexistent/path".to_string()),
        );
        assert!(result.is_none());
    }

    #[test]
    fn find_config_dir_inner_env_var_no_vendors() {
        let dir = tempdir().unwrap();
        // dir exists but has no vendors/ subdirectory

        let result = find_config_dir_inner(
            Path::new("/nonexistent"),
            None,
            Some(dir.path().to_str().unwrap().to_string()),
        );
        assert!(result.is_none());
    }

    #[test]
    fn find_config_dir_inner_priority_order() {
        let cwd_dir = tempdir().unwrap();
        let env_dir = tempdir().unwrap();
        fs::create_dir_all(cwd_dir.path().join("vendors")).unwrap();
        fs::create_dir_all(env_dir.path().join("vendors")).unwrap();

        // CWD should win over env var
        let result = find_config_dir_inner(
            cwd_dir.path(),
            None,
            Some(env_dir.path().to_str().unwrap().to_string()),
        );
        assert_eq!(result, Some(cwd_dir.path().to_path_buf()));
    }

    #[test]
    fn find_config_dir_inner_none_inputs_returns_none() {
        let result = find_config_dir_inner(Path::new("/nonexistent"), None, None);
        assert!(result.is_none());
    }

    #[test]
    fn find_config_dir_inner_exe_none_parent() {
        // Edge: exe_path is "/" so parent() returns None for parent-of-root
        let result =
            find_config_dir_inner(Path::new("/nonexistent"), Some(PathBuf::from("/")), None);
        assert!(result.is_none());
    }

    #[test]
    fn find_config_dir_inner_exe_no_grandparent() {
        // exe at /a/exe → exe_dir=/a, parent=/, grandparent=None
        let result = find_config_dir_inner(
            Path::new("/nonexistent"),
            Some(PathBuf::from("/a/exe")),
            None,
        );
        assert!(result.is_none());
    }

    #[test]
    fn find_config_dir_inner_exe_dir_is_root() {
        // exe at /myexe → exe_dir=/, exe_dir.parent()=None
        let result = find_config_dir_inner(
            Path::new("/nonexistent"),
            Some(PathBuf::from("/myexe")),
            None,
        );
        assert!(result.is_none());
    }

    #[test]
    fn find_config_dir_inner_cwd_with_debug_tracing() {
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(std::io::sink)
                .finish(),
        );
        let dir = tempdir().unwrap();
        let cwd_config = dir.path().join("config");
        fs::create_dir_all(cwd_config.join("vendors")).unwrap();

        let result = find_config_dir_inner(&cwd_config, None, None);
        assert_eq!(result, Some(cwd_config));
    }

    #[test]
    fn find_config_dir_inner_exe_config_with_debug_tracing() {
        let _guard = tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(std::io::sink)
                .finish(),
        );
        let dir = tempdir().unwrap();
        let bin_dir = dir.path().join("bin");
        fs::create_dir_all(bin_dir.join("config").join("vendors")).unwrap();
        let exe_path = bin_dir.join("myexe");

        let result = find_config_dir_inner(Path::new("/nonexistent"), Some(exe_path), None);
        assert!(result.is_some());
    }

    #[test]
    fn get_all_domain_mappings_skips_orphaned_domain() {
        let mut reg = VendorRegistry::new();
        reg.domain_to_vendor
            .insert("orphan.com".to_string(), "nonexistent-vendor".to_string());
        let mappings = reg.get_all_domain_mappings();
        assert!(mappings.is_empty());
    }

    #[test]
    fn filter_vendor_path_io_error() {
        let err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "test");
        let result = filter_vendor_path(Err(err));
        assert!(result.is_none());
    }

    #[test]
    fn filter_vendor_path_valid_json() {
        let dir = tempdir().unwrap();
        let json_path = dir.path().join("vendor.json");
        fs::write(&json_path, "{}").unwrap();

        let entry = std::fs::read_dir(dir.path()).unwrap().next().unwrap();
        let result = filter_vendor_path(entry);
        assert!(result.is_some());
    }

    #[test]
    fn filter_vendor_path_non_json() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("readme.txt"), "text").unwrap();

        let entry = std::fs::read_dir(dir.path()).unwrap().next().unwrap();
        let result = filter_vendor_path(entry);
        assert!(result.is_none());
    }

    #[test]
    fn filter_vendor_path_schema_json() {
        let dir = tempdir().unwrap();
        fs::write(dir.path().join("_schema.json"), "{}").unwrap();

        let entry = std::fs::read_dir(dir.path()).unwrap().next().unwrap();
        let result = filter_vendor_path(entry);
        assert!(result.is_none());
    }

    #[test]
    fn global_functions_with_initialized_registry() {
        // Try to initialize with an empty registry; may fail if another test already did
        let _ = VENDOR_REGISTRY.set(VendorRegistry::new());

        // Now get() returns Some, exercising the closure bodies of global functions
        assert!(lookup_organization("nonexistent.example.com").is_none());
        assert!(!is_known_domain("nonexistent.example.com"));
        assert!(get_vendor_by_domain("nonexistent.example.com").is_none());
        assert!(find_vendor_by_verification("nonexistent").is_none());
        let tenants = get_all_saas_tenants();
        let _ = tenants; // result depends on which test initialized the global registry first
    }
}
