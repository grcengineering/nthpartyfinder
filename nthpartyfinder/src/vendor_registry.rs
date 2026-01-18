//! Vendor Registry - Consolidated vendor configuration management

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum DomainType { Primary, Service, Api, Cdn, Acquired, Alias, Email }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum RiskCategory {
    Platform, Infrastructure, Tracking, Advertising, Security, Payment,
    Communication, Storage, Development, Monitoring, Media, Support, Analytics
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

        for entry in std::fs::read_dir(&vendors_dir)
            .with_context(|| format!("Failed to read: {:?}", vendors_dir))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map_or(true, |e| e != "json") { continue; }
            if path.file_name().map_or(false, |n| n == "_schema.json") { continue; }
            match registry.load_vendor_file(&path) {
                Ok(c) => debug!("Loaded vendor: {} with {} domains", c.id, c.domains.len()),
                Err(e) => warn!("Failed to load {:?}: {}", path, e),
            }
        }
        info!("Loaded {} vendors", registry.vendors.len());
        Ok(registry)
    }

    fn load_vendor_file(&mut self, path: &Path) -> Result<Arc<VendorConfig>> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read: {:?}", path))?;
        let config: VendorConfig = serde_json::from_str(&content)
            .with_context(|| format!("Failed to parse: {:?}", path))?;
        let vendor_id = config.id.clone();
        let config = Arc::new(config);

        for domain in config.domains.keys() {
            self.domain_to_vendor.insert(domain.to_lowercase(), vendor_id.clone());
        }
        let primary = config.primary_domain.to_lowercase();
        if !self.domain_to_vendor.contains_key(&primary) {
            self.domain_to_vendor.insert(primary, vendor_id.clone());
        }
        for alias in &config.provider_aliases {
            self.alias_to_vendor.insert(alias.to_lowercase(), vendor_id.clone());
        }
        for pattern in &config.verification_patterns {
            self.verification_patterns.push((pattern.clone(), vendor_id.clone()));
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
            let base = parts[parts.len()-2..].join(".");
            if let Some(id) = self.domain_to_vendor.get(&base) {
                return self.vendors.get(id).cloned();
            }
        }
        None
    }

    pub fn get_vendor_by_alias(&self, alias: &str) -> Option<Arc<VendorConfig>> {
        self.alias_to_vendor.get(&alias.to_lowercase())
            .and_then(|id| self.vendors.get(id).cloned())
    }

    pub fn get_vendor(&self, id: &str) -> Option<Arc<VendorConfig>> {
        self.vendors.get(id).cloned()
    }

    pub fn get_organization(&self, domain: &str) -> Option<String> {
        self.get_vendor_by_domain(domain).map(|v| v.organization.clone())
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

    pub fn vendor_count(&self) -> usize { self.vendors.len() }
    pub fn domain_count(&self) -> usize { self.domain_to_vendor.len() }

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
    fn default() -> Self { Self::new() }
}

// ============================================================================
// Global Registry Access
// ============================================================================

use std::sync::OnceLock;

/// Global vendor registry instance
static VENDOR_REGISTRY: OnceLock<VendorRegistry> = OnceLock::new();

/// Find the config directory by checking multiple locations
fn find_config_dir() -> Option<PathBuf> {
    // Priority 1: Relative to current working directory
    let cwd_config = PathBuf::from("./config");
    if cwd_config.exists() && cwd_config.is_dir() {
        if cwd_config.join("vendors").exists() {
            debug!("Found config directory at: {:?}", cwd_config.canonicalize().unwrap_or(cwd_config.clone()));
            return Some(cwd_config);
        }
    }

    // Priority 2: Relative to executable directory
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(exe_dir) = exe_path.parent() {
            let exe_config = exe_dir.join("config");
            if exe_config.exists() && exe_config.join("vendors").exists() {
                debug!("Found config directory next to executable: {:?}", exe_config);
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
    if let Ok(env_config) = std::env::var("NTHPARTYFINDER_CONFIG_DIR") {
        let env_path = PathBuf::from(&env_config);
        if env_path.exists() && env_path.join("vendors").exists() {
            return Some(env_path);
        }
    }

    None
}

/// Initialize the global vendor registry
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

    VENDOR_REGISTRY.set(registry)
        .map_err(|_| anyhow::anyhow!("Vendor registry already initialized"))?;

    if vendor_count > 0 {
        info!("Vendor registry initialized: {} vendors, {} domains", vendor_count, domain_count);
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
    get().map_or(false, |r| r.is_known_domain(domain))
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
