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
