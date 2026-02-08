// checkpoint.rs - Resume interrupted analysis feature (E004)
//
// This module provides checkpoint save/load functionality for long-running
// analyses. When Ctrl+C is pressed or the analysis is interrupted, the
// checkpoint is saved. On restart, the user can resume from the checkpoint.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::vendor::VendorRelationship;

/// Checkpoint file name - hidden file to avoid cluttering output directory
pub const CHECKPOINT_FILENAME: &str = ".nthpartyfinder-checkpoint.json";

/// Current checkpoint format version - bump when making breaking changes
pub const CHECKPOINT_VERSION: u32 = 1;

/// Analysis checkpoint containing all state needed to resume an interrupted analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Checkpoint format version for compatibility checking
    pub version: u32,

    /// UTC timestamp when checkpoint was created
    pub created_at: DateTime<Utc>,

    /// The root domain being analyzed
    pub root_domain: String,

    /// The root organization name (if resolved)
    pub root_organization: Option<String>,

    /// Maximum depth setting (None = unlimited)
    pub max_depth: Option<u32>,

    /// Current analysis depth reached so far
    pub current_depth_reached: u32,

    /// Domains that have been fully processed
    pub completed_domains: HashSet<String>,

    /// Domains that are pending processing (queued but not started)
    pub pending_domains: Vec<PendingDomain>,

    /// Discovered vendor domain -> organization name mappings
    pub discovered_vendors: HashMap<String, String>,

    /// Partial results collected so far
    pub partial_results: Vec<VendorRelationship>,

    /// Analysis settings hash to verify same settings on resume
    pub settings_hash: String,

    /// Output directory where checkpoint is stored
    #[serde(skip)]
    pub checkpoint_dir: Option<PathBuf>,
}

/// A domain pending processing with its analysis context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingDomain {
    /// The domain to analyze
    pub domain: String,

    /// Depth at which to analyze this domain
    pub depth: u32,

    /// Customer domain that discovered this vendor
    pub customer_domain: String,

    /// Customer organization name
    pub customer_organization: String,
}

impl Checkpoint {
    /// Create a new checkpoint for starting an analysis
    pub fn new(
        root_domain: String,
        root_organization: Option<String>,
        max_depth: Option<u32>,
        settings_hash: String,
    ) -> Self {
        Self {
            version: CHECKPOINT_VERSION,
            created_at: Utc::now(),
            root_domain,
            root_organization,
            max_depth,
            current_depth_reached: 0,
            completed_domains: HashSet::new(),
            pending_domains: Vec::new(),
            discovered_vendors: HashMap::new(),
            partial_results: Vec::new(),
            settings_hash,
            checkpoint_dir: None,
        }
    }

    /// Get the checkpoint file path for a given output directory
    pub fn get_checkpoint_path(output_dir: &Path) -> PathBuf {
        output_dir.join(CHECKPOINT_FILENAME)
    }

    /// Check if a checkpoint file exists in the given directory
    pub fn exists(output_dir: &Path) -> bool {
        Self::get_checkpoint_path(output_dir).exists()
    }

    /// Load a checkpoint from the given output directory
    pub fn load(output_dir: &Path) -> Result<Self> {
        let path = Self::get_checkpoint_path(output_dir);
        let content = std::fs::read_to_string(&path)?;
        let mut checkpoint: Checkpoint = serde_json::from_str(&content)?;
        checkpoint.checkpoint_dir = Some(output_dir.to_path_buf());
        Ok(checkpoint)
    }

    /// Save the checkpoint to its output directory using atomic write
    /// (write to temp file, then rename to prevent corruption on interrupt)
    pub fn save(&self, output_dir: &Path) -> Result<()> {
        let path = Self::get_checkpoint_path(output_dir);
        let temp_path = output_dir.join(".nthpartyfinder-checkpoint.tmp");
        let content = serde_json::to_string_pretty(self)?;

        // Write to temporary file first, then fsync to ensure data is flushed to disk (H007 fix)
        {
            let mut file = std::fs::File::create(&temp_path)?;
            std::io::Write::write_all(&mut file, content.as_bytes())?;
            file.sync_all()?; // Ensure data is flushed before rename
        }

        // Atomically rename temp file to final checkpoint file
        // On most filesystems, rename is atomic
        std::fs::rename(&temp_path, &path)?;

        Ok(())
    }

    /// Save checkpoint with a specific timestamp (for testing)
    pub fn save_with_timestamp(&mut self, output_dir: &Path) -> Result<()> {
        self.created_at = chrono::Utc::now();
        self.save(output_dir)
    }

    /// Delete the checkpoint file (called on successful completion)
    pub fn delete(output_dir: &Path) -> Result<()> {
        let path = Self::get_checkpoint_path(output_dir);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }

    /// Check if this checkpoint is compatible with the given settings
    pub fn is_compatible(&self, root_domain: &str, settings_hash: &str) -> bool {
        self.root_domain == root_domain && self.settings_hash == settings_hash
    }

    /// Mark a domain as completed
    pub fn mark_completed(&mut self, domain: &str) {
        self.completed_domains.insert(domain.to_string());
        // Remove from pending if present
        self.pending_domains.retain(|p| p.domain != domain);
    }

    /// Check if a domain has been completed
    pub fn is_completed(&self, domain: &str) -> bool {
        self.completed_domains.contains(domain)
    }

    /// Add a pending domain to process
    pub fn add_pending(&mut self, pending: PendingDomain) {
        // Only add if not already completed or pending
        if !self.completed_domains.contains(&pending.domain) {
            if !self.pending_domains.iter().any(|p| p.domain == pending.domain) {
                self.pending_domains.push(pending);
            }
        }
    }

    /// Get the next pending domain to process (if any)
    pub fn pop_pending(&mut self) -> Option<PendingDomain> {
        self.pending_domains.pop()
    }

    /// Add a vendor relationship result
    pub fn add_result(&mut self, result: VendorRelationship) {
        // Track depth
        if result.nth_party_layer > self.current_depth_reached {
            self.current_depth_reached = result.nth_party_layer;
        }
        self.partial_results.push(result);
    }

    /// Add multiple vendor relationship results
    pub fn add_results(&mut self, results: Vec<VendorRelationship>) {
        for result in results {
            self.add_result(result);
        }
    }

    /// Record a discovered vendor mapping
    pub fn record_vendor(&mut self, domain: String, organization: String) {
        self.discovered_vendors.insert(domain, organization);
    }

    /// Get summary statistics for the checkpoint
    pub fn summary(&self) -> CheckpointSummary {
        CheckpointSummary {
            root_domain: self.root_domain.clone(),
            created_at: self.created_at,
            completed_count: self.completed_domains.len(),
            pending_count: self.pending_domains.len(),
            results_count: self.partial_results.len(),
            depth_reached: self.current_depth_reached,
            max_depth: self.max_depth,
        }
    }
}

/// Summary of checkpoint state for display
#[derive(Debug, Clone)]
pub struct CheckpointSummary {
    pub root_domain: String,
    pub created_at: DateTime<Utc>,
    pub completed_count: usize,
    pub pending_count: usize,
    pub results_count: usize,
    pub depth_reached: u32,
    pub max_depth: Option<u32>,
}

impl std::fmt::Display for CheckpointSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Checkpoint for '{}' - {} domains processed, {} pending, {} results (depth {}/{})",
            self.root_domain,
            self.completed_count,
            self.pending_count,
            self.results_count,
            self.depth_reached,
            self.max_depth.map(|d| d.to_string()).unwrap_or("unlimited".to_string())
        )
    }
}

/// Generate a settings hash for checkpoint compatibility checking
/// This ensures we don't try to resume with different analysis settings
pub fn generate_settings_hash(
    max_depth: Option<u32>,
    subprocessor_enabled: bool,
    subdomain_enabled: bool,
    saas_tenant_enabled: bool,
    ct_enabled: bool,
    web_org_enabled: bool,
) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    max_depth.hash(&mut hasher);
    subprocessor_enabled.hash(&mut hasher);
    subdomain_enabled.hash(&mut hasher);
    saas_tenant_enabled.hash(&mut hasher);
    ct_enabled.hash(&mut hasher);
    web_org_enabled.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Resume mode options
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ResumeMode {
    /// Prompt user if checkpoint exists
    Prompt,
    /// Auto-resume if checkpoint exists
    AutoResume,
    /// Start fresh, ignore any existing checkpoint
    Fresh,
}

impl Default for ResumeMode {
    fn default() -> Self {
        ResumeMode::Prompt
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::RecordType;
    use tempfile::TempDir;

    fn create_test_relationship(depth: u32) -> VendorRelationship {
        VendorRelationship {
            nth_party_domain: format!("vendor{}.com", depth),
            nth_party_organization: format!("Vendor {} Inc", depth),
            nth_party_layer: depth,
            nth_party_customer_domain: "customer.com".to_string(),
            nth_party_customer_organization: "Customer Inc".to_string(),
            nth_party_record: "v=spf1 include:vendor.com".to_string(),
            nth_party_record_type: RecordType::DnsTxtSpf,
            root_customer_domain: "root.com".to_string(),
            root_customer_organization: "Root Inc".to_string(),
            evidence: "SPF record".to_string(),
        }
    }

    #[test]
    fn test_checkpoint_creation() {
        let checkpoint = Checkpoint::new(
            "example.com".to_string(),
            Some("Example Inc".to_string()),
            Some(3),
            "abc123".to_string(),
        );

        assert_eq!(checkpoint.version, CHECKPOINT_VERSION);
        assert_eq!(checkpoint.root_domain, "example.com");
        assert_eq!(checkpoint.root_organization, Some("Example Inc".to_string()));
        assert_eq!(checkpoint.max_depth, Some(3));
        assert_eq!(checkpoint.current_depth_reached, 0);
        assert!(checkpoint.completed_domains.is_empty());
        assert!(checkpoint.pending_domains.is_empty());
        assert!(checkpoint.partial_results.is_empty());
    }

    #[test]
    fn test_checkpoint_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path();

        // Create and populate checkpoint
        let mut checkpoint = Checkpoint::new(
            "example.com".to_string(),
            Some("Example Inc".to_string()),
            Some(3),
            "abc123".to_string(),
        );

        checkpoint.mark_completed("example.com");
        checkpoint.add_pending(PendingDomain {
            domain: "vendor1.com".to_string(),
            depth: 2,
            customer_domain: "example.com".to_string(),
            customer_organization: "Example Inc".to_string(),
        });
        checkpoint.record_vendor("vendor1.com".to_string(), "Vendor One".to_string());
        checkpoint.add_result(create_test_relationship(1));

        // Save checkpoint
        checkpoint.save(output_dir).unwrap();

        // Verify file exists
        assert!(Checkpoint::exists(output_dir));

        // Load checkpoint
        let loaded = Checkpoint::load(output_dir).unwrap();

        assert_eq!(loaded.version, CHECKPOINT_VERSION);
        assert_eq!(loaded.root_domain, "example.com");
        assert_eq!(loaded.root_organization, Some("Example Inc".to_string()));
        assert_eq!(loaded.max_depth, Some(3));
        assert!(loaded.completed_domains.contains("example.com"));
        assert_eq!(loaded.pending_domains.len(), 1);
        assert_eq!(loaded.pending_domains[0].domain, "vendor1.com");
        assert_eq!(loaded.discovered_vendors.get("vendor1.com"), Some(&"Vendor One".to_string()));
        assert_eq!(loaded.partial_results.len(), 1);
    }

    #[test]
    fn test_checkpoint_delete() {
        let temp_dir = TempDir::new().unwrap();
        let output_dir = temp_dir.path();

        let checkpoint = Checkpoint::new(
            "example.com".to_string(),
            None,
            None,
            "abc123".to_string(),
        );

        checkpoint.save(output_dir).unwrap();
        assert!(Checkpoint::exists(output_dir));

        Checkpoint::delete(output_dir).unwrap();
        assert!(!Checkpoint::exists(output_dir));
    }

    #[test]
    fn test_checkpoint_compatibility() {
        let checkpoint = Checkpoint::new(
            "example.com".to_string(),
            None,
            Some(3),
            "abc123".to_string(),
        );

        // Same domain and settings - compatible
        assert!(checkpoint.is_compatible("example.com", "abc123"));

        // Different domain - not compatible
        assert!(!checkpoint.is_compatible("other.com", "abc123"));

        // Different settings - not compatible
        assert!(!checkpoint.is_compatible("example.com", "xyz789"));
    }

    #[test]
    fn test_mark_completed_removes_from_pending() {
        let mut checkpoint = Checkpoint::new(
            "example.com".to_string(),
            None,
            None,
            "abc123".to_string(),
        );

        // Add pending domain
        checkpoint.add_pending(PendingDomain {
            domain: "vendor.com".to_string(),
            depth: 2,
            customer_domain: "example.com".to_string(),
            customer_organization: "Example Inc".to_string(),
        });

        assert_eq!(checkpoint.pending_domains.len(), 1);

        // Mark as completed
        checkpoint.mark_completed("vendor.com");

        // Should be in completed and removed from pending
        assert!(checkpoint.is_completed("vendor.com"));
        assert!(checkpoint.pending_domains.is_empty());
    }

    #[test]
    fn test_add_pending_deduplication() {
        let mut checkpoint = Checkpoint::new(
            "example.com".to_string(),
            None,
            None,
            "abc123".to_string(),
        );

        let pending = PendingDomain {
            domain: "vendor.com".to_string(),
            depth: 2,
            customer_domain: "example.com".to_string(),
            customer_organization: "Example Inc".to_string(),
        };

        // Add same domain twice
        checkpoint.add_pending(pending.clone());
        checkpoint.add_pending(pending.clone());

        // Should only have one entry
        assert_eq!(checkpoint.pending_domains.len(), 1);

        // Mark as completed and try to add again
        checkpoint.mark_completed("vendor.com");
        checkpoint.add_pending(pending);

        // Should still be empty (domain is completed)
        assert!(checkpoint.pending_domains.is_empty());
    }

    #[test]
    fn test_depth_tracking() {
        let mut checkpoint = Checkpoint::new(
            "example.com".to_string(),
            None,
            Some(5),
            "abc123".to_string(),
        );

        assert_eq!(checkpoint.current_depth_reached, 0);

        checkpoint.add_result(create_test_relationship(1));
        assert_eq!(checkpoint.current_depth_reached, 1);

        checkpoint.add_result(create_test_relationship(3));
        assert_eq!(checkpoint.current_depth_reached, 3);

        checkpoint.add_result(create_test_relationship(2));
        assert_eq!(checkpoint.current_depth_reached, 3); // Should stay at max
    }

    #[test]
    fn test_settings_hash() {
        let hash1 = generate_settings_hash(Some(3), true, true, false, false, true);
        let hash2 = generate_settings_hash(Some(3), true, true, false, false, true);
        let hash3 = generate_settings_hash(Some(3), true, true, true, false, true); // saas changed

        // Same settings should produce same hash
        assert_eq!(hash1, hash2);

        // Different settings should produce different hash
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_checkpoint_summary() {
        let mut checkpoint = Checkpoint::new(
            "example.com".to_string(),
            Some("Example Inc".to_string()),
            Some(3),
            "abc123".to_string(),
        );

        checkpoint.mark_completed("domain1.com");
        checkpoint.mark_completed("domain2.com");
        checkpoint.add_pending(PendingDomain {
            domain: "pending.com".to_string(),
            depth: 2,
            customer_domain: "example.com".to_string(),
            customer_organization: "Example Inc".to_string(),
        });
        checkpoint.add_result(create_test_relationship(2));
        checkpoint.add_result(create_test_relationship(2));

        let summary = checkpoint.summary();

        assert_eq!(summary.root_domain, "example.com");
        assert_eq!(summary.completed_count, 2);
        assert_eq!(summary.pending_count, 1);
        assert_eq!(summary.results_count, 2);
        assert_eq!(summary.depth_reached, 2);
        assert_eq!(summary.max_depth, Some(3));
    }

    #[test]
    fn test_pop_pending() {
        let mut checkpoint = Checkpoint::new(
            "example.com".to_string(),
            None,
            None,
            "abc123".to_string(),
        );

        checkpoint.add_pending(PendingDomain {
            domain: "vendor1.com".to_string(),
            depth: 2,
            customer_domain: "example.com".to_string(),
            customer_organization: "Example Inc".to_string(),
        });
        checkpoint.add_pending(PendingDomain {
            domain: "vendor2.com".to_string(),
            depth: 2,
            customer_domain: "example.com".to_string(),
            customer_organization: "Example Inc".to_string(),
        });

        assert_eq!(checkpoint.pending_domains.len(), 2);

        let popped = checkpoint.pop_pending();
        assert!(popped.is_some());
        assert_eq!(checkpoint.pending_domains.len(), 1);

        let popped = checkpoint.pop_pending();
        assert!(popped.is_some());
        assert_eq!(checkpoint.pending_domains.len(), 0);

        let popped = checkpoint.pop_pending();
        assert!(popped.is_none());
    }
}
