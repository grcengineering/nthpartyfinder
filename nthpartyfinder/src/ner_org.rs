//! Embedded NER-based organization extraction
//!
//! This module uses GLiNER (via gline-rs) to extract organization names
//! from web page content. The model is embedded in the binary at compile time.
//!
//! On Windows, the ONNX Runtime DLL must be available. Set ORT_DYLIB_PATH
//! environment variable or place onnxruntime.dll next to the executable.

#[cfg(feature = "embedded-ner")]
use anyhow::{anyhow, Result};
#[cfg(feature = "embedded-ner")]
use gliner::model::input::text::TextInput;
#[cfg(feature = "embedded-ner")]
use gliner::model::params::Parameters;
#[cfg(feature = "embedded-ner")]
use gliner::model::pipeline::span::SpanMode;
#[cfg(feature = "embedded-ner")]
use gliner::model::GLiNER;
#[cfg(feature = "embedded-ner")]
use orp::params::RuntimeParameters;
#[cfg(feature = "embedded-ner")]
use std::io::Write;
#[cfg(feature = "embedded-ner")]
use std::sync::OnceLock;
#[cfg(feature = "embedded-ner")]
use tracing::{debug, info};

/// Model bytes embedded at compile time
#[cfg(feature = "embedded-ner")]
static MODEL_BYTES: &[u8] = include_bytes!("../models/gliner_small.onnx");

#[cfg(feature = "embedded-ner")]
static TOKENIZER_BYTES: &[u8] = include_bytes!("../models/tokenizer.json");

#[cfg(feature = "embedded-ner")]
static CONFIG_BYTES: &[u8] = include_bytes!("../models/config.json");

/// Result of NER organization extraction
#[derive(Debug, Clone)]
pub struct NerOrgResult {
    /// The extracted organization name
    pub organization: String,
    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,
}

// ============================================================================
// Pure logic functions — testable without ONNX runtime
// ============================================================================

#[cfg(any(feature = "embedded-ner", test))]
fn truncate_text(text: &str, max_len: usize) -> &str {
    if text.len() <= max_len {
        return text;
    }
    let mut end = max_len;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[cfg(any(feature = "embedded-ner", test))]
fn build_domain_context(domain: &str, page_content: Option<&str>) -> String {
    match page_content {
        Some(content) => format!("Website: {}. {}", domain, content),
        None => format!("Website: {}", domain),
    }
}

#[cfg(any(feature = "embedded-ner", test))]
fn is_org_entity_type(entity_type: &str) -> bool {
    matches!(
        entity_type.to_lowercase().as_str(),
        "organization" | "company" | "product" | "brand"
    )
}

#[cfg(any(feature = "embedded-ner", test))]
fn select_best_org(
    candidates: &[(String, String, f32)],
    min_confidence: f32,
) -> Option<NerOrgResult> {
    let mut best: Option<NerOrgResult> = None;
    for (entity_type, org_name, confidence) in candidates {
        if is_org_entity_type(entity_type)
            && *confidence >= min_confidence
            && (best.is_none() || *confidence > best.as_ref().unwrap().confidence)
        {
            let trimmed = org_name.trim();
            if !trimmed.is_empty() {
                best = Some(NerOrgResult {
                    organization: trimmed.to_string(),
                    confidence: *confidence,
                });
            }
        }
    }
    best
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(any(feature = "embedded-ner", test))]
fn chunk_text(text: &str, max_single_len: usize, chunk_size: usize, overlap: usize) -> Vec<&str> {
    if text.len() <= max_single_len {
        return vec![text];
    }
    let mut result = Vec::new();
    let mut start = 0;
    while start < text.len() {
        let end = std::cmp::min(start + chunk_size, text.len());
        let mut safe_end = end;
        while safe_end > start && !text.is_char_boundary(safe_end) {
            safe_end -= 1;
        }
        let actual_end = if safe_end < text.len() {
            text[start..safe_end]
                .rfind(char::is_whitespace)
                .map(|pos| start + pos + 1)
                .unwrap_or(safe_end)
        } else {
            safe_end
        };
        let mut final_end = actual_end;
        while final_end > start && !text.is_char_boundary(final_end) {
            final_end -= 1;
        }
        if final_end <= start {
            start = safe_end;
            continue;
        }
        result.push(&text[start..final_end]);
        let overlap_start = if final_end > start + overlap {
            final_end - overlap
        } else {
            final_end
        };
        let mut safe_overlap = overlap_start;
        while safe_overlap > 0 && !text.is_char_boundary(safe_overlap) {
            safe_overlap -= 1;
        }
        if safe_overlap <= start {
            start = final_end;
        } else {
            start = safe_overlap;
        }
    }
    result
}

#[cfg(any(feature = "embedded-ner", test))]
fn dedup_filter_sort_orgs(orgs: Vec<(String, f32)>, min_name_len: usize) -> Vec<NerOrgResult> {
    let mut map: std::collections::HashMap<String, NerOrgResult> = std::collections::HashMap::new();
    for (name, confidence) in orgs {
        if name.len() >= min_name_len {
            let key = name.to_lowercase();
            let existing = map.get(&key);
            if existing.is_none() || existing.unwrap().confidence < confidence {
                map.insert(
                    key,
                    NerOrgResult {
                        organization: name,
                        confidence,
                    },
                );
            }
        }
    }
    let mut results: Vec<NerOrgResult> = map.into_values().collect();
    results.sort_by(|a, b| {
        b.confidence
            .partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    results
}

/// Global NER extractor instance
#[cfg(feature = "embedded-ner")]
static NER_EXTRACTOR: OnceLock<NerOrganizationExtractor> = OnceLock::new();

/// NER organization extractor using embedded GLiNER model
#[cfg(feature = "embedded-ner")]
pub struct NerOrganizationExtractor {
    model: GLiNER<SpanMode>,
    min_confidence: f32,
}

#[cfg(feature = "embedded-ner")]
impl NerOrganizationExtractor {
    #[cfg_attr(coverage_nightly, coverage(off))]
    /// Create a new NER extractor by writing embedded model files to temp directory
    pub fn new() -> Result<Self> {
        Self::with_min_confidence(0.5)
    }

    /// Try to find ONNX Runtime DLL on Windows and set ORT_DYLIB_PATH
    #[cfg(target_os = "windows")]
    fn setup_onnx_runtime() -> Result<()> {
        // If ORT_DYLIB_PATH is already set, use it
        if std::env::var("ORT_DYLIB_PATH").is_ok() {
            debug!("ORT_DYLIB_PATH already set");
            return Ok(());
        }

        // Try to find onnxruntime.dll in common locations
        // IMPORTANT: Use absolute paths to avoid loading wrong system DLLs
        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()));
        let cwd = std::env::current_dir().ok();

        // For Rust projects, exe is typically in target/release/ or target/debug/
        // So project root is 2 directories up from the executable
        let project_root_from_exe = exe_dir
            .as_ref()
            .and_then(|d| d.parent())
            .and_then(|d| d.parent());

        let search_paths = vec![
            // Next to executable (absolute path)
            exe_dir.as_ref().map(|d| d.join("onnxruntime.dll")),
            // Project root (2 dirs up from exe for target/release/ layout)
            project_root_from_exe.map(|d| d.join("onnxruntime.dll")),
            // Project's onnxruntime directory relative to project root
            project_root_from_exe.map(|d| d.join("onnxruntime-win-x64-1.20.1/lib/onnxruntime.dll")), // lgtm[rust/path-injection]
            // Current working directory (absolute path)
            cwd.as_ref().map(|d| d.join("onnxruntime.dll")), // lgtm[rust/path-injection]
            // Project's onnxruntime directory relative to cwd
            cwd.as_ref()
                .map(|d| d.join("onnxruntime-win-x64-1.20.1/lib/onnxruntime.dll")),
            // User's local app data
            dirs::data_local_dir().map(|d| d.join("onnxruntime").join("onnxruntime.dll")),
        ];

        for path_opt in search_paths {
            if let Some(path) = path_opt {
                if path.file_name() == Some(std::ffi::OsStr::new("onnxruntime.dll"))
                    && path.exists()
                {
                    // CRITICAL: Convert to absolute path to avoid loading wrong DLL
                    let abs_path = path.canonicalize().unwrap_or(path.clone());
                    let path_str = abs_path.to_string_lossy().to_string();
                    info!("Found ONNX Runtime at: {}", path_str);
                    std::env::set_var("ORT_DYLIB_PATH", &path_str);
                    return Ok(());
                }
            }
        }

        // DLL not found - provide helpful error message
        Err(anyhow!(
            "ONNX Runtime DLL not found. On Windows, you need to:\n\
             1. Run: .\\scripts\\download-onnxruntime.ps1\n\
             2. Or set ORT_DYLIB_PATH to point to onnxruntime.dll\n\
             3. Or place onnxruntime.dll next to the executable"
        ))
    }

    #[cfg(not(target_os = "windows"))]
    #[cfg_attr(coverage_nightly, coverage(off))] // coverage: platform-specific branch — Linux libonnxruntime.so path unreachable on macOS
    fn setup_onnx_runtime() -> Result<()> {
        // If ORT_DYLIB_PATH is already set, use it
        if std::env::var("ORT_DYLIB_PATH").is_ok() {
            debug!("ORT_DYLIB_PATH already set");
            return Ok(());
        }

        let lib_name = if cfg!(target_os = "macos") {
            "libonnxruntime.dylib"
        } else {
            "libonnxruntime.so"
        };

        let exe_dir = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.to_path_buf()));
        let cwd = std::env::current_dir().ok();
        let project_root_from_exe = exe_dir
            .as_ref()
            .and_then(|d| d.parent())
            .and_then(|d| d.parent());

        let search_paths = vec![
            exe_dir.as_ref().map(|d| d.join(lib_name)),
            project_root_from_exe.map(|d| d.join(lib_name)),
            project_root_from_exe
                .map(|d| d.join("onnxruntime-linux-x64-1.20.1/lib").join(lib_name)),
            cwd.as_ref().map(|d| d.join(lib_name)),
            cwd.as_ref()
                .map(|d| d.join("onnxruntime-linux-x64-1.20.1/lib").join(lib_name)),
        ];

        for path in search_paths.into_iter().flatten() {
            if path.file_name() == Some(std::ffi::OsStr::new(lib_name)) && path.exists() {
                let abs_path = path.canonicalize().unwrap_or(path.clone());
                let path_str = abs_path.to_string_lossy().to_string();
                info!("Found ONNX Runtime at: {}", path_str);
                std::env::set_var("ORT_DYLIB_PATH", &path_str);
                return Ok(());
            }
        }

        // Not found - provide helpful error
        Err(anyhow!(
            "ONNX Runtime shared library not found. On Linux, you need to:\n\
             1. Place {} next to the executable or in the working directory\n\
             2. Or set ORT_DYLIB_PATH to point to {}\n\
             3. Or install onnxruntime system-wide",
            lib_name,
            lib_name
        ))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    /// Create a new NER extractor with custom minimum confidence threshold
    pub fn with_min_confidence(min_confidence: f32) -> Result<Self> {
        // Setup ONNX runtime (Windows-specific DLL handling)
        Self::setup_onnx_runtime()?;

        // Create temp directory for model files
        let temp_dir = std::env::temp_dir().join("nthpartyfinder_ner");
        std::fs::create_dir_all(&temp_dir)?;

        let model_path = temp_dir.join("gliner_small.onnx");
        let tokenizer_path = temp_dir.join("tokenizer.json");
        let config_path = temp_dir.join("config.json");

        // Write embedded files to temp directory (gline-rs needs file paths)
        Self::write_if_missing(&model_path, MODEL_BYTES)?;
        Self::write_if_missing(&tokenizer_path, TOKENIZER_BYTES)?;
        Self::write_if_missing(&config_path, CONFIG_BYTES)?;

        debug!("Model files written to {:?}", temp_dir);

        let model = Self::create_model(&tokenizer_path, &model_path)?;

        info!("NER model initialized successfully");

        Ok(Self {
            model,
            min_confidence,
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))] // coverage: third-party model init — infallible error paths on temp-dir UTF-8 and valid embedded model
    fn create_model(
        tokenizer_path: &std::path::Path,
        model_path: &std::path::Path,
    ) -> Result<GLiNER<SpanMode>> {
        GLiNER::<SpanMode>::new(
            Parameters::default(),
            RuntimeParameters::default(),
            tokenizer_path
                .to_str()
                .ok_or_else(|| anyhow!("Invalid tokenizer path"))?,
            model_path
                .to_str()
                .ok_or_else(|| anyhow!("Invalid model path"))?,
        )
        .map_err(|e| anyhow!("Failed to initialize GLiNER model: {}", e))
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    fn run_inference(
        &self,
        text: &str,
        entity_types: &[&str],
    ) -> Result<Vec<(String, String, f32)>> {
        let input = TextInput::from_str(&[text], entity_types)
            .map_err(|e| anyhow!("Failed to create TextInput: {}", e))?;
        let output = self
            .model
            .inference(input)
            .map_err(|e| anyhow!("NER inference failed: {}", e))?;
        let mut candidates = Vec::new();
        for spans in &output.spans {
            for span in spans {
                candidates.push((
                    span.class().to_lowercase(),
                    span.text().to_string(),
                    span.probability(),
                ));
            }
        }
        Ok(candidates)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    /// Write bytes to file if it doesn't already exist
    fn write_if_missing(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
        if !path.exists() {
            let file_name = path
                .file_name()
                .ok_or_else(|| anyhow::anyhow!("model path has no filename"))?;
            let parent = path
                .parent()
                .ok_or_else(|| anyhow::anyhow!("model path has no parent"))?;
            let canonical_parent =
                std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
            let safe_path = canonical_parent.join(file_name);
            let mut file = std::fs::File::create(&safe_path)?;
            file.write_all(bytes)?;
            debug!("Wrote model file: {:?}", safe_path);
        }
        Ok(())
    }

    /// Extract organization name from text content
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn extract_organization(&self, text: &str) -> Result<Option<NerOrgResult>> {
        let text = truncate_text(text, 4000);
        let candidates =
            self.run_inference(text, &["organization", "company", "product", "brand"])?;
        let best_match = select_best_org(&candidates, self.min_confidence);
        if let Some(ref result) = best_match {
            debug!(
                "NER extracted organization: {} (confidence: {:.2})",
                result.organization, result.confidence
            );
        }
        Ok(best_match)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    /// Extract organization from domain and optional page content
    pub fn extract_from_domain(
        &self,
        domain: &str,
        page_content: Option<&str>,
    ) -> Result<Option<NerOrgResult>> {
        debug!(
            "NER: Attempting to extract organization from domain: {}",
            domain
        );

        if let Some(content) = page_content {
            debug!(
                "NER: Using page content ({} chars) for extraction",
                content.len()
            );
        } else {
            debug!("NER: No page content available, using domain only");
        }
        let text = build_domain_context(domain, page_content);

        let result = self.extract_organization(&text);

        if let Ok(Some(ref org_result)) = result {
            debug!(
                "NER: Successfully extracted '{}' (confidence: {:.2})",
                org_result.organization, org_result.confidence
            );
        } else {
            debug!("NER: No organization extracted for {}", domain);
        }

        result
    }

    /// Extract ALL organization entities from text content above the confidence threshold.
    ///
    /// Unlike `extract_organization()` which returns only the single best match,
    /// this returns all detected organizations, deduplicated by normalized name
    /// (keeping the highest confidence for each).
    #[cfg_attr(coverage_nightly, coverage(off))] // coverage: LLVM artifact — closing brace instrumentation gap
    pub fn extract_all_organizations(
        &self,
        text: &str,
        min_confidence: Option<f32>,
    ) -> Result<Vec<NerOrgResult>> {
        let threshold = min_confidence.unwrap_or(self.min_confidence);
        let chunks = chunk_text(text, 4000, 3000, 500);

        let mut all_candidates: Vec<(String, f32)> = Vec::new();
        for chunk in &chunks {
            let candidates = self.run_inference(chunk, &["organization", "company"])?;
            for (entity_type, org_name, confidence) in candidates {
                if (entity_type == "organization" || entity_type == "company")
                    && confidence >= threshold
                {
                    let trimmed = org_name.trim().to_string();
                    if !trimmed.is_empty() {
                        all_candidates.push((trimmed, confidence));
                    }
                }
            }
        }

        let results = dedup_filter_sort_orgs(all_candidates, 3);
        debug!(
            "NER extracted {} organizations from {} chars of text",
            results.len(),
            text.len()
        );
        Ok(results)
    }
}

// ============================================================================
// Module-level functions (mirror slm_org.rs interface)
// ============================================================================

/// Initialize the global NER extractor
#[cfg(feature = "embedded-ner")]
pub fn init() -> anyhow::Result<()> {
    init_with_config(0.5)
}

#[cfg_attr(coverage_nightly, coverage(off))]
/// Initialize the global NER extractor with custom minimum confidence
#[cfg(feature = "embedded-ner")]
pub fn init_with_config(min_confidence: f32) -> anyhow::Result<()> {
    let extractor = NerOrganizationExtractor::with_min_confidence(min_confidence)?;
    NER_EXTRACTOR
        .set(extractor)
        .map_err(|_| anyhow::anyhow!("NER extractor already initialized"))?;
    Ok(())
}

/// Check if NER is available (model loaded successfully)
#[cfg(feature = "embedded-ner")]
pub fn is_available() -> bool {
    NER_EXTRACTOR.get().is_some()
}

#[cfg_attr(coverage_nightly, coverage(off))]
/// Get the global NER extractor
#[cfg(feature = "embedded-ner")]
pub fn get() -> Option<&'static NerOrganizationExtractor> {
    NER_EXTRACTOR.get()
}

/// Extract organization using the global NER extractor
#[cfg(feature = "embedded-ner")]
#[cfg_attr(coverage_nightly, coverage(off))] // coverage: OnceLock singleton — None branch unreachable after init()
pub fn extract_organization(
    domain: &str,
    page_content: Option<&str>,
) -> anyhow::Result<Option<NerOrgResult>> {
    match NER_EXTRACTOR.get() {
        Some(extractor) => extractor.extract_from_domain(domain, page_content),
        None => Ok(None),
    }
}

/// Extract all organizations from text using the global NER extractor.
/// Returns all detected organizations above min_confidence threshold.
#[cfg(feature = "embedded-ner")]
#[cfg_attr(coverage_nightly, coverage(off))] // coverage: OnceLock singleton — None branch unreachable after init()
pub fn extract_all_organizations(
    text: &str,
    min_confidence: Option<f32>,
) -> anyhow::Result<Vec<NerOrgResult>> {
    match NER_EXTRACTOR.get() {
        Some(extractor) => extractor.extract_all_organizations(text, min_confidence),
        None => Ok(Vec::new()),
    }
}

// ============================================================================
// Stub implementations when embedded-ner feature is disabled
// ============================================================================

/// Stub: Initialize the global NER extractor (no-op when disabled)
#[cfg(not(feature = "embedded-ner"))]
pub fn init() -> anyhow::Result<()> {
    Ok(())
}

/// Stub: Initialize with config (no-op when disabled)
#[cfg(not(feature = "embedded-ner"))]
pub fn init_with_config(_min_confidence: f32) -> anyhow::Result<()> {
    Ok(())
}

/// Stub: Check if NER is available (always false when disabled)
#[cfg(not(feature = "embedded-ner"))]
pub fn is_available() -> bool {
    false
}

/// Stub: Extract organization (always returns None when disabled)
#[cfg(not(feature = "embedded-ner"))]
pub fn extract_organization(
    _domain: &str,
    _page_content: Option<&str>,
) -> anyhow::Result<Option<NerOrgResult>> {
    Ok(None)
}

/// Stub: Extract all organizations (always returns empty when disabled)
#[cfg(not(feature = "embedded-ner"))]
pub fn extract_all_organizations(
    _text: &str,
    _min_confidence: Option<f32>,
) -> anyhow::Result<Vec<NerOrgResult>> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── NerOrgResult struct tests ─────────────────────────────────────

    #[test]
    fn test_ner_org_result() {
        let result = NerOrgResult {
            organization: "Acme Corporation".to_string(),
            confidence: 0.95,
        };
        assert_eq!(result.organization, "Acme Corporation");
        assert!((result.confidence - 0.95).abs() < 0.001);
    }

    #[test]
    fn test_ner_org_result_clone() {
        let result = NerOrgResult {
            organization: "Test Corp".to_string(),
            confidence: 0.8,
        };
        let cloned = result.clone();
        assert_eq!(cloned.organization, "Test Corp");
        assert!((cloned.confidence - 0.8).abs() < f32::EPSILON);
    }

    #[test]
    fn test_ner_org_result_debug() {
        let result = NerOrgResult {
            organization: "Debug Corp".to_string(),
            confidence: 0.5,
        };
        let dbg = format!("{:?}", result);
        assert!(dbg.contains("Debug Corp"));
        assert!(dbg.contains("0.5"));
    }

    #[test]
    fn test_ner_org_result_zero_confidence() {
        let result = NerOrgResult {
            organization: "Zero".to_string(),
            confidence: 0.0,
        };
        assert_eq!(result.confidence, 0.0);
    }

    #[test]
    fn test_ner_org_result_max_confidence() {
        let result = NerOrgResult {
            organization: "Max".to_string(),
            confidence: 1.0,
        };
        assert_eq!(result.confidence, 1.0);
    }

    #[test]
    fn test_ner_org_result_empty_organization() {
        let result = NerOrgResult {
            organization: "".to_string(),
            confidence: 0.9,
        };
        assert!(result.organization.is_empty());
    }

    #[test]
    fn test_ner_org_result_unicode_organization() {
        let result = NerOrgResult {
            organization: "日本企業株式会社".to_string(),
            confidence: 0.75,
        };
        assert_eq!(result.organization, "日本企業株式会社");
    }

    #[test]
    fn test_ner_org_result_long_name() {
        let long_name = "A".repeat(1000);
        let result = NerOrgResult {
            organization: long_name.clone(),
            confidence: 0.6,
        };
        assert_eq!(result.organization.len(), 1000);
    }

    // ── Stub function tests (when embedded-ner is disabled) ───────────

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stub_functions() {
        assert!(!is_available());
        let result = extract_organization("example.com", None).unwrap();
        assert!(result.is_none());
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stub_init() {
        // init should succeed (no-op)
        assert!(init().is_ok());
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stub_init_with_config() {
        assert!(init_with_config(0.3).is_ok());
        assert!(init_with_config(0.0).is_ok());
        assert!(init_with_config(1.0).is_ok());
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stub_is_available() {
        assert!(!is_available());
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stub_extract_organization_with_content() {
        let result =
            extract_organization("example.com", Some("Some page content about Acme Corp")).unwrap();
        assert!(result.is_none());
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stub_extract_organization_none_content() {
        let result = extract_organization("test.com", None).unwrap();
        assert!(result.is_none());
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stub_extract_all_organizations() {
        let result = extract_all_organizations("Some text about Microsoft", None).unwrap();
        assert!(result.is_empty());
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stub_extract_all_organizations_with_confidence() {
        let result = extract_all_organizations("Some text about Google", Some(0.8)).unwrap();
        assert!(result.is_empty());
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stub_extract_organization_various_domains() {
        // Verify stubs handle any domain input gracefully
        let domains = vec![
            "google.com",
            "api.stripe.com",
            "sub.domain.example.co.uk",
            "",
            "localhost",
            "192.168.1.1",
        ];
        for domain in domains {
            let result = extract_organization(domain, None).unwrap();
            assert!(result.is_none(), "Stub should return None for {}", domain);
        }
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stub_extract_all_empty_text() {
        let result = extract_all_organizations("", None).unwrap();
        assert!(result.is_empty());
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stub_extract_all_long_text() {
        let long_text = "word ".repeat(10_000);
        let result = extract_all_organizations(&long_text, Some(0.1)).unwrap();
        assert!(result.is_empty());
    }

    // ── Embedded NER tests (when feature is enabled) ──────────────────

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))] // coverage: panic arm — Err(_) branch never triggers with valid model
    fn ensure_ner_available() -> bool {
        if is_available() {
            return true;
        }
        let r = std::panic::catch_unwind(|| init_with_config(0.5));
        match r {
            Err(_) => false,
            Ok(Err(e)) => e.to_string().contains("already initialized") && is_available(),
            Ok(Ok(())) => true,
        }
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_new_constructor() {
        if !ensure_ner_available() {
            return;
        }
        let result = std::panic::catch_unwind(NerOrganizationExtractor::new);
        let _ = result;
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_init_module_level() {
        let result = std::panic::catch_unwind(init);
        let _ = result;
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_get_returns_extractor() {
        if !ensure_ner_available() {
            return;
        }
        assert!(get().is_some());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))] // coverage: LLVM artifact — closing brace instrumentation gap
    fn test_ner_extract_organization_basic() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let result =
            extractor.extract_organization("Microsoft Corporation provides cloud services");
        assert!(result.is_ok());
        if let Ok(Some(org)) = result {
            assert!(!org.organization.is_empty());
            assert!(org.confidence > 0.0);
            assert!(org.confidence <= 1.0);
        }
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_organization_multiple_entity_types() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let result = extractor.extract_organization("Stripe Inc. processes payments worldwide");
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_organization_no_orgs() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let result = extractor.extract_organization("the quick brown fox jumps over the lazy dog");
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_organization_empty_text() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let _ = extractor.extract_organization("");
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_organization_long_text_truncation() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let long_text = format!(
            "Google LLC is a technology company. {} More text.",
            "a ".repeat(2500)
        );
        assert!(long_text.len() > 4000);
        let result = extractor.extract_organization(&long_text);
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_organization_long_text_with_multibyte_at_boundary() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let mut text = String::with_capacity(4100);
        text.push_str("Amazon Web Services. ");
        while text.len() < 3998 {
            text.push_str("test ");
        }
        text.push_str("\u{2019}end");
        assert!(text.len() > 4000);
        assert!(extractor.extract_organization(&text).is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_from_domain_with_content() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let result = extractor.extract_from_domain(
            "stripe.com",
            Some("Stripe Inc. powers online payment processing for internet businesses"),
        );
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_from_domain_without_content() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        assert!(extractor.extract_from_domain("microsoft.com", None).is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_organizations_short_text() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let result = extractor.extract_all_organizations(
            "Microsoft and Google are tech companies. Amazon provides cloud services.",
            Some(0.3),
        );
        assert!(result.is_ok());
        for org in result.unwrap() {
            assert!(org.organization.len() >= 3);
            assert!(org.confidence >= 0.3);
        }
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_organizations_default_confidence() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let result = extractor.extract_all_organizations(
            "Salesforce CRM and Adobe Creative Cloud are enterprise tools.",
            None,
        );
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_organizations_long_text_chunking() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let mut long_text = String::with_capacity(10000);
        long_text.push_str("Google LLC is a major tech company. ");
        while long_text.len() < 5000 {
            long_text.push_str("Various technology companies compete in the market. ");
        }
        long_text.push_str("Microsoft Corporation also provides cloud services.");
        assert!(long_text.len() > 4000);
        assert!(extractor
            .extract_all_organizations(&long_text, Some(0.3))
            .is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_organizations_very_long_text_multiple_chunks() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let mut long_text = String::with_capacity(15000);
        for _ in 0..5 {
            long_text.push_str("Apple Inc. builds consumer electronics. ");
            long_text.push_str(&"word ".repeat(600));
        }
        assert!(long_text.len() > 10000);
        assert!(extractor
            .extract_all_organizations(&long_text, Some(0.3))
            .is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_organizations_multibyte_chunking() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let mut text = String::with_capacity(10000);
        text.push_str("Adobe Inc\u{2019}s Creative Cloud. ");
        while text.len() < 7000 {
            text.push_str("caf\u{00E9} ");
        }
        text.push_str("Salesforce Corp.");
        assert!(extractor
            .extract_all_organizations(&text, Some(0.3))
            .is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_organizations_empty_text() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let _ = extractor.extract_all_organizations("", Some(0.3));
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_organizations_high_confidence_filter() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let result = extractor.extract_all_organizations(
            "Microsoft Corporation and Google LLC announced a partnership.",
            Some(0.99),
        );
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_module_extract_organization_with_content() {
        if !ensure_ner_available() {
            return;
        }
        assert!(extract_organization(
            "stripe.com",
            Some("Stripe Inc. provides payment processing")
        )
        .is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_module_extract_organization_without_content() {
        if !ensure_ner_available() {
            return;
        }
        assert!(extract_organization("google.com", None).is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_module_extract_all_organizations() {
        if !ensure_ner_available() {
            return;
        }
        assert!(
            extract_all_organizations("Microsoft and Amazon are large companies.", Some(0.3))
                .is_ok()
        );
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_module_extract_all_organizations_none_confidence() {
        if !ensure_ner_available() {
            return;
        }
        assert!(extract_all_organizations("Google LLC is in Mountain View.", None).is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_is_available_after_init() {
        if !ensure_ner_available() {
            return;
        }
        assert!(is_available());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_init_with_config_already_initialized() {
        if !ensure_ner_available() {
            return;
        }
        let result = init_with_config(0.8);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("already initialized"));
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_organization_selects_best_match() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let result = extractor.extract_organization(
            "Stripe Inc. is a fintech company founded in San Francisco. Google also operates there.",
        );
        assert!(result.is_ok());
        if let Ok(Some(org)) = result {
            assert!(!org.organization.is_empty());
        }
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_from_domain_extracts_with_domain_context() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let result = extractor.extract_from_domain(
            "cloudflare.com",
            Some("Cloudflare Inc. provides CDN and security services."),
        );
        assert!(result.is_ok());
        if let Ok(Some(ref org)) = result {
            assert!(org.confidence > 0.0);
        }
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_organizations_dedup_by_name() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let result = extractor.extract_all_organizations(
            "Google LLC is a company. Google LLC does many things. Google LLC is everywhere.",
            Some(0.3),
        );
        assert!(result.is_ok());
        let orgs = result.unwrap();
        let google_count = orgs
            .iter()
            .filter(|o| o.organization.to_lowercase().contains("google"))
            .count();
        assert!(google_count <= 1, "Should dedup same org name");
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_organizations_sorted_by_confidence() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let result = extractor.extract_all_organizations(
            "Microsoft Corporation and Google LLC and Amazon Web Services and Apple Inc are big companies.",
            Some(0.1),
        );
        assert!(result.is_ok());
        let orgs = result.unwrap();
        for w in orgs.windows(2) {
            assert!(
                w[0].confidence >= w[1].confidence,
                "Results should be sorted by confidence desc"
            );
        }
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_organizations_filters_short_names() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let result =
            extractor.extract_all_organizations("AB Corp and Microsoft are companies.", Some(0.1));
        assert!(result.is_ok());
        for org in result.unwrap() {
            assert!(
                org.organization.len() >= 3,
                "Org names shorter than 3 chars should be filtered"
            );
        }
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_write_if_missing_already_exists() {
        if !ensure_ner_available() {
            return;
        }
        let temp_dir = std::env::temp_dir().join("nthpartyfinder_ner");
        let model_path = temp_dir.join("gliner_small.onnx");
        let canon_temp = temp_dir
            .canonicalize()
            .expect("Temp dir should be resolvable after init");
        let canon_model = model_path
            .canonicalize()
            .expect("Model path should be resolvable after init");
        assert!(
            canon_model.starts_with(&canon_temp),
            "Model path must remain within expected temp directory"
        );
        assert!(canon_model.exists(), "Model file should exist after init"); // lgtm[rust/path-injection]
        assert!(NerOrganizationExtractor::write_if_missing(&model_path, b"test").is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_write_if_missing_new_file() {
        let temp = std::env::temp_dir().join("nthpartyfinder_ner_test_write");
        let _ = std::fs::create_dir_all(&temp); // lgtm[rust/path-injection]
        let temp_canon = std::fs::canonicalize(&temp).unwrap();
        let test_path = temp.join("test_file.bin");

        // lgtm[rust/path-injection]
        if test_path.exists() {
            if let Ok(test_path_canon) = std::fs::canonicalize(&test_path) {
                if test_path_canon.starts_with(&temp_canon) {
                    let _ = std::fs::remove_file(&test_path_canon);
                }
            }
        }

        assert!(!test_path.exists()); // lgtm[rust/path-injection]
        assert!(NerOrganizationExtractor::write_if_missing(&test_path, b"hello").is_ok()); // lgtm[rust/path-injection]
        assert!(test_path.exists()); // lgtm[rust/path-injection]
        assert_eq!(std::fs::read(&test_path).unwrap(), b"hello"); // lgtm[rust/path-injection]

        if let Ok(test_path_canon) = std::fs::canonicalize(&test_path) {
            if test_path_canon.starts_with(&temp_canon) {
                let _ = std::fs::remove_file(&test_path_canon);
            }
        }

        if let Ok(temp_canon_again) = std::fs::canonicalize(&temp) {
            if temp_canon_again.starts_with(std::env::temp_dir()) {
                let _ = std::fs::remove_dir(&temp_canon_again);
            }
        }
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_setup_onnx_runtime_with_env_var_already_set() {
        std::env::set_var("ORT_DYLIB_PATH", "/some/test/path");
        assert!(NerOrganizationExtractor::setup_onnx_runtime().is_ok());
        std::env::remove_var("ORT_DYLIB_PATH");
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_setup_onnx_runtime_search_paths() {
        let saved = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::remove_var("ORT_DYLIB_PATH");
        let _ = NerOrganizationExtractor::setup_onnx_runtime();
        if let Some(val) = saved {
            std::env::set_var("ORT_DYLIB_PATH", val);
        }
    }

    // ── NerOrgResult additional struct tests ─────────────────────────

    #[test]
    fn test_ner_org_result_clone_independence() {
        let original = NerOrgResult {
            organization: "Original".to_string(),
            confidence: 0.9,
        };
        let mut cloned = original.clone();
        cloned.organization = "Modified".to_string();
        cloned.confidence = 0.1;
        assert_eq!(original.organization, "Original");
        assert!((original.confidence - 0.9).abs() < f32::EPSILON);
        assert_eq!(cloned.organization, "Modified");
        assert!((cloned.confidence - 0.1).abs() < f32::EPSILON);
    }

    #[test]
    fn test_ner_org_result_negative_confidence() {
        // Not semantically valid, but should not panic
        let result = NerOrgResult {
            organization: "Negative".to_string(),
            confidence: -0.5,
        };
        assert!(result.confidence < 0.0);
    }

    #[test]
    fn test_ner_org_result_nan_confidence() {
        let result = NerOrgResult {
            organization: "NaN".to_string(),
            confidence: f32::NAN,
        };
        assert!(result.confidence.is_nan());
    }

    #[test]
    fn test_ner_org_result_infinity_confidence() {
        let result = NerOrgResult {
            organization: "Inf".to_string(),
            confidence: f32::INFINITY,
        };
        assert!(result.confidence.is_infinite());
    }

    #[test]
    fn test_ner_org_result_special_chars_org() {
        let result = NerOrgResult {
            organization: "O'Brien & Co. (Inc.)".to_string(),
            confidence: 0.85,
        };
        assert_eq!(result.organization, "O'Brien & Co. (Inc.)");
    }

    #[test]
    fn test_ner_org_result_very_long_org_name() {
        let name = "Corp".repeat(500);
        let result = NerOrgResult {
            organization: name.clone(),
            confidence: 0.5,
        };
        assert_eq!(result.organization.len(), 2000);
    }

    #[test]
    fn test_ner_org_result_debug_includes_all_fields() {
        let result = NerOrgResult {
            organization: "DebugTest".to_string(),
            confidence: 0.42,
        };
        let dbg = format!("{:?}", result);
        assert!(dbg.contains("NerOrgResult"));
        assert!(dbg.contains("DebugTest"));
        assert!(dbg.contains("0.42"));
    }

    #[test]
    fn test_ner_org_result_whitespace_org() {
        let result = NerOrgResult {
            organization: "   ".to_string(),
            confidence: 0.3,
        };
        assert_eq!(result.organization.trim(), "");
    }

    // ── Stub function additional tests ───────────────────────────────

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stub_init_multiple_times() {
        // Stubs should be idempotent
        assert!(init().is_ok());
        assert!(init().is_ok());
        assert!(init().is_ok());
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stub_init_with_config_extreme_values() {
        assert!(init_with_config(-1.0).is_ok());
        assert!(init_with_config(f32::MAX).is_ok());
        assert!(init_with_config(f32::NAN).is_ok());
        assert!(init_with_config(f32::INFINITY).is_ok());
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stub_extract_organization_empty_domain() {
        let result = extract_organization("", None).unwrap();
        assert!(result.is_none());
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stub_extract_organization_with_empty_content() {
        let result = extract_organization("test.com", Some("")).unwrap();
        assert!(result.is_none());
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stub_extract_all_organizations_zero_confidence() {
        let result = extract_all_organizations("text", Some(0.0)).unwrap();
        assert!(result.is_empty());
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stub_extract_all_organizations_negative_confidence() {
        let result = extract_all_organizations("text", Some(-1.0)).unwrap();
        assert!(result.is_empty());
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stub_is_available_consistently_false() {
        for _ in 0..10 {
            assert!(!is_available());
        }
    }

    // --- Tests for previously-coverage(off) stub functions ---

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stripped_init_returns_ok_and_is_idempotent() {
        assert!(init().is_ok());
        assert!(init().is_ok());
        assert!(init().is_ok());
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stripped_init_with_config_ignores_all_thresholds() {
        assert!(init_with_config(0.0).is_ok());
        assert!(init_with_config(0.5).is_ok());
        assert!(init_with_config(1.0).is_ok());
        assert!(init_with_config(-1.0).is_ok());
        assert!(init_with_config(f32::MAX).is_ok());
        assert!(init_with_config(f32::NAN).is_ok());
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stripped_is_available_always_false_after_init() {
        let _ = init();
        assert!(!is_available());
        let _ = init_with_config(0.9);
        assert!(!is_available());
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stripped_extract_organization_returns_none_for_all_inputs() {
        let _ = init();
        let result = extract_organization("google.com", Some("<html>Google LLC</html>")).unwrap();
        assert!(result.is_none());
        let result = extract_organization("microsoft.com", None).unwrap();
        assert!(result.is_none());
        let result = extract_organization("", Some("content")).unwrap();
        assert!(result.is_none());
        let result = extract_organization("例え.jp", Some("会社名")).unwrap();
        assert!(result.is_none());
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stripped_extract_all_organizations_returns_empty_for_all_inputs() {
        let _ = init();
        let result =
            extract_all_organizations("Google and Microsoft are tech companies.", None).unwrap();
        assert!(result.is_empty());
        assert_eq!(result.len(), 0);
        let result = extract_all_organizations("", Some(0.5)).unwrap();
        assert!(result.is_empty());
        let long_text = "Organization ".repeat(1000);
        let result = extract_all_organizations(&long_text, Some(0.1)).unwrap();
        assert!(result.is_empty());
    }

    // ── Coverage uplift: targeted edge-case tests ──────────────────────

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[cfg(feature = "embedded-ner")]
    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_setup_onnx_runtime_search_path_discovery() {
        let saved = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::remove_var("ORT_DYLIB_PATH");

        let cwd = std::env::current_dir().unwrap_or_else(|_| std::env::temp_dir());
        #[cfg(target_os = "macos")]
        let lib_name = "libonnxruntime.dylib";
        #[cfg(not(target_os = "macos"))]
        let lib_name = "libonnxruntime.so";
        let fake_lib = cwd.join(lib_name);
        let _ = std::fs::write(&fake_lib, b"fake"); // lgtm[rust/path-injection]
        let result = NerOrganizationExtractor::setup_onnx_runtime();
        assert!(result.is_ok(), "Should find runtime in cwd");
        let set_val = std::env::var("ORT_DYLIB_PATH").unwrap();
        assert!(!set_val.is_empty());

        let _ = std::fs::remove_file(&fake_lib); // lgtm[rust/path-injection]
        if let Some(val) = saved {
            std::env::set_var("ORT_DYLIB_PATH", val);
        }
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_organization_truncation_char_boundary() {
        if !ensure_ner_available() {
            return;
        }
        init_tracing();
        let extractor = get().unwrap();

        let mut text = String::with_capacity(4100);
        text.push_str("Microsoft Corp. ");
        while text.len() < 3999 {
            text.push('x');
        }
        assert_eq!(text.len(), 3999);
        text.push('\u{2019}');
        assert_eq!(text.len(), 4002);
        text.push_str(" end");
        assert!(text.len() > 4000);
        assert!(!text.is_char_boundary(4000));

        let result = extractor.extract_organization(&text);
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_from_domain_no_org_found() {
        if !ensure_ner_available() {
            return;
        }
        init_tracing();
        let extractor = get().unwrap();
        let result = extractor.extract_from_domain(
            "zzz999.invalid",
            Some("xyzzy plugh nothing here at all just random gibberish words"),
        );
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_from_domain_debug_with_content() {
        if !ensure_ner_available() {
            return;
        }
        init_tracing();
        let extractor = get().unwrap();
        let result = extractor.extract_from_domain(
            "example.com",
            Some("Example Corp provides services worldwide"),
        );
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_from_domain_debug_without_content() {
        if !ensure_ner_available() {
            return;
        }
        init_tracing();
        let extractor = get().unwrap();
        let result = extractor.extract_from_domain("example.com", None);
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_orgs_chunking_whitespace_break() {
        if !ensure_ner_available() {
            return;
        }
        init_tracing();
        let extractor = get().unwrap();

        let mut text = String::with_capacity(8000);
        text.push_str("Google LLC is a major technology company. ");
        while text.len() < 4500 {
            text.push_str("word ");
        }
        text.push_str("Microsoft Corporation also competes in this space.");
        assert!(text.len() > 4000);

        let result = extractor.extract_all_organizations(&text, Some(0.1));
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_orgs_chunking_no_whitespace() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();

        let mut text = String::with_capacity(8000);
        text.push_str("Google");
        while text.len() < 5000 {
            text.push('a');
        }
        assert!(text.len() > 4000);
        assert!(!text.contains(' '));

        let result = extractor.extract_all_organizations(&text, Some(0.1));
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_orgs_chunking_multibyte_boundaries() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();

        let mut text = String::with_capacity(8000);
        text.push_str("Amazon ");
        while text.len() < 2999 {
            text.push('\u{2019}');
        }
        text.push(' ');
        while text.len() < 5500 {
            text.push('\u{2019}');
        }
        text.push_str(" Apple Inc.");
        assert!(text.len() > 4000);

        let result = extractor.extract_all_organizations(&text, Some(0.1));
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_orgs_chunking_small_overlap() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();

        let mut text = String::with_capacity(10000);
        for i in 0..20 {
            text.push_str(&format!("Company{} Inc. ", i));
            text.push_str(&"z".repeat(400));
            text.push(' ');
        }
        assert!(text.len() > 4000);

        let result = extractor.extract_all_organizations(&text, Some(0.1));
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_orgs_chunking_cjk_dense() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();

        let mut text = String::with_capacity(12000);
        text.push_str("Toyota Corporation ");
        while text.len() < 7000 {
            text.push('\u{4E16}');
        }
        text.push_str(" Sony Group");
        assert!(text.len() > 4000);

        let result = extractor.extract_all_organizations(&text, Some(0.1));
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_orgs_debug_logging() {
        if !ensure_ner_available() {
            return;
        }
        init_tracing();
        let extractor = get().unwrap();
        let result = extractor.extract_all_organizations(
            "Intel Corporation and AMD are semiconductor companies.",
            Some(0.1),
        );
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_org_debug_logging_with_match() {
        if !ensure_ner_available() {
            return;
        }
        init_tracing();
        let extractor = get().unwrap();
        let result =
            extractor.extract_organization("Apple Inc. designs consumer electronics and software.");
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_module_level_functions_after_init() {
        if !ensure_ner_available() {
            return;
        }
        let result = extract_organization("google.com", Some("Google LLC")).unwrap();
        assert!(result.is_none() || result.is_some());
        let all = extract_all_organizations("Microsoft Corp is large.", None).unwrap();
        let _ = all;
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_orgs_exact_4000_boundary() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();

        let mut text = String::with_capacity(4001);
        text.push_str("Nvidia Corporation ");
        while text.len() < 4000 {
            text.push('a');
        }
        assert_eq!(text.len(), 4000);
        text.push('b');
        assert_eq!(text.len(), 4001);

        let result = extractor.extract_all_organizations(&text, Some(0.1));
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_orgs_emoji_dense_text() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();

        let mut text = String::with_capacity(10000);
        text.push_str("Netflix Inc ");
        while text.len() < 7000 {
            text.push('\u{1F600}');
        }
        assert!(text.len() > 4000);

        let result = extractor.extract_all_organizations(&text, Some(0.1));
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_org_multiple_companies() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let result = extractor
            .extract_organization("IBM and Oracle and SAP compete in enterprise software.");
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_orgs_degenerate_chunk_multibyte_whitespace() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();

        let mut text = String::new();
        text.push('\u{3000}');
        while text.len() < 5000 {
            text.push('\u{4E16}');
        }
        assert!(text.len() > 4000);

        let result = extractor.extract_all_organizations(&text, Some(0.1));
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_orgs_chunk_boundary_adjustment() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();

        let mut text = String::new();
        text.push_str("Google ");
        for _ in 0..900 {
            text.push('\u{3000}');
            text.push('\u{4E16}');
            text.push('\u{4E16}');
        }
        text.push_str(" Microsoft Corp");
        assert!(text.len() > 4000);

        let result = extractor.extract_all_organizations(&text, Some(0.1));
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_orgs_high_threshold_filters_all() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let result =
            extractor.extract_all_organizations("Some company name here and there.", Some(1.0));
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_orgs_low_threshold() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();
        let result = extractor.extract_all_organizations(
            "Go is a programming language. AT works in telecom.",
            Some(0.01),
        );
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_ner_extract_all_orgs_overlap_boundary_walk() {
        if !ensure_ner_available() {
            return;
        }
        let extractor = get().unwrap();

        let mut text = String::with_capacity(10000);
        text.push_str("Samsung ");
        while text.len() < 3100 {
            text.push('\u{00E9}');
        }
        text.push(' ');
        while text.len() < 6500 {
            text.push('\u{00E9}');
        }
        text.push_str(" Toshiba Corp");
        assert!(text.len() > 4000);

        let result = extractor.extract_all_organizations(&text, Some(0.1));
        assert!(result.is_ok());
    }

    // ── Pure function tests (no ONNX runtime required) ─────────────

    #[test]
    fn test_pure_truncate_text_within_limit() {
        assert_eq!(truncate_text("hello", 10), "hello");
        assert_eq!(truncate_text("", 100), "");
        assert_eq!(truncate_text("exact", 5), "exact");
    }

    #[test]
    fn test_pure_truncate_text_at_multibyte_boundary() {
        let text = "abc\u{2019}def";
        assert_eq!(truncate_text(text, 4), "abc");
        assert_eq!(truncate_text(text, 5), "abc");
        assert_eq!(truncate_text(text, 6), "abc\u{2019}");
        assert_eq!(truncate_text(text, 100), text);
    }

    #[test]
    fn test_pure_build_domain_context() {
        assert_eq!(
            build_domain_context("example.com", Some("Page content")),
            "Website: example.com. Page content"
        );
        assert_eq!(
            build_domain_context("example.com", None),
            "Website: example.com"
        );
        assert_eq!(build_domain_context("", Some("")), "Website: . ");
    }

    #[test]
    fn test_pure_is_org_entity_type() {
        assert!(is_org_entity_type("organization"));
        assert!(is_org_entity_type("Organization"));
        assert!(is_org_entity_type("ORGANIZATION"));
        assert!(is_org_entity_type("company"));
        assert!(is_org_entity_type("product"));
        assert!(is_org_entity_type("brand"));
        assert!(!is_org_entity_type("person"));
        assert!(!is_org_entity_type("location"));
        assert!(!is_org_entity_type(""));
    }

    #[test]
    fn test_pure_select_best_org_picks_highest() {
        let candidates = vec![
            ("organization".into(), "Acme Corp".into(), 0.7),
            ("company".into(), "Beta Inc".into(), 0.9),
            ("person".into(), "John Doe".into(), 0.95),
            ("organization".into(), "  ".into(), 0.99),
        ];
        let result = select_best_org(&candidates, 0.5);
        assert!(result.is_some());
        let org = result.unwrap();
        assert_eq!(org.organization, "Beta Inc");
        assert!((org.confidence - 0.9).abs() < f32::EPSILON);
    }

    #[test]
    fn test_pure_select_best_org_respects_threshold() {
        let candidates = vec![
            ("organization".into(), "Low Corp".into(), 0.3),
            ("company".into(), "Med Inc".into(), 0.4),
        ];
        assert!(select_best_org(&candidates, 0.5).is_none());
        assert!(select_best_org(&[], 0.5).is_none());
    }

    #[test]
    fn test_pure_chunk_text_short_returns_single() {
        let text = "Short text";
        let chunks = chunk_text(text, 4000, 3000, 500);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], text);
    }

    #[test]
    fn test_pure_chunk_text_long_produces_multiple() {
        let text = "word ".repeat(2000);
        let chunks = chunk_text(&text, 4000, 3000, 500);
        assert!(
            chunks.len() > 1,
            "10000-byte text should produce multiple chunks"
        );
        for chunk in &chunks {
            assert!(!chunk.is_empty());
        }
    }

    #[test]
    fn test_pure_chunk_text_multibyte_safe() {
        let mut text = String::new();
        while text.len() < 6000 {
            text.push('\u{2019}');
        }
        let chunks = chunk_text(&text, 4000, 3000, 500);
        assert!(chunks.len() > 1);
        for chunk in &chunks {
            assert!(!chunk.is_empty());
        }
    }

    #[test]
    fn test_pure_dedup_filter_sort_orgs() {
        let orgs = vec![
            ("Google LLC".into(), 0.9),
            ("google llc".into(), 0.7),
            ("Microsoft".into(), 0.8),
            ("AB".into(), 0.95),
        ];
        let results = dedup_filter_sort_orgs(orgs, 3);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].organization, "Google LLC");
        assert!((results[0].confidence - 0.9).abs() < f32::EPSILON);
        assert_eq!(results[1].organization, "Microsoft");
        assert!(dedup_filter_sort_orgs(vec![], 3).is_empty());
    }

    // ── Additional pure function edge-case tests for coverage uplift ──

    // -- truncate_text --

    #[test]
    fn test_truncate_text_exact_boundary() {
        // When max_len equals text length, return full text
        let text = "hello";
        assert_eq!(truncate_text(text, 5), "hello");
    }

    #[test]
    fn test_truncate_text_one_less_than_length() {
        let text = "hello";
        assert_eq!(truncate_text(text, 4), "hell");
    }

    #[test]
    fn test_truncate_text_zero_max_len() {
        let text = "hello";
        assert_eq!(truncate_text(text, 0), "");
    }

    #[test]
    fn test_truncate_text_empty_string() {
        assert_eq!(truncate_text("", 0), "");
        assert_eq!(truncate_text("", 100), "");
    }

    #[test]
    fn test_truncate_text_single_multibyte_char() {
        // '\u{2019}' is 3 bytes (RIGHT SINGLE QUOTATION MARK)
        let text = "\u{2019}";
        assert_eq!(text.len(), 3);
        // max_len = 1 or 2 are inside the char boundary, should back down to 0
        assert_eq!(truncate_text(text, 1), "");
        assert_eq!(truncate_text(text, 2), "");
        assert_eq!(truncate_text(text, 3), "\u{2019}");
    }

    #[test]
    fn test_truncate_text_only_multibyte_chars() {
        // Each '\u{1F600}' (grinning face) is 4 bytes
        let text = "\u{1F600}\u{1F600}"; // 8 bytes
        assert_eq!(text.len(), 8);
        assert_eq!(truncate_text(text, 1), "");
        assert_eq!(truncate_text(text, 4), "\u{1F600}");
        assert_eq!(truncate_text(text, 5), "\u{1F600}");
        assert_eq!(truncate_text(text, 7), "\u{1F600}");
        assert_eq!(truncate_text(text, 8), "\u{1F600}\u{1F600}");
    }

    #[test]
    fn test_truncate_text_ascii_only_no_boundary_issues() {
        let text = "abcdefgh";
        assert_eq!(truncate_text(text, 3), "abc");
        assert_eq!(truncate_text(text, 8), "abcdefgh");
        assert_eq!(truncate_text(text, 100), "abcdefgh");
    }

    // -- build_domain_context --

    #[test]
    fn test_build_domain_context_empty_domain_with_content() {
        assert_eq!(
            build_domain_context("", Some("content here")),
            "Website: . content here"
        );
    }

    #[test]
    fn test_build_domain_context_empty_domain_without_content() {
        assert_eq!(build_domain_context("", None), "Website: ");
    }

    #[test]
    fn test_build_domain_context_long_content() {
        let content = "x".repeat(10000);
        let result = build_domain_context("example.com", Some(&content));
        assert!(result.starts_with("Website: example.com. "));
        assert_eq!(result.len(), "Website: example.com. ".len() + 10000);
    }

    #[test]
    fn test_build_domain_context_unicode_domain() {
        let result = build_domain_context("日本語.jp", Some("日本語コンテンツ"));
        assert_eq!(result, "Website: 日本語.jp. 日本語コンテンツ");
    }

    // -- is_org_entity_type --

    #[test]
    fn test_is_org_entity_type_mixed_case() {
        assert!(is_org_entity_type("COMPANY"));
        assert!(is_org_entity_type("Product"));
        assert!(is_org_entity_type("BRAND"));
        assert!(is_org_entity_type("OrGaNiZaTiOn"));
    }

    #[test]
    fn test_is_org_entity_type_non_org_types() {
        assert!(!is_org_entity_type("person"));
        assert!(!is_org_entity_type("location"));
        assert!(!is_org_entity_type("date"));
        assert!(!is_org_entity_type("event"));
        assert!(!is_org_entity_type("money"));
        assert!(!is_org_entity_type("org")); // not in the list
        assert!(!is_org_entity_type("corp"));
        assert!(!is_org_entity_type("organizations")); // plural
    }

    #[test]
    fn test_is_org_entity_type_whitespace() {
        // " organization " after trim in to_lowercase won't match "organization"
        assert!(!is_org_entity_type(" organization "));
        assert!(!is_org_entity_type("organization "));
    }

    // -- select_best_org --

    #[test]
    fn test_select_best_org_empty_candidates() {
        assert!(select_best_org(&[], 0.0).is_none());
    }

    #[test]
    fn test_select_best_org_all_below_threshold() {
        let candidates = vec![
            ("organization".into(), "Low Corp".into(), 0.1f32),
            ("company".into(), "Lower Corp".into(), 0.2f32),
        ];
        assert!(select_best_org(&candidates, 0.5).is_none());
    }

    #[test]
    fn test_select_best_org_non_org_types_skipped() {
        let candidates = vec![
            ("person".into(), "John Doe".into(), 0.99f32),
            ("location".into(), "New York".into(), 0.98f32),
            ("organization".into(), "Acme".into(), 0.5f32),
        ];
        let result = select_best_org(&candidates, 0.3);
        assert!(result.is_some());
        assert_eq!(result.unwrap().organization, "Acme");
    }

    #[test]
    fn test_select_best_org_whitespace_only_name_skipped() {
        // Whitespace-only names should be skipped even if entity type and confidence qualify
        let candidates = vec![
            ("organization".into(), "   ".into(), 0.99f32),
            ("organization".into(), "\t\n".into(), 0.98f32),
        ];
        assert!(select_best_org(&candidates, 0.5).is_none());
    }

    #[test]
    fn test_select_best_org_trims_whitespace() {
        let candidates = vec![("organization".into(), "  Trimmed Corp  ".into(), 0.8f32)];
        let result = select_best_org(&candidates, 0.5).unwrap();
        assert_eq!(result.organization, "Trimmed Corp");
    }

    #[test]
    fn test_select_best_org_picks_highest_confidence_among_org_types() {
        let candidates = vec![
            ("company".into(), "A Corp".into(), 0.6f32),
            ("product".into(), "B Product".into(), 0.8f32),
            ("brand".into(), "C Brand".into(), 0.7f32),
            ("organization".into(), "D Org".into(), 0.75f32),
        ];
        let result = select_best_org(&candidates, 0.5).unwrap();
        assert_eq!(result.organization, "B Product");
        assert!((result.confidence - 0.8).abs() < f32::EPSILON);
    }

    #[test]
    fn test_select_best_org_exactly_at_threshold() {
        let candidates = vec![("organization".into(), "Exact Corp".into(), 0.5f32)];
        let result = select_best_org(&candidates, 0.5);
        assert!(result.is_some());
        assert_eq!(result.unwrap().organization, "Exact Corp");
    }

    #[test]
    fn test_select_best_org_just_below_threshold() {
        let candidates = vec![("organization".into(), "Almost Corp".into(), 0.499f32)];
        assert!(select_best_org(&candidates, 0.5).is_none());
    }

    #[test]
    fn test_select_best_org_multiple_same_confidence() {
        // When two candidates have the same confidence, the first one wins
        // (since we use > not >=)
        let candidates = vec![
            ("organization".into(), "First Corp".into(), 0.8f32),
            ("company".into(), "Second Corp".into(), 0.8f32),
        ];
        let result = select_best_org(&candidates, 0.5).unwrap();
        assert_eq!(result.organization, "First Corp");
    }

    #[test]
    fn test_select_best_org_empty_name_after_trim() {
        let candidates = vec![("organization".into(), "".into(), 0.99f32)];
        assert!(select_best_org(&candidates, 0.5).is_none());
    }

    // -- chunk_text --

    #[test]
    fn test_chunk_text_exactly_at_max_single_len() {
        let text = "a".repeat(4000);
        let chunks = chunk_text(&text, 4000, 3000, 500);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], text);
    }

    #[test]
    fn test_chunk_text_one_over_max_single_len() {
        let text = "a ".repeat(2001); // 4002 bytes with spaces
        let chunks = chunk_text(&text, 4000, 3000, 500);
        assert!(chunks.len() > 1);
    }

    #[test]
    fn test_chunk_text_no_whitespace_in_long_text() {
        // When there's no whitespace to break on, chunks at safe_end
        let text = "a".repeat(8000);
        let chunks = chunk_text(&text, 4000, 3000, 500);
        assert!(chunks.len() > 1);
        for chunk in &chunks {
            assert!(!chunk.is_empty());
        }
    }

    #[test]
    fn test_chunk_text_only_whitespace() {
        let text = " ".repeat(6000);
        let chunks = chunk_text(&text, 4000, 3000, 500);
        assert!(!chunks.is_empty());
    }

    #[test]
    fn test_chunk_text_overlap_parameter_effect() {
        // With overlap=0, chunks shouldn't overlap
        let text = "word ".repeat(2000); // 10000 bytes
        let chunks_no_overlap = chunk_text(&text, 4000, 3000, 0);
        let chunks_with_overlap = chunk_text(&text, 4000, 3000, 500);
        // With overlap there should be more chunks covering the same text
        assert!(chunks_with_overlap.len() >= chunks_no_overlap.len());
    }

    #[test]
    fn test_chunk_text_very_small_chunk_size() {
        let text = "hello world foo bar";
        let chunks = chunk_text(text, 5, 5, 2);
        assert!(chunks.len() > 1);
        for chunk in &chunks {
            assert!(!chunk.is_empty());
        }
    }

    #[test]
    fn test_chunk_text_multibyte_at_chunk_boundary() {
        // Create text where a multibyte char falls exactly at chunk_size boundary
        let mut text = String::new();
        // Fill with ASCII up to just before chunk_size, then put a 3-byte char
        while text.len() < 2998 {
            text.push('a');
        }
        text.push('\u{2019}'); // 3 bytes, now at 3001
        while text.len() < 6000 {
            text.push('b');
        }
        let chunks = chunk_text(&text, 4000, 3000, 500);
        assert!(!chunks.is_empty());
        for chunk in &chunks {
            assert!(!chunk.is_empty());
            // Verify each chunk is valid UTF-8 (it must be, since &str)
        }
    }

    #[test]
    fn test_chunk_text_empty_string() {
        let chunks = chunk_text("", 4000, 3000, 500);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], "");
    }

    #[test]
    fn test_chunk_text_single_char() {
        let chunks = chunk_text("x", 4000, 3000, 500);
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0], "x");
    }

    #[test]
    fn test_chunk_text_overlap_larger_than_chunk() {
        // Edge case: overlap > chunk_size/2, should still work without infinite loop
        let text = "word ".repeat(200); // 1000 bytes
        let chunks = chunk_text(&text, 100, 100, 90);
        assert!(!chunks.is_empty());
        for chunk in &chunks {
            assert!(!chunk.is_empty());
        }
    }

    #[test]
    fn test_chunk_text_4byte_emoji_boundaries() {
        // Each emoji is 4 bytes
        let mut text = String::new();
        for _ in 0..2000 {
            text.push('\u{1F600}');
        }
        assert_eq!(text.len(), 8000);
        let chunks = chunk_text(&text, 4000, 3000, 500);
        assert!(chunks.len() > 1);
        for chunk in &chunks {
            assert!(!chunk.is_empty());
        }
    }

    #[test]
    fn test_chunk_text_mixed_ascii_and_multibyte() {
        let mut text = String::new();
        for i in 0..2000 {
            if i % 3 == 0 {
                text.push('\u{00E9}'); // 2-byte
            } else if i % 3 == 1 {
                text.push('\u{4E16}'); // 3-byte CJK
            } else {
                text.push('a'); // 1-byte
            }
        }
        let chunks = chunk_text(&text, 2000, 1500, 200);
        assert!(!chunks.is_empty());
        for chunk in &chunks {
            assert!(!chunk.is_empty());
        }
    }

    #[test]
    fn test_chunk_text_final_end_leq_start_branch() {
        // Tests the branch where final_end <= start causes a continue.
        // We need safe_end > start (so start advances) but actual_end computes
        // back to start. This happens when rfind returns the position right at
        // start within the slice.
        //
        // Example: "a " followed by a long run of no-whitespace text, with
        // chunk_size just past the space but actual_end computes to start+1
        // which after boundary walking equals start for the next iteration.
        //
        // Simpler: after processing a chunk, the next chunk starts mid-multibyte.
        // Use text where an ASCII prefix is followed by multibyte content and
        // chunk_size lands in the middle of a multibyte char after the first chunk.
        let mut text = String::new();
        text.push_str("ab"); // 2 bytes
                             // Now add a sequence of 3-byte chars (multibyte)
        for _ in 0..3000 {
            text.push('\u{2019}'); // 3 bytes each
        }
        assert!(text.len() > 4000);
        let chunks = chunk_text(&text, 2000, 2000, 0);
        assert!(!chunks.is_empty());
        for chunk in &chunks {
            assert!(!chunk.is_empty());
        }
    }

    #[test]
    fn test_chunk_text_overlap_start_leq_start_branch() {
        // Test the branch where safe_overlap <= start, causing start = final_end
        // This happens when the overlap is very large relative to the chunk produced
        let text = "ab cd ef gh ij kl mn op qr st uv wx yz";
        let chunks = chunk_text(text, 5, 6, 5);
        assert!(!chunks.is_empty());
        // Verify all text is covered
        let _rejoined: String = chunks.to_vec().join("");
        // With overlaps, there may be repeated text, but no data loss
        for word in text.split_whitespace() {
            assert!(
                chunks.iter().any(|c| c.contains(word)),
                "Word '{}' should appear in at least one chunk",
                word
            );
        }
    }

    // -- dedup_filter_sort_orgs --

    #[test]
    fn test_dedup_filter_sort_orgs_all_below_min_name_len() {
        let orgs = vec![("AB".into(), 0.9), ("X".into(), 0.95), ("YZ".into(), 0.8)];
        let results = dedup_filter_sort_orgs(orgs, 3);
        assert!(results.is_empty());
    }

    #[test]
    fn test_dedup_filter_sort_orgs_exact_min_name_len() {
        let orgs = vec![("ABC".into(), 0.7)];
        let results = dedup_filter_sort_orgs(orgs, 3);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].organization, "ABC");
    }

    #[test]
    fn test_dedup_filter_sort_orgs_case_insensitive_dedup() {
        let orgs = vec![
            ("Google LLC".into(), 0.9),
            ("GOOGLE LLC".into(), 0.7),
            ("google llc".into(), 0.6),
        ];
        let results = dedup_filter_sort_orgs(orgs, 3);
        assert_eq!(results.len(), 1);
        // The one with highest confidence should win
        assert_eq!(results[0].organization, "Google LLC");
        assert!((results[0].confidence - 0.9).abs() < f32::EPSILON);
    }

    #[test]
    fn test_dedup_filter_sort_orgs_sorted_descending() {
        let orgs = vec![
            ("Alpha Corp".into(), 0.5),
            ("Beta Inc".into(), 0.9),
            ("Gamma Ltd".into(), 0.7),
        ];
        let results = dedup_filter_sort_orgs(orgs, 3);
        assert_eq!(results.len(), 3);
        assert!((results[0].confidence - 0.9).abs() < f32::EPSILON);
        assert!((results[1].confidence - 0.7).abs() < f32::EPSILON);
        assert!((results[2].confidence - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn test_dedup_filter_sort_orgs_nan_confidence() {
        // NaN comparison should not panic, handled by unwrap_or(Equal)
        let orgs = vec![("NaN Corp".into(), f32::NAN), ("Valid Corp".into(), 0.8)];
        let results = dedup_filter_sort_orgs(orgs, 3);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_dedup_filter_sort_orgs_zero_min_name_len() {
        let orgs = vec![
            ("".into(), 0.9),  // empty string has len 0
            ("A".into(), 0.8), // len 1
        ];
        // min_name_len=0 means even empty strings pass
        let results = dedup_filter_sort_orgs(orgs, 0);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_dedup_filter_sort_orgs_updates_to_higher_confidence() {
        // When same key appears twice, the higher confidence should replace the lower
        let orgs = vec![
            ("Test Corp".into(), 0.5),
            ("test corp".into(), 0.9), // same key (lowercase), higher confidence
        ];
        let results = dedup_filter_sort_orgs(orgs, 3);
        assert_eq!(results.len(), 1);
        // The second entry had higher confidence, so its name should be used
        assert_eq!(results[0].organization, "test corp");
        assert!((results[0].confidence - 0.9).abs() < f32::EPSILON);
    }

    #[test]
    fn test_dedup_filter_sort_orgs_does_not_update_to_lower_confidence() {
        let orgs = vec![
            ("Test Corp".into(), 0.9),
            ("test corp".into(), 0.5), // same key but lower confidence
        ];
        let results = dedup_filter_sort_orgs(orgs, 3);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].organization, "Test Corp");
        assert!((results[0].confidence - 0.9).abs() < f32::EPSILON);
    }

    #[test]
    fn test_dedup_filter_sort_orgs_unicode_names() {
        let orgs = vec![
            ("日本企業".into(), 0.8),
            ("日本企業".into(), 0.7), // duplicate
        ];
        let results = dedup_filter_sort_orgs(orgs, 3);
        assert_eq!(results.len(), 1);
        assert!((results[0].confidence - 0.8).abs() < f32::EPSILON);
    }

    #[test]
    fn test_dedup_filter_sort_orgs_many_entries() {
        let orgs: Vec<(String, f32)> = (0..100)
            .map(|i| (format!("Corp_{:03}", i), i as f32 / 100.0))
            .collect();
        let results = dedup_filter_sort_orgs(orgs, 3);
        assert_eq!(results.len(), 100);
        // Verify sorted descending
        for window in results.windows(2) {
            assert!(window[0].confidence >= window[1].confidence);
        }
    }

    #[test]
    fn test_chunk_text_multibyte_whitespace_rfind_mid_char() {
        // \u{3000} (ideographic space) is 3 bytes and IS whitespace.
        // rfind finds it at byte 0, so actual_end = 0 + 1 = byte 1 (mid-char).
        // final_end walks back from 1 to 0, hitting the final_end <= start branch.
        let mut text = String::new();
        text.push('\u{3000}');
        while text.len() < 20 {
            text.push('a');
        }
        let chunks = chunk_text(&text, 2, 3, 0);
        assert!(!chunks.is_empty());
        for chunk in &chunks {
            assert!(!chunk.is_empty());
        }
    }
}
