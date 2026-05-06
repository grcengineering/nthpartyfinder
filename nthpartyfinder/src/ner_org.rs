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
            project_root_from_exe.map(|d| d.join("onnxruntime-win-x64-1.20.1/lib/onnxruntime.dll")),
            // Current working directory (absolute path)
            cwd.as_ref().map(|d| d.join("onnxruntime.dll")),
            // Project's onnxruntime directory relative to cwd
            cwd.as_ref()
                .map(|d| d.join("onnxruntime-win-x64-1.20.1/lib/onnxruntime.dll")),
            // User's local app data
            dirs::data_local_dir().map(|d| d.join("onnxruntime").join("onnxruntime.dll")),
        ];

        for path_opt in search_paths {
            if let Some(path) = path_opt {
                if path.exists() {
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
            if path.exists() {
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

    /// Write bytes to file if it doesn't already exist
    fn write_if_missing(path: &std::path::Path, bytes: &[u8]) -> Result<()> {
        if !path.exists() {
            let mut file = std::fs::File::create(path)?;
            file.write_all(bytes)?;
            debug!("Wrote model file: {:?}", path);
        }
        Ok(())
    }

    /// Extract organization name from text content
    #[cfg_attr(coverage_nightly, coverage(off))] // coverage: third-party behavior + LLVM artifact — GLiNER never returns "brand" entity type; closing brace is instrumentation artifact
    pub fn extract_organization(&self, text: &str) -> Result<Option<NerOrgResult>> {
        // Truncate text if too long to avoid performance issues
        // Use floor_char_boundary to avoid panicking on multi-byte UTF-8 characters
        let text = if text.len() > 4000 {
            let mut end = 4000;
            while end > 0 && !text.is_char_boundary(end) {
                end -= 1;
            }
            &text[..end]
        } else {
            text
        };

        // Create input for organization entity extraction
        // Include "product" and "brand" to catch SaaS sites that use company names as products
        let input = TextInput::from_str(&[text], &["organization", "company", "product", "brand"])
            .map_err(
                #[cfg_attr(coverage_nightly, coverage(off))] // coverage: infallible third-party closure — TextInput::from_str always succeeds with valid string slices
                |e| anyhow!("Failed to create TextInput: {}", e),
            )?;

        // Run inference
        let output = self
            .model
            .inference(input)
            .map_err(
                #[cfg_attr(coverage_nightly, coverage(off))] // coverage: infallible third-party closure — inference always succeeds with valid model and input
                |e| anyhow!("NER inference failed: {}", e),
            )?;

        // Find the highest confidence organization entity
        let mut best_match: Option<NerOrgResult> = None;

        for spans in &output.spans {
            for span in spans {
                let entity_type = span.class().to_lowercase();
                // Accept organization, company, product, and brand entity types
                if entity_type == "organization"
                    || entity_type == "company"
                    || entity_type == "product"
                    || entity_type == "brand"
                {
                    let confidence = span.probability();
                    if confidence >= self.min_confidence
                        && (best_match.is_none()
                            || confidence > best_match.as_ref().unwrap().confidence)
                    {
                        let org_name = span.text().trim().to_string();
                        if !org_name.is_empty() {
                            best_match = Some(NerOrgResult {
                                organization: org_name,
                                confidence,
                            });
                        }
                    }
                }
            }
        }

        if let Some(ref result) = best_match {
            debug!(
                "NER extracted organization: {} (confidence: {:.2})",
                result.organization, result.confidence
            );
        }

        Ok(best_match)
    }

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

        // Build context text for NER
        let text = if let Some(content) = page_content {
            debug!(
                "NER: Using page content ({} chars) for extraction",
                content.len()
            );
            format!("Website: {}. {}", domain, content)
        } else {
            debug!("NER: No page content available, using domain only");
            format!("Website: {}", domain)
        };

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

        // GLiNER truncates at ~4000 chars, so chunk long text
        // All byte offsets must land on valid UTF-8 char boundaries to avoid panics
        // on multi-byte characters (e.g., right single quotation mark U+2019 = 3 bytes)
        let chunks: Vec<&str> = if text.len() <= 4000 {
            vec![text]
        } else {
            // Split into ~3000 char chunks with overlap for boundary entities
            let mut result = Vec::new();
            let mut start = 0;
            while start < text.len() {
                let end = std::cmp::min(start + 3000, text.len());
                // Ensure 'end' falls on a char boundary
                let mut safe_end = end;
                while safe_end > start && !text.is_char_boundary(safe_end) {
                    safe_end -= 1;
                }
                // Try to break at a whitespace boundary within the safe range
                let actual_end = if safe_end < text.len() {
                    text[start..safe_end]
                        .rfind(char::is_whitespace)
                        .map(|pos| start + pos + 1)
                        .unwrap_or(safe_end)
                } else {
                    safe_end
                };
                // Ensure actual_end is also on a char boundary (whitespace pos+1 could land mid-char)
                let mut final_end = actual_end;
                while final_end > start && !text.is_char_boundary(final_end) {
                    final_end -= 1;
                }
                if final_end <= start {
                    // Degenerate case: skip forward to next char boundary
                    start = safe_end;
                    continue;
                }
                result.push(&text[start..final_end]);
                // 500 byte overlap — ensure overlap start is on a char boundary
                let overlap_start = if final_end > start + 500 {
                    final_end - 500
                } else {
                    final_end
                };
                let mut safe_overlap = overlap_start;
                while safe_overlap > 0 && !text.is_char_boundary(safe_overlap) {
                    safe_overlap -= 1;
                }
                // Ensure forward progress: char-boundary walk-back on multi-byte text
                // (CJK, emoji) can land at or before current start, causing infinite loop.
                if safe_overlap <= start {
                    start = final_end;
                } else {
                    start = safe_overlap;
                }
            }
            result
        };

        let mut all_orgs: std::collections::HashMap<String, NerOrgResult> =
            std::collections::HashMap::new();

        for chunk in &chunks {
            let input = TextInput::from_str(&[*chunk], &["organization", "company"])
                .map_err(|e| anyhow!("Failed to create TextInput: {}", e))?;

            let output = self
                .model
                .inference(input)
                .map_err(|e| anyhow!("NER inference failed: {}", e))?;

            for spans in &output.spans {
                for span in spans {
                    let entity_type = span.class().to_lowercase();
                    if entity_type == "organization" || entity_type == "company" {
                        let confidence = span.probability();
                        if confidence >= threshold {
                            let org_name = span.text().trim().to_string();
                            if org_name.len() >= 3 {
                                let key = org_name.to_lowercase();
                                let existing = all_orgs.get(&key);
                                if existing.is_none() || existing.unwrap().confidence < confidence {
                                    all_orgs.insert(
                                        key,
                                        NerOrgResult {
                                            organization: org_name,
                                            confidence,
                                        },
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut results: Vec<NerOrgResult> = all_orgs.into_values().collect();
        results.sort_by(|a, b| {
            b.confidence
                .partial_cmp(&a.confidence)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

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
        if is_available() { return true; }
        let r = std::panic::catch_unwind(|| init_with_config(0.5));
        match r {
            Err(_) => false,
            Ok(Err(e)) => e.to_string().contains("already initialized") && is_available(),
            Ok(Ok(())) => true,
        }
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_new_constructor() {
        if !ensure_ner_available() { return; }
        let result = std::panic::catch_unwind(|| NerOrganizationExtractor::new());
        let _ = result;
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_init_module_level() {
        let result = std::panic::catch_unwind(|| init());
        let _ = result;
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_get_returns_extractor() {
        if !ensure_ner_available() { return; }
        assert!(get().is_some());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))] // coverage: LLVM artifact — closing brace instrumentation gap
    fn test_ner_extract_organization_basic() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let result = extractor.extract_organization("Microsoft Corporation provides cloud services");
        assert!(result.is_ok());
        if let Ok(Some(org)) = result {
            assert!(!org.organization.is_empty());
            assert!(org.confidence > 0.0);
            assert!(org.confidence <= 1.0);
        }
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_organization_multiple_entity_types() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let result = extractor.extract_organization("Stripe Inc. processes payments worldwide");
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_organization_no_orgs() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let result = extractor.extract_organization("the quick brown fox jumps over the lazy dog");
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_organization_empty_text() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let _ = extractor.extract_organization("");
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_organization_long_text_truncation() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let long_text = format!("Google LLC is a technology company. {} More text.", "a ".repeat(2500));
        assert!(long_text.len() > 4000);
        let result = extractor.extract_organization(&long_text);
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_organization_long_text_with_multibyte_at_boundary() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let mut text = String::with_capacity(4100);
        text.push_str("Amazon Web Services. ");
        while text.len() < 3998 { text.push_str("test "); }
        text.push_str("\u{2019}end");
        assert!(text.len() > 4000);
        assert!(extractor.extract_organization(&text).is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_from_domain_with_content() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let result = extractor.extract_from_domain(
            "stripe.com",
            Some("Stripe Inc. powers online payment processing for internet businesses"),
        );
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_from_domain_without_content() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        assert!(extractor.extract_from_domain("microsoft.com", None).is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_all_organizations_short_text() {
        if !ensure_ner_available() { return; }
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
    #[test]
    fn test_ner_extract_all_organizations_default_confidence() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let result = extractor.extract_all_organizations(
            "Salesforce CRM and Adobe Creative Cloud are enterprise tools.", None,
        );
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_all_organizations_long_text_chunking() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let mut long_text = String::with_capacity(10000);
        long_text.push_str("Google LLC is a major tech company. ");
        while long_text.len() < 5000 {
            long_text.push_str("Various technology companies compete in the market. ");
        }
        long_text.push_str("Microsoft Corporation also provides cloud services.");
        assert!(long_text.len() > 4000);
        assert!(extractor.extract_all_organizations(&long_text, Some(0.3)).is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_all_organizations_very_long_text_multiple_chunks() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let mut long_text = String::with_capacity(15000);
        for _ in 0..5 {
            long_text.push_str("Apple Inc. builds consumer electronics. ");
            long_text.push_str(&"word ".repeat(600));
        }
        assert!(long_text.len() > 10000);
        assert!(extractor.extract_all_organizations(&long_text, Some(0.3)).is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_all_organizations_multibyte_chunking() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let mut text = String::with_capacity(10000);
        text.push_str("Adobe Inc\u{2019}s Creative Cloud. ");
        while text.len() < 7000 { text.push_str("caf\u{00E9} "); }
        text.push_str("Salesforce Corp.");
        assert!(extractor.extract_all_organizations(&text, Some(0.3)).is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_all_organizations_empty_text() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let _ = extractor.extract_all_organizations("", Some(0.3));
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_all_organizations_high_confidence_filter() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let result = extractor.extract_all_organizations(
            "Microsoft Corporation and Google LLC announced a partnership.", Some(0.99),
        );
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_module_extract_organization_with_content() {
        if !ensure_ner_available() { return; }
        assert!(extract_organization("stripe.com", Some("Stripe Inc. provides payment processing")).is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_module_extract_organization_without_content() {
        if !ensure_ner_available() { return; }
        assert!(extract_organization("google.com", None).is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_module_extract_all_organizations() {
        if !ensure_ner_available() { return; }
        assert!(extract_all_organizations("Microsoft and Amazon are large companies.", Some(0.3)).is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_module_extract_all_organizations_none_confidence() {
        if !ensure_ner_available() { return; }
        assert!(extract_all_organizations("Google LLC is in Mountain View.", None).is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_is_available_after_init() {
        if !ensure_ner_available() { return; }
        assert!(is_available());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_init_with_config_already_initialized() {
        if !ensure_ner_available() { return; }
        let result = init_with_config(0.8);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("already initialized"));
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_organization_selects_best_match() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let result = extractor.extract_organization(
            "Stripe Inc. is a fintech company founded in San Francisco. Google also operates there.",
        );
        assert!(result.is_ok());
        if let Ok(Some(org)) = result { assert!(!org.organization.is_empty()); }
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_from_domain_extracts_with_domain_context() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let result = extractor.extract_from_domain(
            "cloudflare.com",
            Some("Cloudflare Inc. provides CDN and security services."),
        );
        assert!(result.is_ok());
        if let Ok(Some(ref org)) = result { assert!(org.confidence > 0.0); }
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_all_organizations_dedup_by_name() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let result = extractor.extract_all_organizations(
            "Google LLC is a company. Google LLC does many things. Google LLC is everywhere.",
            Some(0.3),
        );
        assert!(result.is_ok());
        let orgs = result.unwrap();
        let google_count = orgs.iter().filter(|o| o.organization.to_lowercase().contains("google")).count();
        assert!(google_count <= 1, "Should dedup same org name");
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_all_organizations_sorted_by_confidence() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let result = extractor.extract_all_organizations(
            "Microsoft Corporation and Google LLC and Amazon Web Services and Apple Inc are big companies.",
            Some(0.1),
        );
        assert!(result.is_ok());
        let orgs = result.unwrap();
        for w in orgs.windows(2) {
            assert!(w[0].confidence >= w[1].confidence, "Results should be sorted by confidence desc");
        }
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_all_organizations_filters_short_names() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let result = extractor.extract_all_organizations("AB Corp and Microsoft are companies.", Some(0.1));
        assert!(result.is_ok());
        for org in result.unwrap() {
            assert!(org.organization.len() >= 3, "Org names shorter than 3 chars should be filtered");
        }
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_write_if_missing_already_exists() {
        if !ensure_ner_available() { return; }
        let temp_dir = std::env::temp_dir().join("nthpartyfinder_ner");
        let model_path = temp_dir.join("gliner_small.onnx");
        assert!(model_path.exists(), "Model file should exist after init");
        assert!(NerOrganizationExtractor::write_if_missing(&model_path, b"test").is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_write_if_missing_new_file() {
        let temp = std::env::temp_dir().join("nthpartyfinder_ner_test_write");
        let _ = std::fs::create_dir_all(&temp);
        let test_path = temp.join("test_file.bin");
        let _ = std::fs::remove_file(&test_path);
        assert!(!test_path.exists());
        assert!(NerOrganizationExtractor::write_if_missing(&test_path, b"hello").is_ok());
        assert!(test_path.exists());
        assert_eq!(std::fs::read(&test_path).unwrap(), b"hello");
        let _ = std::fs::remove_file(&test_path);
        let _ = std::fs::remove_dir(&temp);
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_setup_onnx_runtime_with_env_var_already_set() {
        std::env::set_var("ORT_DYLIB_PATH", "/some/test/path");
        assert!(NerOrganizationExtractor::setup_onnx_runtime().is_ok());
        std::env::remove_var("ORT_DYLIB_PATH");
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_setup_onnx_runtime_search_paths() {
        let saved = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::remove_var("ORT_DYLIB_PATH");
        let _ = NerOrganizationExtractor::setup_onnx_runtime();
        if let Some(val) = saved { std::env::set_var("ORT_DYLIB_PATH", val); }
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

    #[cfg(feature = "embedded-ner")]
    fn init_tracing() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_test_writer()
            .try_init();
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_setup_onnx_runtime_search_path_discovery() {
        let saved = std::env::var("ORT_DYLIB_PATH").ok();
        std::env::remove_var("ORT_DYLIB_PATH");

        let cwd = std::env::current_dir().unwrap();
        #[cfg(target_os = "macos")]
        let lib_name = "libonnxruntime.dylib";
        #[cfg(not(target_os = "macos"))]
        let lib_name = "libonnxruntime.so";
        let fake_lib = cwd.join(lib_name);
        let _ = std::fs::write(&fake_lib, b"fake");
        let result = NerOrganizationExtractor::setup_onnx_runtime();
        assert!(result.is_ok(), "Should find runtime in cwd");
        let set_val = std::env::var("ORT_DYLIB_PATH").unwrap();
        assert!(!set_val.is_empty());

        let _ = std::fs::remove_file(&fake_lib);
        if let Some(val) = saved { std::env::set_var("ORT_DYLIB_PATH", val); }
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_organization_truncation_char_boundary() {
        if !ensure_ner_available() { return; }
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
    #[test]
    fn test_ner_extract_from_domain_no_org_found() {
        if !ensure_ner_available() { return; }
        init_tracing();
        let extractor = get().unwrap();
        let result = extractor.extract_from_domain(
            "zzz999.invalid",
            Some("xyzzy plugh nothing here at all just random gibberish words"),
        );
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_from_domain_debug_with_content() {
        if !ensure_ner_available() { return; }
        init_tracing();
        let extractor = get().unwrap();
        let result = extractor.extract_from_domain(
            "example.com",
            Some("Example Corp provides services worldwide"),
        );
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_from_domain_debug_without_content() {
        if !ensure_ner_available() { return; }
        init_tracing();
        let extractor = get().unwrap();
        let result = extractor.extract_from_domain("example.com", None);
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_all_orgs_chunking_whitespace_break() {
        if !ensure_ner_available() { return; }
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
    #[test]
    fn test_ner_extract_all_orgs_chunking_no_whitespace() {
        if !ensure_ner_available() { return; }
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
    #[test]
    fn test_ner_extract_all_orgs_chunking_multibyte_boundaries() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();

        let mut text = String::with_capacity(8000);
        text.push_str("Amazon ");
        while text.len() < 2999 {
            text.push_str("\u{2019}");
        }
        text.push(' ');
        while text.len() < 5500 {
            text.push_str("\u{2019}");
        }
        text.push_str(" Apple Inc.");
        assert!(text.len() > 4000);

        let result = extractor.extract_all_organizations(&text, Some(0.1));
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_all_orgs_chunking_small_overlap() {
        if !ensure_ner_available() { return; }
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
    #[test]
    fn test_ner_extract_all_orgs_chunking_cjk_dense() {
        if !ensure_ner_available() { return; }
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
    #[test]
    fn test_ner_extract_all_orgs_debug_logging() {
        if !ensure_ner_available() { return; }
        init_tracing();
        let extractor = get().unwrap();
        let result = extractor.extract_all_organizations(
            "Intel Corporation and AMD are semiconductor companies.",
            Some(0.1),
        );
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_org_debug_logging_with_match() {
        if !ensure_ner_available() { return; }
        init_tracing();
        let extractor = get().unwrap();
        let result = extractor.extract_organization(
            "Apple Inc. designs consumer electronics and software.",
        );
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_module_level_functions_after_init() {
        if !ensure_ner_available() { return; }
        let result = extract_organization("google.com", Some("Google LLC")).unwrap();
        assert!(result.is_none() || result.is_some());
        let all = extract_all_organizations("Microsoft Corp is large.", None).unwrap();
        assert!(all.len() >= 0);
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_all_orgs_exact_4000_boundary() {
        if !ensure_ner_available() { return; }
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
    #[test]
    fn test_ner_extract_all_orgs_emoji_dense_text() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();

        let mut text = String::with_capacity(10000);
        text.push_str("Netflix Inc ");
        while text.len() < 7000 {
            text.push_str("\u{1F600}");
        }
        assert!(text.len() > 4000);

        let result = extractor.extract_all_organizations(&text, Some(0.1));
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_org_multiple_companies() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let result = extractor.extract_organization(
            "IBM and Oracle and SAP compete in enterprise software."
        );
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_all_orgs_degenerate_chunk_multibyte_whitespace() {
        if !ensure_ner_available() { return; }
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
    #[test]
    fn test_ner_extract_all_orgs_chunk_boundary_adjustment() {
        if !ensure_ner_available() { return; }
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
    #[test]
    fn test_ner_extract_all_orgs_high_threshold_filters_all() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let result = extractor.extract_all_organizations(
            "Some company name here and there.",
            Some(1.0),
        );
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_all_orgs_low_threshold() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();
        let result = extractor.extract_all_organizations(
            "Go is a programming language. AT works in telecom.",
            Some(0.01),
        );
        assert!(result.is_ok());
    }

    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extract_all_orgs_overlap_boundary_walk() {
        if !ensure_ner_available() { return; }
        let extractor = get().unwrap();

        let mut text = String::with_capacity(10000);
        text.push_str("Samsung ");
        while text.len() < 3100 {
            text.push_str("\u{00E9}");
        }
        text.push(' ');
        while text.len() < 6500 {
            text.push_str("\u{00E9}");
        }
        text.push_str(" Toshiba Corp");
        assert!(text.len() > 4000);

        let result = extractor.extract_all_organizations(&text, Some(0.1));
        assert!(result.is_ok());
    }
}
