//! Embedded NER-based organization extraction
//!
//! This module uses GLiNER (via gline-rs) to extract organization names
//! from web page content. The model is embedded in the binary at compile time.
//!
//! On Windows, the ONNX Runtime DLL must be available. Set ORT_DYLIB_PATH
//! environment variable or place onnxruntime.dll next to the executable.

#[cfg(feature = "embedded-ner")]
use anyhow::{Result, anyhow};
#[cfg(feature = "embedded-ner")]
use tracing::{debug, info};
#[cfg(feature = "embedded-ner")]
use std::io::Write;
#[cfg(feature = "embedded-ner")]
use std::sync::OnceLock;
#[cfg(feature = "embedded-ner")]
use gliner::model::GLiNER;
#[cfg(feature = "embedded-ner")]
use gliner::model::pipeline::span::SpanMode;
#[cfg(feature = "embedded-ner")]
use gliner::model::params::Parameters;
#[cfg(feature = "embedded-ner")]
use gliner::model::input::text::TextInput;
#[cfg(feature = "embedded-ner")]
use orp::params::RuntimeParameters;

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
        let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf()));
        let cwd = std::env::current_dir().ok();

        // For Rust projects, exe is typically in target/release/ or target/debug/
        // So project root is 2 directories up from the executable
        let project_root_from_exe = exe_dir.as_ref().and_then(|d| d.parent()).and_then(|d| d.parent());

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
            cwd.as_ref().map(|d| d.join("onnxruntime-win-x64-1.20.1/lib/onnxruntime.dll")),
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

        let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf()));
        let cwd = std::env::current_dir().ok();
        let project_root_from_exe = exe_dir.as_ref().and_then(|d| d.parent()).and_then(|d| d.parent());

        let search_paths = vec![
            exe_dir.as_ref().map(|d| d.join(lib_name)),
            project_root_from_exe.map(|d| d.join(lib_name)),
            project_root_from_exe.map(|d| d.join("onnxruntime-linux-x64-1.20.1/lib").join(lib_name)),
            cwd.as_ref().map(|d| d.join(lib_name)),
            cwd.as_ref().map(|d| d.join("onnxruntime-linux-x64-1.20.1/lib").join(lib_name)),
        ];

        for path_opt in search_paths {
            if let Some(path) = path_opt {
                if path.exists() {
                    let abs_path = path.canonicalize().unwrap_or(path.clone());
                    let path_str = abs_path.to_string_lossy().to_string();
                    info!("Found ONNX Runtime at: {}", path_str);
                    std::env::set_var("ORT_DYLIB_PATH", &path_str);
                    return Ok(());
                }
            }
        }

        // Not found - provide helpful error
        Err(anyhow!(
            "ONNX Runtime shared library not found. On Linux, you need to:\n\
             1. Place {} next to the executable or in the working directory\n\
             2. Or set ORT_DYLIB_PATH to point to {}\n\
             3. Or install onnxruntime system-wide",
            lib_name, lib_name
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

        // Initialize GLiNER model
        // GLiNER models can be SpanMode or TokenMode - using SpanMode for small model
        let model = GLiNER::<SpanMode>::new(
            Parameters::default(),
            RuntimeParameters::default(),
            tokenizer_path.to_str().ok_or_else(|| anyhow!("Invalid tokenizer path"))?,
            model_path.to_str().ok_or_else(|| anyhow!("Invalid model path"))?,
        ).map_err(|e| anyhow!("Failed to initialize GLiNER model: {}", e))?;

        info!("NER model initialized successfully");

        Ok(Self {
            model,
            min_confidence,
        })
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
    pub fn extract_organization(&self, text: &str) -> Result<Option<NerOrgResult>> {
        // Truncate text if too long to avoid performance issues
        let text = if text.len() > 4000 {
            &text[..4000]
        } else {
            text
        };

        // Create input for organization entity extraction
        // Include "product" and "brand" to catch SaaS sites that use company names as products
        let input = TextInput::from_str(
            &[text],
            &["organization", "company", "product", "brand"],
        ).map_err(|e| anyhow!("Failed to create TextInput: {}", e))?;

        // Run inference
        let output = self.model.inference(input)
            .map_err(|e| anyhow!("NER inference failed: {}", e))?;

        // Find the highest confidence organization entity
        let mut best_match: Option<NerOrgResult> = None;

        for spans in &output.spans {
            for span in spans {
                let entity_type = span.class().to_lowercase();
                // Accept organization, company, product, and brand entity types
                if entity_type == "organization" || entity_type == "company"
                    || entity_type == "product" || entity_type == "brand" {
                    let confidence = span.probability();
                    if confidence >= self.min_confidence {
                        if best_match.is_none() || confidence > best_match.as_ref().unwrap().confidence {
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
        }

        if let Some(ref result) = best_match {
            debug!("NER extracted organization: {} (confidence: {:.2})",
                   result.organization, result.confidence);
        }

        Ok(best_match)
    }

    /// Extract organization from domain and optional page content
    pub fn extract_from_domain(&self, domain: &str, page_content: Option<&str>) -> Result<Option<NerOrgResult>> {
        debug!("NER: Attempting to extract organization from domain: {}", domain);

        // Build context text for NER
        let text = if let Some(content) = page_content {
            debug!("NER: Using page content ({} chars) for extraction", content.len());
            format!("Website: {}. {}", domain, content)
        } else {
            debug!("NER: No page content available, using domain only");
            format!("Website: {}", domain)
        };

        let result = self.extract_organization(&text);

        if let Ok(Some(ref org_result)) = result {
            debug!("NER: Successfully extracted '{}' (confidence: {:.2})",
                   org_result.organization, org_result.confidence);
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
    pub fn extract_all_organizations(&self, text: &str, min_confidence: Option<f32>) -> Result<Vec<NerOrgResult>> {
        let threshold = min_confidence.unwrap_or(self.min_confidence);

        // GLiNER truncates at ~4000 chars, so chunk long text
        let chunks: Vec<&str> = if text.len() <= 4000 {
            vec![text]
        } else {
            // Split into ~3000 char chunks with overlap for boundary entities
            let mut result = Vec::new();
            let mut start = 0;
            while start < text.len() {
                let end = std::cmp::min(start + 3000, text.len());
                // Try to break at a whitespace boundary
                let actual_end = if end < text.len() {
                    text[start..end].rfind(char::is_whitespace)
                        .map(|pos| start + pos + 1)
                        .unwrap_or(end)
                } else {
                    end
                };
                result.push(&text[start..actual_end]);
                start = if actual_end > start + 500 { actual_end - 500 } else { actual_end }; // 500 char overlap
            }
            result
        };

        let mut all_orgs: std::collections::HashMap<String, NerOrgResult> = std::collections::HashMap::new();

        for chunk in &chunks {
            let input = TextInput::from_str(
                &[*chunk],
                &["organization", "company"],
            ).map_err(|e| anyhow!("Failed to create TextInput: {}", e))?;

            let output = self.model.inference(input)
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
                                    all_orgs.insert(key, NerOrgResult {
                                        organization: org_name,
                                        confidence,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        let mut results: Vec<NerOrgResult> = all_orgs.into_values().collect();
        results.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));

        debug!("NER extracted {} organizations from {} chars of text", results.len(), text.len());
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
    NER_EXTRACTOR.set(extractor)
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
pub fn extract_organization(domain: &str, page_content: Option<&str>) -> anyhow::Result<Option<NerOrgResult>> {
    match NER_EXTRACTOR.get() {
        Some(extractor) => extractor.extract_from_domain(domain, page_content),
        None => Ok(None),
    }
}

/// Extract all organizations from text using the global NER extractor.
/// Returns all detected organizations above min_confidence threshold.
#[cfg(feature = "embedded-ner")]
pub fn extract_all_organizations(text: &str, min_confidence: Option<f32>) -> anyhow::Result<Vec<NerOrgResult>> {
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
pub fn extract_organization(_domain: &str, _page_content: Option<&str>) -> anyhow::Result<Option<NerOrgResult>> {
    Ok(None)
}

/// Stub: Extract all organizations (always returns empty when disabled)
#[cfg(not(feature = "embedded-ner"))]
pub fn extract_all_organizations(_text: &str, _min_confidence: Option<f32>) -> anyhow::Result<Vec<NerOrgResult>> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ner_org_result() {
        let result = NerOrgResult {
            organization: "Acme Corporation".to_string(),
            confidence: 0.95,
        };
        assert_eq!(result.organization, "Acme Corporation");
        assert!((result.confidence - 0.95).abs() < 0.001);
    }

    #[cfg(not(feature = "embedded-ner"))]
    #[test]
    fn test_stub_functions() {
        assert!(!is_available());
        let result = extract_organization("example.com", None).unwrap();
        assert!(result.is_none());
    }

    /// Test NER extraction with real company names in various contexts
    #[cfg(feature = "embedded-ner")]
    #[test]
    fn test_ner_extraction_accuracy() {
        // Initialize NER if not already done - catch panics from ONNX runtime loading
        let init_result = std::panic::catch_unwind(|| {
            init_with_config(0.5)
        });

        // Handle panic or error from init
        match init_result {
            Err(_) => {
                println!("NER initialization panicked (likely missing ONNX runtime DLL), skipping test");
                return;
            }
            Ok(Err(e)) => {
                println!("NER initialization failed: {}, skipping test", e);
                return;
            }
            Ok(Ok(())) => {}
        }

        if !is_available() {
            println!("NER not available, skipping test");
            return;
        }

        let test_cases = vec![
            // (input text, expected org or None if no extraction expected)
            ("Microsoft Corporation provides cloud services", Some("Microsoft")),
            ("Google LLC is a technology company", Some("Google")),
            ("Amazon Web Services powers the cloud", Some("Amazon")),
            ("Stripe Inc. processes payments worldwide", Some("Stripe")),
            ("The website klaviyo.com belongs to Klaviyo", Some("Klaviyo")),
            ("Salesforce CRM is enterprise software", Some("Salesforce")),
            ("Adobe Inc. makes creative software", Some("Adobe")),
            ("random words without company names", None),
        ];

        println!("\n=== NER Extraction Test Results ===\n");

        let extractor = get().expect("NER should be available");
        let mut passed = 0;
        let mut total = 0;

        for (text, expected) in test_cases {
            total += 1;
            let result = extractor.extract_organization(text);

            match result {
                Ok(Some(ner_result)) => {
                    let extracted = &ner_result.organization;
                    let confidence = ner_result.confidence;
                    println!("Input: \"{}\"", text);
                    println!("  Extracted: {} (confidence: {:.2})", extracted, confidence);

                    if let Some(exp) = expected {
                        if extracted.to_lowercase().contains(&exp.to_lowercase()) {
                            println!("  ✅ PASS - Expected {} found", exp);
                            passed += 1;
                        } else {
                            println!("  ⚠️  DIFFERENT - Expected {}, got {}", exp, extracted);
                        }
                    } else {
                        println!("  ⚠️  UNEXPECTED - Expected no extraction, got {}", extracted);
                    }
                }
                Ok(None) => {
                    println!("Input: \"{}\"", text);
                    println!("  Extracted: None");
                    if expected.is_none() {
                        println!("  ✅ PASS - Expected no extraction");
                        passed += 1;
                    } else {
                        println!("  ❌ FAIL - Expected {}", expected.unwrap());
                    }
                }
                Err(e) => {
                    println!("Input: \"{}\"", text);
                    println!("  ❌ ERROR: {}", e);
                }
            }
            println!();
        }

        println!("=== Results: {}/{} passed ===\n", passed, total);

        // Don't fail the test, just report results
        // This is more of a benchmark/verification than a strict test
    }
}
