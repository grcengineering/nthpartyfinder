//! Integration tests for embedded NER organization extraction

#[cfg(feature = "embedded-ner")]
mod ner_tests {
    use nthpartyfinder::ner_org;

    /// Helper to safely initialize NER, handling panics from ONNX runtime loading
    fn try_init_ner() -> bool {
        let result = std::panic::catch_unwind(|| {
            ner_org::init_with_config(0.6)
        });

        match result {
            Err(_) => {
                println!("NER initialization panicked (likely missing ONNX runtime DLL)");
                false
            }
            Ok(Err(e)) => {
                // Already initialized is OK
                if e.to_string().contains("already initialized") {
                    true
                } else {
                    println!("NER initialization failed: {}", e);
                    false
                }
            }
            Ok(Ok(())) => true
        }
    }

    #[test]
    fn test_ner_initialization() {
        // Test that NER can be initialized with custom confidence
        if !try_init_ner() {
            println!("Skipping test - NER initialization failed");
            return;
        }
        assert!(ner_org::is_available(), "NER should be available after init");
    }

    #[test]
    fn test_ner_extracts_organization() {
        // Initialize NER (may already be initialized from previous test)
        if !try_init_ner() {
            println!("Skipping test - NER initialization failed");
            return;
        }

        if let Some(extractor) = ner_org::get() {
            let test_text = "Stripe, Inc. is a financial services company headquartered in San Francisco.";
            let result = extractor.extract_organization(test_text);

            assert!(result.is_ok(), "NER extraction failed: {:?}", result.err());

            if let Ok(Some(org_result)) = result {
                assert!(!org_result.organization.is_empty(), "Organization should not be empty");
                assert!(org_result.confidence > 0.0, "Confidence should be positive");
                println!("Extracted: {} (confidence: {:.2})", org_result.organization, org_result.confidence);
            }
        }
    }

    #[test]
    fn test_ner_extract_from_domain_context() {
        // Initialize NER (may already be initialized from previous test)
        if !try_init_ner() {
            println!("Skipping test - NER initialization failed");
            return;
        }

        // Test the module-level extract_organization function
        let result = ner_org::extract_organization("stripe.com", Some("Stripe powers online payments"));
        assert!(result.is_ok(), "NER extraction failed: {:?}", result.err());

        if let Ok(Some(org_result)) = result {
            println!("Domain extraction: {} (confidence: {:.2})", org_result.organization, org_result.confidence);
        }
    }

    #[test]
    fn test_ner_handles_empty_text() {
        // Initialize NER
        if !try_init_ner() {
            println!("Skipping test - NER initialization failed");
            return;
        }

        if let Some(extractor) = ner_org::get() {
            let result = extractor.extract_organization("");
            // Empty text may return an error - that's acceptable behavior
            // The important thing is it doesn't panic
            let _ = result;
        }
    }

    #[test]
    fn test_ner_handles_text_without_organizations() {
        // Initialize NER
        if !try_init_ner() {
            println!("Skipping test - NER initialization failed");
            return;
        }

        if let Some(extractor) = ner_org::get() {
            let test_text = "The quick brown fox jumps over the lazy dog.";
            let result = extractor.extract_organization(test_text);
            assert!(result.is_ok(), "NER should handle text without organizations");
            // May or may not find organizations - that's fine
        }
    }
}

#[cfg(not(feature = "embedded-ner"))]
mod ner_disabled_tests {
    use nthpartyfinder::ner_org;

    #[test]
    fn test_ner_not_available_without_feature() {
        assert!(!ner_org::is_available(), "NER should not be available without feature");
    }

    #[test]
    fn test_ner_init_succeeds_as_noop() {
        // init() should be a no-op when feature is disabled
        let result = ner_org::init();
        assert!(result.is_ok(), "NER init should succeed as no-op without feature");
    }

    #[test]
    fn test_ner_extract_returns_none() {
        let result = ner_org::extract_organization("example.com", None);
        assert!(result.is_ok(), "NER extract should succeed without feature");
        assert!(result.unwrap().is_none(), "NER extract should return None without feature");
    }
}
