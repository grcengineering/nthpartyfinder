//! HTML Report Generation Tests
//!
//! Tests for the HTML report template functionality including:
//! - CSS selector escaping for record-type badges
//! - Askama whitespace trimming in conditional blocks
//! - ARIA accessibility attributes
//! - JavaScript function presence
//! - Pagination and export functionality

use nthpartyfinder::vendor::{VendorRelationship, RecordType};
use nthpartyfinder::export::export_html;
use std::fs;
use tempfile::tempdir;

/// Helper function to create test vendor relationships
fn create_test_relationships() -> Vec<VendorRelationship> {
    vec![
        VendorRelationship {
            root_customer_domain: "example.com".to_string(),
            root_customer_organization: "Example Inc.".to_string(),
            nth_party_domain: "mailprovider.com".to_string(),
            nth_party_organization: "Mail Provider Inc.".to_string(),
            nth_party_layer: 1,
            nth_party_customer_domain: "example.com".to_string(),
            nth_party_customer_organization: "Example Inc.".to_string(),
            nth_party_record: "mailprovider.com".to_string(),
            nth_party_record_type: RecordType::DnsTxtSpf,
            evidence: "v=spf1 include:mailprovider.com -all".to_string(),
        },
        VendorRelationship {
            root_customer_domain: "example.com".to_string(),
            root_customer_organization: "Example Inc.".to_string(),
            nth_party_domain: "google.com".to_string(),
            nth_party_organization: "Google Inc.".to_string(),
            nth_party_layer: 1,
            nth_party_customer_domain: "example.com".to_string(),
            nth_party_customer_organization: "Example Inc.".to_string(),
            nth_party_record: "google.com".to_string(),
            nth_party_record_type: RecordType::DnsTxtVerification,
            evidence: "google-site-verification=abc123".to_string(),
        },
        VendorRelationship {
            root_customer_domain: "example.com".to_string(),
            root_customer_organization: "Example Inc.".to_string(),
            nth_party_domain: "subprocessor.com".to_string(),
            nth_party_organization: "Subprocessor Inc.".to_string(),
            nth_party_layer: 1,
            nth_party_customer_domain: "example.com".to_string(),
            nth_party_customer_organization: "Example Inc.".to_string(),
            nth_party_record: "https://example.com/subprocessors".to_string(),
            nth_party_record_type: RecordType::HttpSubprocessor,
            evidence: "Listed on subprocessor page".to_string(),
        },
        VendorRelationship {
            root_customer_domain: "example.com".to_string(),
            root_customer_organization: "Example Inc.".to_string(),
            nth_party_domain: "dmarc-service.com".to_string(),
            nth_party_organization: "DMARC Service Inc.".to_string(),
            nth_party_layer: 1,
            nth_party_customer_domain: "example.com".to_string(),
            nth_party_customer_organization: "Example Inc.".to_string(),
            nth_party_record: "dmarc-service.com".to_string(),
            nth_party_record_type: RecordType::DnsTxtDmarc,
            evidence: "v=DMARC1; rua=mailto:dmarc@dmarc-service.com".to_string(),
        },
    ]
}

// =============================================================================
// CSS SELECTOR ESCAPING TESTS
// =============================================================================

#[test]
fn test_record_type_hierarchy_string_for_spf() {
    // RED: Test that RecordType::DnsTxtSpf produces correct hierarchy string
    let record_type = RecordType::DnsTxtSpf;
    assert_eq!(record_type.as_hierarchy_string(), "DNS::TXT::SPF");
}

#[test]
fn test_record_type_hierarchy_string_for_verification() {
    // RED: Test that RecordType::DnsTxtVerification produces correct hierarchy string
    let record_type = RecordType::DnsTxtVerification;
    assert_eq!(record_type.as_hierarchy_string(), "DNS::TXT::VERIFICATION");
}

#[test]
fn test_record_type_hierarchy_string_for_dmarc() {
    // RED: Test that RecordType::DnsTxtDmarc produces correct hierarchy string
    let record_type = RecordType::DnsTxtDmarc;
    assert_eq!(record_type.as_hierarchy_string(), "DNS::TXT::DMARC");
}

#[test]
fn test_record_type_hierarchy_string_for_subprocessor() {
    // RED: Test that RecordType::HttpSubprocessor produces correct hierarchy string
    let record_type = RecordType::HttpSubprocessor;
    assert_eq!(record_type.as_hierarchy_string(), "HTTP::SUBPROCESSOR");
}

#[test]
fn test_css_selector_escaping_in_html() {
    // RED: Test that CSS selectors for record types use single backslash escaping
    // The CSS selector .record-type-DNS\:\:TXT\:\:SPF should match class="record-type-DNS::TXT::SPF"
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships = create_test_relationships();

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    // CSS selectors should use single backslash escaping (in the source, shown as \:)
    // NOT double backslashes \\:
    assert!(
        html_content.contains(r".record-type-DNS\:\:TXT\:\:SPF"),
        "CSS selector for SPF should use single backslash escaping"
    );
    assert!(
        html_content.contains(r".record-type-DNS\:\:TXT\:\:VERIFICATION"),
        "CSS selector for VERIFICATION should use single backslash escaping"
    );
    assert!(
        html_content.contains(r".record-type-DNS\:\:TXT\:\:DMARC"),
        "CSS selector for DMARC should use single backslash escaping"
    );
    assert!(
        html_content.contains(r".record-type-HTTP\:\:SUBPROCESSOR"),
        "CSS selector for SUBPROCESSOR should use single backslash escaping"
    );

    // Should NOT contain double backslash escaping
    assert!(
        !html_content.contains(r".record-type-DNS\\:\"),
        "CSS selector should NOT use double backslash escaping"
    );
}

#[test]
fn test_html_class_names_without_escaping() {
    // RED: Test that HTML class attributes contain the raw record type string (no escaping)
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships = create_test_relationships();

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    // HTML class attributes should NOT have backslashes
    assert!(
        html_content.contains(r#"class="record-type-badge record-type-DNS::TXT::SPF""#),
        "HTML class for SPF should not have backslashes"
    );
    assert!(
        html_content.contains(r#"class="record-type-badge record-type-DNS::TXT::VERIFICATION""#),
        "HTML class for VERIFICATION should not have backslashes"
    );
}

// =============================================================================
// WHITESPACE TRIMMING TESTS
// =============================================================================

#[test]
fn test_no_excessive_whitespace_in_spf_table() {
    // RED: Test that the SPF table doesn't have excessive empty lines from Askama conditionals
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships = create_test_relationships();

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    // Find the SPF table section and check for excessive newlines
    if let Some(spf_start) = html_content.find(r#"id="spf-table""#) {
        if let Some(tbody_start) = html_content[spf_start..].find("<tbody>") {
            if let Some(tbody_end) = html_content[spf_start + tbody_start..].find("</tbody>") {
                let tbody_content = &html_content[spf_start + tbody_start..spf_start + tbody_start + tbody_end];

                // Count consecutive empty lines (more than 3 consecutive newlines is excessive)
                let excessive_whitespace = tbody_content.contains("\n\n\n\n\n");
                assert!(
                    !excessive_whitespace,
                    "SPF table should not have excessive whitespace (5+ consecutive newlines)"
                );
            }
        }
    }
}

#[test]
fn test_no_excessive_whitespace_in_verification_table() {
    // RED: Test that the verification table doesn't have excessive empty lines
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships = create_test_relationships();

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    // Find the verification table section and check for excessive newlines
    if let Some(start) = html_content.find(r#"id="verification-table""#) {
        if let Some(tbody_start) = html_content[start..].find("<tbody>") {
            if let Some(tbody_end) = html_content[start + tbody_start..].find("</tbody>") {
                let tbody_content = &html_content[start + tbody_start..start + tbody_start + tbody_end];

                let excessive_whitespace = tbody_content.contains("\n\n\n\n\n");
                assert!(
                    !excessive_whitespace,
                    "Verification table should not have excessive whitespace"
                );
            }
        }
    }
}

// =============================================================================
// ARIA ACCESSIBILITY TESTS
// =============================================================================

#[test]
fn test_tabs_have_aria_role_tablist() {
    // RED: Test that the tabs container has role="tablist"
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships = create_test_relationships();

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    assert!(
        html_content.contains(r#"role="tablist""#),
        "Tabs container should have role='tablist'"
    );
}

#[test]
fn test_tab_buttons_have_aria_role_tab() {
    // RED: Test that individual tab buttons have role="tab"
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships = create_test_relationships();

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    assert!(
        html_content.contains(r#"role="tab""#),
        "Tab buttons should have role='tab'"
    );
}

#[test]
fn test_tab_panels_have_aria_role_tabpanel() {
    // RED: Test that tab content panels have role="tabpanel"
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships = create_test_relationships();

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    assert!(
        html_content.contains(r#"role="tabpanel""#),
        "Tab panels should have role='tabpanel'"
    );
}

#[test]
fn test_active_tab_has_aria_selected_true() {
    // RED: Test that the active tab has aria-selected="true"
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships = create_test_relationships();

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    assert!(
        html_content.contains(r#"aria-selected="true""#),
        "Active tab should have aria-selected='true'"
    );
}

#[test]
fn test_tabs_have_aria_controls() {
    // RED: Test that tabs have aria-controls linking to their panels
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships = create_test_relationships();

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    assert!(
        html_content.contains(r#"aria-controls="all-tab""#),
        "Tab should have aria-controls='all-tab'"
    );
    assert!(
        html_content.contains(r#"aria-controls="summary-tab""#),
        "Tab should have aria-controls='summary-tab'"
    );
}

#[test]
fn test_search_boxes_have_aria_labels() {
    // RED: Test that search inputs have aria-label for screen readers
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships = create_test_relationships();

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    assert!(
        html_content.contains(r#"aria-label="Search all relationships""#),
        "All relationships search box should have aria-label"
    );
    assert!(
        html_content.contains(r#"aria-label="Search organizations""#),
        "Organizations search box should have aria-label"
    );
}

// =============================================================================
// JAVASCRIPT FUNCTIONALITY TESTS
// =============================================================================

#[test]
fn test_keyboard_navigation_handler_exists() {
    // RED: Test that handleTabKeydown function exists for keyboard navigation
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships = create_test_relationships();

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    assert!(
        html_content.contains("function handleTabKeydown"),
        "handleTabKeydown function should exist for keyboard navigation"
    );
}

#[test]
fn test_loading_overlay_functions_exist() {
    // RED: Test that loading state functions exist
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships = create_test_relationships();

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    assert!(
        html_content.contains("function showTableLoading"),
        "showTableLoading function should exist"
    );
    assert!(
        html_content.contains("function hideTableLoading"),
        "hideTableLoading function should exist"
    );
    assert!(
        html_content.contains("function initializeLoadingOverlays"),
        "initializeLoadingOverlays function should exist"
    );
}

#[test]
fn test_pagination_functions_exist() {
    // RED: Test that pagination functions exist
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships = create_test_relationships();

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    assert!(
        html_content.contains("function initializePagination"),
        "initializePagination function should exist"
    );
    assert!(
        html_content.contains("function goToPage"),
        "goToPage function should exist"
    );
    assert!(
        html_content.contains("function changePageSize"),
        "changePageSize function should exist"
    );
}

#[test]
fn test_csv_export_functions_exist() {
    // RED: Test that CSV export functions exist
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships = create_test_relationships();

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    assert!(
        html_content.contains("function exportTableToCSV"),
        "exportTableToCSV function should exist"
    );
    assert!(
        html_content.contains("function escapeCSVField"),
        "escapeCSVField function should exist"
    );
    assert!(
        html_content.contains("function addExportButton"),
        "addExportButton function should exist"
    );
}

#[test]
fn test_filter_count_function_exists() {
    // RED: Test that filter result count function exists
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships = create_test_relationships();

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    assert!(
        html_content.contains("function updateFilterCount"),
        "updateFilterCount function should exist"
    );
}

// =============================================================================
// CSS STYLES TESTS
// =============================================================================

#[test]
fn test_loading_overlay_css_exists() {
    // RED: Test that loading overlay CSS styles exist
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships = create_test_relationships();

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    assert!(
        html_content.contains(".table-loading-overlay"),
        "Loading overlay CSS should exist"
    );
    assert!(
        html_content.contains(".table-loading-overlay.active"),
        "Active loading overlay CSS should exist"
    );
}

#[test]
fn test_pagination_css_exists() {
    // RED: Test that pagination CSS styles exist
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships = create_test_relationships();

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    assert!(
        html_content.contains(".pagination"),
        "Pagination CSS should exist"
    );
    assert!(
        html_content.contains(".pagination-btn"),
        "Pagination button CSS should exist"
    );
}

#[test]
fn test_export_button_css_exists() {
    // RED: Test that export button CSS styles exist
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships = create_test_relationships();

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    assert!(
        html_content.contains(".export-btn"),
        "Export button CSS should exist"
    );
}

// =============================================================================
// DATA ATTRIBUTE TESTS
// =============================================================================

#[test]
fn test_table_rows_have_data_layer_attribute() {
    // RED: Test that table rows have data-layer attribute for filtering
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships = create_test_relationships();

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    assert!(
        html_content.contains(r#"data-layer="1""#),
        "Table rows should have data-layer attribute"
    );
}

#[test]
fn test_table_rows_have_data_type_attribute() {
    // RED: Test that table rows have data-type attribute for filtering
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships = create_test_relationships();

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    assert!(
        html_content.contains(r#"data-type="DNS::TXT::SPF""#),
        "Table rows should have data-type attribute"
    );
}

// =============================================================================
// EMPTY REPORT TESTS
// =============================================================================

#[test]
fn test_empty_relationships_generates_valid_html() {
    // RED: Test that empty relationships still generates valid HTML
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("test_report.html");
    let relationships: Vec<VendorRelationship> = vec![];

    export_html(&relationships, output_path.to_str().unwrap()).unwrap();

    let html_content = fs::read_to_string(&output_path).unwrap();

    // Should still have basic structure
    assert!(html_content.contains("<!DOCTYPE html>"));
    assert!(html_content.contains("<html"));
    assert!(html_content.contains("</html>"));
}
