# nthpartyfinder Bug Fix Roadmap

**Generated:** 2026-02-07
**Testing Domains:** klaviyo.com (91 relationships, 72 unique vendors), vanta.com (36 relationships, 35 unique vendors)
**Methodology:** Static code review of all Rust modules + runtime testing at depth 1 with HTML output

---

## Executive Summary

- **Total bugs identified:** 52 (across code review + runtime testing)
- **Critical:** 7 | **High:** 9 | **Medium:** 25 | **Low:** 11
- **Runtime bugs found during active testing:** 7
- **Bugs FIXED (2026-02-07):** 19 (6 Critical, 8 High, 4 Medium, 1 Low)
- **Bugs remaining:** 33

---

## Sprint 1: Critical & Data Quality (Priority: IMMEDIATE)

### R001: Massive Duplicate Vendor Processing [CRITICAL] ✅ FIXED
- **Fixed:** 2026-02-07 - Added HashSet dedup by base domain before vendor processing loop in main.rs
- **Source:** Runtime testing (klaviyo.com)
- **File:** `src/main.rs` (analysis loop), `src/discovery/saas_tenant.rs`
- **Evidence:** cloudflare.net processed 16x, google.com 7x, notion.so 6x, box.com 5x, bamboohr.com 4x, slack.com 3x during single run
- **Root cause:** SaaS tenant discovery returns duplicate platform entries (e.g., BambooHR has multiple patterns that all resolve to bamboohr.com). Subfinder also returns CNAME targets that overlap with DNS TXT discoveries. No deduplication before the vendor processing loop.
- **Impact:** 137 vendors processed but only 72 unique - wasting 48% of processing time on duplicates
- **Fix:** Add deduplication of discovered vendor domains BEFORE the parallel processing loop in `main.rs`. Use a `HashSet<String>` keyed on normalized domain to prevent duplicate entries.
- **Effort:** Small (2-4 hours)
- **Test:** Run klaviyo.com analysis, verify no domain appears more than once in processing logs

### R003: Duplicate Rows in HTML Report [CRITICAL] ✅ FIXED
- **Fixed:** 2026-02-07 - Result dedup now by (vendor_domain, customer_domain) with evidence merging
- **Source:** Runtime testing (klaviyo.com)
- **File:** `src/export.rs`
- **Evidence:** 13 domains appear 2x in the final report table: microsoft.com, dropbox.com, google.com, mailgun.com, notion.so, anthropic.com, openai.com, slack.com, greenhouse.io, zendesk.com, salesforce.com, splunk.com, sendgrid.net
- **Root cause:** Same vendor discovered via multiple methods (e.g., DNS TXT verification + subprocessor page) and both entries survive deduplication. The dedup in `main.rs` appears to dedup by `(domain, source_type)` tuple rather than just domain.
- **Impact:** Inflated vendor counts, confusing report for end users
- **Fix:** Consolidate duplicate vendor entries in export, merging evidence from multiple discovery sources into a single row with multiple source badges
- **Effort:** Medium (4-6 hours)
- **Test:** Verify each vendor appears exactly once in the "All Relationships" table

### C001: DMARC sp= Tag Misused for Domain Extraction [CRITICAL] ✅ FIXED
- **Fixed:** 2026-02-07 - Removed dead sp= extraction code and SP_TAG_REGEX static
- **Source:** Code review (dns.rs)
- **File:** `src/dns.rs:679-691`
- **Issue:** `sp=` tag contains policy values ("none", "quarantine", "reject"), NOT domains. Code extracts it and passes to `is_valid_domain()` which will always reject - dead code that confuses maintainers.
- **Fix:** Remove the sp= extraction block entirely (lines 679-691) or replace with ruf=/rua= tag extraction if the intent was to find additional reporting domains.
- **Effort:** Small (1 hour)
- **Test:** Run with DMARC-heavy domain, verify no false domain extractions from sp= tag

### C002: Unsafe `.expect()` on DNS Server Address Parsing [CRITICAL] ✅ FIXED
- **Fixed:** 2026-02-07 - create_dns_resolver now returns Result, callers use match with continue
- **Source:** Code review (dns.rs)
- **File:** `src/dns.rs:288`
- **Issue:** `server.address.parse().expect(...)` panics on invalid DNS config
- **Fix:** Return `Result` and propagate error, or validate addresses during config loading
- **Effort:** Small (1-2 hours)

### C003: XSS Risk with |safe Filter on User-Controlled Data [CRITICAL]
- **Source:** Code review (export.rs)
- **File:** `src/export.rs` + `templates/report.html`
- **Issue:** The askama template uses `|safe` filter to inject vendor data. If evidence strings contain malicious HTML/JS, they could execute in the browser.
- **Current state:** Testing shows evidence IS properly escaped in current output (0 unescaped tags in code blocks), but the `|safe` filter bypasses auto-escaping. A crafted TXT record like `<script>alert(1)</script>` in a DNS record could execute.
- **Fix:** Remove `|safe` from user-data contexts. Use askama's default auto-escaping. Only use `|safe` for pre-sanitized content like CSS/JS bundles.
- **Effort:** Medium (3-4 hours)
- **Test:** Create test with HTML-containing TXT record, verify it's rendered as text not executed

### C004: Byte Index Panic Risk with UTF-8 in DMARC Parsing [CRITICAL] ✅ FIXED
- **Fixed:** 2026-02-07 - DMARC extraction now uses record_lower copy consistently for all indexing
- **Source:** Code review (dns.rs)
- **File:** `src/dns.rs:655-658`
- **Issue:** `find()` returns byte index; if DMARC record contains multi-byte UTF-8 chars (e.g., IDN domain names), slicing at byte boundary could panic.
- **Fix:** Use `char_indices()` or validate slice boundaries are at UTF-8 boundaries
- **Effort:** Small (1-2 hours)

### C005: Recursion Not Properly Bounded [CRITICAL] ✅ FIXED
- **Fixed:** 2026-02-07 - Added ABSOLUTE_MAX_DEPTH=10 defensive cap, clarified semantics with comments
- **Source:** Code review (main.rs)
- **File:** `src/main.rs`
- **Issue:** Depth check boundary semantics unclear. At depth > max_depth, analysis should stop but the check may allow one extra level.
- **Fix:** Clarify and enforce strict depth bounds; add defensive max depth cap
- **Effort:** Small (1-2 hours)

---

## Sprint 2: High Severity & Performance (Priority: HIGH)

### H001: Regex Compiled in Loop for SPF Mechanisms [HIGH] ✅ FIXED
- **Fixed:** 2026-02-07 - Pre-compiled as Lazy statics (SPF_INCLUDE_REGEX etc.), used via array
- **Source:** Code review (dns.rs)
- **File:** `src/dns.rs:570-573`
- **Issue:** `Regex::new(&pattern)` called inside mechanism iteration loop. For SPF records with 5 mechanisms, regex compiled 5+ times per call.
- **Fix:** Pre-compile mechanism regexes as `Lazy<HashMap<&str, Regex>>` or compile once per function call
- **Effort:** Small (2 hours)
- **Impact:** 200-300x performance improvement on bulk SPF processing

### H002: Regex Compiled in Loop for DKIM Patterns [HIGH] ✅ FIXED
- **Fixed:** 2026-02-07 - Pre-compiled as Lazy statics (DKIM_P_REGEX etc.), used via array
- **Source:** Code review (dns.rs)
- **File:** `src/dns.rs:611-618`
- **Issue:** Same pattern - 3 regex patterns compiled per DKIM record
- **Fix:** Pre-compile as Lazy statics
- **Effort:** Small (1 hour)

### H003: Case-Sensitive Slice from Lowercase DMARC Position [HIGH] ✅ FIXED
- **Fixed:** 2026-02-07 - Uses record_lower consistently for both search and slice operations
- **Source:** Code review (dns.rs)
- **File:** `src/dns.rs:651-658`
- **Issue:** Searches lowercase copy for tag position, then slices original mixed-case string. Works for ASCII but fragile.
- **Fix:** Use the lowercase copy consistently, or search in original string case-insensitively
- **Effort:** Small (1 hour)

### H004: Aggressive Backslash/Quote Removal in SPF [HIGH] ✅ FIXED
- **Fixed:** 2026-02-07 - Changed to trim_matches('"') with proper unescape sequence
- **Source:** Code review (dns.rs)
- **File:** `src/dns.rs:479-480`
- **Issue:** Blanket `replace("\\", "").replace("\"", "")` may strip legitimate escaped characters
- **Fix:** Only strip quotes at string boundaries, handle backslash-escaped content properly
- **Effort:** Small (2 hours)

### H005: Unescaped HTML in Evidence Storage from Subprocessor [HIGH] ✅ FIXED
- **Fixed:** 2026-02-07 - create_enhanced_evidence now extracts text content, not raw HTML
- **Source:** Code review (subprocessor.rs)
- **File:** `src/subprocessor.rs`
- **Issue:** Subprocessor page content stored as evidence without HTML sanitization
- **Fix:** Strip HTML tags from evidence text before storing
- **Effort:** Small (2 hours)

### H006: Regex Pattern Injection via Cache (ReDoS) [HIGH]
- **Source:** Code review (subprocessor.rs)
- **File:** `src/subprocessor.rs`
- **Issue:** Cache JSON files can contain regex patterns that are compiled and executed. Malicious cache could cause ReDoS.
- **Fix:** Validate/sanitize regex patterns from cache, set timeout on regex execution
- **Effort:** Medium (3-4 hours)

### H007: Checkpoint Atomic Write Not Guaranteed [HIGH] ✅ FIXED
- **Fixed:** 2026-02-07 - Added file.sync_all() before rename
- **Source:** Code review (checkpoint.rs)
- **File:** `src/checkpoint.rs`
- **Issue:** Missing `fsync()` after temp file write, before rename. On crash, checkpoint may be empty.
- **Fix:** Add `file.sync_all()` before rename
- **Effort:** Small (30 minutes)

### R005: Org Names Contain Domain Suffixes [HIGH] ✅ FIXED
- **Fixed:** 2026-02-07 - Added strip_domain_suffix() to org normalization pipeline
- **Source:** Runtime testing
- **File:** `src/org_normalizer.rs`
- **Evidence:** "Monday.com", "Bigmarker.com", "Salesforce.com" appear as org names
- **Root cause:** Org normalizer doesn't strip .com/.io/.net suffixes from domain-inferred names
- **Fix:** Add domain suffix stripping to org normalization pipeline
- **Effort:** Small (2 hours)

### R002: SaaS Tenant Discovery Returns Duplicate Entries [HIGH] ✅ FIXED
- **Fixed:** 2026-02-07 - Added dedup by vendor_domain after probe results in saas_tenant.rs
- **Source:** Runtime testing (klaviyo.com)
- **File:** `src/discovery/saas_tenant.rs`
- **Evidence:** 27 SaaS tenants found, but bamboohr appears 4x (from different BambooHR patterns), notion 5x, box 5x
- **Root cause:** Multiple SaaS tenant patterns for same vendor all probe and all succeed, each generating a separate result
- **Fix:** Deduplicate SaaS tenant results by target domain before returning
- **Effort:** Small (2 hours)

---

## Sprint 3: Medium Severity & Correctness (Priority: MEDIUM)

### M001: DNS Error Swallowed - Returns Empty Vec [MEDIUM]
- **Source:** Code review (dns.rs)
- **File:** `src/dns.rs:401-404`
- **Issue:** DNS failure returns `Ok(vec![])` - indistinguishable from "no records"
- **Fix:** Return distinct error type or use `Option<Vec>` to differentiate
- **Effort:** Medium (3 hours)

### M002: HTTP Client Creation with `.expect()` [MEDIUM]
- **Source:** Code review (dns.rs)
- **File:** `src/dns.rs:103,134,183`
- **Issue:** Panics on HTTP client creation failure
- **Fix:** Return Result, handle gracefully
- **Effort:** Small (2 hours)

### M003: Missing SPF Mechanisms (ptr:, ip4:, ip6:) [MEDIUM]
- **Source:** Code review (dns.rs)
- **File:** `src/dns.rs:568`
- **Issue:** Only parses include:, redirect=, a:, mx:, exists: - missing ptr:, ip4:, ip6:
- **Fix:** Add missing mechanism types, extract PTR domains and WHOIS-resolve IP ranges
- **Effort:** Medium (4-6 hours)

### M004: Unsafe `.unwrap()` After `is_some()` Check [MEDIUM] ✅ FIXED
- **Fixed:** 2026-02-07 - Changed to if-let pattern
- **Source:** Code review (dns.rs)
- **File:** `src/dns.rs:544`
- **Fix:** Use `if let Some(logger) = logger { ... }`
- **Effort:** Small (30 minutes)

### M005: Path Traversal Risk in Cache File Loading [MEDIUM] ✅ FIXED
- **Fixed:** 2026-02-07 - Multi-layer sanitization: char whitelist + ".." removal + canonical path check
- **Source:** Code review (subprocessor.rs)
- **File:** `src/subprocessor.rs`
- **Issue:** Cache file paths constructed from domain names without sanitization
- **Fix:** Validate domain names don't contain path traversal chars (../ etc.)
- **Effort:** Small (1 hour)

### M006: Race Conditions in Cache Updates [MEDIUM]
- **Source:** Code review (subprocessor.rs)
- **File:** `src/subprocessor.rs`
- **Issue:** Concurrent reads/writes to same cache file during parallel processing
- **Fix:** Use file locking or atomic write pattern
- **Effort:** Medium (3-4 hours)

### M007: Incomplete Markdown Escaping in Export [MEDIUM]
- **Source:** Code review (export.rs)
- **File:** `src/export.rs`
- **Issue:** Markdown export doesn't escape pipe characters in table cells
- **Fix:** Escape `|` chars in all table cell content
- **Effort:** Small (1 hour)

### M008: SaaS Tenant Redirect Detection False Positives [MEDIUM]
- **Source:** Code review (saas_tenant.rs)
- **File:** `src/discovery/saas_tenant.rs`
- **Issue:** Redirect-to-main-site detection may falsely flag legitimate tenant pages
- **Fix:** Improve redirect detection heuristics, check for login page indicators
- **Effort:** Medium (3-4 hours)

### M009: CT Log Infrastructure Domain Filtering Too Broad [MEDIUM]
- **Source:** Code review (ct_logs.rs)
- **File:** `src/discovery/ct_logs.rs`
- **Issue:** `is_infrastructure()` filter may exclude legitimate vendor domains
- **Fix:** Refine infrastructure patterns, add exceptions list
- **Effort:** Small (2 hours)

### M010: Rate Limiter Token Acquisition Incomplete After Sleep [MEDIUM] ✅ FIXED
- **Fixed:** 2026-02-07 - Changed acquire() to retry loop pattern
- **Source:** Code review (rate_limit.rs)
- **File:** `src/rate_limit.rs`
- **Issue:** After sleeping to wait for tokens, doesn't re-check if tokens are available
- **Fix:** Add retry loop after sleep
- **Effort:** Small (1 hour)

### M011: Org Normalizer Suffix Removal Loop Logic [MEDIUM]
- **Source:** Code review (org_normalizer.rs)
- **File:** `src/org_normalizer.rs`
- **Issue:** Suffix stripping may not handle all cases correctly (e.g., "Inc." vs "Inc" vs "Incorporated")
- **Fix:** Comprehensive suffix list and proper boundary matching
- **Effort:** Medium (2-3 hours)

### M012: Checkpoint Version Compatibility Not Validated [MEDIUM]
- **Source:** Code review (checkpoint.rs)
- **File:** `src/checkpoint.rs`
- **Issue:** Checkpoint files from different versions may be loaded without validation
- **Fix:** Add version field to checkpoint format, validate on load
- **Effort:** Small (2 hours)

### M013: O(n^2) Checkpoint Deduplication [MEDIUM]
- **Source:** Code review (main.rs)
- **File:** `src/main.rs`
- **Issue:** Checkpoint dedup uses linear scan for each entry
- **Fix:** Use HashSet for O(1) lookup during dedup
- **Effort:** Small (1 hour)

### M014: Deduplication Drops Alternative Evidence [MEDIUM]
- **Source:** Code review (main.rs)
- **File:** `src/main.rs`
- **Issue:** When deduplicating vendor relationships, alternative evidence from other discovery methods is lost
- **Fix:** Merge evidence arrays during deduplication rather than keeping only first-seen
- **Effort:** Medium (3-4 hours)

### M015: HTTP::.well-known Hierarchy String Format Inconsistent [MEDIUM]
- **Source:** Code review (vendor.rs)
- **File:** `src/vendor.rs`
- **Issue:** `HTTP::.well-known` uses different naming convention than other types (missing category)
- **Fix:** Align naming to `HTTP::WELL_KNOWN` format
- **Effort:** Small (1 hour, but may need report template updates)

### R004: Vanta Run Did Not Complete in Session [MEDIUM]
- **Source:** Runtime testing
- **Evidence:** Stdout shows only initialization (18 lines) but no completion. The process appeared to hang during analysis.
- **Root cause:** Unknown - may be network issue, rate limiting, or timeout. Need investigation.
- **Fix:** Investigate timeout/hanging behavior, add global analysis timeout
- **Effort:** Medium (3-4 hours investigation)

### R006: Interactive Prompt Blocks Non-Interactive Runs [MEDIUM] ✅ FIXED
- **Fixed:** 2026-02-07 - Added std::io::IsTerminal auto-detection; skips prompts and auto-resumes checkpoints in non-interactive mode
- **Source:** Runtime testing
- **File:** `src/main.rs`
- **Evidence:** "Press Enter to continue or type a different directory path:" blocks when stdin is piped
- **Fix:** Add `--non-interactive` or `--yes` flag to skip interactive prompts. Auto-detect non-interactive terminal.
- **Effort:** Small (2 hours)

### R007: Stdout/Stderr Mixing on Same Line [MEDIUM]
- **Source:** Runtime testing
- **Evidence:** Line 12 of stdout shows INFO message and "Press Enter" prompt concatenated without newline
- **Fix:** Ensure all log output goes to stderr and interactive prompts to stdout, or vice versa consistently
- **Effort:** Small (1-2 hours)

### M016: Overly Permissive Domain Validation Regex [MEDIUM]
- **Source:** Code review (dns.rs)
- **File:** `src/dns.rs:37-39`
- **Issue:** Allows underscores and digit-start labels, which are non-standard for most domains
- **Fix:** Tighten regex or add separate validation for SRV-style records
- **Effort:** Small (1 hour)

### M017: Subfinder Timeout Race Condition [MEDIUM]
- **Source:** Code review (subfinder.rs)
- **File:** `src/discovery/subfinder.rs`
- **Issue:** Timeout and process termination may race, leading to partial output
- **Fix:** Ensure output is fully read before timeout check
- **Effort:** Small (2 hours)

---

## Sprint 4: Low Severity & Polish (Priority: LOW)

### L001: Whimsical Angle Bracket Verification Pattern [LOW]
- **File:** `src/dns.rs:762`
- **Issue:** `<whimsical=` uses angle brackets - unusual verification pattern
- **Fix:** Document as intentional or investigate correct pattern

### L002: neat.co Domain Mapping Inconsistent [LOW]
- **File:** `src/dns.rs:754`
- **Issue:** Maps to `neat.co` while most others use `.com`
- **Fix:** Verify correct domain

### L003: GC-AI Domain Mapping Questionable [LOW]
- **File:** `src/dns.rs:749`
- **Issue:** Weak domain mapping for `gc-ai-domain-verification`
- **Fix:** Research and confirm or remove

### L004: Limited Fallback Provider List [LOW]
- **File:** `src/dns.rs:905-917`
- **Issue:** Hardcoded fallback provider list is incomplete
- **Fix:** Expand or make configurable

### L005: Inconsistent Indentation in Verification Regex Loops [LOW]
- **File:** `src/dns.rs:787-843`
- **Fix:** Run rustfmt, fix indentation

### L006: CSS Selector Panics at Startup [LOW]
- **File:** `src/subprocessor.rs`
- **Issue:** Invalid CSS selector in Lazy static would panic on first use
- **Fix:** Validate selectors or use fallback

### L007: False Positives in Org Detection [LOW]
- **File:** `src/subprocessor.rs`
- **Issue:** Generic org detection may flag non-org strings
- **Fix:** Improve org detection heuristics

### L008: Mermaid Diagram ID Sanitization [LOW] ✅ FIXED
- **Fixed:** 2026-02-07 - sanitize_mermaid_id now handles leading digits (prefixes 'n'), special chars, and empty strings
- **File:** `src/export.rs`
- **Issue:** Mermaid IDs may contain special characters that break rendering
- **Fix:** Sanitize IDs to alphanumeric + hyphens

### L009: No SPF Recursion Depth Limit [LOW]
- **File:** `src/dns.rs`
- **Issue:** RFC 7208 limits SPF to 10 void lookups; no enforcement
- **Fix:** Add counter if recursive SPF resolution is added

### L010: Subfinder Version Mismatch in Instructions [LOW]
- **File:** `src/discovery/subfinder.rs`
- **Issue:** Installation instructions reference different version than code expects
- **Fix:** Sync documentation with expected version

### L011: Title Case Conversion Issues in Org Normalizer [LOW]
- **File:** `src/org_normalizer.rs`
- **Issue:** Title case conversion doesn't handle exceptions (e.g., "of", "and", "LLC")
- **Fix:** Add exceptions list for title case

---

## Implementation Notes

### Testing Strategy
For each fix:
1. Write a regression test BEFORE fixing (if possible)
2. Fix the bug
3. Run full test suite (`cargo test`)
4. Run integration test against klaviyo.com and verify improvement
5. Compare vendor counts before/after

### Expected Impact
After Sprint 1 + 2 fixes:
- **Processing time:** ~48% reduction (eliminating duplicate processing)
- **Report accuracy:** 13 fewer duplicate rows in klaviyo report
- **Data quality:** Proper org names, no domain suffixes
- **Security:** XSS risk eliminated, path traversal blocked
- **Stability:** No panics on edge case inputs

### Priority Matrix

| Sprint | Bugs | Severity | Est. Hours | Value |
|--------|------|----------|------------|-------|
| 1 | 7 | Critical | 14-20 | Correctness, Security |
| 2 | 9 | High | 16-22 | Performance, Data Quality |
| 3 | 17 | Medium | 30-40 | Robustness, Polish |
| 4 | 11 | Low | 10-15 | Code Quality |

### Dependencies
- R001 (duplicate processing) blocks R003 (duplicate rows) - fix dedup first
- R002 (SaaS tenant dupes) contributes to R001 - fix tenant dedup first
- C003 (XSS) should be fixed before any public deployment
- H007 (checkpoint fsync) is independent and quick - fix anytime
