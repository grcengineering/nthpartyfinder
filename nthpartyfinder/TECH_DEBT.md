# Technical Debt

## Critical Priority

### T010 - Remove debug eprintln! statements
**Impact:** Critical
**Effort:** Small
**Category:** Code Cleanup
**Related Bug:** B010

Over 50 debug `eprintln!` statements with emoji prefixes (🔥🔥🔥) scattered throughout `subprocessor.rs`. These:
- Pollute production output
- Degrade performance
- May leak sensitive URL/domain information

**Action:** Remove all `eprintln!` calls or convert to `debug!()` tracing macro.

**Files:** `src/subprocessor.rs`

---

### T011 - Add once_cell/lazy_static for regex compilation
**Impact:** High
**Effort:** Small
**Category:** Performance
**Related Bug:** B014

Regex patterns are compiled on every function call in hot paths:

```rust
// src/dns.rs - called for every SPF record
let macro_regex = Regex::new(r"%\{[a-zA-Z]+[0-9]*[a-zA-Z]*\}\.?").unwrap();

// src/dns.rs - called for every domain validation
let domain_regex = Regex::new(r"^[a-zA-Z0-9_]...").unwrap();
```

**Solution:** Add `once_cell` to dependencies and use `Lazy<Regex>`:

```rust
use once_cell::sync::Lazy;

static MACRO_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"%\{[a-zA-Z]+[0-9]*[a-zA-Z]*\}\.?").unwrap()
});
```

**Files:** `src/dns.rs`, `src/subprocessor.rs`

---

### T012 - Add once_cell/lazy_static for CSS selector parsing
**Impact:** High
**Effort:** Medium
**Category:** Performance
**Related Bug:** B015

CSS selectors parsed repeatedly in extraction loops:

```rust
// Called thousands of times during scraping
let paragraph_selector = Selector::parse("p").unwrap();
let div_selector = Selector::parse("div").unwrap();
let row_selector = Selector::parse("tbody tr, tr").unwrap();
```

**Solution:** Create a `Selectors` struct with pre-parsed selectors:

```rust
pub struct Selectors {
    pub paragraph: Selector,
    pub div: Selector,
    pub table_row: Selector,
    // ...
}

static SELECTORS: Lazy<Selectors> = Lazy::new(|| Selectors::new());
```

**Files:** `src/subprocessor.rs` (11+ locations)

---

## High Priority

### T013 - Replace unwrap() with proper error handling
**Impact:** High
**Effort:** Medium
**Category:** Error Handling
**Related Bugs:** B011, B012, B013, B017, B018

38+ instances of `.unwrap()` that could panic:

**Critical paths:**
- `src/main.rs:41` - Ctrl+C handler setup
- `src/main.rs:85` - stdin read
- `src/main.rs:327, 892` - subprocessor analyzer access
- `src/logger.rs` - 10 mutex locks
- `src/dns.rs:129` - IP address parsing

**Solution:**
1. Use `?` operator with `anyhow::Result` where possible
2. Use `.expect("meaningful message")` for truly impossible failures
3. Handle `PoisonError` for mutex operations

---

### T014 - Consolidate HTTP client creation
**Impact:** Medium
**Effort:** Small
**Category:** Architecture
**Related Bug:** B016

HTTP clients created in multiple places with duplicate configuration:

```rust
// src/subprocessor.rs - SubprocessorAnalyzer::new()
let client = reqwest::Client::builder()
    .timeout(Duration::from_secs(30))
    .user_agent("Mozilla/5.0...")
    // ... 7 lines of config

// src/subprocessor.rs - SubprocessorAnalyzer::with_cache()
let client = reqwest::Client::builder()
    .timeout(Duration::from_secs(30))
    .user_agent("Mozilla/5.0...")
    // ... same 7 lines duplicated

// src/dns.rs - DnsServerPool::new()
// Another HTTP client for DoH
```

**Solution:** Create `HttpClientBuilder` utility or shared client factory.

---

### T002 - Remove unused layer-by-layer functions
**Impact:** Medium
**Effort:** Medium
**Category:** Code Cleanup
**Status:** ✅ RESOLVED (2026-01-31)

~~Functions `discover_nth_parties_by_layers` and `discover_single_domain` in `src/main.rs` are not called anywhere.~~

**Resolution:** Removed ~320 lines of dead code. These were alternative implementations that were never integrated into the main code path.

---

### T003 - Verify domain cache centralization
**Impact:** Medium
**Effort:** Medium
**Category:** Architecture

Per CLAUDE.md instructions, ensure nthpartyfinder NEVER uses centralized cache files (e.g., `~/AppData/Local/nthpartyfinder/subprocessor_cache.json`).

**Audit needed:**
- Search for any AppData/home directory usage
- Verify all caching goes through `/cache` directory
- Check `dirs` crate usage in Cargo.toml

**Files:** All files using `dirs` crate

---

### T005 - Improve test coverage for subprocessor module
**Impact:** Medium
**Effort:** Large
**Category:** Testing

Limited test coverage for the new subprocessor analysis feature:

**Missing tests:**
- Integration tests with real domains (using cached responses)
- Tests for custom extraction rules
- Cache persistence and invalidation tests
- PDF parsing tests
- Headless browser fallback tests
- Error handling edge cases

**Current tests:** `tests/subprocessor_tests.rs` (basic unit tests only)

---

## Medium Priority

### T015 - Split large functions in subprocessor.rs
**Impact:** Medium
**Effort:** Medium
**Category:** Code Organization

Several functions exceed 200 lines:

- `scrape_subprocessor_page()` - ~270 lines
- `extract_from_tables_with_patterns()` - ~210 lines
- `analyze_domain_with_logging()` - ~160 lines

**Solution:** Extract logical sections into smaller, testable functions:
- URL fetching
- Content type detection
- HTML vs PDF routing
- Pattern-based extraction
- Cache management

---

### T016 - Add clippy configuration
**Impact:** Medium
**Effort:** Small
**Category:** Code Quality

No clippy configuration in place. Should add `clippy.toml` or `[lints]` section in Cargo.toml:

```toml
[lints.rust]
unsafe_code = "forbid"

[lints.clippy]
unwrap_used = "warn"
expect_used = "warn"
panic = "warn"
```

---

### T006 - Standardize error handling
**Impact:** Medium
**Effort:** Medium
**Category:** Error Handling

Mix of error handling approaches:
- `anyhow::Result` in some places
- `Box<dyn std::error::Error>` in others
- Raw `.unwrap()` calls
- Some functions return `Result`, others panic

**Solution:**
1. Use `anyhow::Result` consistently for fallible operations
2. Add `.context()` for meaningful error chains
3. Document expected failure scenarios

---

### T007 - Extract logging trait for testability
**Impact:** Low
**Effort:** Medium
**Category:** Architecture

`AnalysisLogger` is used directly throughout, making unit testing difficult.

**Solution:**
```rust
pub trait Logger: Send + Sync {
    fn info(&self, message: &str);
    fn warn(&self, message: &str);
    fn debug(&self, message: &str);
}

// For tests
pub struct MockLogger { messages: Vec<String> }
```

---

### T017 - Extract magic numbers to constants
**Impact:** Low
**Effort:** Small
**Category:** Code Quality

Magic numbers scattered throughout:

```rust
// src/subprocessor.rs
const MAX_URLS_TO_TEST: usize = 10;           // OK - has name
Duration::from_secs(30)                        // Should be const
const MAX_CONTENT_SIZE: usize = 10 * 1024 * 1024;  // OK

// src/dns.rs
Duration::from_secs(10)                        // Timeout - should be const
let doh_servers = vec![...];                   // 4 hardcoded servers

// src/logger.rs
tokio::time::sleep(Duration::from_millis(2))  // Should be const
```

---

### T004 - Reorganize domain_utils module
**Impact:** Low
**Effort:** Small
**Category:** Code Organization

`domain_utils.rs` could be better organized. Consider splitting into:
- `domain_utils/normalization.rs` - Domain normalization functions
- `domain_utils/validation.rs` - Domain validation
- `domain_utils/extraction.rs` - Base domain extraction

---

## Low Priority

### T001 - Cleanup backup files
**Impact:** Low
**Effort:** Small
**Category:** Code Cleanup

Remove `backup/main_old.rs` and `backup/progress_old.rs` files.

**Action:** Delete backup directory after confirming all changes merged.

---

### T018 - Add documentation for public API
**Impact:** Low
**Effort:** Medium
**Category:** Documentation

Many public functions lack documentation:

```rust
// Missing doc comments
pub fn extract_base_domain(domain: &str) -> String
pub fn normalize_for_dns_lookup(domain: &str) -> String
pub async fn analyze_domain(&self, domain: &str, ...) -> Result<...>
```

Should add `///` doc comments for public API surface.

---

### T019 - Consider async-std or smol for lighter runtime
**Impact:** Low
**Effort:** Large
**Category:** Performance

Currently using full Tokio runtime. For a CLI tool, a lighter async runtime might reduce binary size and startup time.

**Trade-off:** Tokio has better ecosystem support. Only consider if binary size becomes an issue.

---

## Optimization Quick Wins

These can be done quickly with high impact:

| ID | Task | Effort | Impact |
|----|------|--------|--------|
| T010 | Remove eprintln! statements | 30 min | Critical |
| T011 | Add lazy_static for regex | 1 hr | High |
| T012 | Add lazy_static for selectors | 2 hr | High |
| T016 | Add clippy.toml | 15 min | Medium |
| T001 | Delete backup folder | 5 min | Low |

---

## Guidelines

When addressing technical debt:
1. **Write tests first** - Prevent regressions
2. **Small PRs** - One debt item per change
3. **Document decisions** - Update CLAUDE.md if architectural
4. **Measure impact** - Before/after metrics where applicable
5. **Run clippy** - `cargo clippy -- -W clippy::unwrap_used`
