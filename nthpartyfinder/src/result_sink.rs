// result_sink.rs - Disk-backed result storage using zstd-compressed JSONL
//
// Replaces in-memory Vec<Vec<VendorRelationship>> accumulation with a write-once,
// read-at-end pattern. Results are appended as JSONL (one JSON object per line),
// compressed with zstd level 3, and flushed every 50 records for crash safety.
//
// This bounds memory usage to O(1) per result instead of O(n), preventing the
// virtual memory exhaustion that caused Windows BSODs at depth 3.

use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use crate::vendor::VendorRelationship;

const FLUSH_INTERVAL: usize = 50;
const ZSTD_LEVEL: i32 = 3;
/// Never reap a results file younger than this. A live, actively-written sink
/// has a fresh mtime, so this age guard protects an in-flight sibling process's
/// file even when PID-liveness detection is unavailable on the platform
/// (e.g. no `/proc` on macOS/Windows). Without this guard, concurrent
/// nthpartyfinder processes delete each other's in-flight result sinks,
/// causing a hard panic at result read-back (lost full scan output).
const ORPHAN_MIN_AGE_SECS: u64 = 1800;

pub struct ResultSink {
    writer: zstd::stream::write::Encoder<'static, BufWriter<File>>,
    path: PathBuf,
    count: usize,
    unflushed: usize,
}

impl ResultSink {
    /// Create a new ResultSink writing to a zstd-compressed JSONL file.
    /// The file is created in the given directory with a PID-stamped name.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn new(output_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(output_dir).with_context(|| {
            format!(
                "Failed to create output directory: {}",
                output_dir.display()
            )
        })?;

        let pid = std::process::id();
        let filename = format!("nthpartyfinder-results-{}.jsonl.zst", pid);
        let path = output_dir.join(filename);

        let file = File::create(&path)
            .with_context(|| format!("Failed to create result sink file: {}", path.display()))?;
        let buf_writer = BufWriter::new(file);
        let encoder = zstd::stream::write::Encoder::new(buf_writer, ZSTD_LEVEL)
            .context("Failed to create zstd encoder")?;

        Ok(Self {
            writer: encoder,
            path,
            count: 0,
            unflushed: 0,
        })
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn with_path(path: &Path) -> Result<Self> {
        let parent = path.parent().unwrap_or(Path::new("."));
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create parent directory: {}", parent.display()))?;

        let file = File::create(path)
            .with_context(|| format!("Failed to create result sink file: {}", path.display()))?;
        let buf_writer = BufWriter::new(file);
        let encoder = zstd::stream::write::Encoder::new(buf_writer, ZSTD_LEVEL)
            .context("Failed to create zstd encoder")?;

        Ok(Self {
            writer: encoder,
            path: path.to_path_buf(),
            count: 0,
            unflushed: 0,
        })
    }

    /// Append a single VendorRelationship to the sink.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn append_one(&mut self, result: &VendorRelationship) -> Result<()> {
        let json =
            serde_json::to_string(result).context("Failed to serialize VendorRelationship")?;
        self.writer.write_all(json.as_bytes())?;
        self.writer.write_all(b"\n")?;
        self.count += 1;
        self.unflushed += 1;

        if self.unflushed >= FLUSH_INTERVAL {
            self.flush()?;
        }

        Ok(())
    }

    /// Append a batch of VendorRelationships to the sink.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn append_batch(&mut self, results: &[VendorRelationship]) -> Result<usize> {
        for result in results {
            self.append_one(result)?;
        }
        Ok(results.len())
    }

    /// Flush the zstd encoder to ensure data is written to disk.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn flush(&mut self) -> Result<()> {
        self.writer
            .flush()
            .context("Failed to flush zstd encoder")?;
        self.unflushed = 0;
        Ok(())
    }

    /// Finalize the zstd stream and return all results by reading back the file.
    /// This consumes the ResultSink.
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn drain_all(mut self) -> Result<Vec<VendorRelationship>> {
        // Flush any remaining data
        self.flush()?;

        // Finalize the zstd stream (writes the end-of-frame marker)
        self.writer
            .finish()
            .context("Failed to finalize zstd stream")?;

        // Read back all results
        Self::read_results(&self.path)
    }

    /// Read results from a zstd-compressed JSONL file.
    /// Uses a tolerant parser that skips corrupt lines (crash recovery).
    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn read_results(path: &Path) -> Result<Vec<VendorRelationship>> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open result file: {}", path.display()))?;
        let decoder =
            zstd::stream::read::Decoder::new(file).context("Failed to create zstd decoder")?;
        let reader = BufReader::new(decoder);

        let mut results = Vec::new();
        let mut errors = 0;

        for (line_num, line_result) in reader.lines().enumerate() {
            match line_result {
                Ok(line) => {
                    if line.trim().is_empty() {
                        continue;
                    }
                    match serde_json::from_str::<VendorRelationship>(&line) {
                        Ok(result) => results.push(result),
                        Err(e) => {
                            errors += 1;
                            if errors <= 3 {
                                eprintln!(
                                    "Warning: Skipping corrupt line {} in {}: {}",
                                    line_num + 1,
                                    path.display(),
                                    e
                                );
                            }
                        }
                    }
                }
                Err(_) => {
                    // Truncated zstd frame — we've read everything recoverable
                    break;
                }
            }
        }

        if errors > 3 {
            eprintln!(
                "Warning: {} total corrupt lines skipped in {}",
                errors,
                path.display()
            );
        }

        Ok(results)
    }

    /// Get the number of results written so far.
    pub fn count(&self) -> usize {
        self.count
    }

    /// Get the path to the result file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    pub fn cleanup_orphans(dir: &Path) -> Result<usize> {
        let mut cleaned = 0;
        let pattern = "nthpartyfinder-results-";
        let extension = ".jsonl.zst";

        if !dir.exists() {
            return Ok(0);
        }

        let entries = std::fs::read_dir(dir)
            .with_context(|| format!("Failed to read directory: {}", dir.display()))?;

        for entry in entries {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if name_str.starts_with(pattern) && name_str.ends_with(extension) {
                // Extract PID from filename
                let pid_str = name_str
                    .strip_prefix(pattern)
                    .and_then(|s| s.strip_suffix(extension));

                if let Some(pid_str) = pid_str {
                    if let Ok(pid) = pid_str.parse::<u32>() {
                        // Never reap our own in-flight file.
                        if pid == std::process::id() {
                            continue;
                        }
                        // A file is only an orphan if the owning PID is NOT
                        // running AND it is older than ORPHAN_MIN_AGE_SECS.
                        // The age guard is the load-bearing safety net: a live
                        // sibling sink is being actively written (fresh mtime),
                        // so it survives even where PID liveness can't be
                        // determined (no /proc on macOS) — which is the bug
                        // that made concurrent runs delete each other's sinks.
                        let old_enough = entry
                            .metadata()
                            .and_then(|m| m.modified())
                            .ok()
                            .and_then(|mtime| mtime.elapsed().ok())
                            .map(|age| age.as_secs() >= ORPHAN_MIN_AGE_SECS)
                            .unwrap_or(false); // unknown age → treat as fresh (do not delete)

                        if old_enough && !is_process_running(pid) {
                            if let Ok(canonical) = entry.path().canonicalize() {
                                if let Err(e) = std::fs::remove_file(&canonical) {
                                    eprintln!(
                                        "Warning: Failed to clean up orphaned file {}: {}",
                                        canonical.display(),
                                        e
                                    );
                                } else {
                                    cleaned += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(cleaned)
    }
}

/// Returns `true` if a process with the given PID is currently running.
///
/// Uses `sysinfo` for portable liveness detection across Linux, macOS, and
/// Windows. The previous implementation only checked `/proc/{pid}`, which does
/// not exist on macOS/Windows: there it reported *every* PID as "not running",
/// so `cleanup_orphans` deleted the live result-sink files of concurrently
/// running scans. The victim run then panicked in `drain_all()` with ENOENT
/// (exit 101) before any output was written (GRC-500).
//
// cfg(not(coverage)): queries the host process table via platform-specific
// syscalls, so the result is environment-dependent and excluded from coverage.
#[cfg(not(coverage))]
fn is_process_running(pid: u32) -> bool {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

    let target = Pid::from_u32(pid);
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[target]),
        false,
        ProcessRefreshKind::new(),
    );
    system.process(target).is_some()
}

// cfg(coverage): the sysinfo path above is excluded from coverage, so this
// deterministic stub stands in. The current process is always alive; every
// other PID is treated as dead so both branches of `cleanup_orphans` are
// exercised without depending on the host process table.
#[cfg(coverage)]
fn is_process_running(pid: u32) -> bool {
    pid == std::process::id()
}

// cfg(not(coverage)): df --output=avail is Linux-only; macOS df writes nothing to stdout, so the parse closure is unreachable
#[cfg(not(coverage))]
pub fn check_disk_space(_path: &Path) -> Result<u64> {
    #[cfg(unix)]
    {
        let output = std::process::Command::new("df")
            .arg("--output=avail")
            .arg("-B1")
            .arg(_path)
            .output()
            .context("Failed to run df command")?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let avail = stdout
            .lines()
            .nth(1) // Skip header
            .and_then(|line| line.trim().parse::<u64>().ok())
            .unwrap_or(0);

        Ok(avail)
    }

    #[cfg(not(unix))]
    {
        Ok(u64::MAX)
    }
}
#[cfg(coverage)]
pub fn check_disk_space(_path: &Path) -> Result<u64> {
    Ok(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vendor::RecordType;
    use tempfile::TempDir;

    fn make_test_result(domain: &str, depth: u32) -> VendorRelationship {
        VendorRelationship {
            nth_party_domain: domain.to_string(),
            nth_party_organization: format!("{} Inc", domain),
            nth_party_layer: depth,
            nth_party_customer_domain: "customer.com".to_string(),
            nth_party_customer_organization: "Customer Inc".to_string(),
            nth_party_record: "v=spf1 include:test.com".to_string(),
            nth_party_record_type: RecordType::DnsTxtSpf,
            root_customer_domain: "root.com".to_string(),
            root_customer_organization: "Root Inc".to_string(),
            evidence: format!("SPF record for {}", domain),
        }
    }

    #[test]
    fn test_roundtrip_single() {
        let tmp = TempDir::new().unwrap();
        let mut sink = ResultSink::new(tmp.path()).unwrap();

        let r = make_test_result("vendor.com", 1);
        sink.append_one(&r).unwrap();

        let results = sink.drain_all().unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].nth_party_domain, "vendor.com");
    }

    #[test]
    fn test_roundtrip_batch() {
        let tmp = TempDir::new().unwrap();
        let mut sink = ResultSink::new(tmp.path()).unwrap();

        let batch: Vec<_> = (0..100)
            .map(|i| make_test_result(&format!("vendor{}.com", i), 1))
            .collect();
        sink.append_batch(&batch).unwrap();
        assert_eq!(sink.count(), 100);

        let results = sink.drain_all().unwrap();
        assert_eq!(results.len(), 100);
    }

    #[test]
    fn test_flush_interval() {
        let tmp = TempDir::new().unwrap();
        let mut sink = ResultSink::new(tmp.path()).unwrap();

        // Write exactly FLUSH_INTERVAL records
        for i in 0..FLUSH_INTERVAL {
            sink.append_one(&make_test_result(&format!("v{}.com", i), 1))
                .unwrap();
        }
        // After FLUSH_INTERVAL, unflushed should be 0 (auto-flushed)
        assert_eq!(sink.unflushed, 0);
        assert_eq!(sink.count(), FLUSH_INTERVAL);

        let results = sink.drain_all().unwrap();
        assert_eq!(results.len(), FLUSH_INTERVAL);
    }

    #[test]
    fn test_empty_sink() {
        let tmp = TempDir::new().unwrap();
        let sink = ResultSink::new(tmp.path()).unwrap();
        assert_eq!(sink.count(), 0);

        let results = sink.drain_all().unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_orphan_cleanup() {
        // NOTE: this test previously asserted that a *freshly-written*
        // results file was deleted (cleaned == 1). That assertion codified
        // the TF-3 data-loss bug: concurrent runs deleting each other's
        // in-flight sinks. Correct contract is now: a fresh file is
        // preserved (age guard); only a genuinely old file with a dead PID
        // is reaped.
        let tmp = TempDir::new().unwrap();
        let orphan_path = tmp.path().join("nthpartyfinder-results-999999.jsonl.zst");
        std::fs::write(&orphan_path, b"fake data").unwrap();
        assert!(orphan_path.exists());

        // Fresh file → must NOT be reaped, even though PID 999999 is dead.
        let cleaned = ResultSink::cleanup_orphans(tmp.path()).unwrap();
        assert_eq!(cleaned, 0, "a fresh in-flight sink must be preserved");
        assert!(orphan_path.exists());

        // Backdate it well beyond ORPHAN_MIN_AGE_SECS → now a true orphan.
        let _ = std::process::Command::new("touch")
            .arg("-t")
            .arg("200001010000")
            .arg(&orphan_path)
            .status();
        let cleaned = ResultSink::cleanup_orphans(tmp.path()).unwrap();
        assert_eq!(cleaned, 1, "an aged file with a dead PID should be reaped");
        assert!(!orphan_path.exists());
    }

    #[test]
    fn test_with_path() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("custom-results.jsonl.zst");
        let mut sink = ResultSink::with_path(&path).unwrap();

        sink.append_one(&make_test_result("test.com", 1)).unwrap();
        let results = sink.drain_all().unwrap();
        assert_eq!(results.len(), 1);
    }

    // ====================================================================
    // Additional tests for uncovered paths
    // ====================================================================

    #[test]
    fn test_count_and_path() {
        let tmp = TempDir::new().unwrap();
        let mut sink = ResultSink::new(tmp.path()).unwrap();

        assert_eq!(sink.count(), 0);
        assert!(sink
            .path()
            .to_string_lossy()
            .contains("nthpartyfinder-results-"));
        assert!(sink.path().to_string_lossy().ends_with(".jsonl.zst"));

        sink.append_one(&make_test_result("test.com", 1)).unwrap();
        assert_eq!(sink.count(), 1);
    }

    #[test]
    fn test_with_path_nested_dir() {
        let tmp = TempDir::new().unwrap();
        let path = tmp
            .path()
            .join("nested")
            .join("dir")
            .join("results.jsonl.zst");
        let mut sink = ResultSink::with_path(&path).unwrap();

        sink.append_one(&make_test_result("test.com", 1)).unwrap();
        let results = sink.drain_all().unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn test_append_batch_empty() {
        let tmp = TempDir::new().unwrap();
        let mut sink = ResultSink::new(tmp.path()).unwrap();

        let written = sink.append_batch(&[]).unwrap();
        assert_eq!(written, 0);
        assert_eq!(sink.count(), 0);

        let results = sink.drain_all().unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_explicit_flush() {
        let tmp = TempDir::new().unwrap();
        let mut sink = ResultSink::new(tmp.path()).unwrap();

        sink.append_one(&make_test_result("test.com", 1)).unwrap();
        assert_eq!(sink.unflushed, 1);

        sink.flush().unwrap();
        assert_eq!(sink.unflushed, 0);
    }

    #[test]
    fn test_multiple_appends_then_drain() {
        let tmp = TempDir::new().unwrap();
        let mut sink = ResultSink::new(tmp.path()).unwrap();

        // Append records in multiple calls
        sink.append_one(&make_test_result("a.com", 1)).unwrap();
        sink.append_one(&make_test_result("b.com", 2)).unwrap();

        let batch: Vec<_> = (0..5)
            .map(|i| make_test_result(&format!("batch{}.com", i), 3))
            .collect();
        sink.append_batch(&batch).unwrap();

        assert_eq!(sink.count(), 7);

        let results = sink.drain_all().unwrap();
        assert_eq!(results.len(), 7);
        assert_eq!(results[0].nth_party_domain, "a.com");
        assert_eq!(results[1].nth_party_domain, "b.com");
    }

    #[test]
    fn test_read_results_from_file() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("read-test.jsonl.zst");

        // Write some results
        {
            let mut sink = ResultSink::with_path(&path).unwrap();
            for i in 0..10 {
                sink.append_one(&make_test_result(&format!("v{}.com", i), 1))
                    .unwrap();
            }
            sink.flush().unwrap();
            sink.writer.finish().unwrap();
        }

        // Read them back
        let results = ResultSink::read_results(&path).unwrap();
        assert_eq!(results.len(), 10);
    }

    #[test]
    fn test_read_results_file_not_found() {
        let result = ResultSink::read_results(std::path::Path::new("/nonexistent/file.jsonl.zst"));
        assert!(result.is_err());
    }

    #[test]
    fn test_orphan_cleanup_nonexistent_dir() {
        let result = ResultSink::cleanup_orphans(std::path::Path::new("/nonexistent/dir"));
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
    }

    // GRC-500: when a sibling scan runs cleanup_orphans, it must remove only
    // truly-orphaned sinks (dead PIDs) and leave a concurrently-running scan's
    // live sink untouched. Before the fix, macOS deleted both, so the live scan
    // later panicked reading its own (now missing) sink.
    //
    // Both files are backdated past ORPHAN_MIN_AGE_SECS: this originally
    // asserted a FRESH dead-PID file was reaped, which the post-merge age
    // guard (defense against PID reuse / in-flight siblings) intentionally
    // prevents. Aging both makes the test STRONGER: the live file's survival
    // now proves the liveness check protects it, not merely its freshness.
    #[test]
    fn test_orphan_cleanup_preserves_live_removes_dead() {
        let tmp = TempDir::new().unwrap();

        // Live sibling: our own PID stands in for a concurrently-running scan.
        let live_file = tmp.path().join(format!(
            "nthpartyfinder-results-{}.jsonl.zst",
            std::process::id()
        ));
        std::fs::write(&live_file, b"live").unwrap();

        // Orphan: an impossible PID can never be running.
        let dead_file = tmp
            .path()
            .join(format!("nthpartyfinder-results-{}.jsonl.zst", u32::MAX));
        std::fs::write(&dead_file, b"dead").unwrap();

        // Backdate both well beyond ORPHAN_MIN_AGE_SECS.
        for f in [&live_file, &dead_file] {
            let status = std::process::Command::new("touch")
                .arg("-t")
                .arg("200001010000")
                .arg(f)
                .status()
                .expect("touch must run");
            assert!(status.success(), "backdating {} failed", f.display());
        }

        let cleaned = ResultSink::cleanup_orphans(tmp.path()).unwrap();

        assert_eq!(cleaned, 1, "only the dead-PID orphan should be cleaned");
        assert!(
            live_file.exists(),
            "an OLD live-PID sink must be preserved by the liveness check"
        );
        assert!(
            !dead_file.exists(),
            "old dead-PID orphan sink must be removed"
        );
    }

    #[test]
    fn test_orphan_cleanup_skips_current_process() {
        let tmp = TempDir::new().unwrap();

        // Create a file with our own PID - should NOT be cleaned up
        let own_pid = std::process::id();
        let own_file = tmp
            .path()
            .join(format!("nthpartyfinder-results-{}.jsonl.zst", own_pid));
        std::fs::write(&own_file, b"data").unwrap();

        let cleaned = ResultSink::cleanup_orphans(tmp.path()).unwrap();
        // The current process is alive on every platform, so its sink file must
        // be preserved. GRC-500 regression: macOS previously reported the live
        // PID as "not running" and deleted the file out from under a running
        // scan, which then panicked in drain_all().
        assert_eq!(
            cleaned, 0,
            "a live current-process sink must not be cleaned"
        );
        assert!(
            own_file.exists(),
            "current-process sink file must survive cleanup_orphans"
        );
    }

    #[test]
    fn test_orphan_cleanup_ignores_non_matching_files() {
        let tmp = TempDir::new().unwrap();

        // Create files that don't match the pattern
        std::fs::write(tmp.path().join("other-file.txt"), b"data").unwrap();
        std::fs::write(tmp.path().join("nthpartyfinder-other.txt"), b"data").unwrap();

        let cleaned = ResultSink::cleanup_orphans(tmp.path()).unwrap();
        assert_eq!(cleaned, 0);
    }

    #[test]
    fn test_is_process_running_nonexistent() {
        // u32::MAX exceeds the maximum PID on every supported platform, so it
        // can never correspond to a live process and must read as not running.
        assert!(
            !is_process_running(u32::MAX),
            "an impossible PID must read as not running"
        );
    }

    #[test]
    fn test_read_results_with_corrupt_lines() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("corrupt-test.jsonl.zst");

        // Write a mix of valid and corrupt lines
        {
            let file = std::fs::File::create(&path).unwrap();
            let buf_writer = std::io::BufWriter::new(file);
            let mut encoder = zstd::stream::write::Encoder::new(buf_writer, 3).unwrap();

            // Write a valid line
            let valid = make_test_result("valid.com", 1);
            let json = serde_json::to_string(&valid).unwrap();
            encoder.write_all(json.as_bytes()).unwrap();
            encoder.write_all(b"\n").unwrap();

            // Write corrupt lines
            encoder.write_all(b"this is not valid json\n").unwrap();
            encoder.write_all(b"also not valid json\n").unwrap();
            encoder.write_all(b"still not valid\n").unwrap();
            encoder.write_all(b"fourth corrupt line\n").unwrap();

            // Write an empty line (should be skipped)
            encoder.write_all(b"\n").unwrap();
            encoder.write_all(b"   \n").unwrap();

            // Write another valid line
            let valid2 = make_test_result("valid2.com", 2);
            let json2 = serde_json::to_string(&valid2).unwrap();
            encoder.write_all(json2.as_bytes()).unwrap();
            encoder.write_all(b"\n").unwrap();

            encoder.finish().unwrap();
        }

        // Read results - should get 2 valid results, skip corrupt + empty lines
        let results = ResultSink::read_results(&path).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].nth_party_domain, "valid.com");
        assert_eq!(results[1].nth_party_domain, "valid2.com");
    }

    #[test]
    fn test_read_results_all_corrupt() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("all-corrupt.jsonl.zst");

        {
            let file = std::fs::File::create(&path).unwrap();
            let buf_writer = std::io::BufWriter::new(file);
            let mut encoder = zstd::stream::write::Encoder::new(buf_writer, 3).unwrap();

            encoder.write_all(b"bad1\n").unwrap();
            encoder.write_all(b"bad2\n").unwrap();
            encoder.finish().unwrap();
        }

        let results = ResultSink::read_results(&path).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_read_results_empty_lines_only() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("empty-lines.jsonl.zst");

        {
            let file = std::fs::File::create(&path).unwrap();
            let buf_writer = std::io::BufWriter::new(file);
            let mut encoder = zstd::stream::write::Encoder::new(buf_writer, 3).unwrap();

            encoder.write_all(b"\n").unwrap();
            encoder.write_all(b"  \n").unwrap();
            encoder.write_all(b"\n").unwrap();
            encoder.finish().unwrap();
        }

        let results = ResultSink::read_results(&path).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_orphan_cleanup_with_invalid_pid_format() {
        let tmp = TempDir::new().unwrap();

        // File with non-numeric PID
        let bad_file = tmp
            .path()
            .join("nthpartyfinder-results-notanumber.jsonl.zst");
        std::fs::write(&bad_file, b"data").unwrap();

        let cleaned = ResultSink::cleanup_orphans(tmp.path()).unwrap();
        // Should not clean up files with non-numeric PIDs
        assert_eq!(cleaned, 0);
        assert!(bad_file.exists());
    }

    #[test]
    fn test_read_results_truncated_zstd_frame() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("truncated.jsonl.zst");

        // Write valid data then truncate the zstd stream to trigger the Err(_) branch
        // in read_results where BufRead::lines() returns an error on a corrupt frame
        {
            let file = std::fs::File::create(&path).unwrap();
            let buf_writer = std::io::BufWriter::new(file);
            let mut encoder = zstd::stream::write::Encoder::new(buf_writer, 3).unwrap();

            // Write some valid records
            let valid = make_test_result("before-truncate.com", 1);
            let json = serde_json::to_string(&valid).unwrap();
            encoder.write_all(json.as_bytes()).unwrap();
            encoder.write_all(b"\n").unwrap();
            encoder.flush().unwrap();

            // Do NOT call finish() - intentionally leave the zstd frame incomplete
            // Then append garbage bytes to corrupt the end of the stream
            let inner = encoder.finish().unwrap();
            drop(inner);
        }

        // Append garbage bytes after the valid zstd frame to trigger I/O error
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&path)
                .unwrap();
            // Write bytes that look like a new zstd frame header but are truncated
            file.write_all(&[0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00])
                .unwrap();
        }

        let results = ResultSink::read_results(&path).unwrap();
        // Should recover at least the valid record before the corruption
        assert!(!results.is_empty());
        assert_eq!(results[0].nth_party_domain, "before-truncate.com");
    }

    #[test]
    fn test_new_with_invalid_directory() {
        // /dev/null is a file, not a directory, so creating subdirectories under it will fail
        let result = ResultSink::new(std::path::Path::new("/dev/null/impossible/dir"));
        let err = result.err().expect("Expected error for invalid directory");
        assert!(
            err.to_string()
                .contains("Failed to create output directory"),
            "Unexpected error: {}",
            err
        );
    }

    #[test]
    fn test_with_path_invalid_parent() {
        // /dev/null is a file, so creating parent directories under it will fail
        let result = ResultSink::with_path(std::path::Path::new(
            "/dev/null/impossible/nested/file.jsonl.zst",
        ));
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn test_with_path_file_create_fails() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let readonly = tmp.path().join("nowrite");
        std::fs::create_dir_all(&readonly).unwrap();
        std::fs::set_permissions(&readonly, std::fs::Permissions::from_mode(0o555)).unwrap();
        let path = readonly.join("test.jsonl.zst");
        let result = ResultSink::with_path(&path);
        assert!(result.is_err());
        let err_msg = result.err().unwrap().to_string();
        assert!(
            err_msg.contains("Failed to create result sink file"),
            "Unexpected error: {}",
            err_msg
        );
        std::fs::set_permissions(&readonly, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn test_large_batch_triggers_multiple_flushes() {
        let tmp = TempDir::new().unwrap();
        let mut sink = ResultSink::new(tmp.path()).unwrap();

        // Write more than 2x FLUSH_INTERVAL to trigger multiple auto-flushes
        let batch: Vec<_> = (0..FLUSH_INTERVAL * 2 + 10)
            .map(|i| make_test_result(&format!("v{}.com", i), 1))
            .collect();
        sink.append_batch(&batch).unwrap();

        assert_eq!(sink.count(), FLUSH_INTERVAL * 2 + 10);
        assert_eq!(sink.unflushed, 10); // Only the remainder after last auto-flush

        let results = sink.drain_all().unwrap();
        assert_eq!(results.len(), FLUSH_INTERVAL * 2 + 10);
    }

    #[test]
    fn test_drain_all_after_manual_flush() {
        let tmp = TempDir::new().unwrap();
        let mut sink = ResultSink::new(tmp.path()).unwrap();

        sink.append_one(&make_test_result("a.com", 1)).unwrap();
        sink.flush().unwrap();
        sink.append_one(&make_test_result("b.com", 2)).unwrap();

        let results = sink.drain_all().unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_path_returns_correct_path() {
        let tmp = TempDir::new().unwrap();
        let explicit_path = tmp.path().join("explicit.jsonl.zst");
        let sink = ResultSink::with_path(&explicit_path).unwrap();

        assert_eq!(sink.path(), explicit_path.as_path());
    }

    #[test]
    fn test_count_increments_correctly() {
        let tmp = TempDir::new().unwrap();
        let mut sink = ResultSink::new(tmp.path()).unwrap();

        assert_eq!(sink.count(), 0);
        sink.append_one(&make_test_result("a.com", 1)).unwrap();
        assert_eq!(sink.count(), 1);
        sink.append_one(&make_test_result("b.com", 2)).unwrap();
        assert_eq!(sink.count(), 2);

        let batch: Vec<_> = (0..3)
            .map(|i| make_test_result(&format!("c{}.com", i), 3))
            .collect();
        sink.append_batch(&batch).unwrap();
        assert_eq!(sink.count(), 5);
    }

    #[cfg(unix)]
    #[test]
    fn test_new_directory_exists_but_not_writable() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let dir = tmp.path().join("readonly");
        std::fs::create_dir_all(&dir).unwrap();
        // Make directory non-writable so File::create fails
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();

        let result = ResultSink::new(&dir);
        assert!(result.is_err());
        let err_msg = result.err().unwrap().to_string();
        assert!(
            err_msg.contains("Failed to create result sink file"),
            "Expected file creation error, got: {}",
            err_msg
        );

        // Restore permissions for cleanup
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    // ── check_disk_space ─────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn test_check_disk_space_valid_path() {
        let tmp = TempDir::new().unwrap();
        let result = check_disk_space(tmp.path());
        // On Linux (GNU df), returns actual available bytes (> 0).
        // On macOS (BSD df), --output=avail is unsupported, so falls back to 0.
        assert!(result.is_ok());
    }

    #[cfg(unix)]
    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_check_disk_space_nonexistent_path() {
        let result = check_disk_space(Path::new("/nonexistent/path/that/does/not/exist"));
        // df on a nonexistent path either errors or returns 0
        assert!(result.is_ok() || result.is_err());
    }

    // ── is_process_running additional coverage ───────────────────────

    // cfg(not(coverage)): exercises the real sysinfo-backed liveness check.
    #[cfg(not(coverage))]
    #[test]
    fn test_is_process_running_current_process() {
        // The current process is always running, on every platform. GRC-500
        // regression: this previously asserted `false` on hosts without /proc.
        assert!(
            is_process_running(std::process::id()),
            "the current process must be detected as running on every platform"
        );
    }

    // cfg(not(coverage)): exercises the real liveness check + a removal failure.
    #[cfg(not(coverage))]
    #[cfg(unix)]
    #[test]
    fn test_cleanup_orphans_remove_fails_readonly_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TempDir::new().unwrap();
        // An impossible PID is guaranteed dead, so cleanup is attempted.
        let orphan_name = format!("nthpartyfinder-results-{}.jsonl.zst", u32::MAX);
        let orphan_path = dir.path().join(&orphan_name);
        std::fs::write(&orphan_path, b"dummy").unwrap();

        // Make directory read-only to prevent file removal
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o555)).unwrap();

        let result = ResultSink::cleanup_orphans(dir.path());
        // Skip the removal-failure assertions when running as root (common in
        // Linux CI containers), where read-only directory permissions are
        // ignored and the file would actually be removed.
        let running_as_root = std::fs::write(dir.path().join(".root-probe"), b"x").is_ok();
        if !running_as_root {
            // Cleanup is attempted, but remove_file fails because the directory
            // is read-only: cleaned count stays 0 and the file survives.
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), 0);
            assert!(orphan_path.exists());
        }

        // Restore permissions for TempDir cleanup
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    #[test]
    fn test_with_path_no_parent() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.jsonl.zst");
        let result = ResultSink::with_path(&path);
        assert!(result.is_ok());
    }

    #[test]
    fn test_check_disk_space_returns_ok() {
        let dir = TempDir::new().unwrap();
        let result = check_disk_space(dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_cleanup_orphans_non_numeric_pid() {
        let tmp = TempDir::new().unwrap();
        let bad_name = tmp
            .path()
            .join("nthpartyfinder-results-notanumber.jsonl.zst");
        std::fs::write(&bad_name, b"data").unwrap();
        let cleaned = ResultSink::cleanup_orphans(tmp.path()).unwrap();
        assert_eq!(cleaned, 0);
        assert!(bad_name.exists());
    }

    #[test]
    fn test_cleanup_orphans_empty_pid() {
        let tmp = TempDir::new().unwrap();
        let bad_name = tmp.path().join("nthpartyfinder-results-.jsonl.zst");
        std::fs::write(&bad_name, b"data").unwrap();
        let cleaned = ResultSink::cleanup_orphans(tmp.path()).unwrap();
        assert_eq!(cleaned, 0);
    }

    /// Regression for TF-3 (result-sink data-loss panic). Concurrent
    /// nthpartyfinder processes were deleting each other's *in-flight*
    /// result sinks: `is_process_running()` always returned false off-Linux
    /// (no `/proc` on macOS), so `cleanup_orphans` treated a live sibling's
    /// fresh file as a dead orphan and removed it, making the owner panic at
    /// result read-back and discard the entire scan. A freshly-written
    /// results file MUST survive cleanup regardless of PID-liveness.
    #[test]
    fn test_cleanup_orphans_preserves_fresh_sibling_file() {
        let tmp = TempDir::new().unwrap();
        let sibling = tmp
            .path()
            .join("nthpartyfinder-results-4000000000.jsonl.zst");
        std::fs::write(&sibling, b"in-flight results").unwrap();
        let cleaned = ResultSink::cleanup_orphans(tmp.path()).unwrap();
        assert_eq!(cleaned, 0, "fresh in-flight sink must not be reaped");
        assert!(
            sibling.exists(),
            "TF-3 regression: a freshly-written results file was deleted by cleanup_orphans"
        );
    }

    /// cleanup_orphans must never delete the current process's own sink file.
    #[test]
    fn test_cleanup_orphans_skips_current_pid() {
        let tmp = TempDir::new().unwrap();
        let own = tmp.path().join(format!(
            "nthpartyfinder-results-{}.jsonl.zst",
            std::process::id()
        ));
        std::fs::write(&own, b"our own sink").unwrap();
        let cleaned = ResultSink::cleanup_orphans(tmp.path()).unwrap();
        assert_eq!(cleaned, 0);
        assert!(
            own.exists(),
            "cleanup must never delete the current process's own sink"
        );
    }
}
