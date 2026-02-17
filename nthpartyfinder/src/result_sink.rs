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

pub struct ResultSink {
    writer: zstd::stream::write::Encoder<'static, BufWriter<File>>,
    path: PathBuf,
    count: usize,
    unflushed: usize,
}

impl ResultSink {
    /// Create a new ResultSink writing to a zstd-compressed JSONL file.
    /// The file is created in the given directory with a PID-stamped name.
    pub fn new(output_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(output_dir)
            .with_context(|| format!("Failed to create output directory: {}", output_dir.display()))?;

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

    /// Create a ResultSink at a specific path (for testing or explicit path control).
    pub fn with_path(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create parent directory: {}", parent.display()))?;
        }

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
    pub fn append_one(&mut self, result: &VendorRelationship) -> Result<()> {
        let json = serde_json::to_string(result)
            .context("Failed to serialize VendorRelationship")?;
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
    pub fn append_batch(&mut self, results: &[VendorRelationship]) -> Result<usize> {
        for result in results {
            self.append_one(result)?;
        }
        Ok(results.len())
    }

    /// Flush the zstd encoder to ensure data is written to disk.
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush().context("Failed to flush zstd encoder")?;
        self.unflushed = 0;
        Ok(())
    }

    /// Finalize the zstd stream and return all results by reading back the file.
    /// This consumes the ResultSink.
    pub fn drain_all(mut self) -> Result<Vec<VendorRelationship>> {
        // Flush any remaining data
        self.flush()?;

        // Finalize the zstd stream (writes the end-of-frame marker)
        self.writer.finish()
            .context("Failed to finalize zstd stream")?;

        // Read back all results
        Self::read_results(&self.path)
    }

    /// Read results from a zstd-compressed JSONL file.
    /// Uses a tolerant parser that skips corrupt lines (crash recovery).
    pub fn read_results(path: &Path) -> Result<Vec<VendorRelationship>> {
        let file = File::open(path)
            .with_context(|| format!("Failed to open result file: {}", path.display()))?;
        let decoder = zstd::stream::read::Decoder::new(file)
            .context("Failed to create zstd decoder")?;
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
                                eprintln!("Warning: Skipping corrupt line {} in {}: {}",
                                    line_num + 1, path.display(), e);
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
            eprintln!("Warning: {} total corrupt lines skipped in {}", errors, path.display());
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

    /// Clean up orphaned result sink files from previous runs.
    /// Removes any nthpartyfinder-results-*.jsonl.zst files that don't belong
    /// to a currently running process.
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
                        // Check if this PID is still running
                        if !is_process_running(pid) {
                            if let Err(e) = std::fs::remove_file(entry.path()) {
                                eprintln!("Warning: Failed to clean up orphaned file {}: {}", entry.path().display(), e);
                            } else {
                                cleaned += 1;
                            }
                        }
                    }
                }
            }
        }

        Ok(cleaned)
    }
}

/// Check if a process with the given PID is currently running.
fn is_process_running(pid: u32) -> bool {
    // On Unix-like systems (including WSL), check /proc/{pid}
    Path::new(&format!("/proc/{}", pid)).exists()
}

/// Check available disk space at the given path, returning bytes free.
pub fn check_disk_space(path: &Path) -> Result<u64> {
    // Use the `df` approach via statvfs on Linux
    #[cfg(unix)]
    {
        // Shell out to df for available space
        let output = std::process::Command::new("df")
            .arg("--output=avail")
            .arg("-B1")
            .arg(path)
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
        // On Windows, return a large default (we're typically running in WSL anyway)
        Ok(u64::MAX)
    }
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
            sink.append_one(&make_test_result(&format!("v{}.com", i), 1)).unwrap();
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
        let tmp = TempDir::new().unwrap();

        // Create a fake orphan file with a non-existent PID
        let orphan_path = tmp.path().join("nthpartyfinder-results-999999.jsonl.zst");
        std::fs::write(&orphan_path, b"fake data").unwrap();
        assert!(orphan_path.exists());

        let cleaned = ResultSink::cleanup_orphans(tmp.path()).unwrap();
        assert_eq!(cleaned, 1);
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
}
