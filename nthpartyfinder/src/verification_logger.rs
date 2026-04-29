use crate::dns::LogFailure;
use chrono::Utc;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use tracing::warn;

/// Logger for verification records that couldn't be properly inferred to valid domains
pub struct VerificationFailureLogger {
    file_path: String,
    writer: Mutex<Option<std::fs::File>>,
    enabled: bool,
}

impl VerificationFailureLogger {
    /// Create a new verification failure logger
    pub fn new(output_dir: &str, domain: &str, enabled: bool) -> Self {
        let file_path = if enabled {
            let timestamp = Utc::now().format("%Y%m%d_%H%M%S");
            Path::new(output_dir)
                .join(format!(
                    "verification_failures_{}_{}.csv",
                    domain.replace(".", "_"),
                    timestamp
                ))
                .to_string_lossy()
                .to_string()
        } else {
            String::new()
        };

        Self {
            file_path,
            writer: Mutex::new(None),
            enabled,
        }
    }

    /// Initialize the log file with header
    pub fn initialize(&self) -> Result<(), Box<dyn std::error::Error>> {
        if !self.enabled {
            return Ok(());
        }

        let mut writer_guard = self.writer.lock().unwrap();
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.file_path)?;

        let mut file_writer = file;
        writeln!(
            file_writer,
            "Timestamp,Source Domain,Record Type,Raw Record,Extracted Service,Failure Reason"
        )?;

        *writer_guard = Some(file_writer);
        Ok(())
    }

    /// Log a failed verification record inference
    pub fn log_failure(
        &self,
        source_domain: &str,
        record_type: &str,
        raw_record: &str,
        extracted_service: Option<&str>,
        failure_reason: &str,
    ) {
        if !self.enabled {
            return;
        }

        let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
        let service_str = extracted_service.unwrap_or("N/A");

        // Escape CSV fields that contain commas, quotes, or newlines
        let log_line = format!(
            "{},{},{},\"{}\",{},\"{}\"\n",
            timestamp,
            source_domain,
            record_type,
            raw_record.replace("\"", "\"\""), // Escape quotes by doubling them
            service_str,
            failure_reason.replace("\"", "\"\"") // Escape quotes by doubling them
        );

        // Try to write to file with non-blocking approach
        if let Ok(mut writer_guard) = self.writer.try_lock() {
            if let Some(ref mut file) = *writer_guard {
                if let Err(e) = file.write_all(log_line.as_bytes()) {
                    warn!("Failed to write to verification failure log: {}", e);
                }
                // Don't flush immediately to avoid blocking - let OS handle it
            }
        }
        // If lock is contended, skip logging to avoid blocking parallel operations
    }

    /// Close the log file
    pub fn close(&self) {
        if !self.enabled {
            return;
        }

        if let Ok(mut writer_guard) = self.writer.lock() {
            if let Some(ref mut file) = *writer_guard {
                let _ = file.flush();
            }
            *writer_guard = None;
        }
    }

    pub fn get_file_path(&self) -> &str {
        &self.file_path
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

impl LogFailure for VerificationFailureLogger {
    fn log_failure(
        &self,
        source_domain: &str,
        record_type: &str,
        raw_record: &str,
        extracted_service: Option<&str>,
        failure_reason: &str,
    ) {
        self.log_failure(
            source_domain,
            record_type,
            raw_record,
            extracted_service,
            failure_reason,
        );
    }
}

impl Drop for VerificationFailureLogger {
    fn drop(&mut self) {
        self.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::LogFailure;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn new_enabled_creates_file_path() {
        let dir = tempdir().unwrap();
        let logger = VerificationFailureLogger::new(dir.path().to_str().unwrap(), "example.com", true);
        assert!(logger.is_enabled());
        let path = logger.get_file_path();
        assert!(path.contains("verification_failures_example_com_"));
        assert!(path.ends_with(".csv"));
        assert!(path.starts_with(dir.path().to_str().unwrap()));
    }

    #[test]
    fn new_disabled_has_empty_path() {
        let logger = VerificationFailureLogger::new("/tmp", "example.com", false);
        assert!(!logger.is_enabled());
        assert_eq!(logger.get_file_path(), "");
    }

    #[test]
    fn initialize_when_disabled_is_noop() {
        let logger = VerificationFailureLogger::new("/tmp", "example.com", false);
        let result = logger.initialize();
        assert!(result.is_ok());
    }

    #[test]
    fn initialize_creates_file_with_headers() {
        let dir = tempdir().unwrap();
        let logger = VerificationFailureLogger::new(dir.path().to_str().unwrap(), "test.org", true);
        logger.initialize().unwrap();

        let contents = fs::read_to_string(logger.get_file_path()).unwrap();
        assert_eq!(
            contents.trim(),
            "Timestamp,Source Domain,Record Type,Raw Record,Extracted Service,Failure Reason"
        );
    }

    #[test]
    fn log_failure_writes_csv_entry() {
        let dir = tempdir().unwrap();
        let logger = VerificationFailureLogger::new(dir.path().to_str().unwrap(), "test.org", true);
        logger.initialize().unwrap();

        logger.log_failure("test.org", "TXT", "v=spf1 include:example.com", Some("example"), "unknown pattern");

        logger.close();

        let contents = fs::read_to_string(logger.get_file_path()).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2); // header + 1 entry
        let data_line = lines[1];
        assert!(data_line.contains("test.org"));
        assert!(data_line.contains("TXT"));
        assert!(data_line.contains("v=spf1 include:example.com"));
        assert!(data_line.contains("example"));
        assert!(data_line.contains("unknown pattern"));
    }

    #[test]
    fn log_failure_with_none_service() {
        let dir = tempdir().unwrap();
        let logger = VerificationFailureLogger::new(dir.path().to_str().unwrap(), "test.org", true);
        logger.initialize().unwrap();

        logger.log_failure("test.org", "TXT", "some record", None, "reason");
        logger.close();

        let contents = fs::read_to_string(logger.get_file_path()).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[1].contains("N/A"));
    }

    #[test]
    fn log_failure_when_disabled_does_nothing() {
        let logger = VerificationFailureLogger::new("/tmp", "test.org", false);
        // Should not panic or create any file
        logger.log_failure("test.org", "TXT", "record", Some("svc"), "reason");
    }

    #[test]
    fn csv_escaping_quotes() {
        let dir = tempdir().unwrap();
        let logger = VerificationFailureLogger::new(dir.path().to_str().unwrap(), "test.org", true);
        logger.initialize().unwrap();

        logger.log_failure(
            "test.org",
            "TXT",
            "record with \"quotes\" inside",
            Some("svc"),
            "reason with \"more quotes\"",
        );
        logger.close();

        let contents = fs::read_to_string(logger.get_file_path()).unwrap();
        // Quotes should be doubled for CSV escaping
        assert!(contents.contains("\"\"quotes\"\""));
        assert!(contents.contains("\"\"more quotes\"\""));
    }

    #[test]
    fn csv_escaping_commas_and_newlines() {
        let dir = tempdir().unwrap();
        let logger = VerificationFailureLogger::new(dir.path().to_str().unwrap(), "test.org", true);
        logger.initialize().unwrap();

        logger.log_failure(
            "test.org",
            "TXT",
            "record, with commas",
            Some("svc"),
            "reason\nwith newline",
        );
        logger.close();

        let contents = fs::read_to_string(logger.get_file_path()).unwrap();
        // The raw record and failure reason are wrapped in quotes
        assert!(contents.contains("\"record, with commas\""));
        assert!(contents.contains("\"reason\nwith newline\""));
    }

    #[test]
    fn close_when_disabled_is_noop() {
        let logger = VerificationFailureLogger::new("/tmp", "test.org", false);
        logger.close(); // should not panic
    }

    #[test]
    fn close_flushes_and_drops_writer() {
        let dir = tempdir().unwrap();
        let logger = VerificationFailureLogger::new(dir.path().to_str().unwrap(), "test.org", true);
        logger.initialize().unwrap();
        logger.log_failure("d", "TXT", "rec", Some("s"), "r");
        logger.close();

        // Writer should be None after close
        let guard = logger.writer.lock().unwrap();
        assert!(guard.is_none());
    }

    #[test]
    fn multiple_log_entries() {
        let dir = tempdir().unwrap();
        let logger = VerificationFailureLogger::new(dir.path().to_str().unwrap(), "test.org", true);
        logger.initialize().unwrap();

        for i in 0..5 {
            logger.log_failure(
                &format!("domain{}.org", i),
                "TXT",
                &format!("record {}", i),
                Some("svc"),
                &format!("reason {}", i),
            );
        }
        logger.close();

        let contents = fs::read_to_string(logger.get_file_path()).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 6); // header + 5 entries
    }

    #[test]
    fn log_failure_trait_impl_works() {
        let dir = tempdir().unwrap();
        let logger = VerificationFailureLogger::new(dir.path().to_str().unwrap(), "test.org", true);
        logger.initialize().unwrap();

        // Use the trait method explicitly
        LogFailure::log_failure(
            &logger,
            "test.org",
            "MX",
            "mx.example.com",
            Some("example"),
            "not recognized",
        );
        logger.close();

        let contents = fs::read_to_string(logger.get_file_path()).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[1].contains("MX"));
        assert!(lines[1].contains("mx.example.com"));
    }

    #[test]
    fn drop_impl_flushes() {
        let dir = tempdir().unwrap();
        let file_path;
        {
            let logger = VerificationFailureLogger::new(dir.path().to_str().unwrap(), "test.org", true);
            file_path = logger.get_file_path().to_string();
            logger.initialize().unwrap();
            logger.log_failure("test.org", "TXT", "rec", None, "reason");
            // logger is dropped here
        }

        let contents = fs::read_to_string(&file_path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2);
    }

    #[test]
    fn domain_with_dots_replaced_in_filename() {
        let dir = tempdir().unwrap();
        let logger = VerificationFailureLogger::new(dir.path().to_str().unwrap(), "sub.domain.example.com", true);
        let path = logger.get_file_path();
        assert!(path.contains("sub_domain_example_com"));
        assert!(!path.contains("sub.domain.example.com"));
    }

    #[test]
    fn is_enabled_returns_correct_values() {
        let dir = tempdir().unwrap();
        let enabled = VerificationFailureLogger::new(dir.path().to_str().unwrap(), "x.com", true);
        let disabled = VerificationFailureLogger::new(dir.path().to_str().unwrap(), "x.com", false);
        assert!(enabled.is_enabled());
        assert!(!disabled.is_enabled());
    }

    #[test]
    fn get_file_path_returns_correct_path() {
        let dir = tempdir().unwrap();
        let logger = VerificationFailureLogger::new(dir.path().to_str().unwrap(), "x.com", true);
        let path = logger.get_file_path();
        assert!(path.starts_with(dir.path().to_str().unwrap()));
        assert!(path.contains("verification_failures_x_com_"));
    }
}
