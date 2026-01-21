use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use chrono::Utc;
use tracing::warn;
use crate::dns::LogFailure;

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
                .join(format!("verification_failures_{}_{}.csv", domain.replace(".", "_"), timestamp))
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
        writeln!(file_writer, "Timestamp,Source Domain,Record Type,Raw Record,Extracted Service,Failure Reason")?;

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
            failure_reason.replace("\"", "\"\"")  // Escape quotes by doubling them
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
    fn log_failure(&self, source_domain: &str, record_type: &str, raw_record: &str, extracted_service: Option<&str>, failure_reason: &str) {
        self.log_failure(source_domain, record_type, raw_record, extracted_service, failure_reason);
    }
}

impl Drop for VerificationFailureLogger {
    fn drop(&mut self) {
        self.close();
    }
}