//! Runtime fetch + SHA-256 verification of the GLiNER NER model.
//!
//! When the crate is built with the `runtime-ner` feature (the default), the
//! ~183 MB GLiNER model is NOT embedded in the binary. Instead it is fetched at
//! runtime from our own GitHub release, verified against compiled-in SHA-256
//! anchors, and cached on disk. This keeps the published crate small enough for
//! crates.io and for `cargo install` without shipping a 175 MB blob.
//!
//! Security invariants (no exceptions):
//!   * Downloads happen only over HTTPS from `github.com` — any other scheme or
//!     host is rejected before a request is made.
//!   * Every byte is hashed (SHA-256) and compared to a compiled-in expected
//!     digest. A mismatch deletes the partial file and returns an error; we never
//!     keep or load unverified bytes.
//!   * All writes are confined to the cache directory (filenames are fixed
//!     compile-time constants, never attacker-controlled).
//!   * No shell-out: pure `reqwest` + `sha2`.
//!   * Failures are typed and recoverable — the caller degrades to "NER disabled",
//!     never a panic.

#![cfg(feature = "runtime-ner")]

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Base URL for the model assets (our GitHub release).
pub const MODEL_BASE_URL: &str =
    "https://github.com/grcengineering/nthpartyfinder/releases/download/model-gliner-small-v1/";

/// The only host we will ever download model files from.
const ALLOWED_HOST: &str = "github.com";

/// Cache subdirectory under `dirs::cache_dir()`.
const CACHE_SUBDIR: &str = "nthpartyfinder/models/gliner-small-v1";

/// A single model file we must fetch and verify.
#[derive(Debug, Clone, Copy)]
pub struct ModelFile {
    /// Filename on disk and last path segment of the download URL.
    pub name: &'static str,
    /// Lowercase hex SHA-256 of the verified file contents.
    pub sha256: &'static str,
    /// Expected size in bytes (used as a cheap pre-check before hashing).
    pub size: u64,
}

/// The three files that make up the GLiNER small model, with their integrity
/// anchors. These digests are the trust root for the runtime fetch.
pub const MODEL_FILES: [ModelFile; 3] = [
    ModelFile {
        name: "gliner_small.onnx",
        sha256: "c76c90920547fd937aaf505e7f2de5ec73168bf1c25abbb55a298104cb061400",
        size: 183_403_734,
    },
    ModelFile {
        name: "tokenizer.json",
        sha256: "677203884d026e721115cf0daccf70ec4239545a13d6619e3e66d7151e0c9ce3",
        size: 8_657_198,
    },
    ModelFile {
        name: "config.json",
        sha256: "8aece71b73ca0fbd6dd121ad755deb736e7757d053ced523c2e4959ff446d3f5",
        size: 28,
    },
];

/// Errors from model fetching / verification. The caller degrades gracefully on
/// any of these (NER disabled); none of them are panics.
#[derive(Debug, Error)]
pub enum ModelFetchError {
    #[error("could not determine a cache directory for the model")]
    NoCacheDir,
    #[error("invalid download URL '{url}': {reason}")]
    InvalidUrl { url: String, reason: String },
    #[error("network error fetching {name}: {source}")]
    Network {
        name: &'static str,
        #[source]
        source: reqwest::Error,
    },
    #[error("HTTP {status} fetching {name}")]
    HttpStatus { name: &'static str, status: u16 },
    #[error("filesystem error for {name}: {source}")]
    Io {
        name: &'static str,
        #[source]
        source: std::io::Error,
    },
    #[error("SHA-256 mismatch for {name}: expected {expected}, got {actual}")]
    Sha256Mismatch {
        name: &'static str,
        expected: &'static str,
        actual: String,
    },
}

// ── Pure helpers (testable without network or filesystem) ────────────────────

/// Build the full download URL for a file given a base URL.
fn join_url(base: &str, name: &str) -> String {
    if base.ends_with('/') {
        format!("{base}{name}")
    } else {
        format!("{base}/{name}")
    }
}

/// Reject anything that is not HTTPS to `github.com` (or its subdomains). The
/// release-asset redirect target is also on a github.com-controlled host, but we
/// only ever issue the *initial* request to this base URL, so validating the base
/// host is the security boundary that matters here.
fn validate_url(url: &str) -> Result<(), ModelFetchError> {
    let parsed = url::Url::parse(url).map_err(|e| ModelFetchError::InvalidUrl {
        url: url.to_string(),
        reason: e.to_string(),
    })?;

    if parsed.scheme() != "https" {
        return Err(ModelFetchError::InvalidUrl {
            url: url.to_string(),
            reason: format!("scheme must be https, got '{}'", parsed.scheme()),
        });
    }

    let host = parsed
        .host_str()
        .ok_or_else(|| ModelFetchError::InvalidUrl {
            url: url.to_string(),
            reason: "missing host".to_string(),
        })?;

    let host_ok = host == ALLOWED_HOST || host.ends_with(&format!(".{ALLOWED_HOST}"));
    if !host_ok {
        return Err(ModelFetchError::InvalidUrl {
            url: url.to_string(),
            reason: format!("host must be {ALLOWED_HOST}, got '{host}'"),
        });
    }

    Ok(())
}

/// Compute the lowercase hex SHA-256 of a file's contents, streaming it in
/// chunks so we never hold a 183 MB buffer in memory.
fn sha256_file(path: &Path) -> std::io::Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

// ── Cache-location accessors ─────────────────────────────────────────────────

/// Directory where the verified model files live (and where temp files are
/// staged). May not exist yet.
pub fn model_cache_dir() -> Result<PathBuf, ModelFetchError> {
    let base = dirs::cache_dir().ok_or(ModelFetchError::NoCacheDir)?;
    Ok(base.join(CACHE_SUBDIR))
}

/// Path GLiNER loads the model from — same as the cache dir; the three files
/// (`gliner_small.onnx`, `tokenizer.json`, `config.json`) live directly inside.
pub fn model_dir_path() -> Result<PathBuf, ModelFetchError> {
    model_cache_dir()
}

/// True iff all three files are present in the cache AND each re-hashes to its
/// compiled-in expected SHA-256. A size mismatch or hash mismatch returns false
/// (the caller will re-download).
pub fn is_model_cached_and_valid() -> bool {
    let dir = match model_cache_dir() {
        Ok(d) => d,
        Err(_) => return false,
    };
    is_dir_cached_and_valid(&dir)
}

/// Inner form of [`is_model_cached_and_valid`] parameterised on the directory so
/// it is testable against a temp dir.
fn is_dir_cached_and_valid(dir: &Path) -> bool {
    dir_has_valid_files(dir, &MODEL_FILES)
}

/// True iff every file in `files` exists in `dir` with the expected size AND a
/// matching SHA-256. Parameterised on the file table so tests can exercise the
/// real all-valid path with small fixtures (the const [`MODEL_FILES`] sizes are
/// too large to materialise in a unit test).
fn dir_has_valid_files(dir: &Path, files: &[ModelFile]) -> bool {
    for file in files {
        let path = dir.join(file.name);
        let meta = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(_) => return false,
        };
        if meta.len() != file.size {
            return false;
        }
        match sha256_file(&path) {
            Ok(actual) if actual == file.sha256 => {}
            _ => return false,
        }
    }
    true
}

// ── Download + verify ────────────────────────────────────────────────────────

/// Fetch every model file from the real GitHub release, verify each against its
/// compiled-in SHA-256, and atomically place it in the cache dir. On any failure
/// returns a typed error; partially-downloaded temp files are removed.
pub async fn download_and_verify() -> Result<PathBuf, ModelFetchError> {
    let dir = model_cache_dir()?;
    download_and_verify_into(MODEL_BASE_URL, &dir, &MODEL_FILES).await
}

/// Download routine, parameterised on base URL, destination directory, and file
/// table. This is the security boundary: it validates EVERY file's URL (HTTPS +
/// github.com) up front, then delegates the actual bytes-to-disk work to
/// [`stream_files_into`]. The split lets hermetic tests drive the streaming core
/// against a localhost mock while this function's host/scheme validation is
/// asserted directly — production code can never reach the streaming core with an
/// unvalidated URL.
pub async fn download_and_verify_into(
    base_url: &str,
    dest_dir: &Path,
    files: &[ModelFile],
) -> Result<PathBuf, ModelFetchError> {
    for file in files {
        validate_url(&join_url(base_url, file.name))?;
    }
    stream_files_into(base_url, dest_dir, files).await
}

/// Stream every file's body to a temp file inside `dest_dir`, hashing while
/// streaming; on a SHA-256 match atomically rename temp → final, otherwise delete
/// the temp file and abort. Unverified bytes never become the final artifact.
///
/// Callers MUST have already validated `base_url` via [`validate_url`]
/// ([`download_and_verify_into`] does this). Filenames come from the compile-time
/// [`ModelFile`] table, so the writes are confined to `dest_dir` with no
/// attacker-controlled path components.
async fn stream_files_into(
    base_url: &str,
    dest_dir: &Path,
    files: &[ModelFile],
) -> Result<PathBuf, ModelFetchError> {
    use futures::StreamExt;
    use std::io::Write;

    std::fs::create_dir_all(dest_dir).map_err(|source| ModelFetchError::Io {
        name: "<cache dir>",
        source,
    })?;

    let client = reqwest::Client::builder()
        .build()
        .map_err(|source| ModelFetchError::Network {
            name: "<client>",
            source,
        })?;

    for file in files {
        let url = join_url(base_url, file.name);

        // Stage to a temp file confined to the destination dir. The filename is a
        // fixed compile-time constant joined to a known dir — no path traversal.
        let final_path = dest_dir.join(file.name);
        let tmp_path = dest_dir.join(format!("{}.part", file.name));

        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|source| ModelFetchError::Network {
                name: file.name,
                source,
            })?;

        if !resp.status().is_success() {
            return Err(ModelFetchError::HttpStatus {
                name: file.name,
                status: resp.status().as_u16(),
            });
        }

        let mut hasher = Sha256::new();
        {
            let mut out =
                std::fs::File::create(&tmp_path).map_err(|source| ModelFetchError::Io {
                    name: file.name,
                    source,
                })?;
            let mut stream = resp.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = match chunk {
                    Ok(c) => c,
                    Err(source) => {
                        let _ = std::fs::remove_file(&tmp_path);
                        return Err(ModelFetchError::Network {
                            name: file.name,
                            source,
                        });
                    }
                };
                hasher.update(&chunk);
                if let Err(source) = out.write_all(&chunk) {
                    let _ = std::fs::remove_file(&tmp_path);
                    return Err(ModelFetchError::Io {
                        name: file.name,
                        source,
                    });
                }
            }
            if let Err(source) = out.flush() {
                let _ = std::fs::remove_file(&tmp_path);
                return Err(ModelFetchError::Io {
                    name: file.name,
                    source,
                });
            }
        }

        let actual = hex::encode(hasher.finalize());
        if actual != file.sha256 {
            // Never keep unverified bytes.
            let _ = std::fs::remove_file(&tmp_path);
            return Err(ModelFetchError::Sha256Mismatch {
                name: file.name,
                expected: file.sha256,
                actual,
            });
        }

        std::fs::rename(&tmp_path, &final_path).map_err(|source| {
            let _ = std::fs::remove_file(&tmp_path);
            ModelFetchError::Io {
                name: file.name,
                source,
            }
        })?;
    }

    Ok(dest_dir.to_path_buf())
}

// ── Interactive consent + fetch (mirrors dep_check ONNX prompt UX) ────────────

/// Returns true if the user consented to a download prompt. Empty input (just
/// Enter) means "no" here because the model is large — mirrors the explicit
/// `[y/N]` default in the prompt text.
fn is_download_consent(input: &str) -> bool {
    let trimmed = input.trim().to_lowercase();
    trimmed == "y" || trimmed == "yes"
}

/// Ensure the model is cached + valid, prompting the operator for consent when
/// running on an interactive terminal. Behaviour:
///   * already cached + valid → Ok (no-op);
///   * `assume_yes` (e.g. `--download-ner-model`) → download without prompting;
///   * interactive TTY → prompt `[y/N]`; on yes download, on no return an error;
///   * non-interactive, no flag → return an error WITHOUT prompting (never hang).
///
/// The caller turns any `Err` into "NER disabled" + a stderr note.
pub async fn ensure_model_available(assume_yes: bool) -> Result<PathBuf, ModelFetchError> {
    if is_model_cached_and_valid() {
        return model_dir_path();
    }
    ensure_model_available_impl(assume_yes).await
}

#[cfg(not(test))]
#[cfg_attr(coverage_nightly, coverage(off))]
// coverage(off): interactive stdin prompt loop — genuinely untestable I/O. The
// consent parsing (is_download_consent), URL/host validation, hashing, atomic
// write, cache validation, and the full download_and_verify_into path are all
// covered by hermetic wiremock tests. Mirrors dep_check.rs's interactive impl.
async fn ensure_model_available_impl(assume_yes: bool) -> Result<PathBuf, ModelFetchError> {
    use std::io::IsTerminal;

    if !assume_yes {
        if !std::io::stdin().is_terminal() {
            return Err(ModelFetchError::Io {
                name: "<consent>",
                source: std::io::Error::other(
                    "NER model not installed and no consent given. \
                     Re-run with --download-ner-model to fetch it non-interactively, \
                     or --disable-slm to skip NER.",
                ),
            });
        }

        eprintln!();
        eprintln!(
            "The NER model (~183 MB, gliner_small) is not installed. \
             Download it from grcengineering/nthpartyfinder now? [y/N]"
        );
        let mut input = String::new();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|source| ModelFetchError::Io {
                name: "<consent>",
                source,
            })?;
        if !is_download_consent(&input) {
            return Err(ModelFetchError::Io {
                name: "<consent>",
                source: std::io::Error::other(
                    "NER model download declined. Use --disable-slm to skip NER.",
                ),
            });
        }
    }

    eprintln!("  Downloading NER model (~183 MB) from grcengineering/nthpartyfinder...");
    let path = download_and_verify().await?;
    eprintln!("  ✅ NER model downloaded and verified.");
    eprintln!("  Cached at: {}", path.display());
    Ok(path)
}

#[cfg(test)]
async fn ensure_model_available_impl(_assume_yes: bool) -> Result<PathBuf, ModelFetchError> {
    // In tests stdin is never a terminal and we must never hit the live network,
    // so behave like the non-interactive, no-consent branch.
    Err(ModelFetchError::Io {
        name: "<consent>",
        source: std::io::Error::other("NER model not installed and no consent given (test stub)."),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn hex_sha256(bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(bytes);
        hex::encode(h.finalize())
    }

    // Leak a String to obtain a 'static str for ModelFile.sha256/name in tests.
    fn leak(s: String) -> &'static str {
        Box::leak(s.into_boxed_str())
    }

    // ── pure helpers ────────────────────────────────────────────────────────

    #[test]
    fn test_join_url_trailing_slash() {
        assert_eq!(join_url("https://x/y/", "a.bin"), "https://x/y/a.bin");
    }

    #[test]
    fn test_join_url_no_trailing_slash() {
        assert_eq!(join_url("https://x/y", "a.bin"), "https://x/y/a.bin");
    }

    #[test]
    fn test_validate_url_accepts_github_https() {
        assert!(validate_url(MODEL_BASE_URL).is_ok());
        assert!(validate_url("https://github.com/foo/bar").is_ok());
        // Subdomains of github.com are accepted (release redirects stay on-host).
        assert!(validate_url("https://objects.github.com/x").is_ok());
    }

    #[test]
    fn test_validate_url_rejects_non_https() {
        let err = validate_url("http://github.com/x").unwrap_err();
        match err {
            ModelFetchError::InvalidUrl { reason, .. } => assert!(reason.contains("https")),
            other => panic!("expected InvalidUrl, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_url_rejects_other_host() {
        let err = validate_url("https://evil.example.com/x").unwrap_err();
        match err {
            ModelFetchError::InvalidUrl { reason, .. } => assert!(reason.contains("github.com")),
            other => panic!("expected InvalidUrl, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_url_rejects_lookalike_host() {
        // "github.com.evil.com" must NOT pass the suffix check.
        assert!(validate_url("https://github.com.evil.com/x").is_err());
        // bare "notgithub.com" must fail too.
        assert!(validate_url("https://notgithub.com/x").is_err());
    }

    #[test]
    fn test_validate_url_rejects_garbage() {
        assert!(validate_url("not a url").is_err());
        assert!(validate_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn test_validate_url_rejects_missing_host() {
        // A scheme-relative-ish / hostless https URL is rejected.
        assert!(validate_url("https:///path").is_err());
    }

    #[test]
    fn test_sha256_file_matches_known_vector() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("f.bin");
        std::fs::write(&p, b"hello world").unwrap();
        // Known SHA-256 of "hello world".
        assert_eq!(
            sha256_file(&p).unwrap(),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_model_cache_dir_and_dir_path_agree() {
        let a = model_cache_dir().unwrap();
        let b = model_dir_path().unwrap();
        assert_eq!(a, b);
        assert!(a.ends_with("gliner-small-v1"));
        assert!(a.to_string_lossy().contains("nthpartyfinder"));
    }

    #[test]
    fn test_model_files_table_is_sane() {
        assert_eq!(MODEL_FILES.len(), 3);
        for f in MODEL_FILES.iter() {
            assert_eq!(f.sha256.len(), 64, "{} sha must be 64 hex chars", f.name);
            assert!(f.sha256.chars().all(|c| c.is_ascii_hexdigit()));
            assert!(f.size > 0);
        }
        assert_eq!(MODEL_FILES[0].name, "gliner_small.onnx");
        assert_eq!(MODEL_FILES[0].size, 183_403_734);
    }

    // ── is_dir_cached_and_valid ───────────────────────────────────────────────

    #[test]
    fn test_is_dir_cached_and_valid_missing_files() {
        let dir = tempdir().unwrap();
        assert!(!is_dir_cached_and_valid(dir.path()));
    }

    #[test]
    fn test_dir_has_valid_files_happy_path() {
        let dir = tempdir().unwrap();
        // Build a fake file table whose hashes/sizes match real bytes we write,
        // then exercise the REAL validity function.
        let files: Vec<ModelFile> = vec![
            (leak("a.bin".into()), b"alpha".to_vec()),
            (leak("b.bin".into()), b"beta!".to_vec()),
        ]
        .into_iter()
        .map(|(name, bytes)| {
            std::fs::write(dir.path().join(name), &bytes).unwrap();
            ModelFile {
                name,
                sha256: leak(hex_sha256(&bytes)),
                size: bytes.len() as u64,
            }
        })
        .collect();

        assert!(dir_has_valid_files(dir.path(), &files));
    }

    #[test]
    fn test_dir_has_valid_files_size_mismatch_branch() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("a.bin"), b"alpha").unwrap();
        let files = [ModelFile {
            name: "a.bin",
            sha256: leak(hex_sha256(b"alpha")),
            size: 999, // wrong size → false before hashing
        }];
        assert!(!dir_has_valid_files(dir.path(), &files));
    }

    #[test]
    fn test_dir_has_valid_files_hash_mismatch_branch() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("a.bin"), b"alpha").unwrap();
        let files = [ModelFile {
            name: "a.bin",
            sha256: "0000000000000000000000000000000000000000000000000000000000000000",
            size: 5, // correct size, wrong hash → false at hash check
        }];
        assert!(!dir_has_valid_files(dir.path(), &files));
    }

    #[test]
    fn test_dir_has_valid_files_missing_branch() {
        let dir = tempdir().unwrap();
        let files = [ModelFile {
            name: "absent.bin",
            sha256: "0000000000000000000000000000000000000000000000000000000000000000",
            size: 1,
        }];
        assert!(!dir_has_valid_files(dir.path(), &files));
    }

    #[test]
    fn test_is_dir_cached_and_valid_size_mismatch() {
        let dir = tempdir().unwrap();
        // Write all three real model filenames but with wrong sizes/content.
        for f in MODEL_FILES.iter() {
            std::fs::write(dir.path().join(f.name), b"wrong").unwrap();
        }
        assert!(!is_dir_cached_and_valid(dir.path()));
    }

    #[test]
    fn test_is_dir_cached_and_valid_hash_mismatch_right_size() {
        let dir = tempdir().unwrap();
        // config.json is 28 bytes; write 28 bytes that hash differently.
        let twenty_eight = vec![b'x'; 28];
        std::fs::write(dir.path().join("config.json"), &twenty_eight).unwrap();
        std::fs::write(dir.path().join("tokenizer.json"), &twenty_eight).unwrap();
        std::fs::write(dir.path().join("gliner_small.onnx"), &twenty_eight).unwrap();
        assert!(!is_dir_cached_and_valid(dir.path()));
    }

    // ── download_and_verify_into (HERMETIC: wiremock, no live network) ────────

    fn run<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    #[test]
    fn test_download_and_verify_success_and_atomic_write() {
        run(async {
            let server = MockServer::start().await;
            let dir = tempdir().unwrap();

            let bytes_a = b"the onnx model bytes".to_vec();
            let bytes_b = b"{\"config\":true}".to_vec();

            Mock::given(method("GET"))
                .and(path("/model.onnx"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes_a.clone()))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/config.json"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(bytes_b.clone()))
                .mount(&server)
                .await;

            // wiremock serves on http://127.0.0.1, so for the success path we
            // drive the real streaming core (stream_files_into) against the mock.
            // Host/scheme validation is asserted separately via the public entry
            // point download_and_verify_into and validate_url tests.
            let files = [
                ModelFile {
                    name: "model.onnx",
                    sha256: leak(hex_sha256(&bytes_a)),
                    size: bytes_a.len() as u64,
                },
                ModelFile {
                    name: "config.json",
                    sha256: leak(hex_sha256(&bytes_b)),
                    size: bytes_b.len() as u64,
                },
            ];

            let out = stream_files_into(&server.uri(), dir.path(), &files)
                .await
                .expect("download should succeed");

            assert_eq!(out, dir.path());
            // Both final files exist with exact bytes; no .part files remain.
            assert_eq!(
                std::fs::read(dir.path().join("model.onnx")).unwrap(),
                bytes_a
            );
            assert_eq!(
                std::fs::read(dir.path().join("config.json")).unwrap(),
                bytes_b
            );
            assert!(!dir.path().join("model.onnx.part").exists());
            assert!(!dir.path().join("config.json.part").exists());
        });
    }

    #[test]
    fn test_download_rejects_sha_mismatch_and_deletes_temp() {
        run(async {
            let server = MockServer::start().await;
            let dir = tempdir().unwrap();
            let served = b"unexpected bytes".to_vec();

            Mock::given(method("GET"))
                .and(path("/model.onnx"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(served.clone()))
                .mount(&server)
                .await;

            let files = [ModelFile {
                name: "model.onnx",
                // Deliberately wrong digest.
                sha256: "0000000000000000000000000000000000000000000000000000000000000000",
                size: served.len() as u64,
            }];

            let err = stream_files_into(&server.uri(), dir.path(), &files)
                .await
                .expect_err("sha mismatch must error");
            match err {
                ModelFetchError::Sha256Mismatch { name, actual, .. } => {
                    assert_eq!(name, "model.onnx");
                    assert_eq!(actual, hex_sha256(&served));
                }
                other => panic!("expected Sha256Mismatch, got {other:?}"),
            }
            // Unverified bytes must NOT be retained — neither final nor temp.
            assert!(!dir.path().join("model.onnx").exists());
            assert!(!dir.path().join("model.onnx.part").exists());
        });
    }

    #[test]
    fn test_download_http_error_status() {
        run(async {
            let server = MockServer::start().await;
            let dir = tempdir().unwrap();

            Mock::given(method("GET"))
                .and(path("/model.onnx"))
                .respond_with(ResponseTemplate::new(404))
                .mount(&server)
                .await;

            let files = [ModelFile {
                name: "model.onnx",
                sha256: "0000000000000000000000000000000000000000000000000000000000000000",
                size: 1,
            }];

            let err = stream_files_into(&server.uri(), dir.path(), &files)
                .await
                .expect_err("404 must error");
            match err {
                ModelFetchError::HttpStatus { name, status } => {
                    assert_eq!(name, "model.onnx");
                    assert_eq!(status, 404);
                }
                other => panic!("expected HttpStatus, got {other:?}"),
            }
            assert!(!dir.path().join("model.onnx").exists());
        });
    }

    #[test]
    fn test_download_and_verify_into_rejects_bad_host_before_request() {
        run(async {
            let dir = tempdir().unwrap();
            // Real entry point validates host: an http/non-github base must be
            // rejected without any network access.
            let files = [ModelFile {
                name: "model.onnx",
                sha256: "0000000000000000000000000000000000000000000000000000000000000000",
                size: 1,
            }];
            let err = download_and_verify_into("https://evil.example.com/x/", dir.path(), &files)
                .await
                .expect_err("bad host must be rejected");
            assert!(matches!(err, ModelFetchError::InvalidUrl { .. }));
            assert!(!dir.path().join("model.onnx").exists());
        });
    }

    #[test]
    fn test_download_and_verify_into_rejects_http_scheme() {
        run(async {
            let dir = tempdir().unwrap();
            let files = [ModelFile {
                name: "model.onnx",
                sha256: "0000000000000000000000000000000000000000000000000000000000000000",
                size: 1,
            }];
            let err = download_and_verify_into("http://github.com/x/", dir.path(), &files)
                .await
                .expect_err("http scheme must be rejected");
            assert!(matches!(err, ModelFetchError::InvalidUrl { .. }));
        });
    }

    #[test]
    fn test_download_second_file_failure_leaves_first_committed() {
        // Verifies per-file commit semantics: a mismatch on file 2 aborts but the
        // already-verified file 1 stays (the cache-validity check will catch the
        // missing file on next run and re-fetch).
        run(async {
            let server = MockServer::start().await;
            let dir = tempdir().unwrap();
            let good = b"good bytes".to_vec();
            let bad = b"bad bytes".to_vec();

            Mock::given(method("GET"))
                .and(path("/a.bin"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(good.clone()))
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/b.bin"))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(bad.clone()))
                .mount(&server)
                .await;

            let files = [
                ModelFile {
                    name: "a.bin",
                    sha256: leak(hex_sha256(&good)),
                    size: good.len() as u64,
                },
                ModelFile {
                    name: "b.bin",
                    sha256: "1111111111111111111111111111111111111111111111111111111111111111",
                    size: bad.len() as u64,
                },
            ];

            let err = stream_files_into(&server.uri(), dir.path(), &files)
                .await
                .expect_err("second file mismatch must error");
            assert!(matches!(err, ModelFetchError::Sha256Mismatch { name, .. } if name == "b.bin"));
            // First file committed, second neither committed nor left as .part.
            assert_eq!(std::fs::read(dir.path().join("a.bin")).unwrap(), good);
            assert!(!dir.path().join("b.bin").exists());
            assert!(!dir.path().join("b.bin.part").exists());
        });
    }

    #[test]
    fn test_ensure_model_available_impl_test_stub_errors() {
        run(async {
            // The #[cfg(test)] stub never hits the network and always errors.
            assert!(ensure_model_available_impl(true).await.is_err());
            assert!(ensure_model_available_impl(false).await.is_err());
        });
    }

    #[test]
    fn test_is_download_consent() {
        assert!(is_download_consent("y"));
        assert!(is_download_consent("Y"));
        assert!(is_download_consent("yes"));
        assert!(is_download_consent("  YES \n"));
        assert!(!is_download_consent(""));
        assert!(!is_download_consent("\n"));
        assert!(!is_download_consent("n"));
        assert!(!is_download_consent("no"));
        assert!(!is_download_consent("maybe"));
    }

    #[test]
    fn test_error_display_messages() {
        let e = ModelFetchError::NoCacheDir;
        assert!(format!("{e}").contains("cache directory"));
        let e = ModelFetchError::Sha256Mismatch {
            name: "x",
            expected: "aa",
            actual: "bb".into(),
        };
        let s = format!("{e}");
        assert!(s.contains("SHA-256 mismatch"));
        assert!(s.contains("aa"));
        assert!(s.contains("bb"));
        let e = ModelFetchError::HttpStatus {
            name: "x",
            status: 500,
        };
        assert!(format!("{e}").contains("500"));
        let e = ModelFetchError::InvalidUrl {
            url: "u".into(),
            reason: "r".into(),
        };
        assert!(format!("{e}").contains("invalid download URL"));
    }

    // ── public real-cache-dir wrappers (no network) ──────────────────────────

    #[test]
    fn test_is_model_cached_and_valid_agrees_with_dir_check() {
        // The public cache check must delegate to the dir-parameterised inner check
        // against the resolved real cache dir. Env-independent: whether or not a
        // model happens to be cached, both must report the same verdict. Exercises
        // model_cache_dir() + is_model_cached_and_valid() without a 175 MB fixture.
        let dir = model_cache_dir().expect("a cache dir should be resolvable");
        assert_eq!(is_model_cached_and_valid(), is_dir_cached_and_valid(&dir));
    }

    #[test]
    fn test_ensure_model_available_dispatch_matches_cache_state() {
        // ensure_model_available must never panic and must mirror the cache state:
        // cached → Ok(model dir); not cached → routes to the impl (a no-network stub
        // in tests) and surfaces its Err. It must NOT touch the live network here.
        run(async {
            let result = ensure_model_available(false).await;
            if is_model_cached_and_valid() {
                assert!(result.is_ok());
            } else {
                assert!(result.is_err());
            }
        });
    }
}
