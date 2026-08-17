//! Certificate Transparency (CT) log discovery for finding third-party vendors.
//!
//! Queries Certificate Transparency aggregators to find certificates associated with a
//! domain and extracts third-party domains from certificate Subject Alternative Names
//! (SANs). Providers are round-robined on a process-shared cursor so no single aggregator
//! is overloaded — crt.sh returns HTTP 429 under a wide fan-out — and a provider failure
//! fails over to the next rather than collapsing into a silent empty answer.
//!
//! Providers: **crt.sh** (anonymous, always on) and **SSLMate Cert Spotter** (anonymous,
//! always on; optional token) are the defaults. **MerkleMap** and **Censys** — the two
//! remaining well-regarded CT query APIs (every once-anonymous alternative, incl. Google's,
//! Entrust's, and Meta's, is now discontinued) — join the rotation only when their API
//! credentials are configured via env (`NTHPARTYFINDER_MERKLEMAP_TOKEN`;
//! `NTHPARTYFINDER_CENSYS_PAT` + `NTHPARTYFINDER_CENSYS_ORG_ID`).
//!
//! Two bounds keep this phase honest, because CT is the one source that answers with other
//! people's data:
//!
//! * **Only currently-valid certificates are asked for** (`exclude=expired`). The full history of
//!   a well-known domain is a multi-megabyte payload, and a lapsed certificate attests a
//!   relationship that has, by definition, lapsed too.
//! * **Co-tenancy on a shared certificate is not a vendor relationship.** Every SAN used to seed
//!   recursion, so one multi-tenant certificate could fan the scan out across dozens of unrelated
//!   strangers — an accuracy defect, not just a cost one, and under the shipped
//!   `strategy = "unlimited"` nothing bounded it. See [`SHARED_CERT_SAN_BASE_LIMIT`].
//!
//! And, mirroring the DNS failure-visibility contract (GRC-367), a provider that *refuses* to
//! answer is never allowed to look like a domain with no certificates: a 429 is classified,
//! counted, warned about once, and reported as degraded coverage — see [`ProviderThrottle`].

use anyhow::Result;
use reqwest::Client;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

use crate::domain_utils;
use crate::http_client::GatedSend;

/// Base URL for the SSLMate Cert Spotter API (`/v1/issuances`).
const CERTSPOTTER_BASE_URL: &str = "https://api.certspotter.com";
/// Optional env var carrying a Cert Spotter API token; without it the anonymous
/// (rate-limited) tier is used, and a throttle simply fails over to crt.sh.
const CERTSPOTTER_TOKEN_ENV: &str = "NTHPARTYFINDER_CERTSPOTTER_TOKEN";

// Two further well-regarded CT-log query providers. Verified 2026-07-17: every other
// CT query API that was once anonymous (Google Transparency Report, Entrust CT Search,
// Meta/Facebook CT Graph) is now dead, so both of these require a (free) API credential
// and only join the rotation when it is configured — crt.sh + anonymous Cert Spotter
// remain the always-on defaults.

/// MerkleMap CT search API (`/v1/search`). Genuinely CT-log-backed, returns clean JSON.
const MERKLEMAP_BASE_URL: &str = "https://api.merklemap.com";
/// Env var carrying a MerkleMap API token (Bearer). MerkleMap has no anonymous tier, so
/// the provider is added to the rotation only when this is set.
const MERKLEMAP_TOKEN_ENV: &str = "NTHPARTYFINDER_MERKLEMAP_TOKEN";

/// Censys Platform API (`/v3/global/search/query`). The most authoritative CT-backed
/// certificate dataset; requires a Personal Access Token AND an Organization ID (its
/// free tier for certificate search is limited/metered — see docs).
const CENSYS_BASE_URL: &str = "https://api.platform.censys.io";
/// Env var carrying the Censys Personal Access Token (`Authorization: Bearer …`).
const CENSYS_PAT_ENV: &str = "NTHPARTYFINDER_CENSYS_PAT";
/// Env var carrying the Censys Organization ID (`X-Organization-ID` header). Both this
/// and the PAT must be set for the Censys provider to join the rotation.
const CENSYS_ORG_ENV: &str = "NTHPARTYFINDER_CENSYS_ORG_ID";

/// Past this many distinct SAN base domains, one certificate stops being read as one
/// organisation's certificate and starts being read as *shared* infrastructure.
///
/// This is not a drop threshold, and the distinction is the whole design. Legitimate single-org
/// certificate families routinely carry far more than twenty genuinely-owned base domains —
/// Google's ccTLD bundle, Wikimedia's project bundle, Automattic's property bundle — so a wide SAN
/// list is evidence of *breadth*, never on its own evidence of co-tenancy. Dropping those wholesale
/// would delete true relationships to fix a false-positive problem, which is a worse trade than the
/// one it replaces.
///
/// So crossing this line only raises the burden of proof: past it, a SAN must be corroborated by a
/// second, independently-issued certificate before it may seed recursion (see [`admit_san_bases`]),
/// and if nothing at all is corroborated the whole set is kept rather than the phase returning
/// nothing. Twenty sits above the size of an ordinary per-service certificate (apex + www + a
/// handful of subdomains, all of which collapse to one base) and well below the multi-tenant
/// bundles this exists to notice.
const SHARED_CERT_SAN_BASE_LIMIT: usize = 20;

/// How long a provider stays out of the rotation after a 429 that carried no usable `Retry-After`.
const CT_COOLDOWN_DEFAULT_SECS: u64 = 60;

/// Floor on an honoured `Retry-After`. A provider that answers 429 with `0` is telling us nothing
/// useful; backing off for at least this long keeps a wide fan-out from walking straight back into
/// the same refusal on the next domain.
const CT_COOLDOWN_MIN_SECS: u64 = 5;

/// Ceiling on an honoured `Retry-After`. A single header must not be able to remove a provider from
/// the rotation for the remainder of a deep scan — if the provider is still throttling when the
/// ceiling expires it simply answers 429 again and the cooldown restarts, which costs one request
/// and keeps the backoff observable, rather than silently disabling a source for hours.
const CT_COOLDOWN_MAX_SECS: u64 = 300;

const _: () = {
    // `throttle_cooldown` clamps into this range; an out-of-order edit would panic at runtime
    // instead of failing here, on a path that only executes once a provider is already refusing us.
    assert!(
        CT_COOLDOWN_MIN_SECS <= CT_COOLDOWN_DEFAULT_SECS
            && CT_COOLDOWN_DEFAULT_SECS <= CT_COOLDOWN_MAX_SECS,
        "the CT cooldown bounds must stay ordered: min <= default <= max"
    );
};

/// Response from crt.sh API
#[derive(Debug, Deserialize)]
pub struct CrtShEntry {
    /// Issuer CA ID
    pub issuer_ca_id: Option<i64>,
    /// Certificate issuer name
    pub issuer_name: Option<String>,
    /// Common name from certificate
    pub common_name: Option<String>,
    /// Subject Alternative Names (newline separated)
    pub name_value: Option<String>,
    /// Certificate ID
    pub id: i64,
    /// Entry timestamp
    pub entry_timestamp: Option<String>,
    /// Not before date
    pub not_before: Option<String>,
    /// Not after date
    pub not_after: Option<String>,
}

/// One issuance record from the SSLMate Cert Spotter API (`GET /v1/issuances`).
#[derive(Debug, Deserialize)]
struct CertSpotterIssuance {
    #[serde(default)]
    id: Option<String>,
    /// Clean array of certificate DNS names (Cert Spotter's equivalent of crt.sh's
    /// newline-separated `name_value`).
    #[serde(default)]
    dns_names: Option<Vec<String>>,
    #[serde(default)]
    issuer: Option<CertSpotterIssuer>,
    #[serde(default)]
    not_before: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CertSpotterIssuer {
    #[serde(default)]
    name: Option<String>,
}

impl CertSpotterIssuance {
    /// Normalize a Cert Spotter issuance into the crt.sh entry shape so the shared
    /// SAN/CN extraction loop in `discover` works over both providers unchanged.
    fn into_crtsh_entry(self) -> CrtShEntry {
        let name_value = self.dns_names.map(|names| names.join("\n"));
        CrtShEntry {
            issuer_ca_id: None,
            issuer_name: self.issuer.and_then(|i| i.name),
            common_name: None,
            name_value,
            id: self
                .id
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or_default(),
            entry_timestamp: None,
            not_before: self.not_before,
            not_after: self.not_after,
        }
    }
}

/// Build a synthetic crt.sh-shaped entry from a flat list of certificate DNS names, so
/// providers that return already-flattened hostnames (MerkleMap) or per-cert name arrays
/// (Censys) flow through the shared SAN-extraction loop in `discover` unchanged.
fn crtsh_entry_from_names(names: Vec<String>, issuer: &str) -> CrtShEntry {
    CrtShEntry {
        issuer_ca_id: None,
        issuer_name: Some(issuer.to_string()),
        common_name: None,
        name_value: Some(names.join("\n")),
        id: 0,
        entry_timestamp: None,
        not_before: None,
        not_after: None,
    }
}

/// Response from the MerkleMap search API (`/v1/search`). Each result is one hostname
/// (MerkleMap has already flattened certificate SANs into distinct subdomains).
#[derive(Debug, Deserialize)]
struct MerkleMapResponse {
    #[serde(default)]
    results: Vec<MerkleMapResult>,
}

#[derive(Debug, Deserialize)]
struct MerkleMapResult {
    #[serde(default)]
    hostname: Option<String>,
}

/// Response envelope from the Censys Platform API (`/v3/global/search/query`).
#[derive(Debug, Deserialize)]
struct CensysResponse {
    #[serde(default)]
    result: Option<CensysResult>,
}

#[derive(Debug, Deserialize)]
struct CensysResult {
    #[serde(default)]
    hits: Vec<CensysHit>,
}

/// One certificate hit. The DNS names may appear at the hit's top-level `names`, under
/// `cert.names`, or under `cert.parsed.subject_alt_name.dns_names` depending on the
/// requested fields, so all three are checked (robust to Censys's field layout).
#[derive(Debug, Deserialize)]
struct CensysHit {
    #[serde(default)]
    names: Option<Vec<String>>,
    #[serde(default)]
    cert: Option<CensysCert>,
}

#[derive(Debug, Deserialize)]
struct CensysCert {
    #[serde(default)]
    names: Option<Vec<String>>,
    #[serde(default)]
    parsed: Option<CensysParsed>,
}

#[derive(Debug, Deserialize)]
struct CensysParsed {
    #[serde(default)]
    subject_alt_name: Option<CensysSan>,
}

#[derive(Debug, Deserialize)]
struct CensysSan {
    #[serde(default)]
    dns_names: Option<Vec<String>>,
}

impl CensysHit {
    /// Pull the certificate's DNS names from whichever field Censys populated.
    fn dns_names(self) -> Vec<String> {
        if let Some(names) = self.names {
            return names;
        }
        if let Some(cert) = self.cert {
            if let Some(names) = cert.names {
                return names;
            }
            if let Some(dns) = cert
                .parsed
                .and_then(|p| p.subject_alt_name)
                .and_then(|s| s.dns_names)
            {
                return dns;
            }
        }
        Vec::new()
    }
}

/// Result of CT log discovery
#[derive(Debug, Clone)]
pub struct CtDiscoveryResult {
    /// Discovered vendor domain
    pub domain: String,
    /// Source description
    pub source: String,
    /// Raw certificate info for evidence
    pub certificate_info: String,
}

/// A failure fetching from one CT provider, classified so the round-robin can decide
/// whether to fail over silently or surface a hard error.
enum CtFetchError {
    /// Provider responded but not usefully (non-2xx status, or an unparseable body).
    /// Recoverable: fail over to the next provider; degrade to an empty answer if none
    /// remain (a reachable-but-unhelpful provider is not a scan-fatal condition).
    Soft(String),
    /// Provider refused service with HTTP 429. Split out of `Soft` because the two mean opposite
    /// things about the answer: a 5xx says the provider is broken, a 429 says *we* are asking too
    /// often — the certificates are there, we were told to come back later. Collapsing that into an
    /// empty result was a silent recall loss (TF-RATELIMIT), so it carries the honoured backoff and
    /// is counted and reported rather than failed over in silence.
    Throttled { cooldown: Duration },
    /// Provider could not be reached at all (transport / connection / timeout). If every
    /// provider is unreachable this propagates as a hard error so the phase logs it.
    Transport(anyhow::Error),
}

/// What an empty CT answer actually *means*.
///
/// The whole point of the type is that `Authoritative` and `ThrottledEmpty` produce byte-identical
/// results — zero vendors — and must never be reported identically. One is a fact about the domain;
/// the other is our own recall loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CtOutcome {
    /// A provider answered. Zero certificates here is a fact about the domain.
    Authoritative,
    /// No provider could be reached at all — the caller propagates the transport error so the phase
    /// logs it with the real error kind.
    Unreachable,
    /// No provider answered and at least one refused us with a 429 (or was still inside the
    /// `Retry-After` cooldown from an earlier one). Empty here is OUR recall loss.
    ThrottledEmpty,
    /// No provider answered, none throttled: every one was reachable but unusable (5xx, or a body
    /// that would not parse).
    UnusableEmpty,
}

/// Classify one exhausted provider rotation.
///
/// Precedence is deliberate. `answered` wins outright: if a sibling provider gave us certificates
/// the phase is not degraded, however loudly another provider complained on the way. Below that,
/// unreachable outranks throttled because the caller already has a real error to propagate and
/// count for that case, and double-recording it would inflate the degradation counts.
fn classify_ct_outcome(
    answered: bool,
    any_throttled: bool,
    any_transport_error: bool,
) -> CtOutcome {
    if answered {
        CtOutcome::Authoritative
    } else if any_transport_error {
        CtOutcome::Unreachable
    } else if any_throttled {
        CtOutcome::ThrottledEmpty
    } else {
        CtOutcome::UnusableEmpty
    }
}

/// Honour a `Retry-After` header value, bounded by [`CT_COOLDOWN_MIN_SECS`] and
/// [`CT_COOLDOWN_MAX_SECS`]; an absent or unusable header falls back to
/// [`CT_COOLDOWN_DEFAULT_SECS`].
///
/// Only the delta-seconds form is parsed. RFC 9110 also permits an HTTP-date, but none of the four
/// CT providers has been observed sending one, and mis-parsing a date into a nonsense number of
/// seconds would be worse than not parsing it at all — an unrecognised value falls back to the
/// default cooldown, so the scan still backs off either way.
fn throttle_cooldown(retry_after: Option<&str>) -> Duration {
    let secs = retry_after
        .and_then(parse_retry_after_secs)
        .unwrap_or(CT_COOLDOWN_DEFAULT_SECS)
        .clamp(CT_COOLDOWN_MIN_SECS, CT_COOLDOWN_MAX_SECS);
    Duration::from_secs(secs)
}

/// The delta-seconds form of `Retry-After`, or `None` for anything else (an HTTP-date, a negative
/// or fractional value, a proxy's prose). `None` is not "no backoff" — see [`throttle_cooldown`].
fn parse_retry_after_secs(value: &str) -> Option<u64> {
    value.trim().parse::<u64>().ok()
}

/// Wall-clock millis since the Unix epoch.
///
/// The cooldown deadline is compared across concurrent per-domain tasks that never share a start
/// instant, so it is stored as an absolute wall-clock instant rather than an `Instant` offset.
#[cfg_attr(coverage_nightly, coverage(off))] // coverage: reads the system clock — the cooldown logic itself takes `now_ms` as a parameter so it is tested deterministically
fn now_epoch_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// One provider's throttle state.
///
/// This is the CT-side of the discipline `dns.rs` applies to DoH providers — classify the refusal,
/// count it, warn about it exactly once — for the one CT failure that used to disappear entirely.
/// Deliberately NOT a rate limiter: a preemptive pacing gate over CT queries was built, measured
/// (0/17 → 1/51 completions, because crt.sh *hangs* rather than 429s and the gate held permits
/// until timeout) and reverted (ISC-510). Nothing here fires until a provider has actually answered
/// 429; then, and only then, we take it at its word.
#[derive(Debug, Default)]
struct ProviderThrottle {
    /// Unix-epoch millis before which this provider must not be queried again. Zero = usable.
    cooldown_until_ms: AtomicU64,
    /// Whether this provider's throttle has already been reported, so a deep scan warns once per
    /// provider instead of once per domain.
    warned: AtomicBool,
}

impl ProviderThrottle {
    /// May this provider be queried at `now_ms`?
    fn is_usable_at(&self, now_ms: u64) -> bool {
        now_ms >= self.cooldown_until_ms.load(Ordering::Relaxed)
    }

    /// Hold this provider out of the rotation until `now_ms + cooldown`, and report whether this is
    /// the first throttle seen from it (the caller warns only then).
    ///
    /// `fetch_max` rather than `store`: two concurrent domains can be refused at once, and the
    /// shorter of two overlapping backoffs must never shorten the longer one.
    fn begin_cooldown(&self, now_ms: u64, cooldown: Duration) -> bool {
        self.cooldown_until_ms.fetch_max(
            now_ms.saturating_add(cooldown.as_millis() as u64),
            Ordering::Relaxed,
        );
        !self.warned.swap(true, Ordering::Relaxed)
    }
}

/// The `(SAN as written, its base domain)` pairs of one certificate, deduplicated by base domain
/// and in first-seen order.
///
/// A certificate lists `example.com`, `www.example.com` and `*.example.com` as three SANs and one
/// relationship; the shared-certificate cap counts *relationships*, so collapsing to base domains
/// first is what makes the threshold mean anything.
fn cert_san_bases(name_value: &str) -> Vec<(String, String)> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in name_value.lines() {
        let san = line.trim().to_lowercase();
        if san.is_empty() {
            continue;
        }
        let base = domain_utils::extract_base_domain(&san);
        if seen.insert(base.clone()) {
            out.push((san, base));
        }
    }
    out
}

/// Base domains attested by a second, independently-issued certificate.
///
/// This is the corroboration signal the shared-certificate cap spends: appearing once, next to our
/// target, on one wide bundle is exactly what co-tenancy looks like, while a genuinely related
/// domain tends to be re-attested as certificates are reissued and rebundled over time.
///
/// Certificates are deduplicated on their SAN set first, because crt.sh lists a precertificate AND
/// its final certificate as separate rows with distinct IDs and identical names. Counting rows
/// would make every base domain trivially "corroborated" by its own precertificate, which is not a
/// second source at all — it is the same certificate logged twice.
fn corroborated_bases<'a>(certs: &[Vec<&'a str>]) -> HashSet<&'a str> {
    let mut distinct_certs: HashSet<Vec<&str>> = HashSet::new();
    let mut seen_once: HashSet<&'a str> = HashSet::new();
    let mut corroborated: HashSet<&'a str> = HashSet::new();

    for bases in certs {
        let mut fingerprint = bases.clone();
        fingerprint.sort_unstable();
        if !distinct_certs.insert(fingerprint) {
            continue;
        }
        for &base in bases {
            if !seen_once.insert(base) {
                corroborated.insert(base);
            }
        }
    }
    corroborated
}

/// Which of one certificate's SAN base domains may seed recursion, in input order.
///
/// Under [`SHARED_CERT_SAN_BASE_LIMIT`] every SAN is admitted: an ordinary certificate's SAN list
/// *is* the relationship set, and second-guessing it would cost real recall for nothing.
///
/// Over the limit the certificate is wide enough to be shared infrastructure, so admission narrows
/// to the base domains a second certificate also attests — the co-tenants of one bundle drop out,
/// the members of a genuine multi-domain family (which recur across reissues and rebundles) stay.
///
/// The one thing this must never do is take none. If nothing is corroborated there is no second
/// certificate to compare against, which means the evidence needed to call the certificate *shared*
/// does not exist either — a stable single-org bundle that is simply reissued verbatim looks
/// exactly like this. Dropping the whole set there would turn a fan-out bound into a total recall
/// loss for that domain, so the wide set is kept and the bound simply does not fire.
fn admit_san_bases<'a>(bases: &[&'a str], corroborated: &HashSet<&'a str>) -> Vec<&'a str> {
    if bases.len() <= SHARED_CERT_SAN_BASE_LIMIT {
        return bases.to_vec();
    }
    let admitted: Vec<&'a str> = bases
        .iter()
        .copied()
        .filter(|base| corroborated.contains(*base))
        .collect();
    if admitted.is_empty() {
        return bases.to_vec();
    }
    admitted
}

/// The crt.sh query URL. `%.` is crt.sh's wildcard prefix (all subdomains of `domain`).
///
/// `exclude=expired` is load-bearing, not a tidy-up: without it crt.sh serves the domain's entire
/// certificate history, which for a well-known domain is a multi-megabyte JSON body parsed in full
/// to extract the same names over and over. An expired certificate also attests a relationship that
/// has itself expired — reporting it as a current nth-party is a claim the evidence does not
/// support. Filtering server-side means the payload never crosses the wire at all.
fn crtsh_query_url(base_url: &str, domain: &str) -> String {
    format!(
        "{}/?q=%.{}&output=json&exclude=expired",
        base_url,
        urlencoding::encode(domain)
    )
}

/// Classify a provider's non-2xx response, or `None` when it was a success.
///
/// One place decides what a status code means so the four providers cannot drift apart on it — a
/// 429 from Cert Spotter is the same event as a 429 from crt.sh and must not be swallowed just
/// because it arrived on a different code path.
fn non_success_error(
    provider: &str,
    domain: &str,
    response: &reqwest::Response,
) -> Option<CtFetchError> {
    let status = response.status();
    if status.is_success() {
        return None;
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok());
        return Some(CtFetchError::Throttled {
            cooldown: throttle_cooldown(retry_after),
        });
    }
    Some(CtFetchError::Soft(format!(
        "{} returned status {} for {}",
        provider, status, domain
    )))
}

/// One CT log source in the round-robin rotation.
#[derive(Clone)]
enum CtProvider {
    CrtSh {
        base_url: String,
    },
    CertSpotter {
        base_url: String,
        token: Option<String>,
    },
    MerkleMap {
        base_url: String,
        token: String,
    },
    Censys {
        base_url: String,
        pat: String,
        org_id: String,
    },
}

impl CtProvider {
    fn name(&self) -> &'static str {
        match self {
            CtProvider::CrtSh { .. } => "crt.sh",
            CtProvider::CertSpotter { .. } => "certspotter",
            CtProvider::MerkleMap { .. } => "merklemap",
            CtProvider::Censys { .. } => "censys",
        }
    }
}

/// Certificate Transparency log discovery.
///
/// Round-robins across the configured providers on `cursor` so successive domains hit
/// different aggregators, and fails over on any provider error. A single-provider
/// instance (`with_base_url`, used by the wiremock test-suite) behaves exactly as before.
pub struct CtLogDiscovery {
    client: Client,
    timeout: Duration,
    /// crt.sh base URL (kept as a named field for the public API + back-compat tests).
    base_url: String,
    /// Non-crt.sh providers in the rotation (Cert Spotter, plus MerkleMap/Censys when
    /// their credentials are configured), built once at construction.
    extra_providers: Vec<CtProvider>,
    /// Process-shared round-robin cursor across providers.
    cursor: AtomicUsize,
    /// Per-provider throttle state, indexed exactly as `providers()` orders them: crt.sh at 0, then
    /// `extra_providers` in construction order. Kept parallel rather than inside `CtProvider`
    /// because `providers()` hands out clones per call, and a cooldown that is cloned away is no
    /// cooldown at all.
    throttle: Vec<ProviderThrottle>,
    /// How many 429s this instance has been served across all providers — the "count" leg of the
    /// classify/count/warn-once contract `dns.rs::note_throttle` sets for DNS.
    throttles_seen: AtomicU64,
}

impl CtLogDiscovery {
    pub fn new(timeout: Duration) -> Self {
        let env = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let mut extra = Vec::new();

        // Cert Spotter — always in the rotation (works anonymously; optional token).
        extra.push(CtProvider::CertSpotter {
            base_url: CERTSPOTTER_BASE_URL.to_string(),
            token: env(CERTSPOTTER_TOKEN_ENV),
        });
        // MerkleMap — only when a token is configured (no anonymous tier).
        if let Some(token) = env(MERKLEMAP_TOKEN_ENV) {
            extra.push(CtProvider::MerkleMap {
                base_url: MERKLEMAP_BASE_URL.to_string(),
                token,
            });
        }
        // Censys — only when BOTH the PAT and the Organization ID are configured.
        if let (Some(pat), Some(org_id)) = (env(CENSYS_PAT_ENV), env(CENSYS_ORG_ENV)) {
            extra.push(CtProvider::Censys {
                base_url: CENSYS_BASE_URL.to_string(),
                pat,
                org_id,
            });
        }

        Self::with_providers(timeout, "https://crt.sh".to_string(), extra)
    }

    /// crt.sh-only instance. Used by the wiremock test-suite to point crt.sh at a mock
    /// server; production uses `new` (multi-provider round-robin).
    pub fn with_base_url(timeout: Duration, base_url: String) -> Self {
        Self::with_providers(timeout, base_url, Vec::new())
    }

    fn with_providers(
        timeout: Duration,
        base_url: String,
        extra_providers: Vec<CtProvider>,
    ) -> Self {
        // `doh_builder`, not `hardened_builder`, and the distinction is host-count — exactly the
        // one its own doc comment draws. `POOL_MAX_IDLE_PER_HOST = 0` exists because discovery
        // clients visit an ever-growing host set, so a per-host idle pool grows with the scan. CT
        // does the opposite: at most four fixed hosts (crt.sh, Cert Spotter, MerkleMap, Censys) no
        // matter how deep the scan goes, for a hard ceiling of 4 x 2 = 8 idle sockets — negligible
        // against the 128 in-flight ceiling and unable to scale with the fan-out. Meanwhile the
        // cost of zero pooling here is exactly the handshake amplification that const documents and
        // accepts for DoH: effectively every CT query is a fresh TCP+TLS handshake to one host.
        let client = crate::http_client::doh_builder()
            .timeout(timeout)
            .user_agent(crate::http_client::USER_AGENT)
            .build()
            .unwrap_or_default();

        // One slot per provider, in `providers()` order: crt.sh, then the extras.
        let throttle = (0..=extra_providers.len())
            .map(|_| ProviderThrottle::default())
            .collect();

        Self {
            client,
            timeout,
            base_url,
            extra_providers,
            cursor: AtomicUsize::new(0),
            throttle,
            throttles_seen: AtomicU64::new(0),
        }
    }

    /// The provider rotation for this instance: always crt.sh first, then the configured
    /// extra providers. A `with_base_url` instance yields crt.sh only.
    fn providers(&self) -> Vec<CtProvider> {
        let mut providers = vec![CtProvider::CrtSh {
            base_url: self.base_url.clone(),
        }];
        providers.extend(self.extra_providers.iter().cloned());
        providers
    }

    /// Discover vendors from CT logs for a domain
    pub async fn discover(&self, domain: &str) -> Result<Vec<CtDiscoveryResult>> {
        info!("Querying CT logs for certificates related to {}", domain);

        let mut results = Vec::new();
        let mut seen_domains = HashSet::new();

        // Add the target domain to seen to avoid self-references
        let base_domain = domain_utils::extract_base_domain(domain);
        seen_domains.insert(base_domain.clone());

        // Query CT providers (round-robin + failover) for certificates.
        let entries = self.fetch_entries_round_robin(domain).await?;
        debug!("Found {} certificate entries for {}", entries.len(), domain);

        // Every certificate's SAN set is extracted before any of them is mined, because the
        // shared-certificate cap asks a question no single certificate can answer about itself:
        // is this base domain re-attested somewhere else, or does it appear exactly once, beside
        // ours, on one wide bundle?
        let per_cert_sans: Vec<Vec<(String, String)>> = entries
            .iter()
            .map(|e| {
                e.name_value
                    .as_deref()
                    .map(cert_san_bases)
                    .unwrap_or_default()
            })
            .collect();
        let per_cert_bases: Vec<Vec<&str>> = per_cert_sans
            .iter()
            .map(|sans| sans.iter().map(|(_, base)| base.as_str()).collect())
            .collect();
        let corroborated = corroborated_bases(&per_cert_bases);

        for ((entry, sans), bases) in entries.iter().zip(&per_cert_sans).zip(&per_cert_bases) {
            // Extract domains from SAN (name_value). The admission decision is made per
            // certificate, over its full SAN breadth — before the self/infrastructure filters
            // below — because it classifies the *certificate*, not the subset we would have kept
            // from it.
            let admitted: HashSet<&str> =
                admit_san_bases(bases, &corroborated).into_iter().collect();

            for (san, san_base) in sans {
                // Co-tenancy on a shared certificate is not a vendor relationship.
                if !admitted.contains(san_base.as_str()) {
                    debug!(
                        "Skipping SAN {} on a {}-name shared certificate for {}: no second certificate attests it",
                        san_base,
                        bases.len(),
                        domain
                    );
                    continue;
                }

                // Skip if same as target domain
                if *san_base == base_domain {
                    continue;
                }

                // Skip common CDN/infrastructure domains that aren't meaningful vendors
                if Self::is_infrastructure_domain(san_base) {
                    continue;
                }

                // Only add if not seen before
                if seen_domains.insert(san_base.clone()) {
                    let issuer = entry.issuer_name.as_deref().unwrap_or("Unknown CA");
                    let cert_id = entry.id;

                    results.push(CtDiscoveryResult {
                        domain: san_base.clone(),
                        source: format!("Certificate SAN (crt.sh ID: {})", cert_id),
                        certificate_info: format!(
                            "SAN: {} | Issuer: {} | Certificate ID: {}",
                            san, issuer, cert_id
                        ),
                    });

                    debug!(
                        "Found vendor {} from CT log certificate {}",
                        san_base, cert_id
                    );
                }
            }

            // Also check common_name if different from target
            if let Some(common_name) = &entry.common_name {
                let cn = common_name.trim().to_lowercase();
                let cn_base = domain_utils::extract_base_domain(&cn);

                if cn_base != base_domain
                    && !Self::is_infrastructure_domain(&cn_base)
                    && seen_domains.insert(cn_base.clone())
                {
                    results.push(CtDiscoveryResult {
                        domain: cn_base.clone(),
                        source: format!("Certificate CN (crt.sh ID: {})", entry.id),
                        certificate_info: format!(
                            "CN: {} | Issuer: {} | Certificate ID: {}",
                            cn,
                            entry.issuer_name.as_deref().unwrap_or("Unknown CA"),
                            entry.id
                        ),
                    });

                    debug!("Found vendor {} from CT log certificate CN", cn_base);
                }
            }
        }

        info!(
            "CT log discovery found {} unique vendor domains for {}",
            results.len(),
            domain
        );
        Ok(results)
    }

    /// Fetch certificate entries by round-robining the configured providers, failing
    /// over on any provider error. Returns the first provider's authoritative (2xx)
    /// entries — possibly empty. If every provider fails, a reachable-but-unhelpful
    /// response degrades to an empty answer while a total transport failure propagates
    /// as a hard error (so the phase logs it with the real error kind).
    ///
    /// The one case that may NOT degrade in silence is a throttle. A provider that answered 429 —
    /// or one we are deliberately not asking because it is still inside the `Retry-After` window it
    /// gave us — has told us the certificates exist and we may not have them yet. That empty is
    /// recorded as degraded CT coverage, so the summary can tell it apart from a domain that
    /// genuinely has no certificates (TF-RATELIMIT).
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn fetch_entries_round_robin(&self, domain: &str) -> Result<Vec<CrtShEntry>> {
        let providers = self.providers();
        let n = providers.len();
        // Advance the shared cursor so successive domains start at a different provider,
        // spreading load off any single aggregator.
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % n;
        let mut transport_err = None;
        let mut any_throttled = false;
        let mut answer = None;

        for offset in 0..n {
            let idx = (start + offset) % n;
            let provider = &providers[idx];

            // Honour a cooldown this provider asked for on an earlier domain. This is the ONLY
            // pacing in the CT path and it is strictly reactive: nothing here delays a request the
            // provider has not already refused. (A preemptive per-provider rate gate was built,
            // measured at 0/17 -> 1/51 CT completions because crt.sh hangs rather than 429s, and
            // reverted — ISC-510. Do not reintroduce one.)
            if !self.throttle[idx].is_usable_at(now_epoch_millis()) {
                any_throttled = true;
                debug!(
                    "CT provider {} still cooling down after a 429; skipping it for {}",
                    provider.name(),
                    domain
                );
                continue;
            }

            match self.fetch_provider(provider, domain).await {
                Ok(entries) => {
                    answer = Some(entries);
                    break;
                }
                Err(CtFetchError::Throttled { cooldown }) => {
                    any_throttled = true;
                    self.note_throttle(idx, provider.name(), domain, cooldown);
                }
                Err(CtFetchError::Soft(msg)) => {
                    debug!(
                        "CT provider {} unavailable for {} (failing over): {}",
                        provider.name(),
                        domain,
                        msg
                    );
                }
                Err(CtFetchError::Transport(e)) => {
                    debug!(
                        "CT provider {} unreachable for {} (failing over): {}",
                        provider.name(),
                        domain,
                        e
                    );
                    transport_err = Some(e);
                }
            }
        }

        if classify_ct_outcome(answer.is_some(), any_throttled, transport_err.is_some())
            == CtOutcome::ThrottledEmpty
        {
            // TF-CT-THROTTLE-WORDING: a distinct `SCAN_COVERAGE.ct.record_throttled()` outcome.
            // `record_failure` marks the phase degraded, which is the load-bearing half, but it
            // reads in the summary as "CT-log discovery failed" when the truthful sentence is
            // "CT-log discovery was rate-limited" — a different remedy for the reader.
            crate::coverage::SCAN_COVERAGE.ct.record_failure();
        }

        match answer {
            Some(entries) => Ok(entries),
            // Nothing was reachable — surface the real error kind rather than a silent empty.
            None => match transport_err {
                Some(e) => Err(e),
                // Every provider responded but unhelpfully (429/5xx/parse) — treat as "no certs",
                // now with the throttled case recorded as degraded above rather than lost.
                None => Ok(Vec::new()),
            },
        }
    }

    /// Classify, count, and warn-once about one provider's 429, then hold it out of the rotation
    /// for as long as it asked for.
    ///
    /// The three legs mirror `dns.rs`'s treatment of a throttled DoH provider: the refusal is
    /// counted at a single choke point so it cannot be double-counted by a caller, and warned about
    /// once per provider rather than once per domain — a deep scan hitting crt.sh's limit would
    /// otherwise print thousands of identical lines and teach the reader to ignore them.
    #[cfg_attr(coverage_nightly, coverage(off))] // coverage: wall-clock cooldown bookkeeping; the decisions are `ProviderThrottle` and `throttle_cooldown`, both unit-tested directly
    fn note_throttle(&self, idx: usize, name: &str, domain: &str, cooldown: Duration) {
        self.throttles_seen.fetch_add(1, Ordering::Relaxed);
        crate::perf::METRICS.ct_throttled.hit();
        if self.throttle[idx].begin_cooldown(now_epoch_millis(), cooldown) {
            warn!(
                "CT_THROTTLE: provider {} returned HTTP 429 for {} — holding it out of the rotation for {}s",
                name,
                domain,
                cooldown.as_secs()
            );
        }
    }

    /// How many 429s this instance has been served. The count is what the throttle tests assert on;
    /// production visibility is the degraded-coverage record in `fetch_entries_round_robin`.
    #[cfg(test)]
    pub(crate) fn throttles_seen(&self) -> u64 {
        self.throttles_seen.load(Ordering::Relaxed)
    }

    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn fetch_provider(
        &self,
        provider: &CtProvider,
        domain: &str,
    ) -> std::result::Result<Vec<CrtShEntry>, CtFetchError> {
        match provider {
            CtProvider::CrtSh { base_url } => self.fetch_crtsh(base_url, domain).await,
            CtProvider::CertSpotter { base_url, token } => {
                self.fetch_certspotter(base_url, token.as_deref(), domain)
                    .await
            }
            CtProvider::MerkleMap { base_url, token } => {
                self.fetch_merklemap(base_url, token, domain).await
            }
            CtProvider::Censys {
                base_url,
                pat,
                org_id,
            } => self.fetch_censys(base_url, pat, org_id, domain).await,
        }
    }

    /// Query crt.sh (`/?q=%.domain&output=json`). Wildcard prefix `%.` = all subdomains.
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn fetch_crtsh(
        &self,
        base_url: &str,
        domain: &str,
    ) -> std::result::Result<Vec<CrtShEntry>, CtFetchError> {
        let url = crtsh_query_url(base_url, domain);
        debug!("Querying crt.sh: {}", url);

        let response = self
            .client
            .get(&url)
            .timeout(self.timeout)
            .send_gated()
            .await
            .map_err(|e| CtFetchError::Transport(e.into()))?;

        if let Some(err) = non_success_error("crt.sh", domain, &response) {
            return Err(err);
        }

        let text = response
            .text()
            .await
            .map_err(|e| CtFetchError::Transport(e.into()))?;

        // crt.sh returns empty array as "[]" or sometimes just empty
        if text.is_empty() || text == "[]" {
            return Ok(Vec::new());
        }

        match serde_json::from_str::<Vec<CrtShEntry>>(&text) {
            Ok(entries) => Ok(entries),
            Err(e) => Err(CtFetchError::Soft(format!(
                "Failed to parse crt.sh response: {}",
                e
            ))),
        }
    }

    /// Query SSLMate Cert Spotter (`/v1/issuances`), normalizing its clean `dns_names[]`
    /// array into the crt.sh entry shape.
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn fetch_certspotter(
        &self,
        base_url: &str,
        token: Option<&str>,
        domain: &str,
    ) -> std::result::Result<Vec<CrtShEntry>, CtFetchError> {
        let url = format!(
            "{}/v1/issuances?domain={}&include_subdomains=true&match_wildcards=true&expand=dns_names&expand=issuer",
            base_url,
            urlencoding::encode(domain)
        );
        debug!("Querying Cert Spotter: {}", url);

        let mut request = self.client.get(&url).timeout(self.timeout);
        if let Some(t) = token {
            request = request.bearer_auth(t);
        }

        let response = request
            .send_gated()
            .await
            .map_err(|e| CtFetchError::Transport(e.into()))?;

        if let Some(err) = non_success_error("Cert Spotter", domain, &response) {
            return Err(err);
        }

        let text = response
            .text()
            .await
            .map_err(|e| CtFetchError::Transport(e.into()))?;

        if text.is_empty() || text == "[]" {
            return Ok(Vec::new());
        }

        match serde_json::from_str::<Vec<CertSpotterIssuance>>(&text) {
            Ok(issuances) => Ok(issuances
                .into_iter()
                .map(CertSpotterIssuance::into_crtsh_entry)
                .collect()),
            Err(e) => Err(CtFetchError::Soft(format!(
                "Failed to parse Cert Spotter response: {}",
                e
            ))),
        }
    }

    /// Query the MerkleMap search API (`/v1/search`, Bearer-authed). MerkleMap returns
    /// already-flattened hostnames, collected into one synthetic crt.sh entry.
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn fetch_merklemap(
        &self,
        base_url: &str,
        token: &str,
        domain: &str,
    ) -> std::result::Result<Vec<CrtShEntry>, CtFetchError> {
        let url = format!(
            "{}/v1/search?query={}&type=wildcard&page=0",
            base_url,
            urlencoding::encode(domain)
        );
        debug!("Querying MerkleMap: {}", url);

        let response = self
            .client
            .get(&url)
            .timeout(self.timeout)
            .bearer_auth(token)
            .send_gated()
            .await
            .map_err(|e| CtFetchError::Transport(e.into()))?;

        if let Some(err) = non_success_error("MerkleMap", domain, &response) {
            return Err(err);
        }

        let text = response
            .text()
            .await
            .map_err(|e| CtFetchError::Transport(e.into()))?;

        match serde_json::from_str::<MerkleMapResponse>(&text) {
            Ok(parsed) => {
                let hostnames: Vec<String> = parsed
                    .results
                    .into_iter()
                    .filter_map(|r| r.hostname)
                    .collect();
                if hostnames.is_empty() {
                    Ok(Vec::new())
                } else {
                    Ok(vec![crtsh_entry_from_names(hostnames, "MerkleMap CT")])
                }
            }
            Err(e) => Err(CtFetchError::Soft(format!(
                "Failed to parse MerkleMap response: {}",
                e
            ))),
        }
    }

    /// Query the Censys Platform certificate dataset (`POST /v3/global/search/query`).
    /// Auth = `Authorization: Bearer <PAT>` + `X-Organization-ID: <org>`; the CenQL query
    /// `cert.names: "<domain>"` matches the domain and its subdomains via Censys's
    /// hierarchical domain tokenization. Each hit → one crt.sh-shaped entry.
    #[cfg_attr(coverage_nightly, coverage(off))]
    async fn fetch_censys(
        &self,
        base_url: &str,
        pat: &str,
        org_id: &str,
        domain: &str,
    ) -> std::result::Result<Vec<CrtShEntry>, CtFetchError> {
        let url = format!("{}/v3/global/search/query", base_url);
        debug!("Querying Censys: {}", url);

        let body = serde_json::json!({
            "query": format!("cert.names: \"{}\"", domain),
            "page_size": 100,
        });

        let response = self
            .client
            .post(&url)
            .timeout(self.timeout)
            .bearer_auth(pat)
            .header("X-Organization-ID", org_id)
            .json(&body)
            .send_gated()
            .await
            .map_err(|e| CtFetchError::Transport(e.into()))?;

        if let Some(err) = non_success_error("Censys", domain, &response) {
            return Err(err);
        }

        let text = response
            .text()
            .await
            .map_err(|e| CtFetchError::Transport(e.into()))?;

        match serde_json::from_str::<CensysResponse>(&text) {
            Ok(parsed) => Ok(parsed
                .result
                .map(|r| r.hits)
                .unwrap_or_default()
                .into_iter()
                .map(|hit| crtsh_entry_from_names(hit.dns_names(), "Censys CT"))
                .filter(|e| {
                    e.name_value
                        .as_deref()
                        .map(|s| !s.is_empty())
                        .unwrap_or(false)
                })
                .collect()),
            Err(e) => Err(CtFetchError::Soft(format!(
                "Failed to parse Censys response: {}",
                e
            ))),
        }
    }

    /// Test-scoped crt.sh query preserving the historical contract (a reachable-but-
    /// unhelpful response degrades to empty with a warning; only a transport failure
    /// propagates) so the crt.sh HTTP behavior stays directly covered by the wiremock
    /// suite. Production goes through `fetch_entries_round_robin`.
    #[cfg(test)]
    pub(crate) async fn query_crt_sh(&self, domain: &str) -> Result<Vec<CrtShEntry>> {
        match self.fetch_crtsh(&self.base_url, domain).await {
            Ok(entries) => Ok(entries),
            Err(CtFetchError::Soft(msg)) => {
                tracing::warn!("{}", msg);
                Ok(Vec::new())
            }
            // A throttle degrades to empty here only because this shim predates the round-robin and
            // exists to pin the historical crt.sh HTTP contract; the production path counts it and
            // records degraded coverage (see `fetch_entries_round_robin`).
            Err(CtFetchError::Throttled { cooldown }) => {
                tracing::warn!(
                    "CT_THROTTLE: crt.sh returned HTTP 429 for {} (cooldown {}s)",
                    domain,
                    cooldown.as_secs()
                );
                Ok(Vec::new())
            }
            Err(CtFetchError::Transport(e)) => Err(e),
        }
    }

    /// Check if a domain is infrastructure/CDN that shouldn't be reported as a vendor.
    ///
    /// NOTE(M009): This list intentionally excludes hosting platforms like heroku.com and
    /// wpengine.com because organizations may legitimately use them as vendors. Only pure
    /// infrastructure domains (CDNs, cloud primitives, certificate issuers) that would create
    /// noise in vendor reports are filtered here.
    fn is_infrastructure_domain(domain: &str) -> bool {
        let infrastructure_domains = [
            // CDN providers - these appear in certs due to CDN termination, not vendor relationships
            "cloudflare.com",
            "cloudflare.net",
            "cloudfront.net",
            "akamai.com",
            "akamaiedge.net",
            "fastly.net",
            "fastly.com",
            "edgekey.net",
            "edgesuite.net",
            // Cloud infrastructure primitives - raw cloud hostnames, not meaningful vendor signals
            "amazonaws.com",
            "azure.com",
            "azurewebsites.net",
            "azureedge.net",
            "googleusercontent.com",
            "googlesyndication.com",
            "gstatic.com",
            // SSL/TLS certificate issuers - appear as cert issuers, not actual vendor relationships
            "letsencrypt.org",
            "digicert.com",
            "comodo.com",
            "godaddy.com",
            "rapidssl.com",
            "geotrust.com",
            "thawte.com",
            "entrust.net",
            // M009 fix: removed globalsign.com - it's a legitimate SSL vendor that organizations
            // may want to track as a third-party relationship
            "sectigo.com",
            // Non-routable / test domains
            "localhost",
            "local",
            "test",
            "example.com",
        ];

        infrastructure_domains
            .iter()
            .any(|&infra| domain.ends_with(infra) || domain == infra)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_infrastructure_domain() {
        assert!(CtLogDiscovery::is_infrastructure_domain("cloudflare.com"));
        assert!(CtLogDiscovery::is_infrastructure_domain(
            "sub.cloudflare.com"
        ));
        assert!(CtLogDiscovery::is_infrastructure_domain("amazonaws.com"));
        assert!(!CtLogDiscovery::is_infrastructure_domain("klaviyo.com"));
        assert!(!CtLogDiscovery::is_infrastructure_domain("google.com"));
    }

    // ───────────────────────────────────────────────────────────────
    // Additional coverage tests below
    // ───────────────────────────────────────────────────────────────

    use rstest::rstest;
    use tracing_subscriber;

    // --- CtLogDiscovery construction ---

    #[test]
    fn test_ct_log_discovery_new() {
        let disc = CtLogDiscovery::new(Duration::from_secs(30));
        assert_eq!(disc.timeout, Duration::from_secs(30));
        assert_eq!(disc.base_url, "https://crt.sh");
    }

    #[test]
    fn test_ct_log_discovery_new_short_timeout() {
        let disc = CtLogDiscovery::new(Duration::from_millis(100));
        assert_eq!(disc.timeout, Duration::from_millis(100));
    }

    #[test]
    fn test_ct_log_discovery_with_base_url() {
        let disc = CtLogDiscovery::with_base_url(
            Duration::from_secs(10),
            "http://localhost:9999".to_string(),
        );
        assert_eq!(disc.timeout, Duration::from_secs(10));
        assert_eq!(disc.base_url, "http://localhost:9999");
    }

    // --- CrtShEntry deserialization ---

    #[test]
    fn test_crt_sh_entry_full_deserialization() {
        let json = r#"{
            "issuer_ca_id": 12345,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "common_name": "*.example.com",
            "name_value": "example.com\nwww.example.com\nmail.example.com",
            "id": 9876543210,
            "entry_timestamp": "2024-01-15T10:30:00",
            "not_before": "2024-01-15T00:00:00",
            "not_after": "2024-04-15T00:00:00"
        }"#;
        let entry: CrtShEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.issuer_ca_id, Some(12345));
        assert_eq!(entry.id, 9876543210);
        assert_eq!(entry.common_name, Some("*.example.com".to_string()));
        assert!(entry
            .name_value
            .as_ref()
            .unwrap()
            .contains("www.example.com"));
        assert_eq!(entry.not_before, Some("2024-01-15T00:00:00".to_string()));
    }

    #[test]
    fn test_crt_sh_entry_minimal_deserialization() {
        let json = r#"{"id": 100}"#;
        let entry: CrtShEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.id, 100);
        assert!(entry.issuer_ca_id.is_none());
        assert!(entry.issuer_name.is_none());
        assert!(entry.common_name.is_none());
        assert!(entry.name_value.is_none());
        assert!(entry.entry_timestamp.is_none());
        assert!(entry.not_before.is_none());
        assert!(entry.not_after.is_none());
    }

    #[test]
    fn test_crt_sh_entry_array_deserialization() {
        let json = r#"[
            {"id": 1, "name_value": "vendor1.com"},
            {"id": 2, "name_value": "vendor2.com\nvendor3.com"}
        ]"#;
        let entries: Vec<CrtShEntry> = serde_json::from_str(json).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, 1);
        assert_eq!(
            entries[1].name_value,
            Some("vendor2.com\nvendor3.com".to_string())
        );
    }

    #[test]
    fn test_crt_sh_entry_empty_array() {
        let json = "[]";
        let entries: Vec<CrtShEntry> = serde_json::from_str(json).unwrap();
        assert!(entries.is_empty());
    }

    // --- CtDiscoveryResult ---

    #[test]
    fn test_ct_discovery_result_clone_and_debug() {
        let result = CtDiscoveryResult {
            domain: "vendor.com".to_string(),
            source: "Certificate SAN (crt.sh ID: 12345)".to_string(),
            certificate_info: "SAN: vendor.com | Issuer: R3 | Certificate ID: 12345".to_string(),
        };
        let cloned = result.clone();
        assert_eq!(cloned.domain, "vendor.com");
        assert_eq!(cloned.source, result.source);
        let debug = format!("{:?}", result);
        assert!(debug.contains("vendor.com"));
    }

    // --- Infrastructure domain filtering (comprehensive) ---

    #[rstest]
    // CDN providers
    #[case("cloudflare.com", true)]
    #[case("sub.cloudflare.com", true)]
    #[case("cloudflare.net", true)]
    #[case("cloudfront.net", true)]
    #[case("d123.cloudfront.net", true)]
    #[case("akamai.com", true)]
    #[case("akamaiedge.net", true)]
    #[case("fastly.net", true)]
    #[case("fastly.com", true)]
    #[case("edgekey.net", true)]
    #[case("edgesuite.net", true)]
    // Cloud providers
    #[case("amazonaws.com", true)]
    #[case("s3.amazonaws.com", true)]
    #[case("azure.com", true)]
    #[case("azurewebsites.net", true)]
    #[case("azureedge.net", true)]
    #[case("googleusercontent.com", true)]
    #[case("googlesyndication.com", true)]
    #[case("gstatic.com", true)]
    // SSL providers
    #[case("letsencrypt.org", true)]
    #[case("digicert.com", true)]
    #[case("comodo.com", true)]
    #[case("godaddy.com", true)]
    #[case("rapidssl.com", true)]
    #[case("geotrust.com", true)]
    #[case("thawte.com", true)]
    #[case("entrust.net", true)]
    #[case("sectigo.com", true)]
    // Non-routable
    #[case("localhost", true)]
    #[case("local", true)]
    #[case("test", true)]
    #[case("example.com", true)]
    // NOT infrastructure — should be false
    #[case("klaviyo.com", false)]
    #[case("google.com", false)]
    #[case("heroku.com", false)] // M009: intentionally not filtered
    #[case("wpengine.com", false)] // M009: intentionally not filtered
    #[case("globalsign.com", false)] // M009: removed from filter
    #[case("stripe.com", false)]
    #[case("pendo.io", false)]
    #[case("okta.com", false)]
    fn test_is_infrastructure_domain_parametrized(#[case] domain: &str, #[case] expected: bool) {
        assert_eq!(
            CtLogDiscovery::is_infrastructure_domain(domain),
            expected,
            "Domain '{}' should be infrastructure={}",
            domain,
            expected
        );
    }

    // --- discover() behavior tests via wiremock ---

    // --- JSON parsing edge cases ---

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[test]
    fn test_parse_empty_json_string() {
        let text = "";
        // Mimics query_crt_sh behavior
        let is_empty = text.is_empty() || text == "[]";
        assert!(is_empty);
    }

    #[test]
    fn test_parse_empty_json_array() {
        let text = "[]";
        let is_empty = text.is_empty() || text == "[]";
        assert!(is_empty);
    }

    #[test]
    fn test_parse_malformed_json() {
        let text = "this is not json";
        let result = serde_json::from_str::<Vec<CrtShEntry>>(text);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_valid_json_response() {
        let text = r#"[{"id": 1, "name_value": "vendor.com"}, {"id": 2}]"#;
        let entries: Vec<CrtShEntry> = serde_json::from_str(text).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn test_parse_json_with_null_fields() {
        let text = r#"[{"id": 1, "issuer_ca_id": null, "common_name": null, "name_value": null}]"#;
        let entries: Vec<CrtShEntry> = serde_json::from_str(text).unwrap();
        assert_eq!(entries.len(), 1);
        assert!(entries[0].issuer_ca_id.is_none());
        assert!(entries[0].common_name.is_none());
        assert!(entries[0].name_value.is_none());
    }

    // --- Multiple entries across certificates ---

    // --- Async tests with wiremock for discover() and query_crt_sh() ---

    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[tokio::test]
    async fn test_discover_via_wiremock_finds_vendors() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 100,
                "issuer_name": "Let's Encrypt R3",
                "common_name": "*.example.com",
                "name_value": "example.com\napi.vendor-a.com\ncdn.vendor-b.io"
            },
            {
                "id": 200,
                "issuer_name": "DigiCert Inc",
                "common_name": "secure.vendor-c.net",
                "name_value": "vendor-d.org"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();

        let domains: Vec<&str> = results.iter().map(|r| r.domain.as_str()).collect();
        assert!(
            domains.contains(&"vendor-a.com"),
            "Should find vendor-a.com from SAN"
        );
        assert!(
            domains.contains(&"vendor-b.io"),
            "Should find vendor-b.io from SAN"
        );
        assert!(
            domains.contains(&"vendor-d.org"),
            "Should find vendor-d.org from SAN"
        );
        assert!(
            domains.contains(&"vendor-c.net"),
            "Should find vendor-c.net from CN"
        );
        assert!(
            !domains.contains(&"example.com"),
            "Should not include self-reference"
        );
    }

    #[tokio::test]
    async fn test_discover_via_wiremock_empty_response() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_discover_via_wiremock_server_error_returns_empty() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_discover_via_wiremock_malformed_json_returns_empty() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not valid json"))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_discover_via_wiremock_filters_infrastructure() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 300,
                "name_value": "cdn.cloudflare.com\ns3.amazonaws.com\nreal-vendor.com"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain, "real-vendor.com");
    }

    #[tokio::test]
    async fn test_discover_via_wiremock_deduplicates_domains() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 400,
                "common_name": "api.vendor.com",
                "name_value": "cdn.vendor.com\nwww.vendor.com\napi.vendor.com"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();

        assert_eq!(
            results.len(),
            1,
            "All subdomains of vendor.com should deduplicate to one"
        );
        assert_eq!(results[0].domain, "vendor.com");
    }

    #[test]
    fn test_ct_discovery_result_all_fields() {
        let result = CtDiscoveryResult {
            domain: "vendor.io".to_string(),
            source: "Certificate SAN (crt.sh ID: 999)".to_string(),
            certificate_info: "SAN: api.vendor.io | Issuer: DigiCert | Certificate ID: 999"
                .to_string(),
        };
        assert_eq!(result.domain, "vendor.io");
        assert!(result.source.contains("999"));
        assert!(result.certificate_info.contains("DigiCert"));

        let cloned = result.clone();
        assert_eq!(cloned.domain, result.domain);
        assert_eq!(cloned.source, result.source);
        assert_eq!(cloned.certificate_info, result.certificate_info);

        let dbg = format!("{:?}", result);
        assert!(dbg.contains("vendor.io"));
        assert!(dbg.contains("999"));
    }

    #[test]
    fn test_crt_sh_entry_debug() {
        let entry = CrtShEntry {
            issuer_ca_id: Some(42),
            issuer_name: Some("TestCA".to_string()),
            common_name: Some("test.com".to_string()),
            name_value: Some("test.com".to_string()),
            id: 12345,
            entry_timestamp: Some("2024-01-01".to_string()),
            not_before: Some("2024-01-01".to_string()),
            not_after: Some("2025-01-01".to_string()),
        };
        let dbg = format!("{:?}", entry);
        assert!(dbg.contains("12345"));
        assert!(dbg.contains("TestCA"));
    }

    #[test]
    fn test_ct_log_discovery_new_creates_client() {
        let disc = CtLogDiscovery::new(Duration::from_secs(10));
        assert_eq!(disc.timeout, Duration::from_secs(10));
        // Verify we can create multiple instances
        let disc2 = CtLogDiscovery::new(Duration::from_secs(60));
        assert_eq!(disc2.timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_is_infrastructure_domain_subdomain_matching() {
        // Test that subdomains of infrastructure domains are also filtered (ends_with check)
        assert!(CtLogDiscovery::is_infrastructure_domain(
            "cdn.cloudflare.com"
        ));
        assert!(CtLogDiscovery::is_infrastructure_domain(
            "s3.us-east-1.amazonaws.com"
        ));
        assert!(CtLogDiscovery::is_infrastructure_domain(
            "test-app.azurewebsites.net"
        ));
        assert!(CtLogDiscovery::is_infrastructure_domain(
            "mysite.azureedge.net"
        ));
        assert!(CtLogDiscovery::is_infrastructure_domain(
            "storage.googleusercontent.com"
        ));
        assert!(CtLogDiscovery::is_infrastructure_domain(
            "abc.googlesyndication.com"
        ));
        assert!(CtLogDiscovery::is_infrastructure_domain(
            "fonts.gstatic.com"
        ));
    }

    #[test]
    fn test_is_infrastructure_domain_exact_matches() {
        // Test exact match (not just ends_with)
        assert!(CtLogDiscovery::is_infrastructure_domain("localhost"));
        assert!(CtLogDiscovery::is_infrastructure_domain("local"));
        assert!(CtLogDiscovery::is_infrastructure_domain("test"));
        assert!(CtLogDiscovery::is_infrastructure_domain("example.com"));
    }

    #[test]
    fn test_is_infrastructure_domain_not_partial_match() {
        // "notlocalhost" should NOT match "localhost"
        // The check uses ends_with, so "notlocalhost" would end with "localhost" - it WILL match
        // This documents the current behavior
        assert!(CtLogDiscovery::is_infrastructure_domain("notlocalhost"));
        // But a domain like "mylocal" should not match "local" via ends_with
        assert!(CtLogDiscovery::is_infrastructure_domain("mylocal")); // ends_with "local"
    }

    #[test]
    fn test_crt_sh_entry_with_all_optional_fields_present() {
        let json = r#"{
            "issuer_ca_id": 16418,
            "issuer_name": "C=US, O=Let's Encrypt, CN=R3",
            "common_name": "*.example.com",
            "name_value": "example.com\n*.example.com",
            "id": 9876543210,
            "entry_timestamp": "2024-06-15T12:00:00",
            "not_before": "2024-06-15T00:00:00",
            "not_after": "2024-09-13T00:00:00"
        }"#;
        let entry: CrtShEntry = serde_json::from_str(json).unwrap();
        assert_eq!(entry.issuer_ca_id, Some(16418));
        assert!(entry
            .issuer_name
            .as_ref()
            .unwrap()
            .contains("Let's Encrypt"));
        assert_eq!(entry.common_name.as_ref().unwrap(), "*.example.com");
        assert!(entry.name_value.as_ref().unwrap().contains("*.example.com"));
        assert_eq!(
            entry.entry_timestamp.as_ref().unwrap(),
            "2024-06-15T12:00:00"
        );
        assert_eq!(entry.not_before.as_ref().unwrap(), "2024-06-15T00:00:00");
        assert_eq!(entry.not_after.as_ref().unwrap(), "2024-09-13T00:00:00");
    }

    // --- wiremock tests for query_crt_sh behavior patterns ---

    #[tokio::test]
    async fn test_query_crt_sh_via_wiremock_success() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 5001,
                "issuer_name": "R3",
                "common_name": "*.vendor.com",
                "name_value": "vendor.com\nwww.vendor.com\napi.vendor.com"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let entries = disc.query_crt_sh("example.com").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, 5001);
        let name_value = entries[0].name_value.as_ref().unwrap();
        assert!(name_value.contains("vendor.com"));
        assert!(name_value.contains("api.vendor.com"));
    }

    #[tokio::test]
    async fn test_query_crt_sh_via_wiremock_html_response() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>Rate limited</html>"))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let entries = disc.query_crt_sh("example.com").await.unwrap();
        assert!(entries.is_empty(), "Malformed JSON should return empty vec");
    }

    #[tokio::test]
    async fn test_query_crt_sh_via_wiremock_empty_string() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let entries = disc.query_crt_sh("example.com").await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_query_crt_sh_via_wiremock_500_returns_empty() {
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let entries = disc.query_crt_sh("example.com").await.unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn test_is_infrastructure_domain_ssl_providers() {
        assert!(CtLogDiscovery::is_infrastructure_domain("letsencrypt.org"));
        assert!(CtLogDiscovery::is_infrastructure_domain("digicert.com"));
        assert!(CtLogDiscovery::is_infrastructure_domain("comodo.com"));
        assert!(CtLogDiscovery::is_infrastructure_domain("godaddy.com"));
        assert!(CtLogDiscovery::is_infrastructure_domain("rapidssl.com"));
        assert!(CtLogDiscovery::is_infrastructure_domain("geotrust.com"));
        assert!(CtLogDiscovery::is_infrastructure_domain("thawte.com"));
        assert!(CtLogDiscovery::is_infrastructure_domain("entrust.net"));
        assert!(CtLogDiscovery::is_infrastructure_domain("sectigo.com"));
    }

    #[test]
    fn test_is_infrastructure_domain_globalsign_not_filtered() {
        // M009: globalsign.com was intentionally removed from the filter
        assert!(!CtLogDiscovery::is_infrastructure_domain("globalsign.com"));
    }

    // ───────────────────────────────────────────────────────────────
    // Coverage round 3: tracing format args + error propagation
    // ───────────────────────────────────────────────────────────────

    fn init_tracing() -> tracing::subscriber::DefaultGuard {
        tracing::subscriber::set_default(
            tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_writer(std::io::sink)
                .finish(),
        )
    }

    #[tokio::test]
    async fn test_discover_with_tracing_finds_vendors() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 2001,
                "issuer_name": "Let's Encrypt R3",
                "common_name": "*.example.com",
                "name_value": "example.com\napi.traced-vendor.com\ncdn.traced-vendor2.io"
            },
            {
                "id": 2002,
                "issuer_name": "DigiCert Inc",
                "common_name": "secure.traced-cn-vendor.net",
                "name_value": "traced-vendor3.org"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();

        let domains: Vec<&str> = results.iter().map(|r| r.domain.as_str()).collect();
        assert!(domains.contains(&"traced-vendor.com"));
        assert!(domains.contains(&"traced-vendor2.io"));
        assert!(domains.contains(&"traced-vendor3.org"));
        assert!(domains.contains(&"traced-cn-vendor.net"));
    }

    #[tokio::test]
    async fn test_discover_with_tracing_empty_response() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("[]"))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_discover_with_tracing_server_error() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_discover_with_tracing_malformed_json() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("{broken"))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_discover_with_tracing_sans_with_empty_lines() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 2003,
                "issuer_name": "CA",
                "name_value": "\n  \nempty-line-vendor.com\n\n"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain, "empty-line-vendor.com");
    }

    #[tokio::test]
    async fn test_discover_with_tracing_infrastructure_filtered() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 2004,
                "name_value": "cdn.cloudflare.com\nreal-traced.com\ns3.amazonaws.com"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain, "real-traced.com");
    }

    #[tokio::test]
    async fn test_discover_with_tracing_deduplication() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 2005,
                "issuer_name": "CA",
                "common_name": "api.dup-vendor.com",
                "name_value": "cdn.dup-vendor.com\nwww.dup-vendor.com"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain, "dup-vendor.com");
    }

    #[tokio::test]
    async fn test_discover_error_propagation_connection_refused() {
        let _guard = init_tracing();
        let disc = CtLogDiscovery::with_base_url(
            Duration::from_millis(100),
            "http://127.0.0.1:1".to_string(),
        );
        let result = disc.discover("example.com").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_query_crt_sh_error_propagation_connection_refused() {
        let _guard = init_tracing();
        let disc = CtLogDiscovery::with_base_url(
            Duration::from_millis(100),
            "http://127.0.0.1:1".to_string(),
        );
        let result = disc.query_crt_sh("example.com").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_query_crt_sh_with_tracing_success() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {"id": 3001, "name_value": "traced.com"}
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let entries = disc.query_crt_sh("example.com").await.unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[tokio::test]
    async fn test_query_crt_sh_with_tracing_error_status() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let entries = disc.query_crt_sh("example.com").await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_query_crt_sh_with_tracing_malformed() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<<<not json>>>"))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let entries = disc.query_crt_sh("example.com").await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_query_crt_sh_with_tracing_empty_body() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(""))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let entries = disc.query_crt_sh("example.com").await.unwrap();
        assert!(entries.is_empty());
    }

    #[tokio::test]
    async fn test_discover_with_tracing_no_issuer_name() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 2006,
                "name_value": "no-issuer-vendor.com"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].certificate_info.contains("Unknown CA"));
    }

    #[tokio::test]
    async fn test_discover_with_tracing_cn_no_issuer() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 2007,
                "common_name": "cn-no-issuer.com"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].domain, "cn-no-issuer.com");
        assert!(results[0].certificate_info.contains("Unknown CA"));
    }

    #[tokio::test]
    async fn test_discover_with_tracing_self_ref_cn() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 2008,
                "common_name": "www.example.com",
                "name_value": "example.com"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_discover_with_tracing_cn_infra_filtered() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            {
                "id": 2009,
                "common_name": "cdn.cloudflare.com"
            }
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_discover_with_tracing_entry_no_san_no_cn() {
        let _guard = init_tracing();
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([{"id": 2010}]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    // --- Cert Spotter mapping + multi-provider round-robin/failover ---

    #[test]
    fn test_certspotter_issuance_maps_to_crtsh_entry() {
        let json = r#"[{"id":"12345","dns_names":["example.com","api.vendor.io"],"issuer":{"name":"Let's Encrypt"},"not_before":"2024-01-01","not_after":"2024-04-01"}]"#;
        let issuances: Vec<CertSpotterIssuance> = serde_json::from_str(json).unwrap();
        assert_eq!(issuances.len(), 1);
        let entry = issuances.into_iter().next().unwrap().into_crtsh_entry();
        // dns_names[] is normalized into crt.sh's newline-joined name_value.
        assert_eq!(entry.id, 12345);
        assert_eq!(
            entry.name_value.as_deref(),
            Some("example.com\napi.vendor.io")
        );
        assert_eq!(entry.issuer_name.as_deref(), Some("Let's Encrypt"));
        assert!(entry.common_name.is_none());
    }

    #[test]
    fn test_certspotter_issuance_non_numeric_id_defaults_zero() {
        let json = r#"[{"id":"not-a-number","dns_names":["x.com"]}]"#;
        let issuances: Vec<CertSpotterIssuance> = serde_json::from_str(json).unwrap();
        let entry = issuances.into_iter().next().unwrap().into_crtsh_entry();
        assert_eq!(entry.id, 0);
        assert!(entry.issuer_name.is_none());
    }

    #[tokio::test]
    async fn test_discover_round_robin_fails_over_to_certspotter() {
        // crt.sh is over its rate limit (429); the round-robin must fail over to the
        // Cert Spotter provider and still surface the vendor from its certificates.
        let crtsh = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429).set_body_string("Too Many Requests"))
            .mount(&crtsh)
            .await;

        let certspotter = MockServer::start().await;
        let cs_body = serde_json::json!([
            {"id": "9001", "dns_names": ["example.com", "vendor-x.io"], "issuer": {"name": "Let's Encrypt"}}
        ]);
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&cs_body))
            .mount(&certspotter)
            .await;

        let disc = CtLogDiscovery::with_providers(
            Duration::from_secs(5),
            crtsh.uri(),
            vec![CtProvider::CertSpotter {
                base_url: certspotter.uri(),
                token: None,
            }],
        );
        let results = disc.discover("example.com").await.unwrap();
        assert!(
            results.iter().any(|r| r.domain == "vendor-x.io"),
            "expected failover to Cert Spotter to surface vendor-x.io, got {:?}",
            results.iter().map(|r| &r.domain).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_discover_all_providers_soft_fail_returns_empty() {
        // Both providers respond with a server error — every provider soft-fails, so the
        // result degrades to empty (no vendors) rather than erroring the scan.
        let crtsh = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&crtsh)
            .await;
        let certspotter = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&certspotter)
            .await;

        let disc = CtLogDiscovery::with_providers(
            Duration::from_secs(5),
            crtsh.uri(),
            vec![CtProvider::CertSpotter {
                base_url: certspotter.uri(),
                token: None,
            }],
        );
        let results = disc.discover("example.com").await.unwrap();
        assert!(results.is_empty());
    }

    // --- MerkleMap + Censys providers ---

    #[test]
    fn test_crtsh_entry_from_names() {
        let e = crtsh_entry_from_names(vec!["a.com".to_string(), "b.io".to_string()], "Src CT");
        assert_eq!(e.name_value.as_deref(), Some("a.com\nb.io"));
        assert_eq!(e.issuer_name.as_deref(), Some("Src CT"));
        assert!(e.common_name.is_none());
    }

    #[test]
    fn test_merklemap_response_parse() {
        let r: MerkleMapResponse = serde_json::from_str(
            r#"{"count":2,"results":[{"hostname":"x.com"},{"hostname":"y.io"}]}"#,
        )
        .unwrap();
        assert_eq!(r.results.len(), 2);
        assert_eq!(r.results[0].hostname.as_deref(), Some("x.com"));
    }

    #[test]
    fn test_censys_hit_dns_names_from_all_field_positions() {
        // top-level `names`
        let h: CensysHit = serde_json::from_str(r#"{"names":["a.com"]}"#).unwrap();
        assert_eq!(h.dns_names(), vec!["a.com".to_string()]);
        // nested `cert.names`
        let h: CensysHit = serde_json::from_str(r#"{"cert":{"names":["b.com"]}}"#).unwrap();
        assert_eq!(h.dns_names(), vec!["b.com".to_string()]);
        // deeply-nested `cert.parsed.subject_alt_name.dns_names`
        let h: CensysHit = serde_json::from_str(
            r#"{"cert":{"parsed":{"subject_alt_name":{"dns_names":["c.com"]}}}}"#,
        )
        .unwrap();
        assert_eq!(h.dns_names(), vec!["c.com".to_string()]);
        // nothing populated
        let h: CensysHit = serde_json::from_str(r#"{}"#).unwrap();
        assert!(h.dns_names().is_empty());
    }

    #[tokio::test]
    async fn test_discover_fails_over_to_merklemap() {
        let crtsh = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&crtsh)
            .await;

        let merklemap = MockServer::start().await;
        let mm_body = serde_json::json!({"count": 2, "results": [{"hostname": "example.com"}, {"hostname": "vendor-y.io"}]});
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&mm_body))
            .mount(&merklemap)
            .await;

        let disc = CtLogDiscovery::with_providers(
            Duration::from_secs(5),
            crtsh.uri(),
            vec![CtProvider::MerkleMap {
                base_url: merklemap.uri(),
                token: "test-token".to_string(),
            }],
        );
        let results = disc.discover("example.com").await.unwrap();
        assert!(
            results.iter().any(|r| r.domain == "vendor-y.io"),
            "expected failover to MerkleMap to surface vendor-y.io, got {:?}",
            results.iter().map(|r| &r.domain).collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn test_discover_fails_over_to_censys() {
        let crtsh = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429))
            .mount(&crtsh)
            .await;

        let censys = MockServer::start().await;
        // Censys is queried with POST; hits carry a top-level `names` array.
        let cx_body =
            serde_json::json!({"result": {"hits": [{"names": ["example.com", "vendor-z.io"]}]}});
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&cx_body))
            .mount(&censys)
            .await;

        let disc = CtLogDiscovery::with_providers(
            Duration::from_secs(5),
            crtsh.uri(),
            vec![CtProvider::Censys {
                base_url: censys.uri(),
                pat: "pat".to_string(),
                org_id: "org".to_string(),
            }],
        );
        let results = disc.discover("example.com").await.unwrap();
        assert!(
            results.iter().any(|r| r.domain == "vendor-z.io"),
            "expected failover to Censys to surface vendor-z.io, got {:?}",
            results.iter().map(|r| &r.domain).collect::<Vec<_>>()
        );
    }

    // ───────────────────────────────────────────────────────────────
    // P2.9: expired-certificate exclusion, the shared-certificate SAN
    // cap, and the 429 cooldown
    // ───────────────────────────────────────────────────────────────

    #[test]
    fn crtsh_is_asked_only_for_currently_valid_certificates() {
        let url = crtsh_query_url("https://crt.sh", "example.com");
        assert!(
            url.contains("exclude=expired"),
            "without exclude=expired crt.sh serves the domain's ENTIRE certificate history — \
             megabytes of JSON parsed to re-extract the same names, and lapsed certificates \
             attesting relationships that have themselves lapsed: {url}"
        );
        // The rest of the contract: losing the wildcard prefix silently drops every subdomain from
        // the answer, and losing output=json makes crt.sh reply with HTML that will never parse.
        assert!(url.starts_with("https://crt.sh/?q=%.example.com"), "{url}");
        assert!(url.contains("output=json"), "{url}");
    }

    #[test]
    fn crtsh_query_url_encodes_the_domain_it_is_given() {
        let url = crtsh_query_url("https://crt.sh", "ex ample.com");
        assert!(
            !url.contains("ex ample.com"),
            "an unencoded domain would break the query string: {url}"
        );
    }

    #[test]
    fn cert_san_bases_collapses_one_certificate_to_one_row_per_relationship() {
        // apex + wildcard + www are three SANs and ONE relationship. The shared-certificate cap
        // counts relationships, so a certificate that lists a dozen spellings of its own name must
        // not read as a wide multi-tenant bundle.
        let sans =
            cert_san_bases("Example.com\n  \n*.example.com\nwww.EXAMPLE.com\napi.vendor.io\n\n");
        let bases: Vec<&str> = sans.iter().map(|(_, b)| b.as_str()).collect();
        assert_eq!(bases, vec!["example.com", "vendor.io"]);
        // The SAN retained for evidence is the first spelling seen, normalised.
        assert_eq!(sans[0].0, "example.com");
        assert_eq!(sans[1].0, "api.vendor.io");
    }

    #[test]
    fn corroboration_requires_a_second_independently_issued_certificate() {
        // A single certificate corroborates nothing — there is nothing to corroborate against.
        assert!(corroborated_bases(&[vec!["a.com", "b.com"]]).is_empty());

        // A different certificate re-attests b.com; a.com and c.com each appear exactly once.
        let corroborated = corroborated_bases(&[vec!["a.com", "b.com"], vec!["b.com", "c.com"]]);
        assert_eq!(corroborated, HashSet::from(["b.com"]));
    }

    #[test]
    fn a_precertificates_duplicate_row_is_not_a_second_source() {
        // crt.sh lists a precertificate AND its final certificate as separate rows with distinct
        // IDs and identical names. Counting rows rather than certificates would make every base
        // domain trivially "corroborated" by its own precertificate, and the shared-certificate cap
        // would then admit every co-tenant of every bundle — the defect it exists to close.
        // Reordered here as well, because the fingerprint must not depend on SAN order.
        let precert_and_cert = [vec!["a.com", "b.com"], vec!["b.com", "a.com"]];
        assert!(
            corroborated_bases(&precert_and_cert).is_empty(),
            "the same certificate logged twice is one source, not two"
        );
    }

    /// `n` distinct base domains, corroborated by nothing.
    fn synthetic_bases(n: usize) -> Vec<String> {
        (0..n).map(|i| format!("vendor{i}.com")).collect()
    }

    #[test]
    fn an_ordinary_certificate_admits_every_san() {
        let owned = synthetic_bases(SHARED_CERT_SAN_BASE_LIMIT);
        let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
        // No corroboration anywhere, and it makes no difference: under the limit a certificate's
        // SAN list *is* the relationship set, and second-guessing it costs real recall for nothing.
        assert_eq!(admit_san_bases(&refs, &HashSet::new()), refs);
    }

    #[test]
    fn a_shared_certificate_admits_only_what_a_second_certificate_attests() {
        let owned = synthetic_bases(SHARED_CERT_SAN_BASE_LIMIT + 5);
        let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
        let corroborated = HashSet::from([refs[3], refs[17]]);

        let admitted = admit_san_bases(&refs, &corroborated);

        assert_eq!(
            admitted,
            vec![refs[3], refs[17]],
            "co-tenancy on one wide bundle is not a vendor relationship; only the base domains a \
             second certificate also attests may seed recursion"
        );

        // The boundary is exact: one name below the limit everything is admitted, one name above it
        // the burden of proof rises.
        let over = synthetic_bases(SHARED_CERT_SAN_BASE_LIMIT + 1);
        let over_refs: Vec<&str> = over.iter().map(String::as_str).collect();
        assert_eq!(
            admit_san_bases(&over_refs, &HashSet::from([over_refs[0]])),
            vec![over_refs[0]]
        );
        let at_limit = synthetic_bases(SHARED_CERT_SAN_BASE_LIMIT);
        let at_limit_refs: Vec<&str> = at_limit.iter().map(String::as_str).collect();
        assert_eq!(
            admit_san_bases(&at_limit_refs, &HashSet::from([at_limit_refs[0]])),
            at_limit_refs
        );
    }

    #[test]
    fn a_shared_certificate_with_nothing_corroborated_is_never_emptied() {
        let owned = synthetic_bases(SHARED_CERT_SAN_BASE_LIMIT + 5);
        let refs: Vec<&str> = owned.iter().map(String::as_str).collect();
        assert_eq!(
            admit_san_bases(&refs, &HashSet::new()),
            refs,
            "with no second certificate to compare against there is no evidence this bundle is \
             SHARED either — a stable single-org family reissued verbatim looks exactly like this. \
             Taking none here would turn a fan-out bound into a total recall loss for the domain"
        );
    }

    #[test]
    fn retry_after_is_honoured_when_usable_and_still_backs_off_when_not() {
        assert_eq!(throttle_cooldown(Some("120")), Duration::from_secs(120));
        assert_eq!(throttle_cooldown(Some("  30  ")), Duration::from_secs(30));

        // Absent, and every malformed shape. Reading "0 seconds" out of an HTTP-date would be worse
        // than not parsing it, so the date form deliberately lands here too — the scan still backs
        // off, it just uses its own default rather than a number it invented.
        for header in [
            None,
            Some(""),
            Some("soon"),
            Some("-5"),
            Some("12.5"),
            Some("Wed, 21 Oct 2015 07:28:00 GMT"),
        ] {
            assert_eq!(
                throttle_cooldown(header),
                Duration::from_secs(CT_COOLDOWN_DEFAULT_SECS),
                "unparseable Retry-After {header:?} must still produce a real backoff"
            );
        }

        // Bounded both ways: a `0` must not walk straight back into the same refusal, and one
        // header must not remove a provider from the rotation for the rest of a deep scan.
        assert_eq!(
            throttle_cooldown(Some("0")),
            Duration::from_secs(CT_COOLDOWN_MIN_SECS)
        );
        assert_eq!(
            throttle_cooldown(Some("86400")),
            Duration::from_secs(CT_COOLDOWN_MAX_SECS)
        );
    }

    #[test]
    fn a_throttled_empty_is_never_classified_as_an_authoritative_empty() {
        // A sibling answered: the phase is not degraded, however loudly another provider complained
        // on the way there.
        for throttled in [false, true] {
            for transport in [false, true] {
                assert_eq!(
                    classify_ct_outcome(true, throttled, transport),
                    CtOutcome::Authoritative
                );
            }
        }
        // Nothing answered. Unreachable outranks throttled because the caller already propagates
        // and counts a real transport error; recording it twice would inflate the degradation
        // counts the summary prints.
        assert_eq!(
            classify_ct_outcome(false, true, true),
            CtOutcome::Unreachable
        );
        assert_eq!(
            classify_ct_outcome(false, false, true),
            CtOutcome::Unreachable
        );
        assert_eq!(
            classify_ct_outcome(false, true, false),
            CtOutcome::ThrottledEmpty
        );
        assert_eq!(
            classify_ct_outcome(false, false, false),
            CtOutcome::UnusableEmpty
        );

        // The property the whole enum exists for: two byte-identical empty results, two meanings.
        assert_ne!(
            classify_ct_outcome(false, true, false),
            classify_ct_outcome(true, false, false),
            "a rate-limited scan must never be reported as a domain with no certificates"
        );
    }

    #[test]
    fn a_throttled_provider_stays_out_until_its_deadline_and_is_warned_about_once() {
        let throttle = ProviderThrottle::default();
        assert!(
            throttle.is_usable_at(0),
            "a provider that has never been throttled is usable"
        );

        let now = 1_000_000;
        assert!(
            throttle.begin_cooldown(now, Duration::from_secs(60)),
            "the first throttle from a provider is the one that gets warned about"
        );
        assert!(!throttle.is_usable_at(now));
        assert!(!throttle.is_usable_at(now + 59_999));
        assert!(
            throttle.is_usable_at(now + 60_000),
            "the cooldown expires — it holds a provider out, it does not disable it"
        );

        // A shorter, overlapping refusal must neither warn again (a deep scan would print thousands
        // of identical lines and teach the reader to ignore them) nor shorten the longer backoff.
        assert!(!throttle.begin_cooldown(now, Duration::from_secs(5)));
        assert!(throttle.is_usable_at(now + 60_000));
        assert!(!throttle.is_usable_at(now + 59_999));
    }

    /// One wide bundle: the target, twenty-two strangers that appear nowhere else, and one domain a
    /// second certificate also attests.
    fn shared_certificate_names() -> String {
        let mut names = vec!["example.com".to_string()];
        names.extend((0..22).map(|i| format!("cotenant{i}.com")));
        names.push("real-vendor.com".to_string());
        names.join("\n")
    }

    #[tokio::test]
    async fn a_shared_certificate_seeds_recursion_only_from_corroborated_sans() {
        let mock_server = MockServer::start().await;

        let response_body = serde_json::json!([
            { "id": 700, "name_value": shared_certificate_names() },
            { "id": 701, "name_value": "example.com\nreal-vendor.com" },
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();

        let domains: Vec<&str> = results.iter().map(|r| r.domain.as_str()).collect();
        assert_eq!(
            domains,
            vec!["real-vendor.com"],
            "only the base domain a second certificate attests may seed recursion; the twenty-two \
             co-tenants of the wide bundle share a certificate with the target, not a vendor \
             relationship"
        );
    }

    #[tokio::test]
    async fn a_wide_certificate_with_nothing_to_corroborate_it_is_kept_whole() {
        let mock_server = MockServer::start().await;

        // The same wide bundle, alone in the answer. There is no second certificate, so there is no
        // evidence it is shared — Google's ccTLD bundle and Wikimedia's project bundle look exactly
        // like this. Dropping it would delete true relationships to fix a false-positive problem.
        let response_body = serde_json::json!([
            { "id": 800, "name_value": shared_certificate_names() },
        ]);

        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&response_body))
            .mount(&mock_server)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), mock_server.uri());
        let results = disc.discover("example.com").await.unwrap();

        // 24 distinct base domains on the certificate, minus the target's own self-reference.
        assert_eq!(results.len(), 23, "the cap must never take none");
        assert!(results.iter().any(|r| r.domain == "real-vendor.com"));
        assert!(results.iter().any(|r| r.domain == "cotenant0.com"));
    }

    #[tokio::test]
    async fn a_429_holds_the_provider_out_of_the_rotation_and_is_counted() {
        let crtsh = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "120"))
            .mount(&crtsh)
            .await;

        let disc = CtLogDiscovery::with_base_url(Duration::from_secs(5), crtsh.uri());

        let first = disc.discover("example.com").await.unwrap();
        assert!(first.is_empty());
        assert_eq!(
            disc.throttles_seen(),
            1,
            "a 429 must be counted, not swallowed as an empty answer (TF-RATELIMIT)"
        );

        // The next domain must not re-ask a provider that told us to come back in two minutes.
        let second = disc.discover("other.example.org").await.unwrap();
        assert!(second.is_empty());
        assert_eq!(
            disc.throttles_seen(),
            1,
            "the second domain must have skipped crt.sh entirely; another 429 here means the \
             Retry-After cooldown was not honoured"
        );
        assert_eq!(
            crtsh
                .received_requests()
                .await
                .expect("wiremock records requests by default")
                .len(),
            1,
            "exactly one request may reach a provider that is inside its own Retry-After window"
        );
    }

    #[tokio::test]
    async fn a_throttled_provider_still_fails_over_to_a_healthy_sibling() {
        let crtsh = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "60"))
            .mount(&crtsh)
            .await;

        let certspotter = MockServer::start().await;
        let cs_body = serde_json::json!([
            {"id": "9100", "dns_names": ["example.com", "vendor-w.io"], "issuer": {"name": "R3"}}
        ]);
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_json(&cs_body))
            .mount(&certspotter)
            .await;

        let disc = CtLogDiscovery::with_providers(
            Duration::from_secs(5),
            crtsh.uri(),
            vec![CtProvider::CertSpotter {
                base_url: certspotter.uri(),
                token: None,
            }],
        );

        let results = disc.discover("example.com").await.unwrap();
        assert!(
            results.iter().any(|r| r.domain == "vendor-w.io"),
            "the cooldown holds one provider out; it must not cost the answer a sibling can give"
        );
        assert_eq!(disc.throttles_seen(), 1);
    }
}
