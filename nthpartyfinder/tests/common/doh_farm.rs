//! A hermetic 6-provider DoH "farm" for the DNS contention gate (Plan Phase 3, L1).
//!
//! Each provider is one wiremock [`MockServer`] carrying ONE catch-all [`Mock`] whose
//! [`Respond`] implementation is a deterministic, seeded state machine: the behavior served
//! to request `n` is `splitmix64(seed ^ provider_id ^ n) % total_weight`, walked against the
//! profile's weight table. The sequence of behaviors a provider emits is therefore a pure
//! function of `(seed, provider, arrival index)` — reproducible across runs regardless of
//! task-scheduling order (which request GETS a given behavior still depends on arrival
//! order, deliberately: that is what "contention" means).
//!
//! Hermeticity contract: every URL this farm hands out is a loopback IP literal, so the
//! client under test never performs a bootstrap DNS lookup to reach it, and a dead provider
//! is a bound-then-dropped loopback port (true, typed ECONNREFUSED with zero packets beyond
//! the loopback interface).
//!
//! wiremock 0.6.5 note (`Behavior::ConnReset`): the API for raw socket errors exists —
//! `MockBuilder::respond_with_err` — but a `Mock`'s response is `Result<Respond, RespondErr>`
//! fixed at BUILD time, i.e. a mock answers with templates XOR errors, never a per-request
//! mix. So `ConnReset` is supported only as a provider's *sole* behavior (mounted via
//! `respond_with_err`); a weighted mix containing it panics at farm construction with
//! instructions to use [`ProviderSpec::Dead`] instead. No profile in the current gate needs
//! the mixed form.

use std::net::TcpListener;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use wiremock::matchers::any;
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// What one simulated DoH provider does to one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)] // ConnReset / Http400 are part of the farm's vocabulary; not every gate profile uses every word
pub enum Behavior {
    /// Serve a valid dns-json answer for the `name` query param after `delay_ms`.
    Ok { delay_ms: u64 },
    /// HTTP 429 — the DNS_THROTTLE class (backoff + rotation in the client).
    Throttle429,
    /// HTTP 503 — provider-side failure, also classed DNS_THROTTLE by the client.
    Http5xx,
    /// HTTP 400 — the DNS_ENDPOINT class (immediate rotation, no backoff).
    Http400,
    /// HTTP 200 carrying `{"Status": rcode}` — e.g. 2 (SERVFAIL) is the DNS_NAME class.
    Rcode(u16),
    /// Hold the response for `delay_ms` (callers pass >= 3500, beyond the client's 3 s
    /// per-attempt timeout) so the client observes a timeout, not an answer.
    Hang { delay_ms: u64 },
    /// Raw connection reset instead of an HTTP reply. Sole-behavior providers only — see
    /// the module docs for the wiremock 0.6.5 template-XOR-error constraint.
    ConnReset,
}

/// A time-boxed behavior override measured against the farm's construction instant
/// (`Farm::epoch`): requests arriving in `[from_ms, to_ms)` get `behavior` regardless of
/// the weight table.
#[derive(Debug, Clone, Copy)]
pub struct FlapWindow {
    pub from_ms: u64,
    pub to_ms: u64,
    pub behavior: Behavior,
}

/// One provider's behavior distribution: a weight table plus an optional flap window.
#[derive(Debug, Clone)]
pub struct Profile {
    pub weights: Vec<(Behavior, u32)>,
    pub flap: Option<FlapWindow>,
}

impl Profile {
    /// A provider that always does one thing.
    pub fn uniform(behavior: Behavior) -> Self {
        Self {
            weights: vec![(behavior, 1)],
            flap: None,
        }
    }

    /// A provider with a weighted behavior mix.
    #[allow(dead_code)]
    pub fn weighted(weights: Vec<(Behavior, u32)>) -> Self {
        Self {
            weights,
            flap: None,
        }
    }

    /// Add a flap window (see [`FlapWindow`]).
    #[allow(dead_code)]
    pub fn with_flap(mut self, from_ms: u64, to_ms: u64, behavior: Behavior) -> Self {
        self.flap = Some(FlapWindow {
            from_ms,
            to_ms,
            behavior,
        });
        self
    }

    fn total_weight(&self) -> u64 {
        self.weights.iter().map(|(_, w)| u64::from(*w)).sum()
    }

    fn contains_conn_reset(&self) -> bool {
        self.weights
            .iter()
            .any(|(b, _)| matches!(b, Behavior::ConnReset))
            || matches!(
                self.flap,
                Some(FlapWindow {
                    behavior: Behavior::ConnReset,
                    ..
                })
            )
    }

    fn is_pure_conn_reset(&self) -> bool {
        !self.weights.is_empty()
            && self
                .weights
                .iter()
                .all(|(b, _)| matches!(b, Behavior::ConnReset))
            && self.flap.is_none()
    }
}

/// How to build one of the farm's providers.
pub enum ProviderSpec {
    /// A live wiremock server driven by the given behavior profile.
    Mock(Profile),
    /// A bound-then-dropped loopback port: every connection attempt is an instant, typed
    /// ECONNREFUSED. No server exists, so `request_counts()` reports 0 for it forever.
    Dead,
}

struct Provider {
    url: String,
    requests: Arc<AtomicU64>,
    /// Keeps the wiremock server (and its port) alive for the farm's lifetime. `None` for
    /// dead providers.
    _server: Option<MockServer>,
}

/// The farm: an ordered set of simulated DoH providers plus the shared behavior epoch.
pub struct Farm {
    providers: Vec<Provider>,
    epoch: Instant,
}

impl Farm {
    /// Build the farm. All live `MockServer`s are started (their ports bound) BEFORE any
    /// dead-provider port is carved out and released, so a dead port can never be re-issued
    /// to a later server of this same farm.
    pub async fn start(seed: u64, specs: Vec<ProviderSpec>) -> Self {
        let epoch = Instant::now();

        // Pass 1: start every live server.
        let mut live: Vec<Option<(MockServer, Profile)>> = Vec::with_capacity(specs.len());
        for spec in specs {
            match spec {
                ProviderSpec::Mock(profile) => {
                    live.push(Some((MockServer::start().await, profile)));
                }
                ProviderSpec::Dead => live.push(None),
            }
        }

        // Pass 2: carve out all dead ports while every live port is still held, then drop
        // the listeners together for instant ECONNREFUSED.
        let mut dead_ports: Vec<Option<u16>> = Vec::with_capacity(live.len());
        {
            let mut listeners: Vec<TcpListener> = Vec::new();
            for slot in &live {
                if slot.is_none() {
                    let listener = TcpListener::bind("127.0.0.1:0")
                        .expect("bind a loopback port for a dead provider");
                    let port = listener
                        .local_addr()
                        .expect("read the dead provider's port")
                        .port();
                    listeners.push(listener);
                    dead_ports.push(Some(port));
                } else {
                    dead_ports.push(None);
                }
            }
            drop(listeners);
        }

        // Pass 3: mount the responders and assemble the ordered provider list.
        let mut providers = Vec::with_capacity(live.len());
        for (provider_id, (slot, dead_port)) in live.into_iter().zip(dead_ports).enumerate() {
            match slot {
                Some((server, profile)) => {
                    let requests = Arc::new(AtomicU64::new(0));
                    if profile.is_pure_conn_reset() {
                        let counter = Arc::clone(&requests);
                        Mock::given(any())
                            .respond_with_err(move |_req: &Request| {
                                counter.fetch_add(1, Ordering::Relaxed);
                                std::io::Error::new(
                                    std::io::ErrorKind::ConnectionReset,
                                    "doh_farm: simulated connection reset",
                                )
                            })
                            .mount(&server)
                            .await;
                    } else {
                        assert!(
                            !profile.contains_conn_reset(),
                            "doh_farm: wiremock 0.6.5 mocks answer with templates XOR errors, \
                             so Behavior::ConnReset cannot be one arm of a weighted mix — make \
                             it the provider's sole behavior or use ProviderSpec::Dead"
                        );
                        assert!(
                            profile.total_weight() > 0,
                            "doh_farm: provider {provider_id} has an empty/zero-weight profile"
                        );
                        Mock::given(any())
                            .respond_with(GateResponder {
                                seed,
                                provider_id: provider_id as u64,
                                counter: Arc::clone(&requests),
                                profile,
                                epoch,
                            })
                            .mount(&server)
                            .await;
                    }
                    providers.push(Provider {
                        url: format!("{}/dns-query", server.uri()),
                        requests,
                        _server: Some(server),
                    });
                }
                None => {
                    let port = dead_port.expect("dead slot carries its carved-out port");
                    providers.push(Provider {
                        url: format!("http://127.0.0.1:{port}/dns-query"),
                        requests: Arc::new(AtomicU64::new(0)),
                        _server: None,
                    });
                }
            }
        }

        Self { providers, epoch }
    }

    /// Provider URLs in construction order, each ending in `/dns-query`.
    pub fn urls(&self) -> Vec<String> {
        self.providers.iter().map(|p| p.url.clone()).collect()
    }

    /// Requests each provider has served so far (dead providers report 0 — a refused
    /// connection never reaches a counter).
    pub fn request_counts(&self) -> Vec<u64> {
        self.providers
            .iter()
            .map(|p| p.requests.load(Ordering::Relaxed))
            .collect()
    }

    /// The farm's behavior epoch — flap windows are measured from this instant.
    #[allow(dead_code)]
    pub fn epoch(&self) -> Instant {
        self.epoch
    }
}

/// SplitMix64 — the deterministic per-request dice. Public so the gate driver can reuse the
/// same generator for its own deterministic choices.
pub fn splitmix64(mut x: u64) -> u64 {
    x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// The deterministic seeded state machine behind each live provider's catch-all mock.
struct GateResponder {
    seed: u64,
    provider_id: u64,
    counter: Arc<AtomicU64>,
    profile: Profile,
    epoch: Instant,
}

impl GateResponder {
    fn pick(&self, n: u64) -> Behavior {
        if let Some(flap) = self.profile.flap {
            let t = self.epoch.elapsed().as_millis() as u64;
            if t >= flap.from_ms && t < flap.to_ms {
                return flap.behavior;
            }
        }
        let total = self.profile.total_weight();
        let mut roll = splitmix64(self.seed ^ self.provider_id ^ n) % total;
        for (behavior, weight) in &self.profile.weights {
            let weight = u64::from(*weight);
            if roll < weight {
                return *behavior;
            }
            roll -= weight;
        }
        unreachable!("roll is reduced mod total_weight, so the walk always terminates")
    }
}

impl Respond for GateResponder {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let name = request
            .url
            .query_pairs()
            .find(|(k, _)| k == "name")
            .map(|(_, v)| v.into_owned())
            .unwrap_or_else(|| "unknown.gate.example".to_string());

        match self.pick(n) {
            Behavior::Ok { delay_ms } => ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({
                    "Status": 0,
                    "Answer": [{
                        "name": name,
                        "type": 16,
                        "data": "\"v=spf1 include:_spf.example.com ~all\""
                    }]
                }))
                .insert_header("content-type", "application/dns-json")
                .set_delay(Duration::from_millis(delay_ms)),
            Behavior::Throttle429 => ResponseTemplate::new(429),
            Behavior::Http5xx => ResponseTemplate::new(503),
            Behavior::Http400 => ResponseTemplate::new(400),
            Behavior::Rcode(rcode) => ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "Status": rcode }))
                .insert_header("content-type", "application/dns-json"),
            Behavior::Hang { delay_ms } => ResponseTemplate::new(200)
                .set_body_json(serde_json::json!({ "Status": 0, "Answer": [] }))
                .insert_header("content-type", "application/dns-json")
                .set_delay(Duration::from_millis(delay_ms)),
            Behavior::ConnReset => unreachable!(
                "pure-ConnReset providers are mounted with respond_with_err; \
                 mixed profiles are rejected at Farm::start"
            ),
        }
    }
}
