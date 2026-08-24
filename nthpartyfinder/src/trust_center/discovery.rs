//! Auto-discovery engine for trust center extraction strategies.
//!
//! When a domain has no cached strategy and the HTML looks like an SPA,
//! this module runs generic probes to discover the extraction strategy.

use anyhow::Result;

#[cfg(not(coverage))]
use std::sync::{Arc, Mutex};
use std::time::Duration;
#[cfg(not(coverage))]
use std::time::Instant;
use tracing::debug;

use super::{
    detect_field_mapping, find_entity_arrays, score_subprocessor_array, CandidateStrategy,
    DiscoveryMetadata, DiscoveryMethod, EndpointConfig, ResponseMapping, StrategyType,
    TrustCenterStrategy,
};
use crate::subprocessor::SubprocessorDomain;

/// A JSON network response captured during a headless page load.
#[derive(Debug, Clone)]
pub(crate) struct InterceptedResponse {
    /// The response URL (used to optionally prefer a specific API/operation).
    url: String,
    /// The raw response body (expected to be JSON).
    body: String,
}

/// Check if HTML content looks like a JavaScript SPA that needs special handling.
pub fn is_likely_spa(html: &str) -> bool {
    // Strip HTML tags to get approximate text content length
    let text_len = html
        .chars()
        .fold((0usize, false), |(count, in_tag), ch| match ch {
            '<' => (count, true),
            '>' => (count, false),
            _ if !in_tag => (count + 1, false),
            _ => (count, in_tag),
        })
        .0;

    let html_len = html.len();
    if html_len == 0 {
        return false;
    }

    // SPA indicator 1: Very little text content relative to HTML size
    let text_ratio = text_len as f64 / html_len as f64;
    if text_ratio < 0.05 && html_len > 1000 {
        debug!("SPA detected: text/HTML ratio {:.3} < 0.05", text_ratio);
        return true;
    }

    // SPA indicator 2: Contains framework markers
    let html_lower = html.to_lowercase();
    let spa_markers = [
        "id=\"__next\"",
        "id=\"root\"",
        "__next_data__",
        "data-reactroot",
        "window.__nuxt__",
        "ng-app",
        "id=\"app\"",
    ];

    for marker in &spa_markers {
        if html_lower.contains(marker) {
            debug!("SPA detected: found framework marker '{}'", marker);
            return true;
        }
    }

    // SPA indicator 3: Body element has no visible content elements — only scripts.
    // Some SPAs (e.g., Vanta trust center) use <body id="body"> with only <script> children
    // and rely entirely on JavaScript to render content. The text ratio check above may be
    // fooled by long meta descriptions that inflate text content counts.
    let body_start = match html_lower.find("<body") {
        Some(pos) => pos,
        None => return false,
    };
    let body_tag_end = match html_lower[body_start..].find('>') {
        Some(pos) => pos,
        None => return false,
    };
    let body_content_start = body_start + body_tag_end + 1;
    let body_content = if let Some(body_end) = html_lower[body_content_start..].find("</body") {
        &html_lower[body_content_start..body_content_start + body_end]
    } else {
        &html_lower[body_content_start..]
    };

    let visible_tags = [
        "<div", "<p", "<table", "<section", "<article", "<main", "<h1", "<h2", "<h3", "<span",
        "<ul", "<ol", "<form",
    ];
    let has_visible_content = visible_tags.iter().any(|tag| body_content.contains(tag));

    if !has_visible_content && body_content.contains("<script") {
        debug!("SPA detected: body has no visible content elements, only scripts");
        return true;
    }

    false
}

/// Discover an extraction strategy from *static* HTML embedded-data patterns
/// (SafeBase, Conveyor, Next.js `__NEXT_DATA__`, JSON `<script>` tags, base64
/// blobs, JS object assignments). This is the cheap, no-browser probe and is
/// tried first.
///
/// SPAs whose subprocessor data only exists behind a runtime API call (e.g.
/// Vanta's Apollo GraphQL) yield nothing here — they are handled by
/// [`discover_and_extract_via_render`], which renders the page and reads the
/// JSON the page itself fetches. Keeping this probe browser-free means the same
/// function runs identically under coverage instrumentation.
pub async fn discover_strategy(
    url: &str,
    static_html: &str,
) -> Result<Option<TrustCenterStrategy>> {
    debug!("Running HTML pattern scan probe on static HTML for {}", url);
    let mut candidates = match discover_via_html_patterns(static_html) {
        Ok(c) => c,
        Err(e) => {
            debug!("HTML pattern scan failed: {}", e);
            Vec::new()
        }
    };

    candidates.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if let Some(best) = candidates.into_iter().next() {
        if best.score >= 0.4 {
            debug!(
                "Selected embedded-data strategy with score {:.2}, {} items",
                best.score, best.item_count
            );
            return Ok(Some(best.strategy));
        }
        debug!(
            "Best embedded-data candidate {:.2} below threshold 0.4",
            best.score
        );
    }

    Ok(None)
}

/// P2.3: the render-capture used to be a fixed 2s settle followed by up to eighteen 1s
/// wait/scroll rounds that only gave up after six consecutive rounds captured nothing. That put
/// an ~8s floor under every page that fetches no subprocessor JSON at all — the *common* case,
/// because marketing sites catch-all-200 every candidate path we probe. The wait is now adaptive;
/// this constant is the old worst case (2s + 18 rounds) preserved exactly as a hard cap, so no
/// page that used to be waited out is now cut short.
const TRUST_CENTER_CAPTURE_HARD_CAP: Duration = Duration::from_millis(20_000);

/// Floor before the idle rule may fire. A capture polled immediately after `wait_until_navigated`
/// can momentarily show nothing in flight and no activity — not because the page is done, but
/// because its scripts have not issued their first request yet. Exiting there would render an SPA
/// and capture none of its API traffic.
const TRUST_CENTER_CAPTURE_MIN_WAIT: Duration = Duration::from_millis(800);

/// Quiet period that ends the capture. Deliberately wider than the web-traffic capture's 800ms
/// window: this handler fetches each JSON body through its own retry ladder, so a body can land in
/// the collected set more than a second after the network event that announced it.
const TRUST_CENTER_CAPTURE_IDLE_WINDOW: Duration = Duration::from_millis(1_500);

/// Total-silence escape hatch for an in-flight counter left non-zero by a redirect chain or a
/// WebSocket, neither of which need emit a matching `loadingFinished`. Sized to the old
/// six-stagnant-round give-up so a genuinely slow page gets the same patience it used to.
const TRUST_CENTER_CAPTURE_STALL_WINDOW: Duration = Duration::from_millis(6_000);

/// Grace granted after the subprocessor array first appears, for the pagination calls that trail
/// it. The old loop spent two 1s rounds here; keeping the same budget keeps paginated trust
/// centers whole.
const SUBPROCESSOR_PAGINATION_GRACE: Duration = Duration::from_millis(2_000);

/// How often the scroll/pagination pass re-runs inside the poll loop — the old per-round cadence.
#[cfg(not(coverage))]
const PAGINATION_INTERVAL: Duration = Duration::from_millis(1_000);

/// Poll granularity of the adaptive wait. Fine enough that the idle window, not the polling, sets
/// the exit latency.
#[cfg(not(coverage))]
const CAPTURE_POLL: Duration = Duration::from_millis(50);

/// Hard caps on what a single (potentially hostile) page may make us accumulate
/// while capturing its network JSON: a response-count ceiling and an aggregate
/// body-byte budget. Real trust centers use tens of small responses; these only
/// bite a page deliberately trying to exhaust memory.
#[cfg(not(coverage))]
const MAX_CAPTURED_RESPONSES: usize = 400;
#[cfg(not(coverage))]
const MAX_CAPTURED_BYTES: usize = 64 * 1024 * 1024;

/// JavaScript that scrolls to the bottom (to trigger lazy-load / infinite scroll)
/// and clicks pagination-style controls so paginated APIs fire all their calls.
/// Restricted to buttons (not links) and strict pagination wording to avoid
/// triggering full-page navigation. Returns the number of controls clicked
/// (ignored by the caller).
#[cfg(not(coverage))]
const PAGINATION_JS: &str = r#"(function(){
  try { window.scrollTo(0, document.body.scrollHeight); } catch (e) {}
  var rx = /(next|show more|load more|view more|show all|see all|view all)/i;
  var clicked = 0;
  try {
    document.querySelectorAll('button, [role="button"]').forEach(function(el){
      try {
        if (el.tagName === 'A' || el.hasAttribute('href')) { return; }
        var label = (el.textContent || '') + ' ' + (el.getAttribute('aria-label') || '');
        if (rx.test(label) && !el.disabled && el.offsetParent !== null) { el.click(); clicked++; }
      } catch (e) {}
    });
  } catch (e) {}
  return clicked;
})()"#;

/// P2.3: URL fragments that mark a response as telemetry, consent, session-replay or
/// feature-flag traffic rather than page data.
///
/// These fire continuously — a beacon every couple of seconds is normal — and the old capture
/// predicate matched any URL containing `/api/`, so each beacon landed in the collected set and
/// reset the stagnation counter. A page with no subprocessor data at all was therefore held open
/// to the full cap by its own analytics. None of these hosts has ever carried a subprocessor
/// array, and this capture feeds subprocessor extraction only, so excluding them costs no recall.
const ANALYTICS_URL_MARKERS: &[&str] = &[
    "google-analytics.com",
    "googletagmanager.com",
    "analytics.google.com",
    "doubleclick.net",
    "segment.io",
    "segment.com",
    "mixpanel.com",
    "amplitude.com",
    "heapanalytics.com",
    "fullstory.com",
    "hotjar.com",
    "hotjar.io",
    "clarity.ms",
    "posthog.com",
    "sentry.io",
    "bugsnag.com",
    "datadoghq.com",
    "newrelic.com",
    "nr-data.net",
    "intercom.io",
    "hs-analytics.net",
    "hubspot.com",
    "pendo.io",
    "launchdarkly.com",
    "statsig.com",
    "cookielaw.org",
    "onetrust.com",
    "/collect",
    "/beacon",
    "/telemetry",
];

/// Whether a URL is one of the telemetry/consent endpoints in [`ANALYTICS_URL_MARKERS`].
pub(crate) fn is_analytics_beacon(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    ANALYTICS_URL_MARKERS.iter().any(|m| lower.contains(m))
}

/// Whether a network response should be collected as candidate subprocessor JSON.
///
/// The `/api/` substring is kept because real trust-center APIs do serve JSON under a wrong or
/// missing `Content-Type`; it is the analytics exclusion, not a narrower positive test, that stops
/// beacons from being treated as page data (P2.3).
pub(crate) fn is_capturable_json(mime: &str, url: &str, status: u32) -> bool {
    if !(200..300).contains(&status) {
        return false;
    }
    if is_analytics_beacon(url) {
        return false;
    }
    let lower = url.to_ascii_lowercase();
    mime.contains("json") || lower.contains("graphql") || lower.contains("/api/")
}

/// P2.3: the pure exit decision for the adaptive render-capture wait, evaluated once per poll.
///
/// Precedence matters and is deliberate:
/// 1. `elapsed >= hard_cap` — the pre-P2.3 worst case, never exceeded.
/// 2. `at_response_cap` — the hostile-page response ceiling; more waiting cannot collect more.
/// 3. subprocessors already captured — stay exactly [`SUBPROCESSOR_PAGINATION_GRACE`] longer for
///    the pagination calls that trail the first page, then stop. This branch deliberately
///    *ignores* the idle rule: a paginated trust center goes quiet between page fetches, and
///    exiting on that quiet is how pages 2..n get lost.
/// 4. otherwise the shared network-idle rule from the web-traffic capture — stop once nothing is
///    in flight and the network has been quiet for the idle window (or dead silent for the stall
///    window, which covers an in-flight counter stranded by a redirect chain or WebSocket).
pub(crate) fn should_exit_trust_center_capture(
    elapsed: Duration,
    at_response_cap: bool,
    pending: bool,
    quiet: Duration,
    since_subprocessors: Option<Duration>,
) -> bool {
    if elapsed >= TRUST_CENTER_CAPTURE_HARD_CAP {
        return true;
    }
    if at_response_cap {
        return true;
    }
    if let Some(age) = since_subprocessors {
        return age >= SUBPROCESSOR_PAGINATION_GRACE;
    }
    crate::discovery::web_traffic::should_exit_network_idle(
        elapsed,
        TRUST_CENTER_CAPTURE_MIN_WAIT,
        TRUST_CENTER_CAPTURE_HARD_CAP,
        TRUST_CENTER_CAPTURE_IDLE_WINDOW,
        TRUST_CENTER_CAPTURE_STALL_WINDOW,
        pending,
        quiet,
    )
}

/// One headless render's yield: the JSON its scripts fetched, plus the DOM as it stood when the
/// capture stopped.
///
/// P2.1(b): the settled DOM is taken while the tab is still alive and exclusively held, because
/// the subprocessor path used to navigate to the *same URL in a second browser tab* purely to read
/// that DOM. Carrying it out of this render is what lets that second render be skipped.
#[derive(Debug, Default)]
pub(crate) struct RenderCapture {
    pub(crate) responses: Vec<InterceptedResponse>,
    /// `None` when the DOM could not be read (a `getContent` failure is not worth failing the
    /// capture over — the JSON is the primary product and the caller still has its own render as
    /// a fallback).
    pub(crate) settled_dom: Option<String>,
}

/// P2.1(a): whether a second full render of the same URL is justified.
///
/// The retry was added because the headless render is mildly racy — the large report response can
/// arrive late or be read mid-stream — and it used to fire whenever the first capture produced no
/// subprocessor array. That condition is true for *every* futile candidate URL, and futile
/// candidates are the common case, so the retry doubled the render cost of the dominant path. The
/// `render.retry_rescued` counter was added to settle it empirically and came back **zero across a
/// 9.15h depth-3 scan (22,482 relationships)**: not one retry ever rescued an array the first
/// capture missed. So a clean capture that simply found no subprocessor array is now taken at its
/// word as a legitimate negative.
///
/// What still earns a retry is the evidence of an actually *racy* attempt: the capture returned an
/// error, collected nothing at all, or collected a body that begins like JSON and does not parse —
/// the fingerprint of the partial `getResponseBody` read the in-handler retry ladder exists to
/// absorb but can still lose on a large payload.
pub(crate) fn should_retry_capture(
    transport_error: bool,
    response_count: usize,
    has_subprocessor_array: bool,
    truncated_body: bool,
) -> bool {
    if has_subprocessor_array {
        return false;
    }
    transport_error || response_count == 0 || truncated_body
}

/// Whether a body looks like a JSON payload that was read mid-stream: it starts like JSON but does
/// not parse. A complete non-JSON payload (an HTML error page served from an `/api/` path, say)
/// fails the parse too, which is why the "starts like JSON" half is load-bearing — without it
/// every catch-all-200 HTML shell would read as truncated and re-trigger the render we just removed.
pub(crate) fn body_is_truncated_json(body: &str) -> bool {
    let trimmed = body.trim_start();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return false;
    }
    serde_json::from_str::<serde_json::Value>(trimmed).is_err()
}

/// Whether any captured body bears the truncation fingerprint described on
/// [`body_is_truncated_json`].
pub(crate) fn responses_look_truncated(responses: &[InterceptedResponse]) -> bool {
    responses.iter().any(|r| body_is_truncated_json(&r.body))
}

/// Which of two capture attempts to hand back when neither found a subprocessor array: the one
/// that saw more responses, and on a tie the one that also came back with a settled DOM. The DOM
/// is what lets the caller skip its own render, so an empty-handed capture holding one is worth
/// strictly more than an identical capture without.
pub(crate) fn prefer_retry_capture(
    first_len: usize,
    first_has_dom: bool,
    retry_len: usize,
    retry_has_dom: bool,
) -> bool {
    if retry_len != first_len {
        return retry_len > first_len;
    }
    retry_has_dom && !first_has_dom
}

/// Stamp the P2.3 activity clock. A poisoned lock is ignored rather than propagated: the clock
/// only decides when to stop waiting, so a lost stamp costs a longer wait, never a lost response.
#[cfg(not(coverage))]
fn mark_activity(clock: &Mutex<Instant>) {
    if let Ok(mut t) = clock.lock() {
        *t = Instant::now();
    }
}

// cfg(not(coverage)): launches headless Chrome to render an SPA and capture the
// JSON its own scripts fetch — requires a browser, so coverage-off.
#[cfg(not(coverage))]
async fn capture_network_json_responses(url: &str) -> Result<RenderCapture> {
    use std::sync::atomic::{AtomicI64, Ordering};

    let responses = Arc::new(Mutex::new(Vec::<InterceptedResponse>::new()));
    let responses_clone = responses.clone();
    let url_owned = url.to_string();

    // P2.3 activity clock. `in_flight` counts network requests; `body_fetches` counts response
    // bodies the handler is still reading. Both must be zero before the idle rule may fire — the
    // body read runs its own retry ladder well after `loadingFinished`, and tearing the tab down
    // mid-ladder would drop exactly the large late payload the whole capture exists for.
    let in_flight = Arc::new(AtomicI64::new(0));
    let body_fetches = Arc::new(AtomicI64::new(0));
    let last_activity = Arc::new(Mutex::new(Instant::now()));
    let in_flight_evt = in_flight.clone();
    let last_activity_evt = last_activity.clone();
    let body_fetches_handler = body_fetches.clone();
    let last_activity_handler = last_activity.clone();

    // Residual-159 RCA (2026-08-23, the dominant tail mechanism): this was the ONE render path
    // whose permit-queue wait never reached the vendor's budget counters — it was excluded from
    // the perf timer and then discarded, so under depth-3 contention (permit waits averaging
    // 155-201s) one candidate booked hundreds of queued seconds as "working time" and was
    // budget-exhausted having done almost no work. Read the armed sink BEFORE spawning
    // (task-locals don't cross spawn_blocking) and credit INSIDE the closure, immediately after
    // the permit is held, so every exit path returns its queue time.
    let render_wait_sink = crate::browser_pool::current_render_wait_sink();

    // headless_chrome operations are blocking, run in a blocking thread
    let handle = tokio::task::spawn_blocking(move || -> Result<RenderCapture> {
        // Declared before the guard so tab close and Chrome recycling are measured.
        let mut render_timer =
            crate::perf::RenderTimer::start().with_source(&crate::perf::METRICS.render_trustcenter);
        let guard = crate::browser_pool::acquire_tab()?;
        render_timer.exclude(guard.permit_wait());
        crate::browser_pool::credit_render_wait(&render_wait_sink, guard.permit_wait());
        let tab = guard.tab();

        // Capture JSON API responses (GraphQL/REST/XHR) as the page loads.
        // Handler signature: (ResponseReceivedEventParams, &dyn Fn() -> Result<GetResponseBodyReturnObject>)
        tab.register_response_handling(
            "trust_center_capture",
            Box::new(move |event_params, fetch_body| {
                let resp = &event_params.response;
                let resp_url = &resp.url;

                if is_capturable_json(&resp.mime_type, resp_url, resp.status) {
                    // Reading the body is real work on this page's behalf, so it counts as
                    // activity for the idle rule — both while it runs and each time an attempt
                    // completes. Without this the quiet clock would keep ticking through a
                    // multi-second body read and the poll loop could stop the capture while the
                    // payload was still being pulled.
                    body_fetches_handler.fetch_add(1, Ordering::SeqCst);
                    // Fetch the body, retrying briefly until it parses as complete
                    // JSON. `getResponseBody` can return early/partial right after
                    // ResponseReceived for large payloads (e.g. Vanta's ~74 KB
                    // report carrying the subprocessor list), which previously made
                    // the subprocessor array intermittently missed.
                    let mut body: Option<String> = None;
                    for attempt in 0..4u64 {
                        std::thread::sleep(Duration::from_millis(120 + 140 * attempt));
                        mark_activity(&last_activity_handler);
                        if let Ok(b) = fetch_body() {
                            let complete =
                                serde_json::from_str::<serde_json::Value>(&b.body).is_ok();
                            body = Some(b.body);
                            if complete {
                                break;
                            }
                        }
                    }
                    if let Some(body_str) = body {
                        if body_str.len() > 50 && body_str.len() < 5_000_000 {
                            // Recover from a poisoned lock rather than panicking:
                            // the guarded Vec is a plain response accumulator and
                            // stays valid even if a peer thread panicked.
                            let mut collected = responses_clone
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            // Bound total memory against a hostile page: cap both
                            // the response count and the aggregate body bytes.
                            let current_bytes: usize = collected.iter().map(|r| r.body.len()).sum();
                            if collected.len() < MAX_CAPTURED_RESPONSES
                                && current_bytes + body_str.len() <= MAX_CAPTURED_BYTES
                            {
                                collected.push(InterceptedResponse {
                                    url: resp_url.clone(),
                                    body: body_str,
                                });
                            }
                        }
                    }
                    mark_activity(&last_activity_handler);
                    body_fetches_handler.fetch_sub(1, Ordering::SeqCst);
                }
            }),
        )
        .map_err(|e| anyhow::anyhow!("Failed to register response handler: {}", e))?;

        // Activity listener for the adaptive wait. The counter is bumped for *every* request so it
        // stays balanced (a `loadingFinished` carries only a request id, so a beacon's completion
        // is indistinguishable from a real one and must not be filtered on one side only); it is
        // the activity *clock* that ignores analytics beacons, which is what stops a page whose
        // only remaining traffic is telemetry from being held open to the hard cap.
        let activity_listener = tab
            .add_event_listener(std::sync::Arc::new(
                move |event: &headless_chrome::protocol::cdp::types::Event| {
                    use headless_chrome::protocol::cdp::types::Event;
                    match event {
                        Event::NetworkRequestWillBeSent(e) => {
                            in_flight_evt.fetch_add(1, Ordering::SeqCst);
                            if !is_analytics_beacon(&e.params.request.url) {
                                mark_activity(&last_activity_evt);
                            }
                        }
                        Event::NetworkLoadingFinished(_) | Event::NetworkLoadingFailed(_) => {
                            in_flight_evt.fetch_sub(1, Ordering::SeqCst);
                            mark_activity(&last_activity_evt);
                        }
                        _ => {}
                    }
                },
            ))
            .map_err(|e| anyhow::anyhow!("Failed to add network activity listener: {}", e))?;

        // Navigate and wait for the page + first round of API calls.
        tab.navigate_to(&url_owned)
            .map_err(|e| anyhow::anyhow!("Navigation failed: {}", e))?;
        tab.wait_until_navigated()
            .map_err(|e| anyhow::anyhow!("Page load failed: {}", e))?;

        // P2.3 adaptive wait, replacing a fixed 2s settle plus 1s-granularity rounds. Scroll and
        // click pagination on the old cadence, but decide when to stop on the shared network-idle
        // rule instead of a stagnation counter, so a page that fetches nothing costs ~2s rather
        // than the old ~8s floor. Everything the old loop protected is preserved:
        // `SUBPROCESSOR_PAGINATION_GRACE` still trails the first subprocessor array, the response
        // ceiling still short-circuits, and the hard cap is the old worst case exactly.
        let started = Instant::now();
        let mut last_pagination: Option<Instant> = None;
        let mut subs_seen_at: Option<Instant> = None;
        let mut checked_len = 0usize;
        let mut at_response_cap = false;
        loop {
            // `None` on the first iteration so the scroll/click pass runs immediately, as the old
            // loop's round 0 did. Computed rather than seeded with `now - interval` because
            // `Instant` subtraction panics on an instant earlier than the clock's origin.
            let pagination_due = match last_pagination {
                Some(t) => t.elapsed() >= PAGINATION_INTERVAL,
                None => true,
            };
            if pagination_due {
                let clicked = tab
                    .evaluate(PAGINATION_JS, false)
                    .ok()
                    .and_then(|obj| obj.value)
                    .and_then(|v| v.as_i64())
                    .unwrap_or(0);
                last_pagination = Some(Instant::now());
                // A click that fired a request needs a moment to show up as in-flight traffic;
                // treating the click itself as activity keeps the idle rule from exiting in that
                // gap and losing the page it just asked for. A pass that clicked nothing has
                // triggered nothing, so it deliberately does not stamp the clock — that is what
                // lets a page with no pagination controls exit promptly.
                if clicked > 0 {
                    mark_activity(&last_activity);
                }

                // Re-deriving this parses every captured body, so it runs on the pagination
                // cadence and only when something new actually landed — not on every 50ms poll.
                let snapshot = responses
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                at_response_cap = snapshot.len() >= MAX_CAPTURED_RESPONSES;
                if subs_seen_at.is_none()
                    && snapshot.len() != checked_len
                    && responses_contain_subprocessor_array(&snapshot)
                {
                    subs_seen_at = Some(Instant::now());
                    debug!("Subprocessor array captured after {:?}", started.elapsed());
                }
                checked_len = snapshot.len();
            }

            let quiet = last_activity
                .lock()
                .map(|t| t.elapsed())
                .unwrap_or(Duration::ZERO);
            let pending =
                in_flight.load(Ordering::SeqCst) > 0 || body_fetches.load(Ordering::SeqCst) > 0;
            if should_exit_trust_center_capture(
                started.elapsed(),
                at_response_cap,
                pending,
                quiet,
                subs_seen_at.map(|t| t.elapsed()),
            ) {
                break;
            }
            std::thread::sleep(CAPTURE_POLL);
        }
        let _ = tab.remove_event_listener(&activity_listener);

        // P2.1(b): read the settled DOM here, while the tab is still alive and exclusively held.
        // The subprocessor path used to navigate a second tab to this same URL just to obtain it.
        let settled_dom = tab.get_content().ok();

        // Deregister and collect results. Recover from a poisoned lock rather
        // than panicking; the accumulated responses remain valid.
        let _ = tab.deregister_response_handling("trust_center_capture");
        let collected = responses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        Ok(RenderCapture {
            responses: collected,
            settled_dom,
        })
    });

    let capture = handle
        .await
        .map_err(|e| anyhow::anyhow!("Blocking task panicked: {}", e))??;

    debug!(
        "Captured {} JSON responses from {}",
        capture.responses.len(),
        url
    );
    Ok(capture)
}

#[cfg(coverage)]
#[cfg_attr(coverage_nightly, coverage(off))]
async fn capture_network_json_responses(_url: &str) -> Result<RenderCapture> {
    Ok(RenderCapture::default())
}

/// Extract subprocessor records directly from captured JSON API responses.
///
/// Every captured response (optionally restricted to URLs containing
/// `url_substring`) is searched for subprocessor-like JSON arrays; each array is
/// field-mapped and extracted with the shared executor logic, then results are
/// unioned and de-duplicated by domain. Unioning across responses is what makes
/// paginated APIs work transparently: each page contributes its slice and
/// duplicates collapse.
///
/// This is the pure, browser-free core of the render-capture path and is fully
/// unit-tested against captured-response fixtures.
pub(crate) fn extract_subprocessors_from_responses(
    responses: &[InterceptedResponse],
    source_domain: &str,
    url_substring: Option<&str>,
) -> Vec<SubprocessorDomain> {
    use std::collections::HashSet;

    /// A subprocessor-like array discovered inside one captured response.
    struct Candidate {
        json_idx: usize,
        path: String,
        mapping: super::DetectedFieldMapping,
        score: f32,
    }

    // Parse every in-scope response once and collect candidate arrays.
    let mut parsed: Vec<serde_json::Value> = Vec::new();
    let mut candidates: Vec<Candidate> = Vec::new();

    for response in responses {
        if let Some(sub) = url_substring {
            if !response.url.contains(sub) {
                continue;
            }
        }
        let json: serde_json::Value = match serde_json::from_str(&response.body) {
            Ok(j) => j,
            Err(_) => continue,
        };
        let json_idx = parsed.len();
        for (path, items) in find_entity_arrays(&json, "") {
            let score = score_subprocessor_array(&items, &path);
            if score < 0.4 {
                continue;
            }
            let mapping = detect_field_mapping(&items);
            if mapping.name_field.is_none() {
                continue; // must have a name field
            }
            // Guard: a subprocessor array must look like vendors, not just any
            // named list. Require a website/URL field OR a subprocessor/vendor-ish
            // path. Without this, when the real subprocessor response is missing
            // from a capture (e.g. a throttled or partial render), a sibling array
            // (control categories, frameworks, …) becomes the top scorer and gets
            // returned as bogus "subprocessors" instead of an honest empty result.
            if mapping.url_field.is_none() && !path_indicates_subprocessors(&path) {
                continue;
            }
            candidates.push(Candidate {
                json_idx,
                path,
                mapping,
                score,
            });
        }
        parsed.push(json);
    }

    if candidates.is_empty() {
        return Vec::new();
    }

    // A large report payload (e.g. Vanta's `fetchDataForTrustReport`) carries
    // several entity arrays — subprocessors *and* frameworks, resource categories,
    // control categories, etc. — all of which have a `name` field and score above
    // threshold. We must pick the ONE that is the subprocessor list.
    // `score_subprocessor_array` already rewards it (item count + name + url +
    // purpose + a subprocessor/vendor path-keyword bonus), so the highest-scoring
    // array is the subprocessor list. Pick it, then union every captured array
    // that shares its leaf path segment — that, and only that, is genuine
    // pagination of the same logical array across multiple API calls. Sibling
    // arrays (a different leaf) and lower-scoring decoys are excluded.
    let Some(best) = candidates.iter().max_by(|a, b| {
        a.score
            .partial_cmp(&b.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    }) else {
        return Vec::new();
    };
    let best_leaf = leaf_segment(&best.path).to_string();
    let selected: Vec<&Candidate> = candidates
        .iter()
        .filter(|c| leaf_segment(&c.path) == best_leaf)
        .collect();

    let mut out: Vec<SubprocessorDomain> = Vec::new();
    // De-duplicate on (domain, name) so genuine pagination overlap — the same row
    // captured twice across page calls — collapses, while distinct rows that
    // happen to share a domain (e.g. a vendor's regional legal entities, all on
    // one corporate domain) are each preserved, matching the page's row count.
    let mut seen: HashSet<(String, String)> = HashSet::new();
    for cand in selected {
        let Some(name_field) = cand.mapping.name_field.clone() else {
            continue;
        };
        let response_mapping = ResponseMapping {
            subprocessors_path: cand.path.clone(),
            name_field,
            url_field: cand.mapping.url_field.clone(),
            purpose_field: cand.mapping.purpose_field.clone(),
            location_field: cand.mapping.location_field.clone(),
            evidence_fields: Vec::new(),
        };
        if let Ok(vendors) = crate::trust_center::executor::extract_subprocessors_from_json(
            &parsed[cand.json_idx],
            &response_mapping,
            source_domain,
        ) {
            for vendor in vendors {
                let key = (
                    vendor.domain.to_lowercase(),
                    vendor.raw_record.to_lowercase(),
                );
                if seen.insert(key) {
                    out.push(vendor);
                }
            }
        }
    }

    out
}

/// The final dot-separated segment of a JSON path (`data.trust.subprocessors` ->
/// `subprocessors`). Two paginated API responses for the same logical array share
/// this leaf even when their wrapper objects differ, so it is the key used to
/// union pages while keeping sibling arrays (a different leaf) out.
fn leaf_segment(path: &str) -> &str {
    path.rsplit('.').next().unwrap_or(path)
}

/// Whether a JSON path looks like it holds subprocessor / vendor data. Used only
/// as a *guard* (alongside "has a URL field") so an arbitrary named list — control
/// categories, frameworks, navigation keys — is never returned as subprocessors
/// when the real subprocessor array is missing from a capture.
fn path_indicates_subprocessors(path: &str) -> bool {
    let p = path.to_lowercase();
    [
        "subprocessor",
        "vendor",
        "processor",
        "provider",
        "supplier",
        "thirdpart",
    ]
    .iter()
    .any(|kw| p.contains(kw))
}

/// Whether any captured response already yields a confident subprocessor array
/// (good score + a name field + a URL field or subprocessor-ish path). Used to
/// keep the render-capture window open until the (often late-arriving)
/// subprocessor payload is actually present, instead of stopping on a fixed timer.
pub(crate) fn responses_contain_subprocessor_array(responses: &[InterceptedResponse]) -> bool {
    responses.iter().any(|r| {
        serde_json::from_str::<serde_json::Value>(&r.body)
            .ok()
            .is_some_and(|json| {
                find_entity_arrays(&json, "").iter().any(|(path, items)| {
                    if score_subprocessor_array(items, path) < 0.5 {
                        return false;
                    }
                    let m = detect_field_mapping(items);
                    m.name_field.is_some()
                        && (m.url_field.is_some() || path_indicates_subprocessors(path))
                })
            })
    })
}

/// Capture network JSON, retrying once only when the first attempt shows evidence of having been
/// raced — see [`should_retry_capture`] for why "found no subprocessor array" is no longer such
/// evidence.
///
/// A capture error is not propagated on the first attempt: the whole point of retrying a
/// transport failure is that the second attempt may succeed, so the error is only surfaced if the
/// retry fails too.
#[cfg(not(coverage))]
async fn capture_with_retry(url: &str) -> Result<RenderCapture> {
    let first = capture_network_json_responses(url).await;
    let (transport_error, capture) = match first {
        Ok(c) => (false, c),
        Err(e) => {
            debug!("First capture for {} failed: {:#}", url, e);
            (true, RenderCapture::default())
        }
    };

    let had_subs = responses_contain_subprocessor_array(&capture.responses);
    if !should_retry_capture(
        transport_error,
        capture.responses.len(),
        had_subs,
        responses_look_truncated(&capture.responses),
    ) {
        return Ok(capture);
    }

    // Residual-159: the retry is an OPTIONAL second full render (permit queue included). Under
    // an armed render budget it may only start while the candidate's envelope has time left —
    // without this gate, capture_with_retry could burn two multi-minute permit queues
    // back-to-back with no check between them. Unarmed callers stay unbounded, as before.
    if !crate::browser_pool::render_retry_permitted() {
        debug!(
            "Skipping capture retry for {} — the candidate's working-time envelope is spent",
            url
        );
        return Ok(capture);
    }

    debug!("First capture for {} looked raced; retrying once", url);
    crate::perf::METRICS.render_capture_retried.hit();
    let retry = capture_network_json_responses(url).await?;
    if responses_contain_subprocessor_array(&retry.responses) {
        // The retry rescued a subprocessor array the first capture missed. A scan-wide non-zero
        // here is what would justify widening the retry gate again; the zero measured across a
        // 9.15h depth-3 scan is what narrowed it to the raced cases in the first place.
        crate::perf::METRICS.render_retry_rescued.hit();
        return Ok(retry);
    }

    // Neither capture found subprocessors — return whichever attempt is worth more so the caller
    // still sees whatever was there (extraction will honestly yield empty if it isn't a
    // subprocessor array).
    Ok(
        if prefer_retry_capture(
            capture.responses.len(),
            capture.settled_dom.is_some(),
            retry.responses.len(),
            retry.settled_dom.is_some(),
        ) {
            retry
        } else {
            capture
        },
    )
}

/// Extract using the cache hint first, falling back to *all* responses when the
/// hint matches nothing — so a stale or over-specific hint can never make the
/// cache-hit path under-capture relative to first discovery.
pub(crate) fn extract_with_hint_fallback(
    responses: &[InterceptedResponse],
    source_domain: &str,
    url_substring: Option<&str>,
) -> Vec<SubprocessorDomain> {
    let vendors = extract_subprocessors_from_responses(responses, source_domain, url_substring);
    if vendors.is_empty() && url_substring.is_some() {
        extract_subprocessors_from_responses(responses, source_domain, None)
    } else {
        vendors
    }
}

/// Derive the soft cache hint stored in a `RenderedNetworkCapture` strategy: the
/// GraphQL operation name (or the generic `"graphql"`) of the first captured
/// response that actually yields subprocessors. `None` when no response does.
pub(crate) fn derive_capture_hint(
    responses: &[InterceptedResponse],
    source_domain: &str,
) -> Option<String> {
    responses
        .iter()
        .find(|r| {
            !extract_subprocessors_from_responses(std::slice::from_ref(*r), source_domain, None)
                .is_empty()
        })
        .and_then(|r| {
            extract_graphql_operation(&r.url).or_else(|| {
                if r.url.contains("graphql") {
                    Some("graphql".to_string())
                } else {
                    None
                }
            })
        })
}

/// Render an SPA in a headless browser, capture the JSON it fetches, and extract
/// subprocessors directly. Used by the executor for cached
/// [`StrategyType::RenderedNetworkCapture`] strategies. The `url_substring` hint
/// is applied first; if it yields nothing we fall back to considering every
/// captured response, so a stale hint can never cause under-capture.
#[cfg(not(coverage))]
pub(crate) async fn render_capture_and_extract(
    url: &str,
    source_domain: &str,
    url_substring: Option<&str>,
) -> Result<Vec<SubprocessorDomain>> {
    let capture = capture_with_retry(url).await?;
    Ok(extract_with_hint_fallback(
        &capture.responses,
        source_domain,
        url_substring,
    ))
}

#[cfg(coverage)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) async fn render_capture_and_extract(
    _url: &str,
    _source_domain: &str,
    _url_substring: Option<&str>,
) -> Result<Vec<SubprocessorDomain>> {
    Ok(Vec::new())
}

/// What a discover-and-extract render pass produced.
///
/// P2.1(c): `settled_dom` is carried out even on the failure paths — especially on the failure
/// paths. A futile candidate URL is precisely the case where this render found nothing *and* the
/// caller was about to render the same URL again just to read its DOM.
#[derive(Debug, Default)]
pub(crate) struct RenderDiscovery {
    pub(crate) vendors: Vec<SubprocessorDomain>,
    /// `Some` only when `vendors` is non-empty — a strategy is only worth caching if it produced
    /// something.
    pub(crate) strategy: Option<TrustCenterStrategy>,
    pub(crate) settled_dom: Option<String>,
}

/// Discover-and-extract for SPA subprocessor pages: render the page, capture the
/// JSON its scripts fetch, and extract subprocessors directly. Returns the
/// extracted vendors (used immediately — no second browser launch), a
/// cacheable [`StrategyType::RenderedNetworkCapture`] strategy for future runs, and the DOM as it
/// stood when the capture settled.
#[cfg(not(coverage))]
pub(crate) async fn discover_and_extract_via_render(
    url: &str,
    source_domain: &str,
) -> Result<RenderDiscovery> {
    let capture = capture_with_retry(url).await?;
    let responses = capture.responses;
    let settled_dom = capture.settled_dom;
    if responses.is_empty() {
        debug!("No JSON responses captured from {}", url);
        return Ok(RenderDiscovery {
            settled_dom,
            ..RenderDiscovery::default()
        });
    }

    let vendors = extract_subprocessors_from_responses(&responses, source_domain, None);
    if vendors.is_empty() {
        debug!(
            "No subprocessors extracted from {} captured responses for {}",
            responses.len(),
            source_domain
        );
        return Ok(RenderDiscovery {
            settled_dom,
            ..RenderDiscovery::default()
        });
    }

    // Record which response/operation actually contributed data, as a soft cache
    // hint for future runs (execution falls back to all responses if it misses).
    let hint = derive_capture_hint(&responses, source_domain);

    let strategy = TrustCenterStrategy {
        strategy_type: StrategyType::RenderedNetworkCapture {
            response_url_substring: hint,
        },
        endpoint: EndpointConfig {
            url: url.to_string(),
            slug: extract_slug_from_url(url),
            requires_browser: true,
        },
        // Mapping is re-detected per captured response at execution time; this is
        // a permissive placeholder kept only for cache-file readability.
        response_mapping: ResponseMapping {
            subprocessors_path: String::new(),
            name_field: "name".to_string(),
            url_field: None,
            purpose_field: None,
            location_field: None,
            evidence_fields: Vec::new(),
        },
        discovery_metadata: DiscoveryMetadata::new(
            DiscoveryMethod::NetworkInterception,
            vendors.len() as u32,
            0.9,
        ),
    };

    debug!(
        "Render-capture extracted {} subprocessors for {}",
        vendors.len(),
        source_domain
    );
    Ok(RenderDiscovery {
        vendors,
        strategy: Some(strategy),
        settled_dom,
    })
}

#[cfg(coverage)]
#[cfg_attr(coverage_nightly, coverage(off))]
pub(crate) async fn discover_and_extract_via_render(
    _url: &str,
    _source_domain: &str,
) -> Result<RenderDiscovery> {
    Ok(RenderDiscovery::default())
}

/// Probe 2: Discover strategies by scanning HTML for embedded data patterns.
fn discover_via_html_patterns(html: &str) -> Result<Vec<CandidateStrategy>> {
    let mut candidates = Vec::new();

    // Probe 2a: SafeBase trust center (detected by __SB_CONFIG__)
    // Must run before generic __NEXT_DATA__ probe since SafeBase uses Next.js
    // but has a specific structure that the generic probe might score poorly.
    probe_safebase(html, &mut candidates);

    // Probe 2b: Conveyor trust center (detected by window.VENDOR_REPORT)
    // Must run before generic JS object probe since Conveyor uses a relational
    // model (canonical_asset_id → canonical_assets) that the generic probe can't handle.
    probe_conveyor(html, &mut candidates);

    // Probe 2c: __NEXT_DATA__ hydration blob (Next.js apps)
    if let Some(candidate) = probe_next_data(html) {
        candidates.push(candidate);
    }

    // Probe 2d: <script type="application/json"> tags
    probe_json_script_tags(html, &mut candidates);

    // Probe 2e: Base64 encoded JSON blobs
    probe_base64_blobs(html, &mut candidates);

    // Probe 2f: JavaScript object assignments (window.X = {...})
    probe_js_object_assignments(html, &mut candidates);

    Ok(candidates)
}

/// SafeBase trust center probe.
///
/// SafeBase (safebase.io) powers trust centers for many companies. It uses Next.js
/// and embeds subprocessor data in the __NEXT_DATA__ hydration blob at:
///   props.pageProps.orgInfo.sp.products.{productId}.raw.spData.items.{itemUid}.listEntries
///
/// Each entry has: { company: { name, domain, logo }, purpose, location, additionalDetails }
///
/// SafeBase also supports multi-product trust centers where multiple products
/// (e.g., "Drata" and "SafeBase") share a single trust center domain.
/// Product info is at: props.pageProps.orgInfo.sp.products (map of productId → product).
fn probe_safebase(html: &str, candidates: &mut Vec<CandidateStrategy>) {
    // Quick check: SafeBase pages contain __SB_CONFIG__
    if !html.contains("__SB_CONFIG__") {
        return;
    }
    debug!("SafeBase trust center detected (found __SB_CONFIG__)");

    // Parse __NEXT_DATA__ to extract the SafeBase structure
    let pattern = r#"<script\s+id="__NEXT_DATA__"[^>]*>([\s\S]*?)</script>"#;
    // Pattern is a hardcoded constant — compile failure is impossible.
    let regex = fancy_regex::Regex::new(pattern)
        .expect("__NEXT_DATA__ extraction pattern is a valid compile-time regex literal");

    let json_str = match regex.captures(html).ok().flatten().and_then(|c| c.get(1)) {
        Some(m) => m.as_str(),
        None => {
            debug!("SafeBase: __NEXT_DATA__ not found despite __SB_CONFIG__ presence");
            return;
        }
    };

    let json: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(j) => j,
        Err(e) => {
            debug!("SafeBase: Failed to parse __NEXT_DATA__: {}", e);
            return;
        }
    };

    // Navigate to the products structure
    let products = match super::navigate_json_path(&json, "props.pageProps.orgInfo.sp.products") {
        Some(p) if p.is_object() => p,
        _ => {
            debug!("SafeBase: products structure not found in __NEXT_DATA__");
            return;
        }
    };

    // products is guaranteed to be an object by the is_object() guard above
    let products_map = products
        .as_object()
        .expect("products is a JSON object (verified by is_object() guard above)");

    debug!("SafeBase: found {} products", products_map.len());

    // Iterate through all products to find subprocessor list items
    for (product_id, product_data) in products_map {
        let slug = product_data
            .get("slug")
            .and_then(|v| v.as_str())
            .unwrap_or(product_id);
        let product_name = product_data
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or(slug);
        let show = product_data
            .get("show")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        if !show {
            debug!(
                "SafeBase: skipping hidden product '{}' (slug: {})",
                product_name, slug
            );
            continue;
        }

        debug!(
            "SafeBase: scanning product '{}' (id: {}, slug: {})",
            product_name, product_id, slug
        );

        // Look for subprocessor items in raw.spData.items
        let items = match super::navigate_json_path(product_data, "raw.spData.items") {
            Some(i) if i.is_object() => i,
            _ => continue,
        };

        // items is guaranteed to be an object by the is_object() guard above
        let items_map = items
            .as_object()
            .expect("items is a JSON object (verified by is_object() guard above)");

        for (item_uid, item_data) in items_map {
            let list_entries = match item_data.get("listEntries").and_then(|v| v.as_array()) {
                Some(arr) if arr.len() >= 3 => arr,
                _ => continue,
            };

            // Verify entries look like subprocessor data (have company.name or name)
            let has_company = list_entries.iter().take(5).any(|entry| {
                entry
                    .get("company")
                    .and_then(|c| c.get("name"))
                    .and_then(|n| n.as_str())
                    .is_some_and(|s| !s.is_empty())
            });

            if !has_company {
                continue;
            }

            let entry_count = list_entries.len();
            debug!(
                "SafeBase: found {} subprocessor entries in product '{}', item {}",
                entry_count, product_name, item_uid
            );

            // Build the full data path for this subprocessor list
            let data_path = format!(
                "props.pageProps.orgInfo.sp.products.{}.raw.spData.items.{}.listEntries",
                product_id, item_uid
            );

            // Score higher since we've positively identified SafeBase structure
            let score = 0.95;

            candidates.push(CandidateStrategy {
                strategy: TrustCenterStrategy {
                    strategy_type: StrategyType::HydrationData {
                        script_selector: "script#__NEXT_DATA__".to_string(),
                        data_path: data_path.clone(),
                    },
                    endpoint: EndpointConfig {
                        url: String::new(), // Filled by caller
                        slug: Some(slug.to_string()),
                        requires_browser: false,
                    },
                    response_mapping: ResponseMapping {
                        subprocessors_path: String::new(), // Not needed for HydrationData
                        name_field: "company.name".to_string(),
                        url_field: Some("company.domain".to_string()),
                        purpose_field: Some("purpose".to_string()),
                        location_field: Some("location".to_string()),
                        evidence_fields: vec![
                            "company.name".to_string(),
                            "purpose".to_string(),
                            "location".to_string(),
                        ],
                    },
                    discovery_metadata: DiscoveryMetadata::new(
                        DiscoveryMethod::HtmlPatternScan,
                        list_entries.len() as u32,
                        score,
                    ),
                },
                score,
                item_count: list_entries.len(),
            });
        }
    }
}

/// Conveyor trust center probe.
///
/// Conveyor (conveyor.com) powers trust centers embedded as `window.VENDOR_REPORT = {...}`.
/// The data uses a relational model:
///   - `_embedded.subprocessors[]` has `canonical_asset_id`, `description`, `data_locations`
///   - `_embedded.canonical_assets[]` has `id`, `name`, `website`
///
/// Subprocessor names/domains are resolved by joining on `canonical_asset_id` → `id`.
///
/// Conveyor also has a public REST API that returns the same data:
///   GET https://api.conveyor.com/public/public_vendor_reports/by_slug?slug={slug}&embed_canonical_assets=true
/// The slug is found in `window.CANONICAL_ASSET = { slug: "company" }`.
///
/// This probe creates a RestApi strategy pointing to the public API.
fn probe_conveyor(html: &str, candidates: &mut Vec<CandidateStrategy>) {
    // Quick check: Conveyor pages contain window.VENDOR_REPORT
    if !html.contains("window.VENDOR_REPORT") {
        return;
    }
    debug!("Conveyor trust center detected (found window.VENDOR_REPORT)");

    // Extract the slug from window.CANONICAL_ASSET
    let slug = extract_conveyor_slug(html);

    if slug.is_none() {
        debug!("Conveyor: could not extract slug from CANONICAL_ASSET");
    }

    // Try to parse window.VENDOR_REPORT to count subprocessors for validation
    let subprocessor_count = count_conveyor_subprocessors(html);

    if subprocessor_count < 3 {
        debug!(
            "Conveyor: found {} subprocessors, below threshold of 3",
            subprocessor_count
        );
        return;
    }

    debug!(
        "Conveyor: found {} subprocessors, slug={:?}",
        subprocessor_count, slug
    );

    let score = 0.95;
    let api_url = match &slug {
        Some(s) => format!(
            "https://api.conveyor.com/public/public_vendor_reports/by_slug?slug={}&embed_canonical_assets=true",
            s
        ),
        None => String::new(),
    };

    candidates.push(CandidateStrategy {
        strategy: TrustCenterStrategy {
            strategy_type: StrategyType::RestApi {
                method: "GET".to_string(),
                body_template: None,
                headers: std::collections::HashMap::new(),
            },
            endpoint: EndpointConfig {
                url: api_url,
                slug,
                requires_browser: false,
            },
            response_mapping: ResponseMapping {
                subprocessors_path: "_embedded.subprocessors".to_string(),
                name_field: "name".to_string(),
                url_field: Some("website".to_string()),
                purpose_field: Some("description".to_string()),
                location_field: Some("data_locations".to_string()),
                evidence_fields: vec!["name".to_string(), "description".to_string()],
            },
            discovery_metadata: DiscoveryMetadata::new(
                DiscoveryMethod::HtmlPatternScan,
                subprocessor_count as u32,
                score,
            ),
        },
        score,
        item_count: subprocessor_count,
    });
}

/// Extract the Conveyor slug from window.CANONICAL_ASSET assignment.
fn extract_conveyor_slug(html: &str) -> Option<String> {
    let json = extract_js_object_assignment(html, "CANONICAL_ASSET")?;
    json.get("slug")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Count the number of subprocessors in a Conveyor VENDOR_REPORT.
fn count_conveyor_subprocessors(html: &str) -> usize {
    let json = extract_js_object_assignment(html, "VENDOR_REPORT");
    match json {
        Some(j) => j
            .get("_embedded")
            .and_then(|e| e.get("subprocessors"))
            .and_then(|s| s.as_array())
            .map(|a| a.len())
            .unwrap_or(0),
        None => 0,
    }
}

/// Extract a JSON object from a `window.VAR_NAME = {...};` assignment using bracket-matching.
/// This handles nested braces correctly unlike regex-based approaches.
fn extract_js_object_assignment(html: &str, var_name: &str) -> Option<serde_json::Value> {
    let marker = format!("window.{}", var_name);
    let marker_pos = html.find(&marker)?;
    let after_marker = &html[marker_pos + marker.len()..];

    // Skip whitespace and '='
    let trimmed = after_marker.trim_start();
    if !trimmed.starts_with('=') {
        return None;
    }
    let after_eq = trimmed[1..].trim_start();

    if !after_eq.starts_with('{') {
        return None;
    }

    // Bracket-match to find the balanced closing brace
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape_next = false;
    let mut end_pos = None;

    for (i, ch) in after_eq.char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }
        match ch {
            '\\' if in_string => {
                escape_next = true;
            }
            '"' => {
                in_string = !in_string;
            }
            '{' if !in_string => {
                depth += 1;
            }
            '}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    end_pos = Some(i + 1);
                    break;
                }
            }
            _ => {}
        }
    }

    let json_str = &after_eq[..end_pos?];
    serde_json::from_str(json_str).ok()
}

/// Search for Next.js __NEXT_DATA__ hydration blob.
#[cfg_attr(coverage_nightly, coverage(off))]
fn probe_next_data(html: &str) -> Option<CandidateStrategy> {
    // Look for <script id="__NEXT_DATA__" type="application/json">...</script>
    let pattern = r#"<script\s+id="__NEXT_DATA__"[^>]*>([\s\S]*?)</script>"#;
    let regex = fancy_regex::Regex::new(pattern).ok()?;

    let captures = regex.captures(html).ok()??;
    let json_str = captures.get(1)?.as_str();

    let json: serde_json::Value = serde_json::from_str(json_str).ok()?;

    // Search for subprocessor arrays in the hydration data
    let arrays = find_entity_arrays(&json, "");

    for (path, items) in &arrays {
        let score = score_subprocessor_array(items, path);
        if score >= 0.4 {
            let field_mapping = detect_field_mapping(items);
            let name_field = field_mapping.name_field?;

            return Some(CandidateStrategy {
                strategy: TrustCenterStrategy {
                    strategy_type: StrategyType::HydrationData {
                        script_selector: "script#__NEXT_DATA__".to_string(),
                        data_path: path.clone(),
                    },
                    endpoint: EndpointConfig {
                        url: String::new(), // Filled by caller
                        slug: None,
                        requires_browser: false,
                    },
                    response_mapping: ResponseMapping {
                        subprocessors_path: String::new(), // Not needed for HydrationData
                        name_field,
                        url_field: field_mapping.url_field,
                        purpose_field: field_mapping.purpose_field,
                        location_field: field_mapping.location_field,
                        evidence_fields: Vec::new(),
                    },
                    discovery_metadata: DiscoveryMetadata::new(
                        DiscoveryMethod::HtmlPatternScan,
                        items.len() as u32,
                        score,
                    ),
                },
                score,
                item_count: items.len(),
            });
        }
    }

    None
}

/// Search for <script type="application/json"> tags containing subprocessor data.
fn probe_json_script_tags(html: &str, candidates: &mut Vec<CandidateStrategy>) {
    let document = scraper::Html::parse_document(html);
    // Selector is a hardcoded constant — parse failure is impossible.
    let selector = scraper::Selector::parse(r#"script[type="application/json"]"#)
        .expect(r#""script[type=\"application/json\"]" is a valid compile-time CSS selector"#);

    for (idx, script) in document.select(&selector).enumerate() {
        let text: String = script.text().collect();
        let trimmed = text.trim();

        if trimmed.len() < 50 {
            continue;
        }

        let json = match serde_json::from_str::<serde_json::Value>(trimmed) {
            Ok(j) => j,
            Err(_) => continue,
        };
        let arrays = find_entity_arrays(&json, "");
        for (path, items) in &arrays {
            let score = score_subprocessor_array(items, path);
            if score < 0.4 {
                continue;
            }
            let field_mapping = detect_field_mapping(items);
            let name_field = match field_mapping.name_field {
                Some(n) => n,
                None => continue,
            };
            candidates.push(CandidateStrategy {
                strategy: TrustCenterStrategy {
                    strategy_type: StrategyType::HydrationData {
                        script_selector: format!(
                            r#"script[type="application/json"]:nth-of-type({})"#,
                            idx + 1
                        ),
                        data_path: path.clone(),
                    },
                    endpoint: EndpointConfig {
                        url: String::new(),
                        slug: None,
                        requires_browser: false,
                    },
                    response_mapping: ResponseMapping {
                        subprocessors_path: String::new(),
                        name_field,
                        url_field: field_mapping.url_field,
                        purpose_field: field_mapping.purpose_field,
                        location_field: field_mapping.location_field,
                        evidence_fields: Vec::new(),
                    },
                    discovery_metadata: DiscoveryMetadata::new(
                        DiscoveryMethod::HtmlPatternScan,
                        items.len() as u32,
                        score,
                    ),
                },
                score,
                item_count: items.len(),
            });
        }
    }
}

/// Search for base64-encoded JSON blobs in HTML.
#[cfg_attr(coverage_nightly, coverage(off))]
fn probe_base64_blobs(html: &str, candidates: &mut Vec<CandidateStrategy>) {
    use base64::Engine;

    let patterns = [
        r#"data-[a-z-]+="([A-Za-z0-9+/=]{200,})""#,
        r#"atob\s*\(\s*["']([A-Za-z0-9+/=]{200,})["']\s*\)"#,
        r#"(?:var|let|const)\s+\w+\s*=\s*["']([A-Za-z0-9+/=]{200,})["']"#,
    ];

    for pattern in &patterns {
        // All patterns are hardcoded constants — compile failure is impossible.
        let regex = fancy_regex::Regex::new(pattern)
            .expect("base64 extraction pattern is a valid compile-time regex literal");
        let mut search_start = 0;
        while search_start < html.len() {
            let search_slice = &html[search_start..];
            let captures = match regex.captures(search_slice) {
                Ok(Some(c)) => c,
                _ => break,
            };
            let b64_match = match captures.get(1) {
                Some(m) => m,
                None => break,
            };
            let b64_str = b64_match.as_str();

            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64_str) {
                if let Ok(json_str) = String::from_utf8(decoded) {
                    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&json_str) {
                        let arrays = find_entity_arrays(&json, "");
                        for (path, items) in &arrays {
                            let score = score_subprocessor_array(items, path);
                            if score < 0.4 {
                                continue;
                            }
                            let field_mapping = detect_field_mapping(items);
                            let name_field = match field_mapping.name_field {
                                Some(n) => n,
                                None => continue,
                            };
                            candidates.push(CandidateStrategy {
                                strategy: TrustCenterStrategy {
                                    strategy_type: StrategyType::EmbeddedBase64Json {
                                        locator_pattern: pattern.to_string(),
                                    },
                                    endpoint: EndpointConfig {
                                        url: String::new(),
                                        slug: None,
                                        requires_browser: false,
                                    },
                                    response_mapping: ResponseMapping {
                                        subprocessors_path: path.clone(),
                                        name_field,
                                        url_field: field_mapping.url_field,
                                        purpose_field: field_mapping.purpose_field,
                                        location_field: field_mapping.location_field,
                                        evidence_fields: Vec::new(),
                                    },
                                    discovery_metadata: DiscoveryMetadata::new(
                                        DiscoveryMethod::HtmlPatternScan,
                                        items.len() as u32,
                                        score,
                                    ),
                                },
                                score,
                                item_count: items.len(),
                            });
                        }
                    }
                }
            }

            search_start += b64_match.end();
        }
    }
}

/// Search for JavaScript object assignments like `window.VENDOR_REPORT = {...}`.
#[cfg_attr(coverage_nightly, coverage(off))]
fn probe_js_object_assignments(html: &str, candidates: &mut Vec<CandidateStrategy>) {
    let pattern = r#"window\.([A-Z_][A-Z_0-9]*)\s*=\s*(\{[\s\S]{200,}?\})(?:\s*;|\s*<)"#;
    // Pattern is a hardcoded constant — compile failure is impossible.
    let regex = fancy_regex::Regex::new(pattern)
        .expect("window.* object-assignment pattern is a valid compile-time regex literal");

    let mut search_start = 0;
    while search_start < html.len() {
        let search_slice = &html[search_start..];
        let captures = match regex.captures(search_slice) {
            Ok(Some(c)) => c,
            _ => break,
        };
        let var_name = captures.get(1).map(|m| m.as_str()).unwrap_or("UNKNOWN");
        let json_match = match captures.get(2) {
            Some(m) => m,
            None => break,
        };
        let json_str = json_match.as_str();

        if let Ok(json) = serde_json::from_str::<serde_json::Value>(json_str) {
            let arrays = find_entity_arrays(&json, "");
            for (path, items) in &arrays {
                let score = score_subprocessor_array(items, path);
                if score < 0.4 {
                    continue;
                }
                let field_mapping = detect_field_mapping(items);
                let name_field = match field_mapping.name_field {
                    Some(n) => n,
                    None => continue,
                };
                let locator = format!(
                    r#"window\.{}\s*=\s*(\{{[\s\S]*?\}})(?:\s*;|\s*<)"#,
                    regex::escape(var_name)
                );
                candidates.push(CandidateStrategy {
                    strategy: TrustCenterStrategy {
                        strategy_type: StrategyType::EmbeddedJsObject {
                            locator_pattern: locator,
                        },
                        endpoint: EndpointConfig {
                            url: String::new(),
                            slug: None,
                            requires_browser: false,
                        },
                        response_mapping: ResponseMapping {
                            subprocessors_path: path.clone(),
                            name_field,
                            url_field: field_mapping.url_field,
                            purpose_field: field_mapping.purpose_field,
                            location_field: field_mapping.location_field,
                            evidence_fields: Vec::new(),
                        },
                        discovery_metadata: DiscoveryMetadata::new(
                            DiscoveryMethod::HtmlPatternScan,
                            items.len() as u32,
                            score,
                        ),
                    },
                    score,
                    item_count: items.len(),
                });
            }
        }

        search_start += json_match.end();
    }
}

/// Extract a GraphQL operation name from a URL query parameter.
fn extract_graphql_operation(url: &str) -> Option<String> {
    if let Ok(parsed) = url::Url::parse(url) {
        for (key, value) in parsed.query_pairs() {
            if key == "operation" || key == "operationName" {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Extract a potential slug from a trust center URL.
/// For example: `https://trust.vanta.com/acme/subprocessors` -> `Some("acme")`
fn extract_slug_from_url(url: &str) -> Option<String> {
    if let Ok(parsed) = url::Url::parse(url) {
        let segments: Vec<&str> = parsed
            .path_segments()
            .map(|s| s.collect())
            .unwrap_or_default();

        // Common pattern: /slug/subprocessors or /slug/trust/subprocessors
        if segments.len() >= 2 {
            let first = segments[0];
            // Skip if it's a common non-slug path
            let non_slugs = [
                "api",
                "graphql",
                "trust",
                "security",
                "legal",
                "privacy",
                "subprocessors",
            ];
            if !non_slugs.contains(&first) && !first.is_empty() {
                return Some(first.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_likely_spa_minimal_html() {
        let spa_html = r#"<!DOCTYPE html><html><head><meta charset="utf-8">
            <script src="/_next/static/chunks/main.js"></script>
            </head><body><div id="__next"></div>
            <script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>
            </body></html>"#;
        assert!(is_likely_spa(spa_html));
    }

    #[test]
    fn test_is_likely_spa_regular_html() {
        let regular_html = r#"<!DOCTYPE html><html><head><title>Subprocessors</title></head>
            <body><h1>Our Subprocessors</h1><table><tr><td>AWS</td><td>Cloud hosting</td></tr>
            <tr><td>Cloudflare</td><td>CDN</td></tr></table></body></html>"#;
        assert!(!is_likely_spa(regular_html));
    }

    #[test]
    fn test_extract_slug_from_url() {
        assert_eq!(
            extract_slug_from_url("https://trust.vanta.com/acme/subprocessors"),
            Some("acme".to_string())
        );
        assert_eq!(
            extract_slug_from_url("https://trust.vanta.com/subprocessors"),
            None
        );
    }

    #[test]
    fn test_probe_next_data() {
        let html = r#"<html><body>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"subprocessors":[
                {"name":"AWS","url":"https://aws.amazon.com","purpose":"Cloud"},
                {"name":"Cloudflare","url":"https://cloudflare.com","purpose":"CDN"},
                {"name":"Datadog","url":"https://datadoghq.com","purpose":"Monitoring"},
                {"name":"Anthropic","url":"https://anthropic.com","purpose":"AI"},
                {"name":"Google","url":"https://google.com","purpose":"Analytics"}
            ]}}}
            </script></body></html>"#;

        let result = probe_next_data(html);
        assert!(result.is_some());
        let candidate = result.unwrap();
        assert_eq!(candidate.item_count, 5);
        assert!(candidate.score >= 0.4);
    }

    #[test]
    fn test_probe_safebase_detects_trust_center() {
        // Minimal SafeBase trust center HTML with __SB_CONFIG__ and __NEXT_DATA__
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {"NEXT_PUBLIC_SITE":"https://app.safebase.io"};</script>
            <div id="__next"></div>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":{
                "default":{
                    "id":"default","slug":"acme","name":"Acme Corp","show":true,"order":1,
                    "raw":{"spData":{"items":{
                        "abc-123":{"listEntries":[
                            {"company":{"name":"Algolia","domain":"algolia.com"},"purpose":"Search","location":"US"},
                            {"company":{"name":"AWS","domain":"amazonaws.com"},"purpose":"Cloud","location":"US"},
                            {"company":{"name":"Datadog","domain":"datadoghq.com"},"purpose":"Monitoring","location":"US"},
                            {"company":{"name":"Stripe","domain":"stripe.com"},"purpose":"Payments","location":"US"}
                        ],"text":{"title":"Subprocessors"}}
                    }}}
                }
            }}}}}}
            </script></body></html>"#;

        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);

        assert_eq!(
            candidates.len(),
            1,
            "Should find exactly one subprocessor list"
        );
        let candidate = &candidates[0];
        assert_eq!(candidate.item_count, 4);
        assert!(
            candidate.score >= 0.9,
            "SafeBase probe should have high confidence"
        );

        // Verify field mapping
        assert_eq!(
            candidate.strategy.response_mapping.name_field,
            "company.name"
        );
        assert_eq!(
            candidate.strategy.response_mapping.url_field,
            Some("company.domain".to_string())
        );
        assert_eq!(
            candidate.strategy.response_mapping.purpose_field,
            Some("purpose".to_string())
        );
        assert_eq!(
            candidate.strategy.response_mapping.location_field,
            Some("location".to_string())
        );

        // Verify slug extraction
        assert_eq!(candidate.strategy.endpoint.slug, Some("acme".to_string()));
    }

    #[test]
    fn test_probe_safebase_multi_product() {
        // Multi-product SafeBase trust center
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":{
                "default":{
                    "id":"default","slug":"acme","name":"Acme","show":true,"order":1,
                    "raw":{"spData":{"items":{
                        "uid-1":{"listEntries":[
                            {"company":{"name":"AWS","domain":"amazonaws.com"},"purpose":"Cloud","location":"US"},
                            {"company":{"name":"GCP","domain":"cloud.google.com"},"purpose":"Cloud","location":"US"},
                            {"company":{"name":"Stripe","domain":"stripe.com"},"purpose":"Pay","location":"US"}
                        ]}
                    }}}
                },
                "product1":{
                    "id":"product1","slug":"safebase","name":"SafeBase","show":true,"order":2,
                    "raw":{"spData":{"items":{
                        "uid-2":{"listEntries":[
                            {"company":{"name":"Okta","domain":"okta.com"},"purpose":"Auth","location":"US"},
                            {"company":{"name":"Snowflake","domain":"snowflake.com"},"purpose":"Data","location":"US"},
                            {"company":{"name":"Twilio","domain":"twilio.com"},"purpose":"Comms","location":"US"}
                        ]}
                    }}}
                },
                "hidden_product":{
                    "id":"hidden","slug":"internal","name":"Internal","show":false,"order":3,
                    "raw":{"spData":{"items":{
                        "uid-3":{"listEntries":[
                            {"company":{"name":"Secret","domain":"secret.com"},"purpose":"Internal","location":"US"},
                            {"company":{"name":"Hidden","domain":"hidden.com"},"purpose":"Internal","location":"US"},
                            {"company":{"name":"Private","domain":"private.com"},"purpose":"Internal","location":"US"}
                        ]}
                    }}}
                }
            }}}}}}
            </script></body></html>"#;

        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);

        // Should find 2 products (not the hidden one)
        assert_eq!(
            candidates.len(),
            2,
            "Should find subprocessors from 2 visible products"
        );
        assert_eq!(candidates[0].item_count, 3);
        assert_eq!(candidates[1].item_count, 3);
    }

    #[test]
    fn test_probe_safebase_skips_non_safebase() {
        // Regular Next.js page without __SB_CONFIG__
        let html = r#"<html><body>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"data":[
                {"name":"AWS","url":"https://aws.amazon.com"}
            ]}}}
            </script></body></html>"#;

        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "Should not detect SafeBase on non-SafeBase pages"
        );
    }

    #[test]
    fn test_probe_safebase_skips_entries_without_company() {
        // SafeBase page with non-subprocessor list entries (no company.name)
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":{
                "default":{
                    "id":"default","slug":"acme","name":"Acme","show":true,"order":1,
                    "raw":{"spData":{"items":{
                        "trusted-by":{"listEntries":[
                            {"name":"Customer A","logo":"a.png"},
                            {"name":"Customer B","logo":"b.png"},
                            {"name":"Customer C","logo":"c.png"},
                            {"name":"Customer D","logo":"d.png"}
                        ]}
                    }}}
                }
            }}}}}}
            </script></body></html>"#;

        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "Should not detect entries without company.name as subprocessors"
        );
    }

    #[test]
    fn test_probe_conveyor_detects_trust_center() {
        let html = r#"<html><body>
            <script>
            window.CANONICAL_ASSET = {"id":"abc-123","slug":"acme","name":"Acme Inc."};
            window.VENDOR_REPORT = {"_embedded":{"subprocessors":[
                {"id":"s1","canonical_asset_id":"ca1","description":"Cloud","data_locations":["US"]},
                {"id":"s2","canonical_asset_id":"ca2","description":"CDN","data_locations":["US"]},
                {"id":"s3","canonical_asset_id":"ca3","description":"Monitoring","data_locations":["US"]},
                {"id":"s4","canonical_asset_id":"ca4","description":"Auth","data_locations":["US"]}
            ],"canonical_assets":[
                {"id":"ca1","name":"AWS","website":"https://aws.amazon.com"},
                {"id":"ca2","name":"Cloudflare","website":"https://cloudflare.com"},
                {"id":"ca3","name":"Datadog","website":"https://datadoghq.com"},
                {"id":"ca4","name":"Okta","website":"https://okta.com"}
            ]}};
            </script></body></html>"#;

        let mut candidates = Vec::new();
        probe_conveyor(html, &mut candidates);

        assert_eq!(candidates.len(), 1, "Should find one Conveyor trust center");
        let candidate = &candidates[0];
        assert_eq!(candidate.item_count, 4);
        assert!(
            candidate.score >= 0.9,
            "Conveyor probe should have high confidence"
        );

        // Verify slug extraction
        assert_eq!(candidate.strategy.endpoint.slug, Some("acme".to_string()));

        // Verify API URL contains slug
        assert!(candidate.strategy.endpoint.url.contains("slug=acme"));

        assert!(matches!(
            &candidate.strategy.strategy_type,
            StrategyType::RestApi { method, .. } if method == "GET"
        ));
    }

    #[test]
    fn test_probe_conveyor_skips_non_conveyor() {
        let html = r#"<html><body>
            <script>
            window.APP_CONFIG = {"key": "value"};
            </script></body></html>"#;

        let mut candidates = Vec::new();
        probe_conveyor(html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "Should not detect Conveyor on non-Conveyor pages"
        );
    }

    #[test]
    fn test_probe_conveyor_handles_missing_slug() {
        // Conveyor page without CANONICAL_ASSET (should still detect but with empty URL)
        let html = r#"<html><body>
            <script>
            window.VENDOR_REPORT = {"_embedded":{"subprocessors":[
                {"id":"s1","canonical_asset_id":"ca1","description":"Cloud","data_locations":["US"]},
                {"id":"s2","canonical_asset_id":"ca2","description":"CDN","data_locations":["US"]},
                {"id":"s3","canonical_asset_id":"ca3","description":"Monitoring","data_locations":["US"]}
            ],"canonical_assets":[
                {"id":"ca1","name":"AWS","website":"https://aws.amazon.com"},
                {"id":"ca2","name":"Cloudflare","website":"https://cloudflare.com"},
                {"id":"ca3","name":"Datadog","website":"https://datadoghq.com"}
            ]}};
            </script></body></html>"#;

        let mut candidates = Vec::new();
        probe_conveyor(html, &mut candidates);

        assert_eq!(
            candidates.len(),
            1,
            "Should detect Conveyor even without slug"
        );
        assert_eq!(candidates[0].strategy.endpoint.slug, None);
        assert!(
            candidates[0].strategy.endpoint.url.is_empty(),
            "URL should be empty without slug"
        );
    }

    #[test]
    fn test_probe_conveyor_skips_few_subprocessors() {
        // Conveyor page with too few subprocessors
        let html = r#"<html><body>
            <script>
            window.VENDOR_REPORT = {"_embedded":{"subprocessors":[
                {"id":"s1","canonical_asset_id":"ca1","description":"Cloud","data_locations":["US"]}
            ],"canonical_assets":[
                {"id":"ca1","name":"AWS","website":"https://aws.amazon.com"}
            ]}};
            </script></body></html>"#;

        let mut candidates = Vec::new();
        probe_conveyor(html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "Should skip Conveyor with < 3 subprocessors"
        );
    }

    #[test]
    fn test_extract_conveyor_slug() {
        let html =
            r#"window.CANONICAL_ASSET = {"id":"abc","slug":"conveyor","name":"Conveyor Inc."};"#;
        assert_eq!(extract_conveyor_slug(html), Some("conveyor".to_string()));

        let html_no_slug = r#"window.APP_CONFIG = {"key":"value"};"#;
        assert_eq!(extract_conveyor_slug(html_no_slug), None);
    }

    // ====================================================================
    // Additional tests for uncovered paths
    // ====================================================================

    // --- is_likely_spa edge cases ---

    #[test]
    fn test_is_likely_spa_empty_html() {
        assert!(!is_likely_spa(""));
    }

    #[test]
    fn test_is_likely_spa_low_text_ratio() {
        // Construct HTML with lots of tags and very little text content
        let mut html = String::from("<html><head>");
        for _ in 0..200 {
            html.push_str("<link rel=\"stylesheet\" href=\"style.css\">");
        }
        html.push_str("</head><body>x</body></html>");
        // The text ratio should be very low, and html_len > 1000
        assert!(html.len() > 1000);
        assert!(is_likely_spa(&html));
    }

    #[test]
    fn test_is_likely_spa_framework_markers() {
        let markers = vec![
            r#"<div id="root"></div>"#,
            r#"<div data-reactroot></div>"#,
            r#"<script>window.__nuxt__={}</script>"#,
            r#"<div ng-app="myApp"></div>"#,
            r#"<div id="app"></div>"#,
        ];
        for marker_html in markers {
            let html = format!("<html><head></head><body>{}</body></html>", marker_html);
            assert!(
                is_likely_spa(&html),
                "Should detect SPA for marker: {}",
                marker_html
            );
        }
    }

    #[test]
    fn test_is_likely_spa_body_scripts_only() {
        // Body with only scripts and no visible content elements
        let html = r#"<html><head><title>Test</title></head>
            <body id="body">
            <script src="/bundle.js"></script>
            <script>window.init()</script>
            </body></html>"#;
        assert!(is_likely_spa(html));
    }

    #[test]
    fn test_is_likely_spa_body_with_visible_content() {
        // Body with div and scripts - should NOT be detected as SPA
        // because it has visible content elements
        let html = r#"<html><head><title>Test</title></head>
            <body>
            <div>Hello world</div>
            <script src="/bundle.js"></script>
            </body></html>"#;
        assert!(!is_likely_spa(html));
    }

    #[test]
    fn test_is_likely_spa_body_no_closing_tag() {
        // Body with scripts but no </body> closing tag - should still detect
        let html = r#"<html><head></head>
            <body>
            <script src="/app.js"></script>
            <script>init()</script>"#;
        assert!(is_likely_spa(html));
    }

    // --- extract_slug_from_url edge cases ---

    #[test]
    fn test_extract_slug_from_url_non_slug_paths() {
        // First path segment is a known non-slug
        assert_eq!(extract_slug_from_url("https://example.com/api/v1"), None);
        assert_eq!(
            extract_slug_from_url("https://example.com/trust/center"),
            None
        );
        assert_eq!(
            extract_slug_from_url("https://example.com/security/info"),
            None
        );
        assert_eq!(
            extract_slug_from_url("https://example.com/legal/terms"),
            None
        );
        assert_eq!(
            extract_slug_from_url("https://example.com/privacy/policy"),
            None
        );
        assert_eq!(
            extract_slug_from_url("https://example.com/subprocessors"),
            None
        );
    }

    #[test]
    fn test_extract_slug_from_url_with_slug() {
        assert_eq!(
            extract_slug_from_url("https://trust.vanta.com/mycompany/trust"),
            Some("mycompany".to_string())
        );
    }

    #[test]
    fn test_extract_slug_from_url_invalid_url() {
        assert_eq!(extract_slug_from_url("not-a-url"), None);
    }

    #[test]
    fn test_extract_slug_from_url_root_path() {
        // Single segment path
        assert_eq!(extract_slug_from_url("https://example.com/"), None);
    }

    // --- extract_graphql_operation ---

    #[test]
    fn test_extract_graphql_operation_with_operation_name() {
        assert_eq!(
            extract_graphql_operation(
                "https://api.example.com/graphql?operationName=GetSubprocessors"
            ),
            Some("GetSubprocessors".to_string())
        );
    }

    #[test]
    fn test_extract_graphql_operation_with_operation_param() {
        assert_eq!(
            extract_graphql_operation("https://api.example.com/graphql?operation=ListVendors"),
            Some("ListVendors".to_string())
        );
    }

    #[test]
    fn test_extract_graphql_operation_no_param() {
        assert_eq!(
            extract_graphql_operation("https://api.example.com/graphql"),
            None
        );
    }

    #[test]
    fn test_extract_graphql_operation_invalid_url() {
        assert_eq!(extract_graphql_operation("not-a-url"), None);
    }

    // --- extract_js_object_assignment ---

    #[test]
    fn test_extract_js_object_simple() {
        let html = r#"window.MY_VAR = {"key": "value"};"#;
        let result = extract_js_object_assignment(html, "MY_VAR");
        assert!(result.is_some());
        let val = result.unwrap();
        assert_eq!(val.get("key").unwrap().as_str().unwrap(), "value");
    }

    #[test]
    fn test_extract_js_object_nested_braces() {
        let html = r#"window.DATA = {"outer": {"inner": {"deep": true}}};"#;
        let result = extract_js_object_assignment(html, "DATA");
        assert!(result.is_some());
        let val = result.unwrap();
        assert!(val
            .get("outer")
            .unwrap()
            .get("inner")
            .unwrap()
            .get("deep")
            .unwrap()
            .as_bool()
            .unwrap());
    }

    #[test]
    fn test_extract_js_object_with_strings_containing_braces() {
        let html = r#"window.TEST = {"text": "hello {world}"};"#;
        let result = extract_js_object_assignment(html, "TEST");
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().get("text").unwrap().as_str().unwrap(),
            "hello {world}"
        );
    }

    #[test]
    fn test_extract_js_object_not_found() {
        let html = r#"window.OTHER = {"key": "value"};"#;
        assert!(extract_js_object_assignment(html, "MISSING").is_none());
    }

    #[test]
    fn test_extract_js_object_no_equals() {
        let html = r#"window.MY_VAR {"key": "value"};"#;
        assert!(extract_js_object_assignment(html, "MY_VAR").is_none());
    }

    #[test]
    fn test_extract_js_object_not_object() {
        let html = r#"window.MY_VAR = "string_value";"#;
        assert!(extract_js_object_assignment(html, "MY_VAR").is_none());
    }

    #[test]
    fn test_extract_js_object_with_escaped_quotes() {
        let html = r#"window.DATA = {"text": "say \"hello\""};"#;
        let result = extract_js_object_assignment(html, "DATA");
        assert!(result.is_some());
    }

    // --- count_conveyor_subprocessors ---

    #[test]
    fn test_count_conveyor_subprocessors_with_data() {
        let html = r#"window.VENDOR_REPORT = {"_embedded":{"subprocessors":[
            {"id":"s1"},{"id":"s2"},{"id":"s3"}
        ]}};"#;
        assert_eq!(count_conveyor_subprocessors(html), 3);
    }

    #[test]
    fn test_count_conveyor_subprocessors_no_report() {
        assert_eq!(count_conveyor_subprocessors("nothing here"), 0);
    }

    #[test]
    fn test_count_conveyor_subprocessors_no_embedded() {
        let html = r#"window.VENDOR_REPORT = {"data": "something"};"#;
        assert_eq!(count_conveyor_subprocessors(html), 0);
    }

    // --- discover_via_html_patterns ---

    #[test]
    fn test_discover_via_html_patterns_empty() {
        let result = discover_via_html_patterns("").unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_discover_via_html_patterns_plain_html() {
        let html = "<html><body><p>Hello world</p></body></html>";
        let result = discover_via_html_patterns(html).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_discover_via_html_patterns_safebase_takes_priority() {
        // SafeBase HTML should be detected by SafeBase probe, not generic Next.js probe
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":{
                "default":{
                    "id":"default","slug":"acme","name":"Acme","show":true,
                    "raw":{"spData":{"items":{
                        "uid-1":{"listEntries":[
                            {"company":{"name":"AWS","domain":"aws.com"},"purpose":"Cloud","location":"US"},
                            {"company":{"name":"GCP","domain":"cloud.google.com"},"purpose":"Cloud","location":"US"},
                            {"company":{"name":"Stripe","domain":"stripe.com"},"purpose":"Pay","location":"US"}
                        ]}
                    }}}
                }
            }}}}}}
            </script></body></html>"#;

        let result = discover_via_html_patterns(html).unwrap();
        assert!(!result.is_empty());
        // The SafeBase candidate should have high score
        let best = result
            .iter()
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap())
            .unwrap();
        assert!(best.score >= 0.9);
    }

    // --- probe_next_data edge cases ---

    #[test]
    fn test_probe_next_data_no_script() {
        assert!(probe_next_data("<html><body>no script</body></html>").is_none());
    }

    #[test]
    fn test_probe_next_data_invalid_json() {
        let html = r#"<html><body>
            <script id="__NEXT_DATA__" type="application/json">
            {invalid json}
            </script></body></html>"#;
        assert!(probe_next_data(html).is_none());
    }

    #[test]
    fn test_probe_next_data_no_arrays() {
        let html = r#"<html><body>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"title":"Hello"}}}
            </script></body></html>"#;
        assert!(probe_next_data(html).is_none());
    }

    #[test]
    fn test_probe_next_data_small_array_low_score() {
        // Array exists but doesn't look like subprocessors
        let html = r#"<html><body>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"items":[
                {"x":1}, {"x":2}, {"x":3}
            ]}}}
            </script></body></html>"#;
        // These items have no name/url/purpose fields, so score will be low
        assert!(probe_next_data(html).is_none());
    }

    // --- probe_json_script_tags ---

    #[test]
    fn test_probe_json_script_tags_empty() {
        let mut candidates = Vec::new();
        probe_json_script_tags("<html><body></body></html>", &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_probe_json_script_tags_short_content() {
        let html = r#"<html><body>
            <script type="application/json">{"a":1}</script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_json_script_tags(html, &mut candidates);
        assert!(candidates.is_empty()); // Too short (< 50 chars)
    }

    #[test]
    fn test_probe_json_script_tags_with_subprocessor_data() {
        let html = r#"<html><body>
            <script type="application/json">
            {"subprocessors":[
                {"name":"AWS","url":"https://aws.amazon.com","purpose":"Cloud infrastructure"},
                {"name":"Cloudflare","url":"https://cloudflare.com","purpose":"CDN and security"},
                {"name":"Datadog","url":"https://datadoghq.com","purpose":"Monitoring services"},
                {"name":"Stripe","url":"https://stripe.com","purpose":"Payment processing"},
                {"name":"Google","url":"https://google.com","purpose":"Analytics and search"}
            ]}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_json_script_tags(html, &mut candidates);
        assert!(!candidates.is_empty());
        assert!(candidates[0].score >= 0.4);
    }

    #[test]
    fn test_probe_json_script_tags_invalid_json() {
        let html = r#"<html><body>
            <script type="application/json">
            this is not json but it is longer than fifty characters so it will attempt to parse
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_json_script_tags(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    // --- probe_base64_blobs ---

    #[test]
    fn test_probe_base64_blobs_empty() {
        let mut candidates = Vec::new();
        probe_base64_blobs("<html><body></body></html>", &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_probe_base64_blobs_with_valid_data() {
        use base64::Engine;
        let json_data = serde_json::json!({"vendors":[
            {"name":"AWS","url":"https://aws.amazon.com","purpose":"Cloud infrastructure hosting"},
            {"name":"Cloudflare","url":"https://cloudflare.com","purpose":"CDN and DDoS protection"},
            {"name":"Datadog","url":"https://datadoghq.com","purpose":"Application monitoring"},
            {"name":"Stripe","url":"https://stripe.com","purpose":"Payment processing"},
            {"name":"Okta","url":"https://okta.com","purpose":"Identity management"}
        ]});
        let b64 =
            base64::engine::general_purpose::STANDARD.encode(json_data.to_string().as_bytes());
        let html = format!(
            r#"<html><body><script>var data = atob("{}");</script></body></html>"#,
            b64
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        assert!(!candidates.is_empty());
    }

    #[test]
    fn test_probe_base64_blobs_invalid_base64() {
        // atob with non-base64 content
        let html = r#"<html><body><script>var x = atob("!!!not-base64-at-all-but-long-enough-to-match-the-regex-pattern-here!!!");</script></body></html>"#;
        let mut candidates = Vec::new();
        probe_base64_blobs(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    // --- probe_js_object_assignments ---

    #[test]
    fn test_probe_js_object_assignments_empty() {
        let mut candidates = Vec::new();
        probe_js_object_assignments("<html><body></body></html>", &mut candidates);
        assert!(candidates.is_empty());
    }

    // --- extract_subprocessors_from_responses ---

    #[test]
    fn test_extract_subprocessors_from_responses_empty() {
        let result = extract_subprocessors_from_responses(&[], "example.com", None);
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_subprocessors_from_responses_invalid_json() {
        let responses = vec![InterceptedResponse {
            url: "https://api.example.com/data".to_string(),
            body: "not valid json".to_string(),
        }];
        let result = extract_subprocessors_from_responses(&responses, "example.com", None);
        assert!(result.is_empty());
    }

    #[test]
    fn test_extract_subprocessors_from_responses_with_subprocessors() {
        let body = serde_json::json!({
            "subprocessors": [
                {"name": "AWS", "url": "https://aws.amazon.com", "purpose": "Cloud hosting and infrastructure"},
                {"name": "Cloudflare", "url": "https://cloudflare.com", "purpose": "CDN and security services"},
                {"name": "Datadog", "url": "https://datadoghq.com", "purpose": "Application monitoring tools"},
                {"name": "Stripe", "url": "https://stripe.com", "purpose": "Payment processing services"},
                {"name": "Google", "url": "https://google.com", "purpose": "Analytics and advertising"}
            ]
        }).to_string();

        let responses = vec![InterceptedResponse {
            url: "https://api.example.com/trust/data".to_string(),
            body,
        }];

        let result = extract_subprocessors_from_responses(&responses, "trust.example.com", None);
        assert_eq!(result.len(), 5);
        // Each vendor resolved a real domain from its url field (no `_org:` placeholders).
        assert!(result
            .iter()
            .all(|v| !v.domain.is_empty() && !v.domain.starts_with("_org:")));
        let names: Vec<&str> = result.iter().map(|v| v.raw_record.as_str()).collect();
        assert!(names.contains(&"AWS"));
        assert!(names.contains(&"Stripe"));
    }

    #[test]
    fn test_extract_subprocessors_from_responses_graphql_shape_and_substring_filter() {
        let body = serde_json::json!({
            "data": {
                "vendors": [
                    {"name": "AWS", "url": "https://aws.amazon.com", "purpose": "Cloud"},
                    {"name": "GCP", "url": "https://cloud.google.com", "purpose": "Cloud"},
                    {"name": "Azure", "url": "https://azure.microsoft.com", "purpose": "Cloud"},
                    {"name": "Stripe", "url": "https://stripe.com", "purpose": "Payments"},
                    {"name": "Datadog", "url": "https://datadoghq.com", "purpose": "Monitoring"}
                ]
            }
        })
        .to_string();

        let responses = vec![InterceptedResponse {
            url: "https://api.example.com/graphql?operation=GetVendors".to_string(),
            body,
        }];

        // Nested `data.vendors` array is found and extracted.
        let all = extract_subprocessors_from_responses(&responses, "trust.example.com", None);
        assert_eq!(all.len(), 5);

        // A matching url substring keeps the response in scope.
        let matched =
            extract_subprocessors_from_responses(&responses, "trust.example.com", Some("graphql"));
        assert_eq!(matched.len(), 5);

        // A non-matching url substring filters the response out entirely.
        let filtered =
            extract_subprocessors_from_responses(&responses, "trust.example.com", Some("rest/v2"));
        assert!(filtered.is_empty());
    }

    #[test]
    fn test_extract_subprocessors_from_responses_low_score_skipped() {
        // JSON with arrays but no name/url fields - low score
        let body = serde_json::json!({
            "numbers": [
                {"x": 1, "y": 2},
                {"x": 3, "y": 4},
                {"x": 5, "y": 6},
                {"x": 7, "y": 8},
                {"x": 9, "y": 10}
            ]
        })
        .to_string();

        let responses = vec![InterceptedResponse {
            url: "https://api.example.com/data".to_string(),
            body,
        }];

        let result = extract_subprocessors_from_responses(&responses, "example.com", None);
        // The items don't have name fields, so they score below 0.4 and are skipped.
        assert!(result.is_empty());
    }

    // --- discover_strategy ---

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tokio::test]
    async fn test_discover_strategy_strong_html_candidate() {
        // If HTML patterns find a strong candidate (score >= 0.7),
        // it should return immediately without browser probes
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":{
                "default":{
                    "id":"default","slug":"test","name":"Test","show":true,
                    "raw":{"spData":{"items":{
                        "uid-1":{"listEntries":[
                            {"company":{"name":"A","domain":"a.com"},"purpose":"P","location":"US"},
                            {"company":{"name":"B","domain":"b.com"},"purpose":"P","location":"US"},
                            {"company":{"name":"C","domain":"c.com"},"purpose":"P","location":"US"}
                        ]}
                    }}}
                }
            }}}}}}
            </script></body></html>"#;

        let result = discover_strategy("https://trust.example.com/test", html)
            .await
            .unwrap();
        assert!(result.is_some());
        let strategy = result.unwrap();
        assert!(matches!(
            &strategy.strategy_type,
            StrategyType::HydrationData { .. }
        ));
    }

    #[tokio::test]
    async fn test_discover_strategy_no_candidates() {
        let html = "<html><body><p>Nothing useful here</p></body></html>";
        let result = discover_strategy("https://example.com/page", html)
            .await
            .unwrap();
        // No network interception candidates either (browser won't launch in test),
        // so result should be None
        assert!(result.is_none());
    }

    // --- SafeBase edge cases ---

    #[test]
    fn test_probe_safebase_missing_next_data() {
        // Has __SB_CONFIG__ but no __NEXT_DATA__
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {"NEXT_PUBLIC_SITE":"https://app.safebase.io"};</script>
            <div id="__next">Hello</div>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_probe_safebase_invalid_json() {
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {invalid json content here}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_probe_safebase_no_products() {
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{}}}}}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_probe_safebase_product_no_items() {
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":{
                "default":{
                    "id":"default","slug":"test","name":"Test","show":true,
                    "raw":{"spData":{}}
                }
            }}}}}}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_probe_safebase_too_few_entries() {
        // listEntries with fewer than 3 items should be skipped
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":{
                "default":{
                    "id":"default","slug":"test","name":"Test","show":true,
                    "raw":{"spData":{"items":{
                        "uid-1":{"listEntries":[
                            {"company":{"name":"A","domain":"a.com"},"purpose":"P","location":"US"},
                            {"company":{"name":"B","domain":"b.com"},"purpose":"P","location":"US"}
                        ]}
                    }}}
                }
            }}}}}}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_probe_safebase_product_default_show() {
        // Product without explicit "show" field should default to true
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":{
                "default":{
                    "id":"default","slug":"acme","name":"Acme",
                    "raw":{"spData":{"items":{
                        "uid-1":{"listEntries":[
                            {"company":{"name":"AWS","domain":"aws.com"},"purpose":"Cloud","location":"US"},
                            {"company":{"name":"GCP","domain":"gcp.com"},"purpose":"Cloud","location":"US"},
                            {"company":{"name":"Azure","domain":"azure.com"},"purpose":"Cloud","location":"US"}
                        ]}
                    }}}
                }
            }}}}}}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert_eq!(
            candidates.len(),
            1,
            "Product without 'show' should default to visible"
        );
    }

    // ====================================================================
    // Coverage gap tests — target remaining uncovered lines
    // ====================================================================

    // --- probe_base64_blobs: data-attribute pattern ---

    #[test]
    fn test_probe_base64_blobs_data_attribute_pattern() {
        use base64::Engine;
        let json_data = serde_json::json!({"vendors":[
            {"name":"Acme Cloud","url":"https://acmecloud.io","purpose":"Cloud infrastructure provider"},
            {"name":"SecureAuth","url":"https://secureauth.io","purpose":"Authentication service provider"},
            {"name":"DataVault","url":"https://datavault.io","purpose":"Data storage and processing"},
            {"name":"NetShield","url":"https://netshield.io","purpose":"Network security protection"},
            {"name":"LogStream","url":"https://logstream.io","purpose":"Log aggregation and monitoring"}
        ]});
        let b64 =
            base64::engine::general_purpose::STANDARD.encode(json_data.to_string().as_bytes());
        let html = format!(
            r#"<html><body><div data-config="{}"></div></body></html>"#,
            b64
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        assert!(
            !candidates.is_empty(),
            "Should find subprocessors in data-attribute base64"
        );
        assert!(matches!(
            &candidates[0].strategy.strategy_type,
            StrategyType::EmbeddedBase64Json { locator_pattern } if locator_pattern.contains("data-")
        ));
    }

    #[test]
    fn test_probe_base64_blobs_variable_assignment_pattern() {
        use base64::Engine;
        let json_data = serde_json::json!({"processors":[
            {"name":"CloudHost","url":"https://cloudhost.io","purpose":"Hosting infrastructure services"},
            {"name":"PayGate","url":"https://paygate.io","purpose":"Payment gateway integration"},
            {"name":"MailPush","url":"https://mailpush.io","purpose":"Email delivery service provider"},
            {"name":"CDNFast","url":"https://cdnfast.io","purpose":"Content delivery network services"},
            {"name":"DBScale","url":"https://dbscale.io","purpose":"Database scaling and management"}
        ]});
        let b64 =
            base64::engine::general_purpose::STANDARD.encode(json_data.to_string().as_bytes());
        let html = format!(
            r#"<html><body><script>var subprocessorData = "{}";</script></body></html>"#,
            b64
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        assert!(
            !candidates.is_empty(),
            "Should find subprocessors in var-assignment base64"
        );
    }

    #[test]
    fn test_probe_base64_blobs_non_utf8_decoded() {
        use base64::Engine;
        // Valid base64 that decodes to non-UTF8 bytes
        let non_utf8: Vec<u8> = [0xFF, 0xFE, 0xFD]
            .iter()
            .copied()
            .cycle()
            .take(300)
            .collect();
        let b64 = base64::engine::general_purpose::STANDARD.encode(&non_utf8);
        let html = format!(
            r#"<html><body><script>var x = atob("{}");</script></body></html>"#,
            b64
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "Non-UTF8 decoded base64 should be skipped"
        );
    }

    #[test]
    fn test_probe_base64_blobs_valid_json_but_no_arrays() {
        use base64::Engine;
        let json_data = serde_json::json!({"key": "value", "number": 42});
        let b64 =
            base64::engine::general_purpose::STANDARD.encode(json_data.to_string().as_bytes());
        let html = format!(
            r#"<html><body><script>var data = atob("{}");</script></body></html>"#,
            b64
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "JSON without arrays should yield no candidates"
        );
    }

    #[test]
    fn test_probe_base64_blobs_valid_json_low_score_array() {
        use base64::Engine;
        // Arrays with items that have no name/url fields -> low score
        let json_data = serde_json::json!({"items":[
            {"x": 1, "y": 2},
            {"x": 3, "y": 4},
            {"x": 5, "y": 6},
            {"x": 7, "y": 8},
            {"x": 9, "y": 10}
        ]});
        let b64 =
            base64::engine::general_purpose::STANDARD.encode(json_data.to_string().as_bytes());
        let html = format!(
            r#"<html><body><script>var data = atob("{}");</script></body></html>"#,
            b64
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "Low-score arrays should be filtered out"
        );
    }

    #[test]
    fn test_probe_base64_blobs_multiple_matches() {
        use base64::Engine;
        let json1 = serde_json::json!({"vendors":[
            {"name":"A1","url":"https://a1.io","purpose":"Service A1 provides hosting"},
            {"name":"B1","url":"https://b1.io","purpose":"Service B1 provides hosting"},
            {"name":"C1","url":"https://c1.io","purpose":"Service C1 provides hosting"},
            {"name":"D1","url":"https://d1.io","purpose":"Service D1 provides hosting"},
            {"name":"E1","url":"https://e1.io","purpose":"Service E1 provides hosting"}
        ]});
        let json2 = serde_json::json!({"vendors":[
            {"name":"A2","url":"https://a2.io","purpose":"Service A2 provides storage"},
            {"name":"B2","url":"https://b2.io","purpose":"Service B2 provides storage"},
            {"name":"C2","url":"https://c2.io","purpose":"Service C2 provides storage"},
            {"name":"D2","url":"https://d2.io","purpose":"Service D2 provides storage"},
            {"name":"E2","url":"https://e2.io","purpose":"Service E2 provides storage"}
        ]});
        let b64_1 = base64::engine::general_purpose::STANDARD.encode(json1.to_string().as_bytes());
        let b64_2 = base64::engine::general_purpose::STANDARD.encode(json2.to_string().as_bytes());
        let html = format!(
            r#"<html><body><script>var first = atob("{}"); var second = atob("{}");</script></body></html>"#,
            b64_1, b64_2
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        let count = candidates.len();
        assert!(
            count >= 2,
            "Should find candidates from multiple base64 blobs, got {count}"
        );
    }

    // --- probe_js_object_assignments: successful match ---

    #[test]
    fn test_probe_js_object_assignments_with_subprocessors() {
        // Build a JSON blob with subprocessor-like data, > 200 chars, ending with };
        let json_obj = serde_json::json!({
            "subprocessors": [
                {"name": "AWS Infrastructure", "url": "https://aws.amazon.com", "purpose": "Cloud infrastructure hosting services"},
                {"name": "Cloudflare CDN", "url": "https://cloudflare.com", "purpose": "Content delivery network and DDoS protection"},
                {"name": "Datadog Monitoring", "url": "https://datadoghq.com", "purpose": "Application performance monitoring tools"},
                {"name": "Stripe Payments", "url": "https://stripe.com", "purpose": "Payment processing and billing services"},
                {"name": "Okta Identity", "url": "https://okta.com", "purpose": "Identity and access management provider"}
            ]
        });
        let json_str = json_obj.to_string();
        let html = format!(
            r#"<html><body><script>window.TRUST_DATA = {};</script></body></html>"#,
            json_str
        );
        let mut candidates = Vec::new();
        probe_js_object_assignments(&html, &mut candidates);
        assert!(
            !candidates.is_empty(),
            "Should find subprocessors in window.TRUST_DATA assignment"
        );
        assert!(matches!(
            &candidates[0].strategy.strategy_type,
            StrategyType::EmbeddedJsObject { locator_pattern } if locator_pattern.contains("TRUST_DATA")
        ));
    }

    #[test]
    fn test_probe_js_object_assignments_low_score_skipped() {
        // JSON blob with arrays that don't look like subprocessors
        let json_obj = serde_json::json!({
            "items": [
                {"x": 1, "y": 2, "z": "padding to make this longer than needed for the minimum"},
                {"x": 3, "y": 4, "z": "padding to make this longer than needed for the minimum"},
                {"x": 5, "y": 6, "z": "padding to make this longer than needed for the minimum"},
                {"x": 7, "y": 8, "z": "padding to make this longer than needed for the minimum"},
                {"x": 9, "y": 10, "z": "padding to make this longer than needed for the minimum"}
            ]
        });
        let json_str = json_obj.to_string();
        let html = format!(
            r#"<html><body><script>window.APP_DATA = {};</script></body></html>"#,
            json_str
        );
        let mut candidates = Vec::new();
        probe_js_object_assignments(&html, &mut candidates);
        assert!(candidates.is_empty(), "Low-score arrays should be skipped");
    }

    #[test]
    fn test_probe_js_object_assignments_invalid_json_content() {
        // The regex captures something that looks like JSON but isn't valid
        // The regex pattern requires at least 200 chars inside the braces
        let padding = "x".repeat(250);
        let html = format!(
            r#"<html><body><script>window.BAD_DATA = {{"not_valid": "{}"}};</script></body></html>"#,
            padding
        );
        let mut candidates = Vec::new();
        probe_js_object_assignments(&html, &mut candidates);
        // May or may not parse, but shouldn't panic
    }

    // --- extract_subprocessors_from_responses: no name_field continue path ---

    #[test]
    fn test_extract_subprocessors_from_responses_no_name_field() {
        // Array with good score but no identifiable name field -> skipped
        let body = serde_json::json!({
            "subprocessors": [
                {"id": 1, "category": "infrastructure", "status": "active", "region": "us-east-1", "tier": "premium"},
                {"id": 2, "category": "security", "status": "active", "region": "eu-west-1", "tier": "standard"},
                {"id": 3, "category": "monitoring", "status": "active", "region": "ap-south-1", "tier": "premium"},
                {"id": 4, "category": "networking", "status": "active", "region": "us-west-2", "tier": "standard"},
                {"id": 5, "category": "database", "status": "active", "region": "eu-central-1", "tier": "premium"}
            ]
        })
        .to_string();

        let responses = vec![InterceptedResponse {
            url: "https://api.example.com/data".to_string(),
            body,
        }];

        let result = extract_subprocessors_from_responses(&responses, "example.com", None);
        // The "subprocessors" path keyword boosts score, but items lack a name
        // field, so detect_field_mapping returns None for name_field -> skipped.
        assert!(
            result.is_empty(),
            "Items without a name field should be skipped"
        );
    }

    #[test]
    fn test_extract_subprocessors_from_responses_unions_and_dedupes_across_pages() {
        // Two captured responses standing in for two paginated API calls. The
        // overlap (DataSync, PayFlow share domains) must collapse so the union is
        // the distinct set, not the sum — this is how pagination is handled.
        let page1 = serde_json::json!({
            "vendors": [
                {"name": "CloudHost Inc", "url": "https://cloudhost.io", "purpose": "Cloud hosting infrastructure services"},
                {"name": "SecureNet LLC", "url": "https://securenet.io", "purpose": "Network security and monitoring"},
                {"name": "DataSync Corp", "url": "https://datasync.io", "purpose": "Data synchronization services"},
                {"name": "PayFlow Ltd", "url": "https://payflow.io", "purpose": "Payment processing and billing"},
                {"name": "LogAnalytics", "url": "https://loganalytics.io", "purpose": "Log aggregation and analysis"}
            ]
        })
        .to_string();
        let page2 = serde_json::json!({
            "vendors": [
                {"name": "DataSync Corp", "url": "https://datasync.io", "purpose": "Data synchronization services"},
                {"name": "PayFlow Ltd", "url": "https://payflow.io", "purpose": "Payment processing and billing"},
                {"name": "Twilio", "url": "https://twilio.com", "purpose": "Messaging and communications"},
                {"name": "Okta", "url": "https://okta.com", "purpose": "Identity and access management"},
                {"name": "Snowflake", "url": "https://snowflake.com", "purpose": "Data warehousing platform"}
            ]
        })
        .to_string();

        let responses = vec![
            InterceptedResponse {
                url: "https://api.example.com/graphql?operation=subprocessors&page=1".to_string(),
                body: page1,
            },
            InterceptedResponse {
                url: "https://api.example.com/graphql?operation=subprocessors&page=2".to_string(),
                body: page2,
            },
        ];

        let result = extract_subprocessors_from_responses(&responses, "example.com", None);
        // 5 from page 1 + 3 new from page 2 (DataSync & PayFlow de-duplicated) = 8.
        assert_eq!(result.len(), 8);
        let domains: Vec<&str> = result.iter().map(|v| v.domain.as_str()).collect();
        assert_eq!(
            domains.iter().filter(|d| **d == "datasync.io").count(),
            1,
            "duplicate domain across pages must collapse to one record"
        );
        assert!(domains.contains(&"twilio.com"));
        assert!(domains.contains(&"snowflake.com"));
    }

    // --- discover_strategy: weak candidates below threshold ---

    #[cfg_attr(coverage_nightly, coverage(off))]
    #[tokio::test]
    async fn test_discover_strategy_weak_candidate_below_threshold() {
        // HTML with a next_data blob that has items scoring between 0.4 and 0.7
        // The score depends on the array data; items with name fields but low count
        // will score moderately. With score < 0.7, it tries network interception.
        // Network interception will fail in test (no browser), so we check if
        // the weak candidate is still returned (if score >= 0.4).
        let html = r#"<html><body>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"vendors":[
                {"name":"Vendor A","url":"https://a.com","purpose":"Service A provides hosting"},
                {"name":"Vendor B","url":"https://b.com","purpose":"Service B provides storage"},
                {"name":"Vendor C","url":"https://c.com","purpose":"Service C provides compute"},
                {"name":"Vendor D","url":"https://d.com","purpose":"Service D provides network"},
                {"name":"Vendor E","url":"https://e.com","purpose":"Service E provides backup"}
            ]}}}
            </script></body></html>"#;

        let result = discover_strategy("https://example.com/trust", html)
            .await
            .unwrap();
        // The HTML candidate might score >= 0.4 (subprocessors path keyword in data),
        // and network interception will fail. If HTML score >= 0.4 it gets returned.
        // If not, result is None. Either way, it should not panic.
        assert!(
            result.is_none()
                || matches!(
                    &result.as_ref().unwrap().strategy_type,
                    StrategyType::HydrationData { .. }
                )
        );
    }

    #[tokio::test]
    async fn test_discover_strategy_empty_html() {
        let result = discover_strategy("https://example.com", "").await.unwrap();
        assert!(result.is_none());
    }

    // --- is_likely_spa: additional body parsing edge cases ---

    #[test]
    fn test_is_likely_spa_body_no_gt_after_body_tag() {
        // <body without closing > — find('>') fails on the truncated content
        let html = "<html><head></head><body";
        assert!(!is_likely_spa(html));
    }

    #[test]
    fn test_is_likely_spa_body_with_noscript_and_scripts() {
        // Body with noscript and scripts but no visible elements
        let html = r#"<html><head></head>
            <body>
            <noscript>Enable JavaScript</noscript>
            <script src="/app.js"></script>
            </body></html>"#;
        assert!(is_likely_spa(html));
    }

    #[test]
    fn test_is_likely_spa_short_html_low_ratio() {
        // Short HTML (< 1000 chars) with low text ratio - should NOT trigger
        // the text ratio check because html_len must be > 1000
        let html = "<html><head></head><body></body></html>";
        assert!(!is_likely_spa(html));
    }

    // --- InterceptedResponse derive coverage ---

    #[test]
    fn test_intercepted_response_debug_clone() {
        let resp = InterceptedResponse {
            url: "https://api.example.com/data".to_string(),
            body: r#"{"data":[]}"#.to_string(),
        };
        let cloned = resp.clone();
        assert_eq!(cloned.url, resp.url);
        assert_eq!(cloned.body, resp.body);
        let debug_str = format!("{:?}", resp);
        assert!(debug_str.contains("InterceptedResponse"));
    }

    #[test]
    fn test_extract_subprocessors_selects_single_highest_scoring_array() {
        // Two sibling arrays in one response, neither at a subprocessor-keyword
        // path: `alpha` (name + url + purpose) outscores `beta` (name only).
        // Only the dominant array's records must return — this pins the selection
        // contract (highest-scoring array + same-leaf union, NOT union-of-all).
        let body = serde_json::json!({
            "alpha": [
                {"name": "Acme Cloud", "url": "https://acmecloud.io", "purpose": "Cloud hosting services"},
                {"name": "Bolt Pay", "url": "https://boltpay.io", "purpose": "Payment processing services"},
                {"name": "Crate DB", "url": "https://cratedb.io", "purpose": "Database hosting services"},
                {"name": "Delta CDN", "url": "https://deltacdn.io", "purpose": "Content delivery network"},
                {"name": "Echo Mail", "url": "https://echomail.io", "purpose": "Transactional email delivery"},
                {"name": "Foxtrot Logs", "url": "https://foxtrotlogs.io", "purpose": "Log aggregation service"}
            ],
            "beta": [
                {"name": "Section One"},
                {"name": "Section Two"},
                {"name": "Section Three"},
                {"name": "Section Four"},
                {"name": "Section Five"}
            ]
        })
        .to_string();
        let responses = vec![InterceptedResponse {
            url: "https://api.example.com/data".to_string(),
            body,
        }];

        let vendors = extract_subprocessors_from_responses(&responses, "example.com", None);
        assert_eq!(
            vendors.len(),
            6,
            "only the dominant `alpha` array should be selected"
        );
        let names: Vec<&str> = vendors.iter().map(|v| v.raw_record.as_str()).collect();
        assert!(names.contains(&"Acme Cloud"));
        assert!(
            !names.iter().any(|n| n.starts_with("Section")),
            "the weaker `beta` sibling array must be excluded"
        );
    }

    #[test]
    fn test_derive_capture_hint_picks_operation_of_first_subprocessor_response() {
        let body = serde_json::json!({
            "data": {"subprocessors": [
                {"name": "AWS", "url": "https://aws.amazon.com"},
                {"name": "GCP", "url": "https://cloud.google.com"},
                {"name": "Azure", "url": "https://azure.microsoft.com"},
                {"name": "Stripe", "url": "https://stripe.com"},
                {"name": "Datadog", "url": "https://datadoghq.com"}
            ]}
        })
        .to_string();
        let responses = vec![
            // A noise response (no subprocessors) precedes the data response.
            InterceptedResponse {
                url: "https://t.example.com/graphql?operation=ping".to_string(),
                body: r#"{"data":{"ok":true}}"#.to_string(),
            },
            InterceptedResponse {
                url: "https://t.example.com/graphql?operation=fetchSubs".to_string(),
                body,
            },
        ];
        assert_eq!(
            derive_capture_hint(&responses, "t.example.com").as_deref(),
            Some("fetchSubs")
        );
    }

    #[test]
    fn test_derive_capture_hint_none_and_bare_graphql() {
        // No response yields subprocessors -> None.
        let none_resp = vec![InterceptedResponse {
            url: "https://t.example.com/api/health".to_string(),
            body: r#"{"status":"ok"}"#.to_string(),
        }];
        assert_eq!(derive_capture_hint(&none_resp, "t.example.com"), None);

        // A graphql URL with no operation param -> the generic "graphql".
        let body = serde_json::json!({"subprocessors":[
            {"name":"AWS","url":"https://aws.amazon.com"},
            {"name":"GCP","url":"https://cloud.google.com"},
            {"name":"Azure","url":"https://azure.microsoft.com"},
            {"name":"Stripe","url":"https://stripe.com"},
            {"name":"Datadog","url":"https://datadoghq.com"}
        ]})
        .to_string();
        let resp = vec![InterceptedResponse {
            url: "https://t.example.com/graphql".to_string(),
            body,
        }];
        assert_eq!(
            derive_capture_hint(&resp, "t.example.com").as_deref(),
            Some("graphql")
        );
    }

    #[test]
    fn test_extract_with_hint_fallback_recovers_from_stale_hint() {
        let body = serde_json::json!({"subprocessors":[
            {"name":"AWS","url":"https://aws.amazon.com"},
            {"name":"GCP","url":"https://cloud.google.com"},
            {"name":"Azure","url":"https://azure.microsoft.com"},
            {"name":"Stripe","url":"https://stripe.com"},
            {"name":"Datadog","url":"https://datadoghq.com"}
        ]})
        .to_string();
        let responses = vec![InterceptedResponse {
            url: "https://t.example.com/graphql?operation=fetchSubs".to_string(),
            body,
        }];
        // Matching hint extracts via the hinted response.
        assert_eq!(
            extract_with_hint_fallback(&responses, "t.example.com", Some("fetchSubs")).len(),
            5
        );
        // A stale/non-matching hint must fall back to all responses, not under-capture.
        assert_eq!(
            extract_with_hint_fallback(&responses, "t.example.com", Some("staleOperation")).len(),
            5
        );
        // No hint -> all responses.
        assert_eq!(
            extract_with_hint_fallback(&responses, "t.example.com", None).len(),
            5
        );
    }

    #[test]
    fn test_extract_subprocessors_rejects_non_subprocessor_arrays() {
        // Real failure mode: the subprocessor response was missing from the
        // capture (Vanta throttled / partial render), leaving only sibling arrays
        // — control categories and frameworks. They carry a `name` field and score
        // >= 0.4, but have NO url field and NO subprocessor-ish path, so they must
        // be rejected: an honest empty result, never returned as bogus "vendors".
        let body = serde_json::json!({
            "data": {"trust": {"trustReportBySlugId": {
                "controlCategoriesExternal": [
                    {"id": 1, "name": "Access Control"},
                    {"id": 2, "name": "Cryptography"},
                    {"id": 3, "name": "Operations Security"},
                    {"id": 4, "name": "Asset Management"},
                    {"id": 5, "name": "Incident Response"},
                    {"id": 6, "name": "Risk Management"}
                ],
                "frameworks": [
                    {"id": 1, "name": "SOC 2"},
                    {"id": 2, "name": "ISO 27001"},
                    {"id": 3, "name": "HIPAA"},
                    {"id": 4, "name": "GDPR"},
                    {"id": 5, "name": "PCI DSS"}
                ]
            }}}
        })
        .to_string();
        let responses = vec![InterceptedResponse {
            url: "https://trust.vanta.com/graphql?operation=fetchCustomizableControlsDataForExternalTrustCenter".to_string(),
            body,
        }];

        let result = extract_subprocessors_from_responses(&responses, "vanta.com", None);
        assert!(
            result.is_empty(),
            "control categories / frameworks must never be returned as subprocessors, got {:?}",
            result
                .iter()
                .map(|v| v.raw_record.as_str())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_responses_contain_subprocessor_array_signal() {
        // Real subprocessor array (name + url + keyword path) -> true; a response
        // with only sibling arrays (control categories, name-only) -> false. This
        // is the signal the render-capture wait polls on, so it must distinguish.
        let real = vec![InterceptedResponse {
            url: "https://t/graphql?operation=fetchDataForTrustReport".to_string(),
            body: serde_json::json!({"data":{"trust":{"trustReportBySlugId":{"subprocessors":[
                {"name":"AWS","url":"https://aws.amazon.com"},
                {"name":"GCP","url":"https://cloud.google.com"},
                {"name":"Azure","url":"https://azure.microsoft.com"},
                {"name":"Stripe","url":"https://stripe.com"},
                {"name":"Datadog","url":"https://datadoghq.com"}
            ]}}}})
            .to_string(),
        }];
        assert!(responses_contain_subprocessor_array(&real));

        let siblings = vec![InterceptedResponse {
            url: "https://t/graphql?operation=fetchCustomizableControls".to_string(),
            body: serde_json::json!({"data":{"trust":{"trustReportBySlugId":{"controlCategoriesExternal":[
                {"id":1,"name":"Access Control"},
                {"id":2,"name":"Cryptography"},
                {"id":3,"name":"Operations"},
                {"id":4,"name":"Assets"},
                {"id":5,"name":"Incidents"},
                {"id":6,"name":"Risk"}
            ]}}}}).to_string(),
        }];
        assert!(!responses_contain_subprocessor_array(&siblings));
        assert!(!responses_contain_subprocessor_array(&[]));
    }

    #[test]
    fn test_extract_subprocessors_vanta_fixture_discriminates_sibling_arrays() {
        // Real captured `fetchDataForTrustReport` payload (trimmed): the
        // subprocessors array sits alongside frameworks, resourceCategories,
        // navigationKeys and mainOverviewSections — all of which carry a `name`
        // field and score above threshold. Only the subprocessors must survive.
        let body = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/trust_center/vanta_subprocessors_response.json"
        ))
        .to_string();
        let responses = vec![InterceptedResponse {
            url: "https://trust.vanta.com/graphql?operation=fetchDataForTrustReport".to_string(),
            body,
        }];

        let vendors = extract_subprocessors_from_responses(&responses, "vanta.com", None);

        // Exactly the 42 real subprocessors — NOT the 12 frameworks, 7 resource
        // categories, navigation keys, or overview sections.
        assert_eq!(
            vendors.len(),
            42,
            "expected exactly 42 subprocessors, got {} (sibling arrays leaking?)",
            vendors.len()
        );

        let domains: Vec<String> = vendors.iter().map(|v| v.domain.to_lowercase()).collect();
        assert!(domains.iter().any(|d| d.contains("amazon")));
        assert!(domains.iter().any(|d| d.contains("cloudflare")));
        assert!(domains.iter().any(|d| d.contains("datadog")));
        assert!(domains.iter().any(|d| d.contains("mongodb")));

        // The two entries with no URL fall back to `_org:` placeholders for
        // downstream org→domain resolution.
        assert!(domains.iter().any(|d| d.starts_with("_org:")));
    }

    /// Live smoke test against Vanta's real trust center (network + headless
    /// Chrome). Exercises the public render-capture entry point end-to-end.
    /// Ignored by default. Run with:
    ///   cargo test --lib -- --ignored --nocapture live_vanta_render_capture
    #[cfg(not(coverage))]
    #[tokio::test]
    #[ignore = "live network + headless Chrome"]
    async fn live_vanta_render_capture() {
        let url = "https://trust.vanta.com/subprocessors";
        let discovery = discover_and_extract_via_render(url, "vanta.com")
            .await
            .expect("render-capture should not error");
        let vendors = discovery.vendors;
        eprintln!("Vanta subprocessors extracted: {}", vendors.len());
        for v in &vendors {
            eprintln!("  {} | {}", v.domain, v.raw_record);
        }
        // Vanta's trust center lists ~42 subprocessors; allow drift but require
        // the full list, not the 3 the legacy HTML-regex path returned.
        assert!(
            vendors.len() >= 40,
            "expected the full Vanta subprocessor list (~42), got {}",
            vendors.len()
        );
        let strategy = discovery
            .strategy
            .expect("a successful discovery must yield a cacheable strategy");
        assert!(matches!(
            strategy.strategy_type,
            StrategyType::RenderedNetworkCapture { .. }
        ));
        // P2.1(b): the settled DOM must come back with the capture — it is what lets the
        // subprocessor path skip its own render of this same URL.
        assert!(
            discovery.settled_dom.is_some_and(|dom| !dom.is_empty()),
            "render-capture must carry out the settled DOM"
        );
    }

    // --- probe_json_script_tags: array with name field but no name detected ---

    #[test]
    fn test_probe_json_script_tags_high_score_no_name_field() {
        // Items in the subprocessors path but without a recognizable name field
        let html = r#"<html><body>
            <script type="application/json">
            {"subprocessors":[
                {"id":1,"category":"infra","status":"active","region":"us-east","tier":"premium","code":"AAA"},
                {"id":2,"category":"security","status":"active","region":"eu-west","tier":"standard","code":"BBB"},
                {"id":3,"category":"monitoring","status":"active","region":"ap-south","tier":"premium","code":"CCC"},
                {"id":4,"category":"network","status":"active","region":"us-west","tier":"standard","code":"DDD"},
                {"id":5,"category":"database","status":"active","region":"eu-central","tier":"premium","code":"EEE"}
            ]}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_json_script_tags(html, &mut candidates);
        // The path "subprocessors" boosts the score, but items lack a name field,
        // so detect_field_mapping returns None -> skipped
        assert!(
            candidates.is_empty(),
            "Items without name field should be skipped"
        );
    }

    // --- probe_next_data: array with good score but no name field ---

    #[test]
    fn test_probe_next_data_good_score_no_name_field() {
        let html = r#"<html><body>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"subprocessors":[
                {"id":1,"category":"infra","status":"active","region":"us-east","tier":"premium","code":"X1"},
                {"id":2,"category":"security","status":"active","region":"eu-west","tier":"standard","code":"X2"},
                {"id":3,"category":"monitoring","status":"active","region":"ap-south","tier":"premium","code":"X3"},
                {"id":4,"category":"network","status":"active","region":"us-west","tier":"standard","code":"X4"},
                {"id":5,"category":"database","status":"active","region":"eu-central","tier":"premium","code":"X5"}
            ]}}}
            </script></body></html>"#;
        // "subprocessors" in path boosts score but no name field -> returns None
        assert!(probe_next_data(html).is_none());
    }

    // --- extract_slug_from_url: URL with empty first segment ---

    #[test]
    fn test_extract_slug_from_url_graphql_path() {
        assert_eq!(
            extract_slug_from_url("https://example.com/graphql/query"),
            None
        );
    }

    // --- extract_js_object_assignment: escaped backslash at end of string ---

    #[test]
    fn test_extract_js_object_assignment_escaped_backslash() {
        let html = r#"window.CFG = {"path": "C:\\Users\\test"};"#;
        let result = extract_js_object_assignment(html, "CFG");
        assert!(result.is_some());
        assert_eq!(
            result.unwrap().get("path").unwrap().as_str().unwrap(),
            "C:\\Users\\test"
        );
    }

    #[test]
    fn test_extract_js_object_assignment_unbalanced_braces() {
        // Opening brace but never closes — should return None
        let html = r#"window.BAD = {"key": "value"  "#;
        assert!(extract_js_object_assignment(html, "BAD").is_none());
    }

    // --- Conveyor: edge case where VENDOR_REPORT has no _embedded ---

    #[test]
    fn test_count_conveyor_subprocessors_no_subprocessors_key() {
        let html = r#"window.VENDOR_REPORT = {"_embedded": {"assets": []}};"#;
        assert_eq!(count_conveyor_subprocessors(html), 0);
    }

    // --- probe_safebase: products is not an object ---

    #[test]
    fn test_probe_safebase_products_not_object() {
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":"not_an_object"}}}}}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    // --- probe_safebase: product where slug is absent (uses product_id as slug) ---

    #[test]
    fn test_probe_safebase_product_no_slug_uses_product_id() {
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":{
                "my_product_id":{
                    "id":"my_product_id","show":true,
                    "raw":{"spData":{"items":{
                        "uid-1":{"listEntries":[
                            {"company":{"name":"AWS","domain":"aws.com"},"purpose":"Cloud","location":"US"},
                            {"company":{"name":"GCP","domain":"gcp.com"},"purpose":"Cloud","location":"US"},
                            {"company":{"name":"Azure","domain":"azure.com"},"purpose":"Cloud","location":"US"}
                        ]}
                    }}}
                }
            }}}}}}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert_eq!(candidates.len(), 1);
        // Slug should be the product_id since there's no explicit slug field
        assert_eq!(
            candidates[0].strategy.endpoint.slug,
            Some("my_product_id".to_string())
        );
    }

    // --- probe_safebase: items map exists but individual item has no listEntries ---

    #[test]
    fn test_probe_safebase_item_without_list_entries() {
        let html = r#"<html><body>
            <script>window.__SB_CONFIG__ = {};</script>
            <script id="__NEXT_DATA__" type="application/json">
            {"props":{"pageProps":{"orgInfo":{"sp":{"products":{
                "default":{
                    "id":"default","slug":"acme","name":"Acme","show":true,
                    "raw":{"spData":{"items":{
                        "uid-1":{"text":{"title":"Section Header"}}
                    }}}
                }
            }}}}}}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    // --- discover_via_html_patterns: all probes run in sequence ---

    #[test]
    #[cfg_attr(coverage_nightly, coverage(off))]
    fn test_discover_via_html_patterns_conveyor_takes_priority() {
        // Conveyor HTML should be detected by Conveyor probe
        let html = r#"<html><body>
            <script>
            window.CANONICAL_ASSET = {"slug":"myco"};
            window.VENDOR_REPORT = {"_embedded":{"subprocessors":[
                {"id":"s1","canonical_asset_id":"ca1","description":"Cloud hosting","data_locations":["US"]},
                {"id":"s2","canonical_asset_id":"ca2","description":"CDN service","data_locations":["US"]},
                {"id":"s3","canonical_asset_id":"ca3","description":"Monitoring","data_locations":["US"]}
            ],"canonical_assets":[
                {"id":"ca1","name":"AWS","website":"https://aws.amazon.com"},
                {"id":"ca2","name":"Cloudflare","website":"https://cloudflare.com"},
                {"id":"ca3","name":"Datadog","website":"https://datadoghq.com"}
            ]}};
            </script></body></html>"#;

        let result = discover_via_html_patterns(html).unwrap();
        assert!(!result.is_empty());
        let best = result
            .iter()
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap())
            .unwrap();
        assert!(best.score >= 0.9);
        // Verify it's a RestApi (Conveyor uses REST)
        assert!(matches!(
            &best.strategy.strategy_type,
            StrategyType::RestApi { method, .. } if method == "GET"
        ));
    }

    // --- probe_base64_blobs: valid base64 but not valid JSON ---

    #[test]
    fn test_probe_base64_blobs_valid_base64_not_json() {
        use base64::Engine;
        let text = "This is just plain text, not JSON at all, and we need to make it long enough to match the regex pattern threshold of 200 characters so lets keep typing more text here to pad it out sufficiently for the test case to work properly with our regex matching requirements";
        let b64 = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
        let html = format!(
            r#"<html><body><script>var data = atob("{}");</script></body></html>"#,
            b64
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "Non-JSON base64 should produce no candidates"
        );
    }

    // --- probe_json_script_tags: multiple scripts, one with valid data ---

    #[test]
    fn test_probe_json_script_tags_multiple_scripts() {
        let html = r#"<html><body>
            <script type="application/json">{"small": true}</script>
            <script type="application/json">
            {"vendors":[
                {"name":"AWS Cloud Services","url":"https://aws.amazon.com","purpose":"Cloud infrastructure and hosting"},
                {"name":"Cloudflare Inc","url":"https://cloudflare.com","purpose":"CDN and DDoS protection"},
                {"name":"Datadog Inc","url":"https://datadoghq.com","purpose":"Application monitoring"},
                {"name":"Stripe Inc","url":"https://stripe.com","purpose":"Payment processing"},
                {"name":"Okta Inc","url":"https://okta.com","purpose":"Identity management"}
            ]}
            </script>
            <script type="application/json">{"another": "small one with not enough content"}</script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_json_script_tags(html, &mut candidates);
        assert!(
            !candidates.is_empty(),
            "Should find data in second script tag"
        );
    }

    // --- extract_graphql_operation: URL with other query params ---

    #[test]
    fn test_extract_graphql_operation_multiple_params() {
        assert_eq!(
            extract_graphql_operation(
                "https://api.example.com/graphql?version=2&operationName=FetchAll&limit=100"
            ),
            Some("FetchAll".to_string())
        );
    }

    // --- extract_slug_from_url: URL without path segments ---

    #[test]
    fn test_extract_slug_from_url_no_path() {
        assert_eq!(extract_slug_from_url("https://example.com"), None);
    }

    #[test]
    fn test_extract_slug_from_url_empty_first_segment() {
        // URL like "https://example.com//something" — first segment is empty
        assert_eq!(
            extract_slug_from_url("https://example.com//something"),
            None
        );
    }

    #[test]
    fn test_is_likely_spa_empty_html_returns_false() {
        assert!(!is_likely_spa(""));
    }

    #[test]
    fn test_is_likely_spa_framework_marker_react() {
        let html = r#"<html><head></head><body><div data-reactroot>Loading...</div></body></html>"#;
        assert!(is_likely_spa(html));
    }

    #[test]
    fn test_is_likely_spa_framework_marker_nuxt() {
        let html = r#"<html><body><script>window.__nuxt__={config:{}}</script></body></html>"#;
        assert!(is_likely_spa(html));
    }

    #[test]
    fn test_is_likely_spa_framework_marker_angular() {
        let html = r#"<html><body ng-app="myApp"><div></div></body></html>"#;
        assert!(is_likely_spa(html));
    }

    #[test]
    fn test_probe_safebase_no_config_exits_early() {
        let html = r#"<html><body><h1>Regular page</h1></body></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "No __SB_CONFIG__ means no candidates"
        );
    }

    #[test]
    fn test_probe_js_object_assignments_no_match() {
        let html = r#"<html><body><script>var x = 42;</script></body></html>"#;
        let mut candidates = Vec::new();
        probe_js_object_assignments(html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "Simple JS assignment should not match"
        );
    }

    #[test]
    fn test_probe_base64_blobs_no_base64_content() {
        let html = r#"<html><body><p>Just a normal page with no base64</p></body></html>"#;
        let mut candidates = Vec::new();
        probe_base64_blobs(html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "No base64 content means no candidates"
        );
    }

    #[test]
    fn test_probe_json_script_tags_no_json_scripts() {
        let html = r#"<html><body><script>console.log("hello")</script></body></html>"#;
        let mut candidates = Vec::new();
        probe_json_script_tags(html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "No application/json scripts means no candidates"
        );
    }

    #[test]
    fn test_is_likely_spa_body_visible_content_with_scripts() {
        let html = r#"<html><head></head><body><div>Content here for real page with substantial text that is not a single page application at all</div><script src="/app.js"></script></body></html>"#;
        assert!(!is_likely_spa(html));
    }

    #[test]
    fn test_is_likely_spa_body_without_scripts() {
        let html = r#"<html><head></head><body><p>Just text content, no scripts here at all, this is a static page.</p></body></html>"#;
        assert!(!is_likely_spa(html));
    }

    #[test]
    fn test_probe_safebase_invalid_regex_resilience() {
        let html = "__SB_CONFIG__";
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_probe_safebase_products_not_object_but_present() {
        let html = r#"<html>__SB_CONFIG__<script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"orgInfo":{"sp":{"products":"not_an_object"}}}}}</script></html>"#;
        let mut candidates = Vec::new();
        probe_safebase(html, &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_probe_safebase_items_not_object_in_product() {
        let next_data = serde_json::json!({
            "props": {
                "pageProps": {
                    "orgInfo": {
                        "sp": {
                            "products": {
                                "prod1": {
                                    "slug": "test",
                                    "visibilityStatus": "visible",
                                    "raw": {
                                        "spData": {
                                            "items": "not_an_object"
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });
        let html = format!(
            r#"<html>__SB_CONFIG__<script id="__NEXT_DATA__" type="application/json">{}</script></html>"#,
            next_data
        );
        let mut candidates = Vec::new();
        probe_safebase(&html, &mut candidates);
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_probe_base64_blobs_valid_json_high_score_with_name() {
        use base64::Engine;
        let json = serde_json::json!({
            "subprocessors": [
                {"name": "AWS", "url": "https://aws.amazon.com", "purpose": "Cloud"},
                {"name": "GCP", "url": "https://cloud.google.com", "purpose": "Cloud"},
                {"name": "Azure", "url": "https://azure.microsoft.com", "purpose": "Cloud"},
                {"name": "Datadog", "url": "https://datadoghq.com", "purpose": "Monitoring"},
                {"name": "Stripe", "url": "https://stripe.com", "purpose": "Payments"}
            ]
        });
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.to_string().as_bytes());
        let html = format!(
            r#"<html><body><script>var data = atob("{}");</script></body></html>"#,
            b64
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        assert!(
            !candidates.is_empty(),
            "Should find candidate from base64 blob with subprocessor data"
        );
    }

    #[test]
    fn test_probe_js_object_assignments_high_score_with_name() {
        let json_obj = serde_json::json!({
            "subprocessors": [
                {"name": "AWS Infrastructure", "url": "https://aws.amazon.com", "purpose": "Cloud infrastructure hosting services"},
                {"name": "Cloudflare CDN", "url": "https://cloudflare.com", "purpose": "Content delivery network"},
                {"name": "Datadog Monitoring", "url": "https://datadoghq.com", "purpose": "Application monitoring"},
                {"name": "Stripe Payments", "url": "https://stripe.com", "purpose": "Payment processing"},
                {"name": "Okta Identity", "url": "https://okta.com", "purpose": "Identity management"}
            ]
        });
        let json_str = serde_json::to_string(&json_obj).unwrap();
        let html = format!(
            r#"<html><body><script>window.VENDOR_REPORT = {};</script></body></html>"#,
            json_str
        );
        let mut candidates = Vec::new();
        probe_js_object_assignments(&html, &mut candidates);
        assert!(
            !candidates.is_empty(),
            "Should find candidate from JS object assignment with subprocessor data"
        );
    }

    #[test]
    fn test_probe_json_script_tags_valid_json_with_candidates() {
        let html = r#"<html><body>
            <script type="application/json">
            {"subprocessors":[
                {"name":"AWS","url":"https://aws.amazon.com","purpose":"Cloud infrastructure"},
                {"name":"Cloudflare","url":"https://cloudflare.com","purpose":"CDN and security"},
                {"name":"Datadog","url":"https://datadoghq.com","purpose":"Monitoring services"},
                {"name":"Stripe","url":"https://stripe.com","purpose":"Payment processing"},
                {"name":"Google Analytics","url":"https://google.com","purpose":"Analytics"}
            ]}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_json_script_tags(html, &mut candidates);
        assert!(
            !candidates.is_empty(),
            "Should find candidates from JSON script tags"
        );
    }

    #[test]
    fn test_is_likely_spa_no_body_tag() {
        let html = "<html><head><title>Test</title></head></html>";
        assert!(!is_likely_spa(html));
    }

    #[test]
    fn test_probe_json_script_tags_low_score_array() {
        let html = r#"<html><body>
            <script type="application/json">
            {"data":[
                {"id":1,"value":"aaa","extra":"bbb","field":"ccc","other":"ddd"},
                {"id":2,"value":"eee","extra":"fff","field":"ggg","other":"hhh"},
                {"id":3,"value":"iii","extra":"jjj","field":"kkk","other":"lll"},
                {"id":4,"value":"mmm","extra":"nnn","field":"ooo","other":"ppp"},
                {"id":5,"value":"qqq","extra":"rrr","field":"sss","other":"ttt"}
            ]}
            </script>
        </body></html>"#;
        let mut candidates = Vec::new();
        probe_json_script_tags(html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "Low-score array without name/url/purpose fields should be skipped"
        );
    }

    #[test]
    fn test_probe_base64_blobs_low_score_array() {
        use base64::Engine;
        let json = serde_json::json!({
            "data": [
                {"id": 1, "value": "aaa", "extra": "bbb"},
                {"id": 2, "value": "ccc", "extra": "ddd"},
                {"id": 3, "value": "eee", "extra": "fff"},
                {"id": 4, "value": "ggg", "extra": "hhh"},
                {"id": 5, "value": "iii", "extra": "jjj"}
            ]
        });
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.to_string().as_bytes());
        let html = format!(
            r#"<html><body><script>var x = atob("{}");</script></body></html>"#,
            b64
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "Low-score base64 array should be skipped"
        );
    }

    #[test]
    fn test_probe_base64_blobs_high_score_no_name_field() {
        use base64::Engine;
        let json = serde_json::json!({
            "subprocessors": [
                {"id": 1, "category": "infra", "status": "active", "region": "us-east", "tier": "premium"},
                {"id": 2, "category": "security", "status": "active", "region": "eu-west", "tier": "standard"},
                {"id": 3, "category": "monitoring", "status": "active", "region": "ap-south", "tier": "premium"},
                {"id": 4, "category": "network", "status": "active", "region": "us-west", "tier": "standard"},
                {"id": 5, "category": "database", "status": "active", "region": "eu-central", "tier": "premium"}
            ]
        });
        let b64 = base64::engine::general_purpose::STANDARD.encode(json.to_string().as_bytes());
        let html = format!(
            r#"<html><body><script>var x = atob("{}");</script></body></html>"#,
            b64
        );
        let mut candidates = Vec::new();
        probe_base64_blobs(&html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "High-score but no name field should be skipped"
        );
    }

    #[test]
    fn test_probe_js_object_assignments_high_score_no_name_field() {
        let json_obj = serde_json::json!({
            "subprocessors": [
                {"id": 1, "category": "infra", "status": "active", "region": "us-east", "tier": "premium", "code": "AAA"},
                {"id": 2, "category": "security", "status": "active", "region": "eu-west", "tier": "standard", "code": "BBB"},
                {"id": 3, "category": "monitoring", "status": "active", "region": "ap-south", "tier": "premium", "code": "CCC"},
                {"id": 4, "category": "network", "status": "active", "region": "us-west", "tier": "standard", "code": "DDD"},
                {"id": 5, "category": "database", "status": "active", "region": "eu-central", "tier": "premium", "code": "EEE"}
            ]
        });
        let json_str = serde_json::to_string(&json_obj).unwrap();
        let html = format!(
            r#"<html><body><script>window.VENDOR_REPORT = {};</script></body></html>"#,
            json_str
        );
        let mut candidates = Vec::new();
        probe_js_object_assignments(&html, &mut candidates);
        assert!(
            candidates.is_empty(),
            "High-score but no name field should be skipped"
        );
    }

    // --- P2.1: capture-retry gating ---

    fn resp(body: &str) -> InterceptedResponse {
        InterceptedResponse {
            url: "https://trust.example.com/api/report".to_string(),
            body: body.to_string(),
        }
    }

    #[test]
    fn clean_empty_capture_does_not_earn_a_second_render() {
        // The whole point of P2.1: a capture that ran fine and simply found no subprocessor array
        // is a legitimate negative, not a race. This is the common case (marketing sites
        // catch-all-200 every candidate path) and it must cost exactly one render.
        assert!(!should_retry_capture(false, 12, false, false));
    }

    #[test]
    fn racy_captures_still_earn_a_second_render() {
        // A transport error produced no evidence at all.
        assert!(should_retry_capture(true, 0, false, false));
        // Zero captured responses from a page we rendered: nothing was observed, so nothing was
        // ruled out.
        assert!(should_retry_capture(false, 0, false, false));
        // A body read mid-stream is exactly the race the retry was written for.
        assert!(should_retry_capture(false, 7, false, true));
    }

    #[test]
    fn a_captured_subprocessor_array_ends_the_capture_however_it_arrived() {
        // Success outranks every racy signal — re-rendering could only lose ground.
        assert!(!should_retry_capture(false, 3, true, false));
        assert!(!should_retry_capture(true, 0, true, false));
        assert!(!should_retry_capture(false, 3, true, true));
        assert!(!should_retry_capture(false, 0, true, false));
    }

    #[test]
    fn truncation_is_distinguished_from_a_complete_non_json_body() {
        // Starts like JSON, does not parse → read mid-stream.
        assert!(body_is_truncated_json(r#"{"data":{"subprocessors":[{"na"#));
        assert!(body_is_truncated_json("  [ {\"name\": \"Acme\""));
        // Complete JSON.
        assert!(!body_is_truncated_json(r#"{"data":{"subprocessors":[]}}"#));
        assert!(!body_is_truncated_json("[]"));
        // A catch-all-200 HTML shell served from an `/api/` path parses as neither, but it is
        // *complete* — treating it as truncated would resurrect the render P2.1 removed.
        assert!(!body_is_truncated_json("<!DOCTYPE html><html></html>"));
        assert!(!body_is_truncated_json("Not Found"));
        assert!(!body_is_truncated_json(""));
    }

    #[test]
    fn responses_look_truncated_flags_any_partial_body() {
        assert!(!responses_look_truncated(&[]));
        assert!(!responses_look_truncated(&[
            resp(r#"{"ok":true}"#),
            resp("<html></html>")
        ]));
        assert!(responses_look_truncated(&[
            resp(r#"{"ok":true}"#),
            resp(r#"{"items":[{"name":"Ac"#)
        ]));
    }

    #[test]
    fn retry_is_preferred_only_when_it_is_actually_worth_more() {
        // More responses wins.
        assert!(prefer_retry_capture(2, true, 5, false));
        // Fewer responses loses, even holding a DOM.
        assert!(!prefer_retry_capture(5, false, 2, true));
        // Tie broken by the DOM, which is what lets the caller skip its own render.
        assert!(prefer_retry_capture(3, false, 3, true));
        assert!(!prefer_retry_capture(3, true, 3, false));
        assert!(!prefer_retry_capture(3, true, 3, true));
        assert!(!prefer_retry_capture(0, false, 0, false));
    }

    // --- P2.3: capture-window predicates ---

    #[test]
    fn analytics_beacons_are_not_captured_as_page_json() {
        // Each of these used to be collected purely because its URL contains `/api/`, and each
        // reset the stagnation counter that decided when to stop waiting.
        assert!(!is_capturable_json(
            "application/json",
            "https://api.segment.io/v1/t",
            200
        ));
        assert!(!is_capturable_json(
            "application/json",
            "https://www.google-analytics.com/collect?v=2",
            200
        ));
        assert!(!is_capturable_json(
            "application/json",
            "https://app.posthog.com/api/e/",
            200
        ));
        assert!(!is_capturable_json(
            "application/json",
            "https://cdn.cookielaw.org/consent/abc/en.json",
            200
        ));
        // Case-insensitively, since CDP reports the URL as the page wrote it.
        assert!(!is_capturable_json(
            "application/json",
            "https://API.SEGMENT.IO/v1/t",
            200
        ));
    }

    #[test]
    fn real_trust_center_traffic_is_still_captured() {
        assert!(is_capturable_json(
            "application/json",
            "https://trust.example.com/graphql",
            200
        ));
        assert!(is_capturable_json(
            "application/json; charset=utf-8",
            "https://trust.example.com/v1/report",
            200
        ));
        // Kept deliberately: real trust-center APIs do serve JSON under a wrong Content-Type.
        assert!(is_capturable_json(
            "text/plain",
            "https://trust.example.com/api/subprocessors",
            200
        ));
        // Non-2xx is not page data.
        assert!(!is_capturable_json(
            "application/json",
            "https://trust.example.com/graphql",
            500
        ));
        assert!(!is_capturable_json(
            "application/json",
            "https://trust.example.com/graphql",
            302
        ));
        // Neither a JSON mime nor a JSON-ish path.
        assert!(!is_capturable_json(
            "text/html",
            "https://trust.example.com/subprocessors",
            200
        ));
    }

    #[test]
    fn capture_never_outlives_the_pre_p23_worst_case() {
        // The hard cap outranks everything, including work still in flight.
        assert!(should_exit_trust_center_capture(
            TRUST_CENTER_CAPTURE_HARD_CAP,
            false,
            true,
            Duration::ZERO,
            None,
        ));
        assert!(should_exit_trust_center_capture(
            TRUST_CENTER_CAPTURE_HARD_CAP,
            false,
            true,
            Duration::ZERO,
            Some(Duration::ZERO),
        ));
        assert!(!should_exit_trust_center_capture(
            TRUST_CENTER_CAPTURE_HARD_CAP - Duration::from_millis(1),
            false,
            true,
            Duration::ZERO,
            None,
        ));
    }

    #[test]
    fn the_response_ceiling_stops_the_capture_immediately() {
        // More waiting cannot collect more, so this outranks the minimum wait.
        assert!(should_exit_trust_center_capture(
            Duration::from_millis(10),
            true,
            true,
            Duration::ZERO,
            None,
        ));
    }

    #[test]
    fn a_page_with_no_json_traffic_exits_far_below_the_old_eight_second_floor() {
        // The regression this item exists to kill: 2s fixed settle + six 1s stagnant rounds.
        let old_floor = Duration::from_millis(8_000);
        let exit_at = TRUST_CENTER_CAPTURE_MIN_WAIT + TRUST_CENTER_CAPTURE_IDLE_WINDOW;
        assert!(
            exit_at < old_floor,
            "adaptive exit {exit_at:?} must beat the old {old_floor:?} floor"
        );
        assert!(should_exit_trust_center_capture(
            exit_at,
            false,
            false,
            TRUST_CENTER_CAPTURE_IDLE_WINDOW,
            None,
        ));
    }

    #[test]
    fn idle_exit_respects_the_minimum_wait_and_the_idle_boundary() {
        // Below the floor an SPA has not necessarily issued its first request yet, so a quiet
        // network proves nothing.
        assert!(!should_exit_trust_center_capture(
            TRUST_CENTER_CAPTURE_MIN_WAIT - Duration::from_millis(1),
            false,
            false,
            Duration::from_millis(9_999),
            None,
        ));
        // One millisecond either side of the idle window.
        assert!(!should_exit_trust_center_capture(
            Duration::from_millis(3_000),
            false,
            false,
            TRUST_CENTER_CAPTURE_IDLE_WINDOW - Duration::from_millis(1),
            None,
        ));
        assert!(should_exit_trust_center_capture(
            Duration::from_millis(3_000),
            false,
            false,
            TRUST_CENTER_CAPTURE_IDLE_WINDOW,
            None,
        ));
    }

    #[test]
    fn work_in_flight_holds_the_capture_open_until_total_silence() {
        // Nothing is idle while a request — or a body read — is still outstanding.
        assert!(!should_exit_trust_center_capture(
            Duration::from_millis(3_000),
            false,
            true,
            TRUST_CENTER_CAPTURE_IDLE_WINDOW,
            None,
        ));
        assert!(!should_exit_trust_center_capture(
            Duration::from_millis(6_000),
            false,
            true,
            TRUST_CENTER_CAPTURE_STALL_WINDOW - Duration::from_millis(1),
            None,
        ));
        // …unless the counter was stranded by a redirect chain or WebSocket and the page has gone
        // completely silent, which the stall window exists to escape.
        assert!(should_exit_trust_center_capture(
            Duration::from_millis(6_000),
            false,
            true,
            TRUST_CENTER_CAPTURE_STALL_WINDOW,
            None,
        ));
    }

    #[test]
    fn pagination_grace_survives_a_quiet_network() {
        // A paginated trust center goes silent between page fetches. Exiting on that silence is
        // how pages 2..n get lost, so once the array is seen the idle rule is deliberately mute.
        assert!(!should_exit_trust_center_capture(
            Duration::from_millis(5_000),
            false,
            false,
            Duration::from_millis(4_000),
            Some(SUBPROCESSOR_PAGINATION_GRACE - Duration::from_millis(1)),
        ));
        assert!(should_exit_trust_center_capture(
            Duration::from_millis(5_000),
            false,
            false,
            Duration::ZERO,
            Some(SUBPROCESSOR_PAGINATION_GRACE),
        ));
        // And the grace is not cut short by traffic still in flight either.
        assert!(should_exit_trust_center_capture(
            Duration::from_millis(5_000),
            false,
            true,
            Duration::ZERO,
            Some(SUBPROCESSOR_PAGINATION_GRACE + Duration::from_millis(500)),
        ));
    }
}
