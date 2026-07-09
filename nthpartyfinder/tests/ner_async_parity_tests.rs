//! Proves the async NER offload did not change what NER extracts.
//!
//! The org-resolution and subprocessor-fallback paths moved GLiNER inference off the async
//! runtime's worker threads and onto the blocking pool, bounded by a permit. That is a
//! *scheduling* change: same model, same inputs, same session configuration. These tests
//! assert that observable claim directly — the async result must equal the sync result,
//! including when many inferences run concurrently under the permit.
//!
//! Thread count and batching were deliberately NOT changed: both alter float reduction
//! order and could flip an argmax at a near-tie, which would be an accuracy change rather
//! than a performance one. If either is ever adopted, these tests are where the resulting
//! output drift would show up first.

#![cfg(any(feature = "embedded-ner", feature = "runtime-ner"))]

use nthpartyfinder::ner_org::{self, NerOrgResult};

/// Text lengths chosen to span the extractor's internal boundaries: below the 4000-char
/// truncation, straddling it, and short enough to be a single span. Variable lengths are
/// deliberate — uniform inputs cannot reveal a length-dependent bug.
fn corpus() -> Vec<(&'static str, String)> {
    let long_prose = format!(
        "Stripe, Inc. provides payment infrastructure. {} Cloudflare, Inc. operates a global network.",
        "Filler sentence establishing document length. ".repeat(120)
    );
    vec![
        ("short", "Stripe, Inc. is a payments company.".to_string()),
        ("single-token-org", "Datadog".to_string()),
        (
            "multi-org",
            "Microsoft Corporation and Google LLC announced a partnership with Amazon Web Services."
                .to_string(),
        ),
        (
            "no-org",
            "The quick brown fox jumps over the lazy dog.".to_string(),
        ),
        ("empty", String::new()),
        ("over-truncation-boundary", long_prose),
    ]
}

/// NER needs both the ONNX runtime dylib and the model on disk. Neither is present on a
/// bare CI runner, so a missing model is a skip, not a failure — matching the convention
/// the other NER test modules use.
fn ner_ready() -> bool {
    let init = std::panic::catch_unwind(|| ner_org::init_with_config(0.6));
    match init {
        Ok(Ok(())) => true,
        // A second init in the same process is expected: OnceLock is already set.
        Ok(Err(e)) => e.to_string().contains("already initialized"),
        Err(_) => false,
    }
}

fn same(a: &Option<NerOrgResult>, b: &Option<NerOrgResult>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => {
            x.organization == y.organization && x.confidence.to_bits() == y.confidence.to_bits()
        }
        _ => false,
    }
}

fn same_all(a: &[NerOrgResult], b: &[NerOrgResult]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(x, y)| {
            x.organization == y.organization && x.confidence.to_bits() == y.confidence.to_bits()
        })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_extract_organization_matches_sync_bit_for_bit() {
    if !ner_ready() {
        eprintln!("skipping: NER model/runtime unavailable");
        return;
    }

    for (label, text) in corpus() {
        let sync = ner_org::extract_organization("example.com", Some(&text))
            .unwrap_or_else(|e| panic!("[{label}] sync extraction errored: {e}"));
        let asynchronous = ner_org::extract_organization_async("example.com", Some(&text))
            .await
            .unwrap_or_else(|e| panic!("[{label}] async extraction errored: {e}"));

        assert!(
            same(&sync, &asynchronous),
            "[{label}] async NER output diverged from sync: sync={sync:?} async={asynchronous:?}"
        );
    }
}

/// Parity is asserted on the whole `Result`, not just on success values.
///
/// This matters for one input: GLiNER's ONNX graph cannot reshape a zero-length sequence,
/// so `extract_all_organizations("")` returns an error. That is pre-existing behavior of the
/// model, unchanged by the offload, and unreachable in production — the only caller gates on
/// `text_content.len() >= 100` (`subprocessor.rs`). The async wrapper must reproduce it
/// exactly rather than paper over it, so the empty case stays in the corpus and the
/// assertion is "both succeed with equal output, or both fail".
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn async_extract_all_organizations_matches_sync_bit_for_bit() {
    if !ner_ready() {
        eprintln!("skipping: NER model/runtime unavailable");
        return;
    }

    for (label, text) in corpus() {
        let sync = ner_org::extract_all_organizations(&text, Some(0.5));
        let asynchronous = ner_org::extract_all_organizations_async(&text, Some(0.5)).await;

        match (&sync, &asynchronous) {
            (Ok(s), Ok(a)) => assert!(
                same_all(s, a),
                "[{label}] async extract_all diverged from sync: sync={s:?} async={a:?}"
            ),
            (Err(_), Err(_)) => { /* both reject the input identically — the parity claim */ }
            _ => panic!(
                "[{label}] sync and async extract_all disagreed on success: \
                 sync_ok={} async_ok={}",
                sync.is_ok(),
                asynchronous.is_ok()
            ),
        }
    }
}

/// The offload exists so that several vendor pipelines can reach NER at once. Running the
/// same inputs concurrently must produce the same answers as running them one at a time:
/// the extractor is shared `&'static` state, and a concurrency bug there would surface as
/// answers that depend on interleaving.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_inferences_agree_with_sequential_results() {
    if !ner_ready() {
        eprintln!("skipping: NER model/runtime unavailable");
        return;
    }

    let corpus = corpus();
    let sequential: Vec<_> = corpus
        .iter()
        .map(|(label, text)| {
            (
                *label,
                ner_org::extract_organization("example.com", Some(text))
                    .unwrap_or_else(|e| panic!("[{label}] sequential extraction errored: {e}")),
            )
        })
        .collect();

    // Four concurrent waves over the corpus: more in-flight inferences than the permit
    // count, so the semaphore's queueing path is exercised rather than bypassed.
    let mut handles = Vec::new();
    for _wave in 0..4 {
        for (label, text) in corpus.clone() {
            handles.push(tokio::spawn(async move {
                let got = ner_org::extract_organization_async("example.com", Some(&text))
                    .await
                    .unwrap_or_else(|e| panic!("[{label}] concurrent extraction errored: {e}"));
                (label, got)
            }));
        }
    }

    for handle in handles {
        let (label, got) = handle.await.expect("concurrent NER task panicked");
        let expected = &sequential
            .iter()
            .find(|(l, _)| *l == label)
            .expect("label present in sequential results")
            .1;
        assert!(
            same(expected, &got),
            "[{label}] concurrent NER output diverged from sequential: expected={expected:?} got={got:?}"
        );
    }
}
