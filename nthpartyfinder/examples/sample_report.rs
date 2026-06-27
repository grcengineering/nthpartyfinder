//! Dev-only: render a sample HTML report with realistic data for visual QA of the
//! GRC Engineering design-system reskin. Not part of the shipped product.
//!
//!   cargo run --example sample_report -- /tmp/sample-report.html

use nthpartyfinder::export::export_html;
use nthpartyfinder::vendor::{RecordType, VendorRelationship};

// Dev-only fixture builder; mirrors VendorRelationship::new's arity.
#[allow(clippy::too_many_arguments)]
fn rel(
    domain: &str,
    org: &str,
    layer: u32,
    cust_domain: &str,
    cust_org: &str,
    record: &str,
    rt: RecordType,
    evidence: &str,
) -> VendorRelationship {
    VendorRelationship::new(
        domain.to_string(),
        org.to_string(),
        layer,
        cust_domain.to_string(),
        cust_org.to_string(),
        record.to_string(),
        rt,
        "vanta.com".to_string(),
        "Vanta Inc".to_string(),
        evidence.to_string(),
    )
}

fn main() {
    let out = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/sample-report.html".to_string());

    let rels = vec![
        rel(
            "google.com",
            "Google LLC",
            1,
            "vanta.com",
            "Vanta Inc",
            "v=spf1 include:_spf.google.com ~all",
            RecordType::DnsTxtSpf,
            "TXT record on vanta.com: v=spf1 include:_spf.google.com ~all",
        ),
        rel(
            "sendgrid.net",
            "Twilio SendGrid",
            1,
            "vanta.com",
            "Vanta Inc",
            "v=spf1 include:sendgrid.net ~all",
            RecordType::DnsTxtVerification,
            "TXT verification token sendgrid",
        ),
        rel(
            "_dmarc.vanta.com",
            "DMARC Policy",
            1,
            "vanta.com",
            "Vanta Inc",
            "v=DMARC1; p=reject; rua=mailto:dmarc@vanta.com",
            RecordType::DnsTxtDmarc,
            "DMARC policy record",
        ),
        rel(
            "aws.amazon.com",
            "Amazon Web Services",
            2,
            "google.com",
            "Google LLC",
            "CNAME -> aws.amazon.com",
            RecordType::DnsSubdomain,
            "Subdomain CNAME to AWS",
        ),
        rel(
            "stripe.com",
            "Stripe Inc",
            2,
            "vanta.com",
            "Vanta Inc",
            "https://vanta.com/legal/subprocessors",
            RecordType::HttpSubprocessor,
            "Listed on subprocessor page row 4",
        ),
        rel(
            "intercom.io",
            "Intercom",
            2,
            "vanta.com",
            "Vanta Inc",
            "subprocessor: Intercom (support chat)",
            RecordType::HttpSubprocessor,
            "Subprocessor table entry",
        ),
        rel(
            "segment.com",
            "Twilio Segment",
            3,
            "stripe.com",
            "Stripe Inc",
            "analytics.segment.com beacon",
            RecordType::WebTrafficNetwork,
            "Network request to segment in checkout",
        ),
        rel(
            "datadoghq.com",
            "Datadog",
            3,
            "aws.amazon.com",
            "Amazon Web Services",
            "subfinder: app.datadoghq.com",
            RecordType::SubfinderDiscovery,
            "Subdomain enumeration",
        ),
        rel(
            "okta.com",
            "Okta Inc",
            3,
            "stripe.com",
            "Stripe Inc",
            "vanta.okta.com tenant",
            RecordType::SaasTenantProbe,
            "SaaS tenant probe succeeded",
        ),
        rel(
            "cloudflare.com",
            "Cloudflare Inc",
            4,
            "datadoghq.com",
            "Datadog",
            "cdnjs.cloudflare.com",
            RecordType::WebTrafficSource,
            "Script src in page source",
        ),
        rel(
            "fastly.net",
            "Fastly",
            4,
            "segment.com",
            "Twilio Segment",
            "cdn.fastly.net asset",
            RecordType::WebTrafficNetwork,
            "Asset served via Fastly",
        ),
        rel(
            "auth0.com",
            "Auth0 (Okta)",
            5,
            "okta.com",
            "Okta Inc",
            "tenant.auth0.com",
            RecordType::SaasTenantProbe,
            "Nested identity provider",
        ),
        rel(
            "akamai.com",
            "Akamai Technologies",
            5,
            "cloudflare.com",
            "Cloudflare Inc",
            "edge.akamai.com",
            RecordType::DnsSubdomain,
            "Edge CDN subdomain",
        ),
        rel(
            "twilio.com",
            "Twilio Inc",
            6,
            "auth0.com",
            "Auth0 (Okta)",
            "api.twilio.com SMS",
            RecordType::WebTrafficNetwork,
            "SMS OTP delivery network call",
        ),
    ];

    export_html(&rels, &out).expect("render sample report");
    println!("wrote {out} ({} relationships)", rels.len());
}
