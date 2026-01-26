use wiremock::matchers::{method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};
use std::time::Duration;

/// Creates a mock DNS-over-HTTPS server that responds with TXT records for a given domain.
///
/// The server responds to GET requests at `/dns-query` with the `name` query parameter
/// matching the provided domain. Returns a JSON response in the DNS-over-HTTPS format.
pub async fn mock_doh_server(domain: &str, txt_records: Vec<&str>) -> MockServer {
    let server = MockServer::start().await;

    // Build the DNS-over-HTTPS JSON response format
    let answers: Vec<serde_json::Value> = txt_records
        .iter()
        .map(|txt| {
            serde_json::json!({
                "name": domain,
                "type": 16,  // TXT record type
                "TTL": 300,
                "data": format!("\"{}\"", txt)
            })
        })
        .collect();

    let response_body = serde_json::json!({
        "Status": 0,
        "TC": false,
        "RD": true,
        "RA": true,
        "AD": false,
        "CD": false,
        "Question": [{
            "name": domain,
            "type": 16
        }],
        "Answer": answers
    });

    Mock::given(method("GET"))
        .and(path("/dns-query"))
        .and(query_param("name", domain))
        .and(query_param("type", "TXT"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(response_body)
                .insert_header("content-type", "application/dns-json"),
        )
        .mount(&server)
        .await;

    server
}

/// Creates a mock HTTP server that serves HTML content at the specified path.
///
/// Useful for testing subprocessor page fetching and parsing.
pub async fn mock_subprocessor_page(url_path: &str, html: &str) -> MockServer {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path(url_path))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string(html.to_string())
                .insert_header("content-type", "text/html; charset=utf-8"),
        )
        .mount(&server)
        .await;

    server
}

/// Creates a mock HTTP server that delays responses to simulate network timeouts.
///
/// The server will wait for `delay_ms` milliseconds before responding with a 200 OK.
pub async fn mock_timeout_server(delay_ms: u64) -> MockServer {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_string("delayed response")
                .set_delay(Duration::from_millis(delay_ms)),
        )
        .mount(&server)
        .await;

    server
}

/// Creates a mock HTTP server that returns the specified HTTP error status code.
///
/// Useful for testing error handling for 4xx and 5xx responses.
pub async fn mock_error_server(status_code: u16) -> MockServer {
    let server = MockServer::start().await;

    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(status_code))
        .mount(&server)
        .await;

    server
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_doh_server_returns_txt_records() {
        let server = mock_doh_server("example.com", vec!["v=spf1 include:_spf.google.com ~all"]).await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/dns-query?name=example.com&type=TXT", server.uri()))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let body: serde_json::Value = response.json().await.unwrap();
        assert_eq!(body["Status"], 0);
        assert!(body["Answer"].as_array().unwrap().len() > 0);
    }

    #[tokio::test]
    async fn test_mock_subprocessor_page_serves_html() {
        let html = "<html><body><h1>Subprocessors</h1></body></html>";
        let server = mock_subprocessor_page("/subprocessors", html).await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/subprocessors", server.uri()))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 200);
        let body = response.text().await.unwrap();
        assert!(body.contains("Subprocessors"));
    }

    #[tokio::test]
    async fn test_mock_error_server_returns_status_code() {
        let server = mock_error_server(503).await;

        let client = reqwest::Client::new();
        let response = client
            .get(format!("{}/any-path", server.uri()))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), 503);
    }
}
