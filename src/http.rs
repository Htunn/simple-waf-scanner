use crate::config::Config;
use reqwest::{Client, ClientBuilder};
use std::time::Duration;

/// Build an HTTP client for scanning
pub fn build_client(config: &Config) -> crate::error::Result<Client> {
    let client = ClientBuilder::new()
        // Allow invalid certificates for testing environments
        .danger_accept_invalid_certs(true)
        // Follow redirects with a limit
        .redirect(reqwest::redirect::Policy::limited(10))
        // Set timeouts
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        // Set custom user agent
        .user_agent(&config.user_agent)
        // Enable cookie handling
        .cookie_store(true)
        // Connection pool settings
        .pool_max_idle_per_host(config.concurrency)
        .pool_idle_timeout(Duration::from_secs(90))
        // Enable gzip compression
        .gzip(true)
        .build()?;

    Ok(client)
}

/// Make a GET request and return response details
pub async fn send_request(
    client: &Client,
    url: &str,
    query_param: Option<(&str, &str)>,
) -> crate::error::Result<HttpResponse> {
    let mut request = client.get(url);

    if let Some((key, value)) = query_param {
        request = request.query(&[(key, value)]);
    }

    let start = std::time::Instant::now();
    let response = request.send().await?;
    let duration = start.elapsed();

    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();

    // Extract cookies
    let cookies: Vec<String> = response.cookies().map(|c| c.name().to_string()).collect();

    let body = response.text().await.unwrap_or_default();

    Ok(HttpResponse {
        status_code: status,
        headers,
        body,
        cookies,
        response_time_ms: duration.as_millis() as u64,
    })
}

/// HTTP response data
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status_code: u16,
    pub headers: std::collections::HashMap<String, String>,
    pub body: String,
    pub cookies: Vec<String>,
    pub response_time_ms: u64,
}
