use crate::config::Config;
use reqwest::{Client, ClientBuilder};
use std::time::Duration;

/// Build an HTTP client for scanning with HTTP/2 support
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
        // Allow both HTTP/1 and HTTP/2 (automatic negotiation)
        // Commented out http2_prior_knowledge to allow fallback to HTTP/1.1
        // .http2_prior_knowledge()  // Enable HTTP/2 without upgrade
        .http2_adaptive_window(true) // Adaptive flow control
        .http2_initial_stream_window_size(Some(2 * 1024 * 1024)) // 2MB stream window
        .http2_initial_connection_window_size(Some(4 * 1024 * 1024)) // 4MB connection window
        .http2_max_frame_size(Some(16384)) // 16KB max frame size
        .http2_keep_alive_interval(Some(Duration::from_secs(20))) // Keep-alive pings
        .http2_keep_alive_timeout(Duration::from_secs(10)) // Keep-alive timeout
        .http2_keep_alive_while_idle(true) // Keep-alive even when idle
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
    let http_version = format!("{:?}", response.version());
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
        http_version,
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
    pub http_version: String,
}

/// Make a POST request with custom headers and body
pub async fn send_post_request(
    client: &Client,
    url: &str,
    headers: Option<Vec<(String, String)>>,
    body: Option<String>,
) -> crate::error::Result<HttpResponse> {
    let mut request = client.post(url);

    // Add custom headers if provided
    if let Some(hdrs) = headers {
        for (key, value) in hdrs {
            request = request.header(&key, &value);
        }
    }

    // Add body if provided
    if let Some(body_content) = body {
        request = request.body(body_content);
    }

    let start = std::time::Instant::now();
    let response = request.send().await?;
    let duration = start.elapsed();

    let status = response.status().as_u16();
    let http_version = format!("{:?}", response.version());
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

    let cookies: Vec<String> = response.cookies().map(|c| c.name().to_string()).collect();
    let body = response.text().await.unwrap_or_default();

    Ok(HttpResponse {
        status_code: status,
        headers,
        body,
        cookies,
        response_time_ms: duration.as_millis() as u64,
        http_version,
    })
}

/// Make a custom method request (OPTIONS, HEAD, etc.)
pub async fn send_custom_request(
    client: &Client,
    method: &str,
    url: &str,
    headers: Option<Vec<(String, String)>>,
) -> crate::error::Result<HttpResponse> {
    let http_method =
        reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET);

    let mut request = client.request(http_method, url);

    // Add custom headers if provided
    if let Some(hdrs) = headers {
        for (key, value) in hdrs {
            request = request.header(&key, &value);
        }
    }

    let start = std::time::Instant::now();
    let response = request.send().await?;
    let duration = start.elapsed();

    let status = response.status().as_u16();
    let http_version = format!("{:?}", response.version());
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

    let cookies: Vec<String> = response.cookies().map(|c| c.name().to_string()).collect();
    let body = response.text().await.unwrap_or_default();

    Ok(HttpResponse {
        status_code: status,
        headers,
        body,
        cookies,
        response_time_ms: duration.as_millis() as u64,
        http_version,
    })
}
