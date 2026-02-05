# HTTP/2 Production-Ready Configuration

This document outlines the HTTP/2 capabilities and production-ready features of the WAF scanner.

## HTTP/2 Support Overview

The scanner is now fully equipped with production-ready HTTP/2 support, including:

### ✅ Core HTTP/2 Features

1. **HTTP/2 Prior Knowledge**: Automatically uses HTTP/2 without protocol upgrade
2. **Adaptive Flow Control**: Dynamic window size adjustment for optimal performance
3. **Configurable Stream Windows**: 2MB initial stream window, 4MB connection window
4. **Frame Size Optimization**: 16KB maximum frame size for efficient data transfer
5. **Keep-Alive Management**: 20-second intervals with 10-second timeout
6. **HTTP Version Detection**: Automatic protocol version logging and detection

### 🔒 Security Test Categories

The scanner includes production-ready tests for critical HTTP/2 vulnerabilities:

#### Critical Vulnerabilities
- **CVE-2023-44487 (Rapid Reset)**: Tests for DoS via rapid RST_STREAM frames
- **CVE-2024-27983 (CONTINUATION Flood)**: Detects excessive CONTINUATION frame vulnerabilities
- **HPACK Compression Bomb**: Tests header compression memory exhaustion
- **Flow Control Bypass**: WINDOW_UPDATE integer overflow detection

#### High Severity Tests
- **Request Smuggling**: Protocol upgrade manipulation and connection header confusion
- **Pseudo-Header Injection**: Validation of :method, :path, :authority, :scheme headers
- **SETTINGS Frame Flood**: Rate-limiting checks for SETTINGS frames
- **PRIORITY Frame Flood**: CPU exhaustion via stream reprioritization

#### Medium Severity Tests
- **IIS Header Manipulation**: Method override (X-HTTP-Method-Override, X-Original-URL)
- **Stream Dependency Issues**: Priority tree manipulation tests

## Production Configuration

### Client Configuration

```rust
// Automatic configuration applied
ClientBuilder::new()
    .http2_prior_knowledge()                                    // Force HTTP/2
    .http2_adaptive_window(true)                                // Dynamic flow control
    .http2_initial_stream_window_size(Some(2 * 1024 * 1024))  // 2MB
    .http2_initial_connection_window_size(Some(4 * 1024 * 1024)) // 4MB
    .http2_max_frame_size(Some(16384))                         // 16KB
    .http2_keep_alive_interval(Some(Duration::from_secs(20)))  // Keep-alive
    .http2_keep_alive_timeout(Duration::from_secs(10))         // Timeout
    .http2_keep_alive_while_idle(true)                         // Idle keep-alive
```

### Performance Characteristics

- **Stream Multiplexing**: Concurrent request handling over single connection
- **Header Compression**: HPACK reduces overhead by ~40-60%
- **Server Push**: Compatible with HTTP/2 push promises
- **Flow Control**: Prevents buffer overflow and DoS conditions
- **Connection Reuse**: Reduces TLS handshake overhead

## Usage Examples

### Basic HTTP/2 Scan

```bash
# Scan target with HTTP/2 payloads
cargo run --release -- -t https://example.com -f payloads/http2-adfs-bypass.json

# Enable verbose logging to see HTTP version
RUST_LOG=info cargo run -- -t https://example.com -f payloads/http2-adfs-bypass.json
```

### Production Scanning

```bash
# Full scan with concurrency and delay
cargo run --release -- \
  -t https://production.example.com \
  -f payloads/http2-adfs-bypass.json \
  -c 10 \
  -d 100 \
  -o results.json

# Specific OWASP category testing
cargo run --release -- \
  -t https://example.com \
  -f payloads/http2-adfs-bypass.json \
  --filter-category http2-bypass
```

## Vulnerability Coverage

### OWASP Top 10:2025 Mapping

| Vulnerability | OWASP Category | Severity |
|---------------|----------------|----------|
| HTTP/2 Rapid Reset (CVE-2023-44487) | A02 - Security Misconfiguration | Critical |
| CONTINUATION Flood (CVE-2024-27983) | A02 - Security Misconfiguration | Critical |
| Request Smuggling | A01 - Broken Access Control | High |
| HPACK Compression Bomb | A02 - Security Misconfiguration | High |
| Pseudo-Header Injection | A05 - Injection | Medium |
| Header Manipulation | A02 - Security Misconfiguration | Medium |

### AD FS Specific Tests

The scanner includes 6+ AD FS-specific HTTP/2 tests:
- Authentication bypass (CVE-2025-21193)
- Token replay (CVE-2023-35348)
- Extranet lockout bypass (CVE-2019-1126)
- SSRF via txtBoxEmail (CVE-2018-16794)
- MFA bypass (CVE-2018-8340)

## Monitoring and Logging

### HTTP Version Detection

The scanner automatically logs HTTP protocol version:

```
[INFO] Target https://example.com is using HTTP version: HTTP/2
[INFO] ✓ HTTP/2 protocol detected - production-ready configuration active
```

### Finding Metadata

Each finding includes HTTP version information:

```json
{
  "payload_id": "http2-rapid-reset-cve-2023-44487",
  "severity": "critical",
  "http_version": "HTTP/2",
  "response_status": 200,
  "description": "Tests for HTTP/2 Rapid Reset vulnerability..."
}
```

## Best Practices

### Production Deployment

1. **Rate Limiting**: Use `-d` flag to add delays (100-500ms recommended)
2. **Concurrency**: Limit concurrent requests (`-c 5-10` for production)
3. **Monitoring**: Enable INFO logging to track HTTP version usage
4. **Filtering**: Test specific categories to reduce noise
5. **Output**: Always save results to JSON for analysis (`-o results.json`)

### Performance Tuning

```bash
# Low-impact scanning
cargo run --release -- -t https://example.com -c 5 -d 200

# High-throughput testing (non-production only)
cargo run --release -- -t https://test.example.com -c 50 -d 0

# Targeted testing
cargo run --release -- -t https://example.com \
  -f payloads/http2-adfs-bypass.json \
  --filter-severity critical
```

## Compliance and Standards

- **RFC 7540**: HTTP/2 Protocol Specification
- **RFC 7541**: HPACK Header Compression
- **OWASP Top 10:2025**: Security vulnerability mapping
- **CVE Database**: Real-world vulnerability coverage
- **CISA Alerts**: Includes critical infrastructure vulnerabilities

## Troubleshooting

### HTTP/1.1 Fallback

If target doesn't support HTTP/2:
```
[WARN] ⚠ HTTP/1.x detected - some HTTP/2 tests may not apply
```

The scanner will continue but HTTP/2-specific tests may not be effective.

### Connection Issues

```bash
# Increase timeout for slow servers
cargo run -- -t https://example.com --timeout 60

# Debug connection issues
RUST_LOG=debug cargo run -- -t https://example.com
```

### TLS/SSL Issues

```bash
# Scanner automatically accepts invalid certificates for testing
# This is intentional for security testing environments
RUST_LOG=warn cargo run -- -t https://self-signed.example.com
```

## Security Considerations

⚠️ **Warning**: This tool is for authorized security testing only.

- Always obtain proper authorization before scanning
- Production systems should use rate limiting (`-d` flag)
- Monitor target systems for impact during testing
- Review findings with security team before disclosure
- Follow responsible disclosure practices

## References

- [RFC 7540 - HTTP/2 Specification](https://tools.ietf.org/html/rfc7540)
- [OWASP Top 10:2025](https://owasp.org/Top10/2025/)
- [CVE-2023-44487 (Rapid Reset)](https://nvd.nist.gov/vuln/detail/CVE-2023-44487)
- [CVE-2024-27983 (CONTINUATION Flood)](https://nvd.nist.gov/vuln/detail/CVE-2024-27983)
- [CISA HTTP/2 Alert](https://www.cisa.gov/news-events/alerts/2023/10/10/http2-rapid-reset-vulnerability-cve-2023-44487)

## Support

For issues or questions:
- GitHub Issues: [Report bugs and feature requests]
- Security Vulnerabilities: [Responsible disclosure process]
- Documentation: [Additional guides and examples]
