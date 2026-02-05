use crate::types::{
    AdfsMetadata, AuthToken, ExtractedData, InfoDisclosure, Severity, VersionInfo,
};
use regex::Regex;
use std::collections::HashSet;
use std::sync::Arc;

/// Data extractor for analyzing HTTP responses
#[derive(Clone)]
pub struct DataExtractor {
    // Regex patterns for various sensitive data (wrapped in Arc for cheap cloning)
    stack_trace_pattern: Arc<Regex>,
    error_pattern: Arc<Regex>,
    path_pattern: Arc<Regex>,
    ip_pattern: Arc<Regex>,
    jwt_pattern: Arc<Regex>,
    api_key_pattern: Arc<Regex>,
    connection_string_pattern: Arc<Regex>,
    certificate_pattern: Arc<Regex>,
}

impl DataExtractor {
    /// Create a new data extractor with compiled regex patterns
    pub fn new() -> Self {
        Self {
            stack_trace_pattern: Arc::new(Regex::new(
                r"(?i)(stack trace|stacktrace|exception|at [a-z0-9_]+\.[a-z0-9_]+\(|\.cs:[0-9]+|\.java:[0-9]+)"
            ).unwrap()),
            error_pattern: Arc::new(Regex::new(
                r"(?i)(error|exception|warning|failed|cannot|unable to|access denied|forbidden|unauthorized)"
            ).unwrap()),
            path_pattern: Arc::new(Regex::new(
                r"(?i)(c:\\|/var/|/etc/|/usr/|/home/|\\windows\\|\\program files\\|/opt/)"
            ).unwrap()),
            ip_pattern: Arc::new(Regex::new(
                r"(?:10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.0\.0\.1)\d{1,3}\.\d{1,3}\.\d{1,3}"
            ).unwrap()),
            jwt_pattern: Arc::new(Regex::new(
                r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
            ).unwrap()),
            api_key_pattern: Arc::new(Regex::new(
                r#"(?i)(api[_-]?key|apikey|access[_-]?token|secret[_-]?key)[\s:=]+['"]?([a-z0-9_-]{20,})['"]?"#
            ).unwrap()),
            connection_string_pattern: Arc::new(Regex::new(
                r"(?i)(server|data source|initial catalog|user id|password|integrated security)=[^;]+;"
            ).unwrap()),
            certificate_pattern: Arc::new(Regex::new(
                r"-----BEGIN (CERTIFICATE|RSA PRIVATE KEY|PUBLIC KEY)-----"
            ).unwrap()),
        }
    }

    /// Extract sensitive data from an HTTP response
    pub fn extract(
        &self,
        response_body: &str,
        response_headers: &std::collections::HashMap<String, String>,
        cookies: &[String],
    ) -> ExtractedData {
        let mut data = ExtractedData::new();

        // Store response snippet
        if !response_body.is_empty() {
            data.response_snippet = Some(
                response_body
                    .chars()
                    .take(500)
                    .collect::<String>()
                    .replace("\n", " ")
                    .replace("\r", ""),
            );
        }

        // Extract information disclosure
        data.info_disclosure.extend(self.extract_info_disclosure(response_body, response_headers));

        // Extract exposed paths
        data.exposed_paths.extend(self.extract_paths(response_body));

        // Extract authentication tokens
        data.auth_tokens.extend(self.extract_auth_tokens(response_body, response_headers, cookies));

        // Extract version information
        data.version_info = self.extract_version_info(response_body, response_headers);

        // Extract internal IPs
        data.internal_ips.extend(self.extract_internal_ips(response_body));

        // Extract ADFS metadata
        if response_body.contains("adfs") || response_body.contains("federation") {
            data.adfs_metadata = self.extract_adfs_metadata(response_body);
        }

        data
    }

    /// Extract information disclosure patterns
    fn extract_info_disclosure(
        &self,
        body: &str,
        headers: &std::collections::HashMap<String, String>,
    ) -> Vec<InfoDisclosure> {
        let mut disclosures = Vec::new();

        // Check for stack traces
        if self.stack_trace_pattern.is_match(body) {
            let traces: Vec<&str> = body
                .lines()
                .filter(|line| {
                    line.contains("at ") || line.contains(".cs:") || line.contains("Exception")
                })
                .take(5)
                .collect();

            if !traces.is_empty() {
                disclosures.push(InfoDisclosure {
                    disclosure_type: "Stack Trace".to_string(),
                    value: traces.join(" | "),
                    severity: Severity::High,
                });
            }
        }

        // Check for SQL errors
        if body.contains("SQL") || body.contains("ORA-") || body.contains("MySQL") {
            for line in body.lines().take(20) {
                if line.contains("SQL") || line.contains("database") || line.contains("ORA-") {
                    disclosures.push(InfoDisclosure {
                        disclosure_type: "SQL Error".to_string(),
                        value: line.chars().take(200).collect(),
                        severity: Severity::Medium,
                    });
                    break;
                }
            }
        }

        // Check for ASP.NET errors
        if body.contains("Server Error") || body.contains("ASP.NET") {
            disclosures.push(InfoDisclosure {
                disclosure_type: "ASP.NET Error Page".to_string(),
                value: "Server Error in Application - Detailed error page exposed".to_string(),
                severity: Severity::High,
            });
        }

        // Check for debug information in headers
        if let Some(debug_header) = headers.get("x-aspnet-version") {
            disclosures.push(InfoDisclosure {
                disclosure_type: "ASP.NET Version Header".to_string(),
                value: debug_header.clone(),
                severity: Severity::Low,
            });
        }

        // Check for connection strings
        if self.connection_string_pattern.is_match(body) {
            disclosures.push(InfoDisclosure {
                disclosure_type: "Database Connection String".to_string(),
                value: "Connection string pattern detected in response".to_string(),
                severity: Severity::Critical,
            });
        }

        // Check for API keys
        if let Some(captures) = self.api_key_pattern.captures(body) {
            if let Some(key_value) = captures.get(2) {
                disclosures.push(InfoDisclosure {
                    disclosure_type: "API Key".to_string(),
                    value: format!("{}...", &key_value.as_str()[..20.min(key_value.as_str().len())]),
                    severity: Severity::Critical,
                });
            }
        }

        // Check for certificates
        if self.certificate_pattern.is_match(body) {
            disclosures.push(InfoDisclosure {
                disclosure_type: "Certificate/Private Key".to_string(),
                value: "PEM-encoded certificate or private key detected".to_string(),
                severity: Severity::Critical,
            });
        }

        disclosures
    }

    /// Extract file system paths
    fn extract_paths(&self, body: &str) -> Vec<String> {
        let mut paths = HashSet::new();

        for capture in self.path_pattern.captures_iter(body) {
            if let Some(matched) = capture.get(0) {
                // Extract the full path from the line
                let line = body
                    .lines()
                    .find(|l| l.contains(matched.as_str()))
                    .unwrap_or("");

                // Try to extract complete path
                for word in line.split_whitespace() {
                    if word.contains(matched.as_str()) {
                        paths.insert(word.trim_matches(|c: char| !c.is_alphanumeric() && c != '/' && c != '\\' && c != ':' && c != '.').to_string());
                    }
                }
            }
        }

        paths.into_iter().take(10).collect()
    }

    /// Extract authentication tokens
    fn extract_auth_tokens(
        &self,
        body: &str,
        headers: &std::collections::HashMap<String, String>,
        cookies: &[String],
    ) -> Vec<AuthToken> {
        let mut tokens = Vec::new();

        // Extract JWT tokens from body
        for capture in self.jwt_pattern.captures_iter(body) {
            if let Some(jwt) = capture.get(0) {
                tokens.push(AuthToken {
                    token_type: "JWT".to_string(),
                    name: "Bearer Token".to_string(),
                    value: format!("{}...", &jwt.as_str()[..30.min(jwt.as_str().len())]),
                    attributes: None,
                });
            }
        }

        // Extract from Authorization header
        if let Some(auth_header) = headers.get("authorization") {
            tokens.push(AuthToken {
                token_type: "Authorization Header".to_string(),
                name: "Authorization".to_string(),
                value: if auth_header.len() > 30 {
                    format!("{}...", &auth_header[..30])
                } else {
                    auth_header.clone()
                },
                attributes: None,
            });
        }

        // Extract cookies
        for cookie in cookies {
            tokens.push(AuthToken {
                token_type: "Cookie".to_string(),
                name: cookie.clone(),
                value: "[Cookie Set]".to_string(),
                attributes: None,
            });
        }

        // Extract from Set-Cookie headers
        if let Some(set_cookie) = headers.get("set-cookie") {
            for cookie_part in set_cookie.split(';') {
                if let Some((name, value)) = cookie_part.split_once('=') {
                    tokens.push(AuthToken {
                        token_type: "Set-Cookie".to_string(),
                        name: name.trim().to_string(),
                        value: if value.len() > 30 {
                            format!("{}...", &value[..30])
                        } else {
                            value.to_string()
                        },
                        attributes: Some(set_cookie.clone()),
                    });
                    break; // Just take the first one to avoid duplicates
                }
            }
        }

        tokens
    }

    /// Extract version information
    fn extract_version_info(
        &self,
        body: &str,
        headers: &std::collections::HashMap<String, String>,
    ) -> Option<VersionInfo> {
        let mut version_info = VersionInfo {
            server: None,
            framework: None,
            details: Vec::new(),
        };

        // Extract from Server header
        if let Some(server) = headers.get("server") {
            version_info.server = Some(server.clone());
        }

        // Extract from X-Powered-By header
        if let Some(powered_by) = headers.get("x-powered-by") {
            version_info.framework = Some(powered_by.clone());
        }

        // Extract from X-AspNet-Version
        if let Some(aspnet_version) = headers.get("x-aspnet-version") {
            version_info.details.push(format!("ASP.NET {}", aspnet_version));
        }

        // Extract from body (look for version patterns)
        let version_regex = Regex::new(r"(?i)(version|v)\s*[:=]?\s*(\d+\.\d+[\.\d]*)").unwrap();
        for capture in version_regex.captures_iter(body).take(3) {
            if let Some(version) = capture.get(2) {
                version_info.details.push(version.as_str().to_string());
            }
        }

        if version_info.server.is_some()
            || version_info.framework.is_some()
            || !version_info.details.is_empty()
        {
            Some(version_info)
        } else {
            None
        }
    }

    /// Extract internal IP addresses
    fn extract_internal_ips(&self, body: &str) -> Vec<String> {
        let mut ips = HashSet::new();

        for capture in self.ip_pattern.captures_iter(body) {
            if let Some(ip) = capture.get(0) {
                ips.insert(ip.as_str().to_string());
            }
        }

        ips.into_iter().take(10).collect()
    }

    /// Extract ADFS metadata
    fn extract_adfs_metadata(&self, body: &str) -> Option<AdfsMetadata> {
        let mut metadata = AdfsMetadata {
            service_identifier: None,
            endpoints: Vec::new(),
            certificates: Vec::new(),
            claims: Vec::new(),
            relying_parties: Vec::new(),
        };

        // Extract federation service identifier
        let service_id_regex = Regex::new(r#"(?i)entityID=['"]([^'"]+)['"]"#).unwrap();
        if let Some(capture) = service_id_regex.captures(body) {
            if let Some(id) = capture.get(1) {
                metadata.service_identifier = Some(id.as_str().to_string());
            }
        }

        // Extract endpoints
        let endpoint_regex = Regex::new(r#"(?i)(https?://[^\s<>'"]+)"#).unwrap();
        for capture in endpoint_regex.captures_iter(body).take(10) {
            if let Some(url) = capture.get(1) {
                let url_str = url.as_str();
                if url_str.contains("adfs") || url_str.contains("federation") {
                    metadata.endpoints.push(url_str.to_string());
                }
            }
        }

        // Extract claim types
        let claim_regex = Regex::new(
            r#"(?i)(?:ClaimType|claim)['"]?\s*[:=]\s*['"]([^'"]+)['"]"#,
        )
        .unwrap();
        for capture in claim_regex.captures_iter(body).take(10) {
            if let Some(claim) = capture.get(1) {
                metadata.claims.push(claim.as_str().to_string());
            }
        }

        // Extract relying parties
        let rp_regex = Regex::new(r#"(?i)(?:RelyingParty|Issuer)['"]?\s*[:=]\s*['"]([^'"]+)['"]"#).unwrap();
        for capture in rp_regex.captures_iter(body).take(10) {
            if let Some(rp) = capture.get(1) {
                metadata.relying_parties.push(rp.as_str().to_string());
            }
        }

        if metadata.service_identifier.is_some()
            || !metadata.endpoints.is_empty()
            || !metadata.claims.is_empty()
            || !metadata.relying_parties.is_empty()
        {
            Some(metadata)
        } else {
            None
        }
    }
}

impl Default for DataExtractor {
    fn default() -> Self {
        Self::new()
    }
}
