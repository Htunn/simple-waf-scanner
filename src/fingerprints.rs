use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Detection criteria for a WAF
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafDetection {
    /// Header patterns to match
    pub headers: HashMap<String, String>,
    /// Body patterns to match
    pub body_patterns: Vec<String>,
    /// Status codes that indicate this WAF
    pub status_codes: Vec<u16>,
    /// Cookie patterns
    pub cookies: Vec<String>,
}

/// WAF signature definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafSignature {
    /// Name of the WAF
    pub name: String,
    /// Vendor/manufacturer
    pub vendor: String,
    /// Detection criteria
    pub detection: WafDetection,
}

/// WAF detector for identifying web application firewalls
pub struct WafDetector {
    signatures: Vec<WafSignature>,
}

impl WafDetector {
    /// Create a new detector with embedded signatures
    pub fn new() -> crate::error::Result<Self> {
        const SIGNATURES: &str = include_str!("../fingerprints/waf-signatures.json");

        let signatures: Vec<WafSignature> = serde_json::from_str(SIGNATURES).map_err(|e| {
            crate::error::ScanError::InvalidPayload(format!("Failed to parse WAF signatures: {}", e))
        })?;

        tracing::info!("Loaded {} WAF signatures", signatures.len());

        Ok(Self { signatures })
    }

    /// Detect WAF from an HTTP response
    pub fn detect(&self, response: &DetectionResponse) -> Option<String> {
        for signature in &self.signatures {
            if self.matches_signature(response, signature) {
                tracing::info!("Detected WAF: {}", signature.name);
                return Some(signature.name.clone());
            }
        }
        None
    }

    /// Check if response matches a signature
    fn matches_signature(&self, response: &DetectionResponse, signature: &WafSignature) -> bool {
        let mut score = 0;
        let mut required_matches = 0;

        // Check headers
        if !signature.detection.headers.is_empty() {
            required_matches += 1;
            for (header_name, pattern) in &signature.detection.headers {
                if let Some(header_value) = response.headers.get(&header_name.to_lowercase()) {
                    if pattern == ".*" || header_value.to_lowercase().contains(&pattern.to_lowercase()) {
                        score += 1;
                        break;
                    }
                }
            }
        }

        // Check body patterns
        if !signature.detection.body_patterns.is_empty() {
            required_matches += 1;
            for pattern in &signature.detection.body_patterns {
                if response.body.to_lowercase().contains(&pattern.to_lowercase()) {
                    score += 1;
                    break;
                }
            }
        }

        // Check status codes
        if !signature.detection.status_codes.is_empty() {
            for status in &signature.detection.status_codes {
                if *status == response.status_code {
                    score += 1;
                    break;
                }
            }
        }

        // Check cookies
        if !signature.detection.cookies.is_empty() {
            for cookie_pattern in &signature.detection.cookies {
                for cookie in &response.cookies {
                    if cookie.contains(cookie_pattern) {
                        score += 1;
                        break;
                    }
                }
            }
        }

        // Require at least 2 matching criteria or all available criteria matched
        score >= 2 || (required_matches > 0 && score >= required_matches)
    }

    /// Get all loaded signatures
    pub fn signatures(&self) -> &[WafSignature] {
        &self.signatures
    }
}

impl Default for WafDetector {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            signatures: Vec::new(),
        })
    }
}

/// Response data for WAF detection
#[derive(Debug, Clone)]
pub struct DetectionResponse {
    /// HTTP status code
    pub status_code: u16,
    /// Response headers (lowercase keys)
    pub headers: HashMap<String, String>,
    /// Response body
    pub body: String,
    /// Cookie names
    pub cookies: Vec<String>,
}

impl DetectionResponse {
    /// Create a new detection response
    pub fn new(status_code: u16, headers: HashMap<String, String>, body: String, cookies: Vec<String>) -> Self {
        Self {
            status_code,
            headers,
            body,
            cookies,
        }
    }
}
