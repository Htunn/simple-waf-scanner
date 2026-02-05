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
            crate::error::ScanError::InvalidPayload(format!(
                "Failed to parse WAF signatures: {}",
                e
            ))
        })?;

        tracing::info!("Loaded {} WAF signatures", signatures.len());

        Ok(Self { signatures })
    }

    /// Detect WAF from an HTTP response
    /// Returns the best matching WAF with highest confidence score
    pub fn detect(&self, response: &DetectionResponse) -> Option<String> {
        let mut best_match: Option<(String, i32, usize)> = None; // (name, score, specificity)
        
        for signature in &self.signatures {
            let (score, specificity) = self.calculate_match_score(response, signature);
            
            if score >= 2 { // Minimum threshold for detection
                match &mut best_match {
                    None => {
                        best_match = Some((signature.name.clone(), score, specificity));
                    }
                    Some((_, best_score, best_specificity)) => {
                        // Prefer higher score, or higher specificity if scores are equal
                        if score > *best_score || (score == *best_score && specificity > *best_specificity) {
                            best_match = Some((signature.name.clone(), score, specificity));
                        }
                    }
                }
            }
        }
        
        if let Some((name, score, _)) = best_match {
            tracing::info!("Detected: {} (confidence score: {})", name, score);
            Some(name)
        } else {
            tracing::debug!("No WAF detected");
            None
        }
    }

    /// Calculate match score and specificity for a signature
    /// Returns (score, specificity) where higher specificity means more unique/specific detection
    fn calculate_match_score(&self, response: &DetectionResponse, signature: &WafSignature) -> (i32, usize) {
        let mut score = 0;
        let mut header_matches = 0;
        let total_criteria = signature.detection.headers.len() 
            + signature.detection.body_patterns.len()
            + signature.detection.status_codes.len()
            + signature.detection.cookies.len();

        // Check headers - require specific header values for high confidence
        for (header_name, pattern) in &signature.detection.headers {
            if let Some(header_value) = response.headers.get(&header_name.to_lowercase()) {
                // Exact match or pattern match
                if pattern == ".*" {
                    score += 1; // Generic header presence
                    header_matches += 1;
                } else if header_value.to_lowercase().contains(&pattern.to_lowercase()) {
                    score += 3; // Specific header value match (stronger indicator)
                    header_matches += 1;
                }
            }
        }

        // Check body patterns
        for pattern in &signature.detection.body_patterns {
            if response.body.to_lowercase().contains(&pattern.to_lowercase()) {
                score += 2; // Body patterns are good indicators
                break; // Only count once
            }
        }

        // Check status codes
        for status in &signature.detection.status_codes {
            if *status == response.status_code {
                score += 1; // Status codes are weak indicators alone
                break;
            }
        }

        // Check cookies
        for cookie_pattern in &signature.detection.cookies {
            for cookie in &response.cookies {
                if cookie.contains(cookie_pattern) {
                    score += 2; // Cookies are good indicators
                    break;
                }
            }
        }

        // Specificity: number of criteria defined + matched headers
        let specificity = total_criteria + header_matches;
        
        (score, specificity)
    }

    /// Check if response matches a signature (legacy method for compatibility)
    #[allow(dead_code)]
    fn matches_signature(&self, response: &DetectionResponse, signature: &WafSignature) -> bool {
        let (score, _) = self.calculate_match_score(response, signature);
        score >= 2
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
    pub fn new(
        status_code: u16,
        headers: HashMap<String, String>,
        body: String,
        cookies: Vec<String>,
    ) -> Self {
        Self {
            status_code,
            headers,
            body,
            cookies,
        }
    }
}
