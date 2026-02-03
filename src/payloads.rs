use serde::{Deserialize, Serialize};

/// A single payload test case
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadTest {
    /// The payload value to send
    pub value: String,
    /// Encoding type (none, url, double-url, etc.)
    pub encoding: String,
    /// HTTP method to use
    pub method: String,
}

/// Matcher for detecting successful attacks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Matcher {
    /// Type of matcher (response_body, response_time, etc.)
    #[serde(rename = "type")]
    pub matcher_type: String,
    /// Condition to check (contains, not_contains, greater_than, etc.)
    pub condition: String,
    /// Patterns to match
    pub patterns: Vec<String>,
}

/// Information about a payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayloadInfo {
    /// Name of the payload
    pub name: String,
    /// Severity level
    pub severity: crate::types::Severity,
    /// Category (injection, xss, sqli, etc.)
    pub category: String,
    /// Description of what the payload tests
    pub description: String,
    /// Reference links
    pub references: Vec<String>,
    /// Tags for categorization
    pub tags: Vec<String>,
}

/// A complete payload definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payload {
    /// Unique identifier
    pub id: String,
    /// Payload metadata
    pub info: PayloadInfo,
    /// List of test payloads
    pub payloads: Vec<PayloadTest>,
    /// Matchers to detect success
    pub matchers: Vec<Matcher>,
}

/// Manager for loading and accessing payloads
pub struct PayloadManager {
    payloads: Vec<Payload>,
}

impl PayloadManager {
    /// Load default embedded payloads
    pub fn with_defaults() -> crate::error::Result<Self> {
        const XSS: &str = include_str!("../payloads/xss.json");
        const SQLI: &str = include_str!("../payloads/sqli.json");
        const LFI: &str = include_str!("../payloads/lfi.json");
        const RCE: &str = include_str!("../payloads/rce.json");
        const PATH_TRAVERSAL: &str = include_str!("../payloads/path-traversal.json");
        const CMD_INJECTION: &str = include_str!("../payloads/command-injection.json");

        let mut all_payloads = Vec::new();

        // Parse each payload file
        for (name, content) in &[
            ("xss", XSS),
            ("sqli", SQLI),
            ("lfi", LFI),
            ("rce", RCE),
            ("path-traversal", PATH_TRAVERSAL),
            ("command-injection", CMD_INJECTION),
        ] {
            match serde_json::from_str::<Vec<Payload>>(content) {
                Ok(mut payloads) => all_payloads.append(&mut payloads),
                Err(e) => {
                    tracing::error!("Failed to parse {} payloads: {}", name, e);
                    return Err(crate::error::ScanError::InvalidPayload(format!(
                        "Failed to parse {} payloads: {}",
                        name, e
                    )));
                }
            }
        }

        if all_payloads.is_empty() {
            return Err(crate::error::ScanError::NoPayloads);
        }

        tracing::info!("Loaded {} default payloads", all_payloads.len());

        Ok(Self {
            payloads: all_payloads,
        })
    }

    /// Load payloads from a custom file
    pub async fn from_file(path: impl AsRef<std::path::Path>) -> crate::error::Result<Self> {
        let content = tokio::fs::read_to_string(path.as_ref()).await?;
        let payloads: Vec<Payload> = serde_json::from_str(&content)?;

        if payloads.is_empty() {
            return Err(crate::error::ScanError::NoPayloads);
        }

        tracing::info!("Loaded {} custom payloads from file", payloads.len());

        Ok(Self { payloads })
    }

    /// Get all payloads
    pub fn payloads(&self) -> &[Payload] {
        &self.payloads
    }

    /// Get payloads by category
    pub fn by_category(&self, category: &str) -> Vec<&Payload> {
        self.payloads
            .iter()
            .filter(|p| p.info.category == category)
            .collect()
    }

    /// Get payloads by severity
    pub fn by_severity(&self, severity: crate::types::Severity) -> Vec<&Payload> {
        self.payloads
            .iter()
            .filter(|p| p.info.severity == severity)
            .collect()
    }
}
