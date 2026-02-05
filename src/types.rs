use serde::{Deserialize, Serialize};
use std::fmt;

/// OWASP Top 10:2025 Categories
/// Reference: https://owasp.org/Top10/2025/
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OwaspCategory {
    /// A01:2025 - Broken Access Control
    /// Includes SSRF, path traversal, unauthorized access
    A01BrokenAccessControl,
    /// A02:2025 - Security Misconfiguration
    /// Default credentials, unnecessary features, insecure defaults
    A02SecurityMisconfiguration,
    /// A03:2025 - Software Supply Chain Failures
    /// Vulnerable dependencies, unsigned components
    A03SoftwareSupplyChainFailures,
    /// A04:2025 - Cryptographic Failures
    /// Weak encryption, cleartext storage of sensitive data
    A04CryptographicFailures,
    /// A05:2025 - Injection
    /// SQL, NoSQL, Command, LDAP, XSS, XXE injection
    A05Injection,
    /// A06:2025 - Insecure Design
    /// Missing security controls, threat modeling failures
    A06InsecureDesign,
    /// A07:2025 - Authentication Failures
    /// Broken session management, weak credentials
    A07AuthenticationFailures,
    /// A08:2025 - Software or Data Integrity Failures
    /// Insecure CI/CD, untrusted updates
    A08SoftwareOrDataIntegrityFailures,
    /// A09:2025 - Security Logging & Alerting Failures
    /// Insufficient logging, missing alerting
    A09SecurityLoggingAlertingFailures,
    /// A10:2025 - Mishandling of Exceptional Conditions
    /// Poor error handling, information disclosure
    A10MishandlingOfExceptionalConditions,
}

impl OwaspCategory {
    /// Get the category identifier (e.g., "A01")
    pub fn id(&self) -> &'static str {
        match self {
            Self::A01BrokenAccessControl => "A01",
            Self::A02SecurityMisconfiguration => "A02",
            Self::A03SoftwareSupplyChainFailures => "A03",
            Self::A04CryptographicFailures => "A04",
            Self::A05Injection => "A05",
            Self::A06InsecureDesign => "A06",
            Self::A07AuthenticationFailures => "A07",
            Self::A08SoftwareOrDataIntegrityFailures => "A08",
            Self::A09SecurityLoggingAlertingFailures => "A09",
            Self::A10MishandlingOfExceptionalConditions => "A10",
        }
    }

    /// Get the full category name
    pub fn name(&self) -> &'static str {
        match self {
            Self::A01BrokenAccessControl => "Broken Access Control",
            Self::A02SecurityMisconfiguration => "Security Misconfiguration",
            Self::A03SoftwareSupplyChainFailures => "Software Supply Chain Failures",
            Self::A04CryptographicFailures => "Cryptographic Failures",
            Self::A05Injection => "Injection",
            Self::A06InsecureDesign => "Insecure Design",
            Self::A07AuthenticationFailures => "Authentication Failures",
            Self::A08SoftwareOrDataIntegrityFailures => "Software or Data Integrity Failures",
            Self::A09SecurityLoggingAlertingFailures => "Security Logging & Alerting Failures",
            Self::A10MishandlingOfExceptionalConditions => "Mishandling of Exceptional Conditions",
        }
    }

    /// Get OWASP reference URL
    pub fn reference_url(&self) -> String {
        format!("https://owasp.org/Top10/2025/{}_2025-{}/", 
            self.id(), 
            self.name().replace(" ", "_").replace("&", "and"))
    }

    /// Map traditional attack category to OWASP Top 10:2025
    pub fn from_attack_type(attack_type: &str) -> Option<Self> {
        match attack_type.to_lowercase().as_str() {
            "xss" | "sqli" | "sql-injection" | "nosql-injection" | "command-injection" 
            | "ldap-injection" | "xxe" | "ssti" => Some(Self::A05Injection),
            "ssrf" | "path-traversal" | "lfi" | "directory-traversal" 
            | "unauthorized-access" => Some(Self::A01BrokenAccessControl),
            "rce" | "code-injection" => Some(Self::A08SoftwareOrDataIntegrityFailures),
            "authentication" | "session" | "auth-bypass" => Some(Self::A07AuthenticationFailures),
            "misconfiguration" | "default-credentials" => Some(Self::A02SecurityMisconfiguration),
            "crypto" | "encryption" | "weak-crypto" => Some(Self::A04CryptographicFailures),
            "error-handling" | "information-disclosure" => Some(Self::A10MishandlingOfExceptionalConditions),
            "http2-bypass" | "http2" => Some(Self::A02SecurityMisconfiguration),
            "adfs" | "windows-auth" => Some(Self::A07AuthenticationFailures),
            _ => None,
        }
    }
}

impl fmt::Display for OwaspCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.id(), self.name())
    }
}

/// Severity levels for security findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// CVSS 0.0 - Informational findings
    Info,
    /// CVSS 0.1-3.9 - Low severity issues
    Low,
    /// CVSS 4.0-6.9 - Medium severity issues
    Medium,
    /// CVSS 7.0-8.9 - High severity issues
    High,
    /// CVSS 9.0-10.0 - Critical severity issues
    Critical,
}

impl Severity {
    /// Get terminal color for the severity level
    pub fn color(&self) -> owo_colors::DynColors {
        match self {
            Severity::Critical => owo_colors::DynColors::Rgb(255, 0, 0),
            Severity::High => owo_colors::DynColors::Rgb(255, 100, 0),
            Severity::Medium => owo_colors::DynColors::Rgb(255, 255, 0),
            Severity::Low => owo_colors::DynColors::Rgb(0, 150, 255),
            Severity::Info => owo_colors::DynColors::Rgb(200, 200, 200),
        }
    }

    /// Convert CVSS score to severity level
    pub fn from_cvss(score: f32) -> Self {
        match score {
            s if s >= 9.0 => Severity::Critical,
            s if s >= 7.0 => Severity::High,
            s if s >= 4.0 => Severity::Medium,
            s if s > 0.0 => Severity::Low,
            _ => Severity::Info,
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "Critical"),
            Severity::High => write!(f, "High"),
            Severity::Medium => write!(f, "Medium"),
            Severity::Low => write!(f, "Low"),
            Severity::Info => write!(f, "Info"),
        }
    }
}

/// Security finding from a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    /// ID of the payload that triggered this finding
    pub payload_id: String,
    /// Severity of the finding
    pub severity: Severity,
    /// Category of the vulnerability
    pub category: String,
    /// OWASP Top 10:2025 mapping (if applicable)
    pub owasp_category: Option<OwaspCategory>,
    /// The actual payload value used
    pub payload_value: String,
    /// The evasion technique that worked (if any)
    pub technique_used: Option<String>,
    /// HTTP response status code
    pub response_status: u16,
    /// Description of the finding
    pub description: String,
    /// HTTP version used (HTTP/1.1, HTTP/2, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_version: Option<String>,
    /// Extracted sensitive data from response
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extracted_data: Option<ExtractedData>,
}

/// Sensitive data extracted from responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedData {
    /// Information disclosure findings
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub info_disclosure: Vec<InfoDisclosure>,
    /// Exposed paths and directories
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub exposed_paths: Vec<String>,
    /// Authentication tokens found
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub auth_tokens: Vec<AuthToken>,
    /// Server/application version info
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_info: Option<VersionInfo>,
    /// Internal IP addresses exposed
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub internal_ips: Vec<String>,
    /// ADFS-specific metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub adfs_metadata: Option<AdfsMetadata>,
    /// Response body snippet (first 500 chars)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_snippet: Option<String>,
}

/// Information disclosure types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InfoDisclosure {
    /// Type of disclosure
    pub disclosure_type: String,
    /// The actual disclosed information
    pub value: String,
    /// Severity of this specific disclosure
    pub severity: Severity,
}

/// Authentication token information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthToken {
    /// Token type (cookie, JWT, bearer, etc.)
    pub token_type: String,
    /// Token name/key
    pub name: String,
    /// Token value (potentially redacted)
    pub value: String,
    /// Additional attributes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<String>,
}

/// Version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    /// Server software and version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Framework/platform version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub framework: Option<String>,
    /// Additional version details
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<String>,
}

/// ADFS-specific metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdfsMetadata {
    /// Federation service identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_identifier: Option<String>,
    /// Exposed endpoints
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub endpoints: Vec<String>,
    /// Certificate information
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<String>,
    /// Claim types exposed
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub claims: Vec<String>,
    /// Relying party trusts
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub relying_parties: Vec<String>,
}

impl ExtractedData {
    /// Create a new empty extracted data instance
    pub fn new() -> Self {
        Self {
            info_disclosure: Vec::new(),
            exposed_paths: Vec::new(),
            auth_tokens: Vec::new(),
            version_info: None,
            internal_ips: Vec::new(),
            adfs_metadata: None,
            response_snippet: None,
        }
    }

    /// Check if any data was extracted
    pub fn has_data(&self) -> bool {
        !self.info_disclosure.is_empty()
            || !self.exposed_paths.is_empty()
            || !self.auth_tokens.is_empty()
            || self.version_info.is_some()
            || !self.internal_ips.is_empty()
            || self.adfs_metadata.is_some()
    }
}

impl Default for ExtractedData {
    fn default() -> Self {
        Self::new()
    }
}

/// Summary statistics from a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    /// Total number of payloads tested
    pub total_payloads: usize,
    /// Number of successful bypasses detected
    pub successful_bypasses: usize,
    /// Number of techniques that were effective
    pub techniques_effective: usize,
    /// Scan duration in seconds
    pub duration_secs: f64,
}

/// Results from a WAF scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResults {
    /// Target URL that was scanned
    pub target: String,
    /// Timestamp of the scan
    pub timestamp: String,
    /// Detected WAF name (if any)
    pub waf_detected: Option<String>,
    /// List of findings
    pub findings: Vec<Finding>,
    /// Summary statistics
    pub summary: ScanSummary,
}

impl ScanResults {
    /// Create a new scan results instance
    pub fn new(target: String, waf_detected: Option<String>) -> Self {
        Self {
            target,
            timestamp: chrono::Utc::now().to_rfc3339(),
            waf_detected,
            findings: Vec::new(),
            summary: ScanSummary {
                total_payloads: 0,
                successful_bypasses: 0,
                techniques_effective: 0,
                duration_secs: 0.0,
            },
        }
    }

    /// Add a finding to the results
    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    /// Sort findings by severity (critical first)
    pub fn sort_by_severity(&mut self) {
        self.findings.sort_by(|a, b| b.severity.cmp(&a.severity));
    }
}
