use serde::{Deserialize, Serialize};
use std::fmt;

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
    /// The actual payload value used
    pub payload_value: String,
    /// The evasion technique that worked (if any)
    pub technique_used: Option<String>,
    /// HTTP response status code
    pub response_status: u16,
    /// Description of the finding
    pub description: String,
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
