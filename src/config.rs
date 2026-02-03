use serde::{Deserialize, Serialize};

/// Configuration for WAF scanner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Target URL to scan
    pub target: String,

    /// Number of concurrent requests
    pub concurrency: usize,

    /// Delay between requests in milliseconds
    pub delay_ms: u64,

    /// Custom payload file path (optional)
    pub payload_file: Option<String>,

    /// Enabled evasion techniques (None = all enabled)
    pub enabled_techniques: Option<Vec<String>>,

    /// Verbose output mode
    pub verbose: bool,

    /// Custom User-Agent header
    pub user_agent: String,
}

impl Config {
    /// Create a new configuration with default values
    pub fn new(target: String) -> Self {
        Self {
            target,
            concurrency: 10,
            delay_ms: 100,
            payload_file: None,
            enabled_techniques: None,
            verbose: false,
            user_agent: "Mozilla/5.0 (WAF Scanner)".to_string(),
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> crate::error::Result<()> {
        if self.target.is_empty() {
            return Err(crate::error::ScanError::ConfigError(
                "Target URL cannot be empty".to_string(),
            ));
        }

        if !self.target.starts_with("http://") && !self.target.starts_with("https://") {
            return Err(crate::error::ScanError::ConfigError(
                "Target URL must start with http:// or https://".to_string(),
            ));
        }

        if self.concurrency == 0 {
            return Err(crate::error::ScanError::ConfigError(
                "Concurrency must be greater than 0".to_string(),
            ));
        }

        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::new(String::new())
    }
}
