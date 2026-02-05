//! Simple WAF Scanner - A tool for detecting and testing web application firewalls
//!
//! This library provides functionality for:
//! - Detecting WAF presence through fingerprinting
//! - Testing WAF bypass techniques with various evasion methods
//! - Scanning endpoints with structured payload sets
//!
//! # Warning
//!
//! This tool is intended for **authorized security testing only**.
//! Unauthorized access to computer systems is illegal.

pub mod config;
pub mod error;
pub mod evasion;
pub mod extractor;
pub mod fingerprints;
pub mod http;
pub mod payloads;
pub mod scanner;
pub mod types;

// Re-export main types
pub use config::Config;
pub use error::{Result, ScanError};
pub use scanner::Scanner;
pub use types::{Finding, ScanResults, Severity};

/// Perform a WAF scan with the given configuration
///
/// # Example
///
/// ```no_run
/// use simple_waf_scanner::{Config, scan};
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let config = Config::new("https://example.com".to_string());
///     let results = scan(config).await?;
///     println!("Found {} findings", results.findings.len());
///     Ok(())
/// }
/// ```
pub async fn scan(config: Config) -> Result<ScanResults> {
    let scanner = Scanner::new(config).await?;
    scanner.scan().await
}
