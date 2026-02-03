use thiserror::Error;

/// Errors that can occur during WAF scanning operations
#[derive(Error, Debug)]
pub enum ScanError {
    /// HTTP request failed
    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    /// Failed to parse JSON data
    #[error("Failed to parse JSON: {0}")]
    ParseError(#[from] serde_json::Error),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    ConfigError(String),

    /// IO operation failed
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Invalid payload format
    #[error("Invalid payload format: {0}")]
    InvalidPayload(String),

    /// No payloads loaded
    #[error("No payloads available for scanning")]
    NoPayloads,

    /// URL parsing error
    #[error("Invalid URL: {0}")]
    UrlError(String),
}

/// Result type for scanner operations
pub type Result<T> = std::result::Result<T, ScanError>;
