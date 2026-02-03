use simple_waf_scanner::{Config, Scanner};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let mut config = Config::new("https://api-prd.ais.gov.sg".to_string());
    config.concurrency = 2;
    config.delay_ms = 1000;

    let scanner = Scanner::new(config).await?;
    let results = scanner.scan().await?;

    println!("\n=== WAF Detection Test ===");
    println!("Target: {}", results.target);
    if let Some(waf) = &results.waf_detected {
        println!("✓ WAF Detected: {}", waf);
    } else {
        println!("✗ No WAF detected");
    }
    println!("Findings: {}", results.findings.len());
    println!("========================\n");

    Ok(())
}
