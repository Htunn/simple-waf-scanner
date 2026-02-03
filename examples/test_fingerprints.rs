use simple_waf_scanner::fingerprints::{DetectionResponse, WafDetector};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Testing WAF detection...\n");

    // Simulate Azure Front Door response
    let mut headers = HashMap::new();
    headers.insert("x-azure-ref".to_string(), "20260203T063349Z-test".to_string());
    headers.insert("x-cache".to_string(), "CONFIG_NOCACHE".to_string());
    
    let response = DetectionResponse::new(
        403,
        headers.clone(),
        "Forbidden".to_string(),
        vec![],
    );

    let detector = WafDetector::new()?;
    
    println!("Test 1: Azure Front Door");
    println!("Headers: {:?}", headers);
    match detector.detect(&response) {
        Some(waf) => println!("✓ Detected: {}\n", waf),
        None => println!("✗ Not detected\n"),
    }

    // Simulate Cloudflare response
    let mut cf_headers = HashMap::new();
    cf_headers.insert("server".to_string(), "cloudflare".to_string());
    cf_headers.insert("cf-ray".to_string(), "abc123-SJC".to_string());
    
    let cf_response = DetectionResponse::new(
        403,
        cf_headers.clone(),
        "Access denied".to_string(),
        vec!["__cf_bm".to_string()],
    );

    println!("Test 2: Cloudflare");
    println!("Headers: {:?}", cf_headers);
    match detector.detect(&cf_response) {
        Some(waf) => println!("✓ Detected: {}\n", waf),
        None => println!("✗ Not detected\n"),
    }

    println!("Loaded {} WAF signatures", detector.signatures().len());
    
    Ok(())
}
