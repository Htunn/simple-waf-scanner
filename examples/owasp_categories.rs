// Example: Using OWASP Categories in WAF Scanner
//
// This example demonstrates how the scanner automatically maps
// findings to OWASP Top 10:2025 categories

use simple_waf_scanner::{Config, scan, types::OwaspCategory};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure the scanner
    let config = Config::new("https://example.com".to_string());
    
    // Run the scan
    let results = scan(config).await?;
    
    println!("WAF Scanner Results - OWASP Top 10:2025 Analysis");
    println!("================================================\n");
    
    // Group findings by OWASP category
    let mut owasp_findings: std::collections::HashMap<String, Vec<_>> = 
        std::collections::HashMap::new();
    
    for finding in &results.findings {
        if let Some(owasp_cat) = &finding.owasp_category {
            let category_name = owasp_cat.to_string();
            owasp_findings
                .entry(category_name)
                .or_insert_with(Vec::new)
                .push(finding);
        }
    }
    
    // Display findings grouped by OWASP category
    for (category, findings) in owasp_findings.iter() {
        println!("📋 {}", category);
        println!("   Findings: {}", findings.len());
        
        for finding in findings {
            println!("   └─ {} - {}", finding.severity, finding.category);
            println!("      Payload: {}", finding.payload_value);
            
            if let Some(owasp_cat) = &finding.owasp_category {
                println!("      Reference: {}", owasp_cat.reference_url());
            }
        }
        println!();
    }
    
    // Example: Map attack types to OWASP categories
    println!("\nOWASP Category Mapping Examples:");
    println!("================================");
    
    let attack_types = vec![
        "xss",
        "sqli", 
        "ssrf",
        "path-traversal",
        "auth-bypass",
        "error-handling",
    ];
    
    for attack_type in attack_types {
        if let Some(owasp) = OwaspCategory::from_attack_type(attack_type) {
            println!("{:20} → {} - {}", 
                attack_type, 
                owasp.id(), 
                owasp.name()
            );
        }
    }
    
    Ok(())
}

// Example output:
//
// WAF Scanner Results - OWASP Top 10:2025 Analysis
// ================================================
//
// 📋 A05: Injection
//    Findings: 15
//    └─ Critical - sqli
//       Payload: 1' OR '1'='1
//       Reference: https://owasp.org/Top10/2025/A05_2025-Injection/
//    └─ High - xss
//       Payload: <script>alert('XSS')</script>
//       Reference: https://owasp.org/Top10/2025/A05_2025-Injection/
//
// 📋 A01: Broken Access Control
//    Findings: 8
//    └─ Critical - ssrf
//       Payload: http://169.254.169.254/latest/meta-data/
//       Reference: https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/
//
// 📋 A07: Authentication Failures
//    Findings: 3
//    └─ Critical - auth-bypass
//       Payload: admin' OR '1'='1'--
//       Reference: https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/
//
// OWASP Category Mapping Examples:
// ================================
// xss                  → A05 - Injection
// sqli                 → A05 - Injection
// ssrf                 → A01 - Broken Access Control
// path-traversal       → A01 - Broken Access Control
// auth-bypass          → A07 - Authentication Failures
// error-handling       → A10 - Mishandling of Exceptional Conditions
