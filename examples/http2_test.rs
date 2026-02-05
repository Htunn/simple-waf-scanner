/// Example demonstrating HTTP/2 capabilities
/// 
/// This example shows how to test HTTP/2 support and verify the scanner
/// can detect and utilize HTTP/2 protocol features.
/// 
/// Usage:
/// ```bash
/// cargo run --example http2_test
/// ```

use simple_waf_scanner::{Config, Scanner};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║         HTTP/2 Production-Ready Configuration Test       ║");
    println!("╚═══════════════════════════════════════════════════════════╝\n");

    // Test against a known HTTP/2 endpoint (Cloudflare's test server)
    let target = "https://cloudflare.com".to_string();

    println!("🎯 Target: {}", target);
    println!("🔧 Configuration:");
    println!("   • HTTP/2 prior knowledge: enabled");
    println!("   • Adaptive flow control: enabled");
    println!("   • Stream window: 2MB");
    println!("   • Connection window: 4MB");
    println!("   • Max frame size: 16KB");
    println!("   • Keep-alive: 20s interval, 10s timeout\n");

    // Create configuration
    let config = Config {
        target: target.clone(),
        user_agent: "WAF-Scanner-HTTP2-Test/0.1".to_string(),
        concurrency: 5,
        delay_ms: 100,
        payload_file: Some("payloads/http2-adfs-bypass.json".to_string()),
        enabled_techniques: None,
        verbose: true,
    };

    println!("📡 Initializing scanner with HTTP/2 support...");

    // Create scanner
    match Scanner::new(config).await {
        Ok(scanner) => {
            println!("✅ Scanner initialized successfully\n");
            
            println!("🚀 Starting scan...");
            println!("   This will test:");
            println!("   • HTTP/2 protocol detection");
            println!("   • Critical vulnerabilities (Rapid Reset, CONTINUATION Flood)");
            println!("   • Request smuggling & pseudo-header injection");
            println!("   • HPACK compression handling");
            println!("   • Flow control mechanisms\n");

            // Run scan
            match scanner.scan().await {
                Ok(results) => {
                    println!("\n╔═══════════════════════════════════════════════════════════╗");
                    println!("║                    Scan Results                           ║");
                    println!("╚═══════════════════════════════════════════════════════════╝\n");

                    println!("📊 Summary:");
                    println!("   • Total payloads tested: {}", results.summary.total_payloads);
                    println!("   • Successful bypasses: {}", results.summary.successful_bypasses);
                    println!("   • Effective techniques: {}", results.summary.techniques_effective);
                    println!("   • Duration: {:.2}s", results.summary.duration_secs);

                    if let Some(waf) = &results.waf_detected {
                        println!("   • WAF detected: {}", waf);
                    }

                    // Show HTTP/2 specific findings
                    let http2_findings: Vec<_> = results.findings.iter()
                        .filter(|f| f.http_version.as_ref().map(|v| v.contains("HTTP/2")).unwrap_or(false))
                        .collect();

                    if !http2_findings.is_empty() {
                        println!("\n🔍 HTTP/2 Specific Findings: {}", http2_findings.len());
                        for finding in http2_findings.iter().take(5) {
                            println!("   • {} [{}] - {}", 
                                finding.payload_id, 
                                finding.severity,
                                finding.http_version.as_ref().unwrap_or(&"Unknown".to_string())
                            );
                        }
                    }

                    println!("\n✅ HTTP/2 test completed successfully!");
                    
                    if results.summary.successful_bypasses > 0 {
                        println!("\n⚠️  Found {} potential vulnerabilities", results.summary.successful_bypasses);
                        println!("   Review findings carefully and patch as needed");
                    } else {
                        println!("\n✅ No vulnerabilities detected");
                        println!("   Target appears to have proper HTTP/2 protections");
                    }
                }
                Err(e) => {
                    eprintln!("❌ Scan failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Err(e) => {
            eprintln!("❌ Failed to initialize scanner: {}", e);
            eprintln!("\n💡 Troubleshooting:");
            eprintln!("   • Ensure target supports HTTPS");
            eprintln!("   • Check network connectivity");
            eprintln!("   • Verify payload file exists: payloads/http2-adfs-bypass.json");
            std::process::exit(1);
        }
    }

    println!("\n📚 For more information, see HTTP2_PRODUCTION.md");

    Ok(())
}
