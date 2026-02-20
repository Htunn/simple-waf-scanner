use clap::Parser;
use comfy_table::{presets::UTF8_FULL, ContentArrangement, Table};
use is_terminal::IsTerminal;
use owo_colors::OwoColorize;
use simple_waf_scanner::{Config, ScanResults};
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "waf-scan")]
#[command(about = "WAF detection and bypass testing tool")]
#[command(long_about = "WAF Scanner - Security testing tool for web applications and LLM/GenAI systems

BASIC USAGE:
  waf-scan https://example.com

WEB APPLICATION TESTING:
  waf-scan https://example.com --verbose
  waf-scan https://example.com --techniques encoding,case,unicode

LLM/GenAI TESTING (OWASP Top 10 for LLM Applications):
  waf-scan https://api.example.com/chat --llm-mode
  waf-scan https://api.example.com/chat --llm-mode --techniques role-reversal,multilingual
  waf-scan https://api.example.com/chat --llm-mode --semantic-analysis --verbose

LLM mode tests for:
  • LLM01: Prompt Injection & Jailbreaks
  • LLM02: Sensitive Information Disclosure
  • LLM03-LLM10: Supply Chain, Data Poisoning, Output Handling, etc.

LLM mode automatically uses optimized settings (concurrency=3, delay=500ms, timeout=60s).
You can override these with --concurrency and --delay if needed.")]
#[command(version)]
struct Args {
    /// Target URL to scan
    target: String,

    /// Path to custom payload file (JSON format)
    #[arg(long)]
    payload_file: Option<String>,

    /// Number of concurrent requests (default: 10 for web apps, 3 for LLM mode)
    #[arg(long)]
    concurrency: Option<usize>,

    /// Delay between requests in milliseconds (default: 100 for web apps, 500 for LLM mode)
    #[arg(long)]
    delay: Option<u64>,

    /// Comma-separated list of evasion techniques to use
    /// Available: encoding, double-encode, case, null-bytes, comments, unicode, path-traversal,
    /// role-reversal, context-splitting, encoding-obfuscation, multilingual, delimiter-confusion, instruction-layering
    #[arg(long)]
    techniques: Option<String>,

    /// Enable LLM/GenAI security testing mode (OWASP Top 10 for LLM Applications).
    /// Tests for prompt injection, jailbreaks, system prompt leakage, sensitive data disclosure,
    /// and other LLM-specific vulnerabilities. Automatically optimizes settings for LLM endpoints
    /// (concurrency=3, delay=500ms, timeout=60s). Override with --concurrency and --delay if needed.
    #[arg(long)]
    llm_mode: bool,

    /// Enable semantic analysis for LLM responses (experimental).
    /// Analyzes response patterns to detect successful jailbreaks and refusal bypasses.
    /// Only effective when combined with --llm-mode
    #[arg(long)]
    semantic_analysis: bool,

    /// Show detailed information including which technique worked
    #[arg(long)]
    verbose: bool,

    /// Output results as JSON
    #[arg(long)]
    output_json: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // Parse arguments
    let args = Args::parse();

    // Require consent - MANDATORY, NO BYPASS
    require_consent()?;

    // Build configuration
    let mut config = Config::new(args.target);
    
    // Auto-adjust defaults for LLM mode if not explicitly set
    if args.llm_mode {
        config.concurrency = args.concurrency.unwrap_or(3);
        config.delay_ms = args.delay.unwrap_or(500);
        tracing::info!("LLM mode enabled: using concurrency={}, delay={}ms", 
                      config.concurrency, config.delay_ms);
    } else {
        config.concurrency = args.concurrency.unwrap_or(10);
        config.delay_ms = args.delay.unwrap_or(100);
    }
    
    config.payload_file = args.payload_file;
    config.verbose = args.verbose;
    config.llm_mode = args.llm_mode;
    config.semantic_analysis = args.semantic_analysis;

    if let Some(techniques_str) = args.techniques {
        config.enabled_techniques = Some(
            techniques_str
                .split(',')
                .map(|s| s.trim().to_string())
                .collect(),
        );
    }

    // Set up graceful shutdown
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);

    tokio::spawn(async move {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to listen for Ctrl+C");
        eprintln!("\n{}", "Shutdown signal received, stopping...".yellow());
        let _ = shutdown_tx.send(()).await;
    });

    // Perform scan
    let scan_future = simple_waf_scanner::scan(config);

    let results = tokio::select! {
        result = scan_future => result?,
        _ = shutdown_rx.recv() => {
            eprintln!("{}", "Scan interrupted by user".red());
            std::process::exit(130);
        }
    };

    // Output results
    if args.output_json {
        print_json_output(&results)?;
    } else {
        print_pretty_output(&results, args.verbose);
    }

    Ok(())
}

/// Require interactive consent - MANDATORY, CANNOT BE BYPASSED
fn require_consent() -> anyhow::Result<()> {
    // Block non-interactive execution
    if !std::io::stdin().is_terminal() {
        eprintln!(
            "{}",
            "ERROR: This tool requires interactive terminal consent."
                .red()
                .bold()
        );
        eprintln!("{}", "Automated/scripted execution is not permitted.".red());
        std::process::exit(1);
    }

    // Display legal warning - ALL TO STDERR so it doesn't get redirected
    eprintln!("\n{}", "⚠️  LEGAL WARNING".red().bold());
    eprintln!("{}", "─".repeat(70).yellow());
    eprintln!("This tool performs security testing that may:");
    eprintln!("  • Send malicious payloads to web servers");
    eprintln!("  • Trigger security alerts and logging");
    eprintln!("  • Violate laws if used without authorization");
    eprintln!();
    eprintln!(
        "{}",
        "You MUST have explicit written permission to scan the target."
            .red()
            .bold()
    );
    eprintln!();
    eprintln!("Unauthorized access to computer systems is a violation of:");
    eprintln!("  • Computer Fraud and Abuse Act (CFAA) in the United States");
    eprintln!("  • Computer Misuse Act in the United Kingdom");
    eprintln!("  • Similar laws in other jurisdictions");
    eprintln!();
    eprintln!("The authors assume NO LIABILITY for misuse of this tool.");
    eprintln!("{}", "─".repeat(70).yellow());

    // Require exact consent
    loop {
        eprint!(
            "\n{}",
            "Type 'I ACCEPT' to confirm you have authorization: ".cyan()
        );
        io::stderr().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let trimmed = input.trim();

        if trimmed == "I ACCEPT" {
            eprintln!(
                "{}",
                "✓ Consent confirmed. Proceeding with scan...\n".green()
            );
            return Ok(());
        } else if trimmed.to_lowercase() == "no" || trimmed.is_empty() {
            eprintln!("{}", "Scan cancelled.".yellow());
            std::process::exit(0);
        } else {
            eprintln!("{}", "Invalid input. Please type 'I ACCEPT' exactly.".red());
        }
    }
}

/// Print results in pretty table format
fn print_pretty_output(results: &ScanResults, verbose: bool) {
    // Print WAF detection banner - TO STDERR to avoid redirection issues
    eprintln!("\n{}", "═".repeat(70).cyan());
    eprintln!("{}", "  WAF BYPASS SCAN RESULTS".cyan().bold());
    eprintln!("{}", "═".repeat(70).cyan());
    eprintln!();

    eprintln!("{} {}", "Target:".bold(), results.target);
    eprintln!("{} {}", "Timestamp:".bold(), results.timestamp);

    if let Some(ref waf) = results.waf_detected {
        if waf.contains("No WAF") {
            eprintln!("{} {} {}", "WAF Detected:".bold(), "None".green(), format!("({})", waf).dimmed());
        } else {
            eprintln!("{} {}", "WAF Detected:".bold(), waf.red().bold());
        }
    } else {
        eprintln!("{} {}", "WAF Detected:".bold(), "None".green());
    }
    eprintln!();

    // Print findings table
    if results.findings.is_empty() {
        eprintln!("{}", "No successful bypasses found.".yellow());
    } else {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .set_content_arrangement(ContentArrangement::Dynamic);

        if verbose {
            table.set_header(vec![
                "Severity",
                "Category",
                "Payload",
                "Technique",
                "Status",
            ]);
        } else {
            table.set_header(vec!["Severity", "Category", "Payload", "Status"]);
        }

        for finding in &results.findings {
            let severity_str = format!("{}", finding.severity)
                .color(finding.severity.color())
                .to_string();

            let category_str = finding.category.green().to_string();
            let payload_str = if finding.payload_value.chars().count() > 50 {
                finding.payload_value.chars().take(47).collect::<String>() + "..."
            } else {
                finding.payload_value.clone()
            };

            let status_str = finding.response_status.to_string();

            if verbose {
                let technique_str = finding
                    .technique_used
                    .as_deref()
                    .unwrap_or("Original")
                    .cyan()
                    .to_string();

                table.add_row(vec![
                    severity_str,
                    category_str,
                    payload_str,
                    technique_str,
                    status_str,
                ]);

                // Print extracted data if available
                if let Some(ref extracted) = finding.extracted_data {
                    eprintln!("\n{}", "  Extracted Data:".yellow().bold());
                    
                    // Information disclosure
                    for disclosure in &extracted.info_disclosure {
                        eprintln!("    {} {}: {}", 
                            "➤".red(),
                            disclosure.disclosure_type.bold(),
                            disclosure.value.trim()
                        );
                    }
                    
                    // Exposed paths
                    if !extracted.exposed_paths.is_empty() {
                        eprintln!("    {} {}: {}", 
                            "➤".yellow(),
                            "Exposed Paths".bold(),
                            extracted.exposed_paths.join(", ")
                        );
                    }
                    
                    // Auth tokens
                    if !extracted.auth_tokens.is_empty() {
                        eprintln!("    {} {}: {} tokens found", 
                            "➤".cyan(),
                            "Auth Tokens".bold(),
                            extracted.auth_tokens.len()
                        );
                        for token in &extracted.auth_tokens {
                            eprintln!("       - {}: {}", token.token_type, token.name);
                        }
                    }
                    
                    // Version info
                    if let Some(ref version) = extracted.version_info {
                        if let Some(ref server) = version.server {
                            eprintln!("    {} {}: {}", "➤".blue(), "Server".bold(), server);
                        }
                        if let Some(ref framework) = version.framework {
                            eprintln!("    {} {}: {}", "➤".blue(), "Framework".bold(), framework);
                        }
                    }
                    
                    // Internal IPs
                    if !extracted.internal_ips.is_empty() {
                        eprintln!("    {} {}: {}", 
                            "➤".magenta(),
                            "Internal IPs".bold(),
                            extracted.internal_ips.join(", ")
                        );
                    }
                    
                    // ADFS metadata
                    if let Some(ref adfs) = extracted.adfs_metadata {
                        eprintln!("    {} {}", "➤".green(), "ADFS Metadata:".bold());
                        if let Some(ref id) = adfs.service_identifier {
                            eprintln!("       - Service ID: {}", id);
                        }
                        if !adfs.endpoints.is_empty() {
                            eprintln!("       - Endpoints: {}", adfs.endpoints.len());
                        }
                        if !adfs.claims.is_empty() {
                            eprintln!("       - Claims: {}", adfs.claims.join(", "));
                        }
                    }
                    
                    // Response snippet
                    if let Some(ref snippet) = extracted.response_snippet {
                        eprintln!("    {} {}: {}", 
                            "➤".white(),
                            "Response Preview".bold(),
                            snippet
                        );
                    }
                    
                    eprintln!();
                }
            } else {
                table.add_row(vec![severity_str, category_str, payload_str, status_str]);
            }
        }

        eprintln!("{}", table);
    }

    // Print summary
    eprintln!();
    eprintln!("{}", "─".repeat(70).cyan());
    eprintln!("{}", "  SUMMARY".bold());
    eprintln!("{}", "─".repeat(70).cyan());
    eprintln!("Total Payloads Tested: {}", results.summary.total_payloads);
    eprintln!(
        "Successful Bypasses: {}",
        results
            .summary
            .successful_bypasses
            .to_string()
            .green()
            .bold()
    );
    eprintln!(
        "Effective Techniques: {}",
        results.summary.techniques_effective
    );
    eprintln!("Scan Duration: {:.2}s", results.summary.duration_secs);
    eprintln!("{}", "═".repeat(70).cyan());
    eprintln!();
}

/// Print results as JSON
fn print_json_output(results: &ScanResults) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    println!("{}", json);
    Ok(())
}
