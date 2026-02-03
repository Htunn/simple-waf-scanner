use clap::Parser;
use comfy_table::{presets::UTF8_FULL, ContentArrangement, Table};
use is_terminal::IsTerminal;
use owo_colors::OwoColorize;
use simple_waf_scanner::{Config, ScanResults};
use std::io::{self, Write};

#[derive(Parser)]
#[command(name = "waf-scan")]
#[command(about = "WAF detection and bypass testing tool", long_about = None)]
#[command(version)]
struct Args {
    /// Target URL to scan
    target: String,

    /// Path to custom payload file (JSON format)
    #[arg(long)]
    payload_file: Option<String>,

    /// Number of concurrent requests
    #[arg(long, default_value = "10")]
    concurrency: usize,

    /// Delay between requests in milliseconds
    #[arg(long, default_value = "100")]
    delay: u64,

    /// Comma-separated list of evasion techniques to use
    /// Available: encoding, double-encode, case, null-bytes, comments, unicode, path-traversal
    #[arg(long)]
    techniques: Option<String>,

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
    config.concurrency = args.concurrency;
    config.delay_ms = args.delay;
    config.payload_file = args.payload_file;
    config.verbose = args.verbose;

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
        eprintln!("{}", "ERROR: This tool requires interactive terminal consent.".red().bold());
        eprintln!("{}", "Automated/scripted execution is not permitted.".red());
        std::process::exit(1);
    }

    // Display legal warning
    println!("\n{}", "⚠️  LEGAL WARNING".red().bold());
    println!("{}", "─".repeat(70).yellow());
    println!("This tool performs security testing that may:");
    println!("  • Send malicious payloads to web servers");
    println!("  • Trigger security alerts and logging");
    println!("  • Violate laws if used without authorization");
    println!();
    println!(
        "{}",
        "You MUST have explicit written permission to scan the target."
            .red()
            .bold()
    );
    println!();
    println!("Unauthorized access to computer systems is a violation of:");
    println!("  • Computer Fraud and Abuse Act (CFAA) in the United States");
    println!("  • Computer Misuse Act in the United Kingdom");
    println!("  • Similar laws in other jurisdictions");
    println!();
    println!("The authors assume NO LIABILITY for misuse of this tool.");
    println!("{}", "─".repeat(70).yellow());

    // Require exact consent
    loop {
        print!("\n{}", "Type 'I ACCEPT' to confirm you have authorization: ".cyan());
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        let trimmed = input.trim();

        if trimmed == "I ACCEPT" {
            println!("{}", "✓ Consent confirmed. Proceeding with scan...\n".green());
            return Ok(());
        } else if trimmed.to_lowercase() == "no" || trimmed.is_empty() {
            println!("{}", "Scan cancelled.".yellow());
            std::process::exit(0);
        } else {
            println!("{}", "Invalid input. Please type 'I ACCEPT' exactly.".red());
        }
    }
}

/// Print results in pretty table format
fn print_pretty_output(results: &ScanResults, verbose: bool) {
    // Print WAF detection banner
    println!("\n{}", "═".repeat(70).cyan());
    println!("{}", "  WAF BYPASS SCAN RESULTS".cyan().bold());
    println!("{}", "═".repeat(70).cyan());
    println!();

    println!("{} {}", "Target:".bold(), results.target);
    println!("{} {}", "Timestamp:".bold(), results.timestamp);

    if let Some(ref waf) = results.waf_detected {
        println!(
            "{} {}",
            "WAF Detected:".bold(),
            waf.red().bold()
        );
    } else {
        println!("{} {}", "WAF Detected:".bold(), "None".green());
    }
    println!();

    // Print findings table
    if results.findings.is_empty() {
        println!("{}", "No successful bypasses found.".yellow());
    } else {
        let mut table = Table::new();
        table
            .load_preset(UTF8_FULL)
            .set_content_arrangement(ContentArrangement::Dynamic);

        if verbose {
            table.set_header(vec!["Severity", "Category", "Payload", "Technique", "Status"]);
        } else {
            table.set_header(vec!["Severity", "Category", "Payload", "Status"]);
        }

        for finding in &results.findings {
            let severity_str = format!("{}", finding.severity)
                .color(finding.severity.color())
                .to_string();

            let category_str = finding.category.green().to_string();
            let payload_str = if finding.payload_value.len() > 50 {
                format!("{}...", &finding.payload_value[..47])
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
            } else {
                table.add_row(vec![severity_str, category_str, payload_str, status_str]);
            }
        }

        println!("{}", table);
    }

    // Print summary
    println!();
    println!("{}", "─".repeat(70).cyan());
    println!("{}", "  SUMMARY".bold());
    println!("{}", "─".repeat(70).cyan());
    println!(
        "Total Payloads Tested: {}",
        results.summary.total_payloads
    );
    println!(
        "Successful Bypasses: {}",
        results.summary.successful_bypasses.to_string().green().bold()
    );
    println!(
        "Effective Techniques: {}",
        results.summary.techniques_effective
    );
    println!(
        "Scan Duration: {:.2}s",
        results.summary.duration_secs
    );
    println!("{}", "═".repeat(70).cyan());
    println!();
}

/// Print results as JSON
fn print_json_output(results: &ScanResults) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(results)?;
    println!("{}", json);
    Ok(())
}
