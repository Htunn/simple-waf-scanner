use simple_waf_scanner::{Config, ScanResults};
use owo_colors::OwoColorize;

/// Example demonstrating LLM-specific vulnerability scanning
/// 
/// This example shows how to:
/// 1. Configure the scanner for LLM endpoint testing
/// 2. Test for OWASP Top 10 for LLM Applications vulnerabilities
/// 3. Use LLM-specific evasion techniques
/// 4. Analyze results for prompt injection, jailbreaks, and system prompt leakage
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    println!("{}", "=== LLM Security Vulnerability Scanner ===".bright_cyan().bold());
    println!();

    // Example target: Replace with your LLM endpoint
    // NOTE: Only scan systems you own or have explicit permission to test
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://api.example.com/chat".to_string());

    println!("{} {}", "Target:".bright_yellow(), target);
    println!();

    // Configure scanner for LLM testing
    let mut config = Config::new(target.clone());
    config.llm_mode = true;
    config.semantic_analysis = true;
    config.concurrency = 5; // Lower concurrency for LLM APIs
    config.delay_ms = 500;  // Higher delay to respect rate limits
    config.verbose = true;

    // Enable LLM-specific evasion techniques
    config.enabled_techniques = Some(vec![
        "role-reversal".to_string(),
        "context-splitting".to_string(),
        "encoding-obfuscation".to_string(),
        "multilingual".to_string(),
        "delimiter-confusion".to_string(),
        "instruction-layering".to_string(),
    ]);

    println!("{}", "Enabled LLM Evasion Techniques:".bright_green());
    for technique in config.enabled_techniques.as_ref().unwrap() {
        println!("  • {}", technique);
    }
    println!();

    println!("{}", "OWASP Top 10 for LLM Applications Coverage:".bright_green());
    println!("  • LLM01: Prompt Injection");
    println!("  • LLM02: Sensitive Information Disclosure");
    println!("  • LLM03: Supply Chain Vulnerabilities");
    println!("  • LLM04: Data & Model Poisoning");
    println!("  • LLM05: Improper Output Handling");
    println!("  • LLM06: Excessive Agency");
    println!("  • LLM07: System Prompt Leakage");
    println!("  • LLM08: Vector & Embedding Weaknesses");
    println!("  • LLM09: Misinformation");
    println!("  • LLM10: Unbounded Consumption");
    println!();

    println!("{}", "Starting LLM vulnerability scan...".bright_cyan());
    println!();

    // Perform scan
    let results = simple_waf_scanner::scan(config).await?;
    print_llm_results(&results);

    Ok(())
}

/// Print LLM-specific scan results
fn print_llm_results(results: &ScanResults) {
    println!("{}", "=== LLM Vulnerability Scan Results ===".bright_cyan().bold());
    println!();

    // Summary
    println!("{}", "Summary:".bright_yellow().bold());
    println!("  Total Payloads Tested: {}", results.summary.total_payloads);
    println!("  Vulnerabilities Found: {}", results.summary.successful_bypasses.to_string().bright_red().bold());
    println!("  Scan Duration: {:.2}s", results.summary.duration_secs);
    println!();

    if results.summary.successful_bypasses == 0 {
        println!("{}", "✓ No LLM vulnerabilities detected".bright_green().bold());
        return;
    }

    // Group vulnerabilities by OWASP LLM category
    println!("{}", "Detected LLM Vulnerabilities:".bright_red().bold());
    println!();

    let mut llm_vulns: Vec<_> = results.findings.iter()
        .filter(|f| {
            if let Some(cat) = &f.owasp_category {
                format!("{:?}", cat).starts_with("LLM")
            } else {
                false
            }
        })
        .collect();
    
    llm_vulns.sort_by(|a, b| {
        let cat_a = format!("{:?}", a.owasp_category.as_ref().unwrap());
        let cat_b = format!("{:?}", b.owasp_category.as_ref().unwrap());
        cat_a.cmp(&cat_b)
    });

    let mut current_category = String::new();
    
    for vuln in llm_vulns {
        let category_str = format!("{:?}", vuln.owasp_category.as_ref().unwrap());
        
        // Print category header if changed
        if category_str != current_category {
            current_category = category_str.clone();
            println!();
            println!("{} {}", "┌─".bright_cyan(), get_llm_category_description(&current_category).bright_cyan().bold());
            println!("{}", "├───────────────────────────────────────────────────".bright_cyan());
        }

        // Print vulnerability details
        let severity_color = match vuln.severity {
            simple_waf_scanner::types::Severity::Critical => "red",
            simple_waf_scanner::types::Severity::High => "red",
            simple_waf_scanner::types::Severity::Medium => "yellow",
            simple_waf_scanner::types::Severity::Low => "blue",
            simple_waf_scanner::types::Severity::Info => "white",
        };

        println!("│");
        println!("│ {} {}", "Payload ID:".bright_white(), vuln.payload_id);
        println!("│ {} {}", "Severity:".bright_white(), format_severity(&format!("{:?}", vuln.severity), severity_color));
        println!("│ {} {}", "Payload Value:".bright_white(), vuln.payload_value);
        
        if let Some(technique) = &vuln.technique_used {
            println!("│ {} {}", "Evasion Technique:".bright_white(), technique.bright_yellow());
        }

        // LLM-specific extracted data
        if let Some(extracted) = &vuln.extracted_data {
            if !extracted.system_prompts.is_empty() {
                println!("│ {} {:?}", "System Prompts Found:".bright_red(), extracted.system_prompts);
            }
            if !extracted.model_info.is_empty() {
                println!("│ {} {:?}", "Model Info Leaked:".bright_red(), extracted.model_info);
            }
            if !extracted.training_data_leaked.is_empty() {
                println!("│ {} {:?}", "Training Data Leaked:".bright_red(), extracted.training_data_leaked);
            }
            if !extracted.rag_context.is_empty() {
                println!("│ {} {:?}", "RAG Context Exposed:".bright_red(), extracted.rag_context);
            }
            if !extracted.jailbreak_indicators.is_empty() {
                println!("│ {} {:?}", "Jailbreak Success:".bright_red(), extracted.jailbreak_indicators);
            }

            if let Some(snippet) = &extracted.response_snippet {
                println!("│ {} {}", "Response Snippet:".bright_white(), snippet);
            }
        }

        println!("│ {} {}", "Description:".bright_white(), vuln.description);
    }

    println!("{}", "└───────────────────────────────────────────────────".bright_cyan());
    println!();

    // Recommendations
    println!("{}", "Security Recommendations:".bright_yellow().bold());
    println!("  1. Implement robust input validation and sanitization");
    println!("  2. Use structured prompts with clear delimiters");
    println!("  3. Apply output filtering for generated content");
    println!("  4. Set up monitoring for jailbreak attempts");
    println!("  5. Limit system prompt exposure in error messages");
    println!("  6. Implement rate limiting and token budgets");
    println!("  7. Use LLM guardrails (e.g., Guardrails AI, NeMo Guardrails)");
    println!("  8. Regular security audits of LLM integrations");
    println!();

    println!("{}", "For more information, visit:".bright_white());
    println!("  • https://genai.owasp.org/");
    println!("  • https://owasp.org/www-project-top-10-for-large-language-model-applications/");
}

/// Get human-readable description for LLM category
fn get_llm_category_description(category: &str) -> String {
    match category {
        "LLM01" => "LLM01: Prompt Injection".to_string(),
        "LLM02" => "LLM02: Sensitive Information Disclosure".to_string(),
        "LLM03" => "LLM03: Supply Chain Vulnerabilities".to_string(),
        "LLM04" => "LLM04: Data & Model Poisoning".to_string(),
        "LLM05" => "LLM05: Improper Output Handling".to_string(),
        "LLM06" => "LLM06: Excessive Agency".to_string(),
        "LLM07" => "LLM07: System Prompt Leakage".to_string(),
        "LLM08" => "LLM08: Vector & Embedding Weaknesses".to_string(),
        "LLM09" => "LLM09: Misinformation".to_string(),
        "LLM10" => "LLM10: Unbounded Consumption".to_string(),
        _ => category.to_string(),
    }
}

/// Format severity with color
fn format_severity(severity: &str, color: &str) -> String {
    match color {
        "red" => severity.red().bold().to_string(),
        "yellow" => severity.yellow().bold().to_string(),
        "blue" => severity.blue().bold().to_string(),
        _ => severity.white().to_string(),
    }
}
