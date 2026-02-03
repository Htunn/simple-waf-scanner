# Manual Testing Guide for WAF Scanner

## Quick Feature Test

Run this command to test basic functionality:

```bash
./target/release/waf-scan https://api.simpleportchecker.com
```

When prompted, type `I ACCEPT` and press Enter.

## All Test Commands

### 1. Basic Scan
```bash
./target/release/waf-scan https://api.simpleportchecker.com
```

### 2. JSON Output
```bash
./target/release/waf-scan https://api.simpleportchecker.com --output-json > results.json
cat results.json | jq '.'
```

### 3. Verbose Mode (shows which evasion technique worked)
```bash
./target/release/waf-scan https://api.simpleportchecker.com --verbose
```

### 4. Specific Evasion Techniques
```bash
./target/release/waf-scan https://api.simpleportchecker.com --techniques encoding,case
```

### 5. Lower Concurrency (gentler on target)
```bash
./target/release/waf-scan https://api.simpleportchecker.com --concurrency 2 --delay 500
```

## Test Examples

```bash
# Test WAF fingerprinting
cargo run --example test_fingerprints

# Test payload detection
cargo run --example test_detection

# Test OWASP categories
cargo run --example owasp_categories
```

## Features to Verify

✅ Legal consent prompt displays and requires "I ACCEPT"
✅ WAF fingerprinting detects protection mechanisms
✅ All 280+ payloads load correctly (check startup message)
✅ OWASP Top 10:2025 categories are mapped to findings
✅ 7+ evasion techniques are applied
✅ Results display in formatted table
✅ JSON output is valid and complete
✅ Verbose mode shows technique details

## Expected Output

You should see:
1. Legal warning banner
2. Consent prompt
3. Scanning progress
4. WAF detection results
5. Findings table with severity, category, payload, and status
6. Summary statistics

## Testing Complete?

Once you've verified the features work, you can:

1. Push to git: `git push origin main`
2. Publish to crates.io: `cargo publish`
