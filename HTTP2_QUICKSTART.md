# HTTP/2 Quick Start Guide

## Overview

This scanner is now production-ready for HTTP/2 testing with full protocol support and comprehensive vulnerability detection.

## Quick Start

### 1. Basic HTTP/2 Scan

```bash
# Scan with HTTP/2 payloads
cargo run --release -- -t https://example.com -f payloads/http2-adfs-bypass.json
```

### 2. Production Scan (Recommended)

```bash
# Lower concurrency, add delay, save results
cargo run --release -- \
  -t https://production.example.com \
  -f payloads/http2-adfs-bypass.json \
  -c 5 \
  -d 200 \
  > http2-scan-results.txt
```

### 3. Test HTTP/2 Detection

```bash
# Run example to verify HTTP/2 support
cargo run --example http2_test
```

### 4. Verbose Logging

```bash
# See HTTP version detection and detailed logs
RUST_LOG=info cargo run --release -- -t https://example.com -f payloads/http2-adfs-bypass.json
```

## Key Features Enabled

✅ **HTTP/2 Prior Knowledge** - Direct HTTP/2 without upgrade  
✅ **Adaptive Flow Control** - Dynamic window management  
✅ **2MB Stream Window** - Optimized for performance  
✅ **4MB Connection Window** - Handles large transfers  
✅ **16KB Max Frame Size** - Efficient chunking  
✅ **Keep-Alive Pings** - 20s interval, 10s timeout  
✅ **Version Detection** - Automatic protocol logging  

## Production Checklist

Before scanning production systems:

- [ ] Obtain written authorization
- [ ] Use rate limiting (`-d 100` or higher)
- [ ] Limit concurrency (`-c 5-10`)
- [ ] Enable logging (`RUST_LOG=info`)
- [ ] Save results to file
- [ ] Monitor target system
- [ ] Have incident response ready

## HTTP/2 Vulnerabilities Tested

### Critical (Production Priority)
- ✓ CVE-2023-44487 - Rapid Reset DoS
- ✓ CVE-2024-27983 - CONTINUATION Flood
- ✓ HPACK Compression Bomb
- ✓ Flow Control Bypass

### High
- ✓ Request Smuggling
- ✓ Pseudo-Header Injection
- ✓ SETTINGS Frame Flood
- ✓ PRIORITY Frame Flood

### Medium
- ✓ Header Manipulation
- ✓ Method Override
- ✓ Stream Dependency Issues

## Examples

### Test Specific Vulnerability

```bash
# Test only Rapid Reset
cargo run --release -- -t https://example.com -f payloads/http2-adfs-bypass.json | grep "rapid-reset"
```

### Compliance Testing

```bash
# Full OWASP A02 testing (Security Misconfiguration)
cargo run --release -- -t https://example.com -f payloads/http2-adfs-bypass.json | grep "owasp-a02"
```

### High-Throughput Testing (Non-Production)

```bash
# Maximum speed (development/testing only)
cargo run --release -- -t https://test.example.com -f payloads/http2-adfs-bypass.json -c 50 -d 0
```

## Troubleshooting

### HTTP/1.1 Detected Instead of HTTP/2

**Symptom:** Log shows `HTTP/1.x detected`

**Solutions:**
- Verify target supports HTTP/2 (check headers: `curl -I --http2 https://example.com`)
- Some servers require ALPN negotiation
- Try different endpoints

### Connection Timeout

**Symptom:** Requests timing out

**Solutions:**
- Reduce concurrency: `-c 3`
- Add delay: `-d 500`
- Check firewall/rate limiting
- Increase timeout in code if needed

### Too Many Results

**Symptom:** Overwhelming number of findings

**Solutions:**
- Filter by severity: grep critical/high
- Test specific payloads
- Review false positives
- Adjust matchers in payload JSON

## Performance Tuning

| Scenario | Concurrency | Delay | Notes |
|----------|-------------|-------|-------|
| Production | 5-10 | 200-500ms | Safe, respectful |
| Staging | 10-20 | 100-200ms | Moderate load |
| Development | 20-50 | 50-100ms | Higher throughput |
| Lab/Testing | 50-100 | 0-50ms | Maximum speed |

## Next Steps

1. Review [HTTP2_PRODUCTION.md](HTTP2_PRODUCTION.md) for detailed documentation
2. Run example: `cargo run --example http2_test`
3. Test against your target with low settings first
4. Review findings and adjust based on results
5. Integrate into CI/CD pipeline if needed

## Support

- Documentation: `HTTP2_PRODUCTION.md`
- Examples: `examples/http2_test.rs`
- Payloads: `payloads/http2-adfs-bypass.json`
- Issues: Report bugs via GitHub

## Legal Notice

⚠️ **Always obtain authorization before testing.**

Unauthorized security testing is illegal and may result in:
- Criminal prosecution
- Civil liability
- Imprisonment
- Financial penalties

Use this tool responsibly and ethically.
