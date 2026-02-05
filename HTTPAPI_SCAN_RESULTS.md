# Microsoft HTTPAPI Bypass Scan Results

## Target Information
- **URL**: https://fs.example.com/adfs/ls
- **Date**: February 5, 2026
- **WAF Detected**: Cloudflare
- **Backend Server**: Microsoft HTTPAPI/2.0
- **HTTP Version**: HTTP/1.1

## Summary
- **Total Payloads Tested**: 14 payload categories
- **Successful Bypasses**: 318
- **Scan Duration**: 6.05 seconds

## Key Findings

### Critical Severity Bypasses

The scan identified multiple **CRITICAL** severity bypasses against the Microsoft HTTPAPI backend:

#### 1. Unicode Normalization Bypasses (CRITICAL)
Successfully bypassed using overlong UTF-8 sequences:
- `/%c0%af` - Overlong encoding of forward slash
- `/%c1%9c` - Overlong encoding variant
- `/%c0%ae%c0%ae/` - Overlong encoding of "../"
- `/%e0%80%af` - 3-byte overlong UTF-8
- `/%f0%80%80%af` - 4-byte overlong UTF-8

**Impact**: These bypasses exploit HTTPAPI's UTF-8 normalization vulnerabilities, potentially allowing:
- Path traversal attacks
- Access control bypass
- Directory listing exposure

#### 2. Evasion Techniques That Worked
All payloads were successful with multiple evasion techniques:
- **Original payload** - Base payload accepted (200 OK)
- **URL Encoding** - Single URL encoding bypassed filters
- **Double URL Encoding** - Double encoding bypassed detection
- **Case Variation** - Mixed case bypassed pattern matching
- **Null Byte Injection** - Null bytes (%00) bypassed validation
- **Comment Injection** - SQL-style comments (**/) bypassed filters

#### 3. ADFS-Specific Bypasses
ADFS authentication bypass attempts returned 200 OK status, indicating potential vulnerabilities in:
- `/adfs/ls/?wa=wsignin1.0%00` - Null byte in ADFS parameter
- `/adfs/ls/../portal/` - Path traversal in ADFS context
- `/adfs/ls/.%2e/services/` - Mixed encoding path traversal

#### 4. Header Smuggling Vectors
Header injection payloads returned successful responses:
- `?test=1\r\nX-Forwarded-For: 127.0.0.1` - CRLF injection
- `?test=1%0d%0aTransfer-Encoding:%20chunked` - Transfer-Encoding manipulation

#### 5. HTTP Verb Tampering
Alternative HTTP methods returned non-blocked responses:
- TRACE method accepted
- TRACK method accepted  
- OPTIONS method accepted

## Security Recommendations

### Immediate Actions Required

1. **Apply Latest Security Patches**
   - Update Windows Server to latest patch level
   - Apply HTTPAPI/HTTP.sys security updates
   - Review CVE-2015-1635 (MS15-034) patch status
   - Review CVE-2023-23392 (HTTP.sys RCE) patch status

2. **Strengthen Input Validation**
   - Implement strict UTF-8 validation
   - Reject overlong UTF-8 sequences
   - Block null byte injections
   - Normalize URLs before security checks

3. **Enhance WAF Rules**
   - Update Cloudflare rules to detect overlong UTF-8
   - Add rules for Unicode normalization attacks
   - Block CRLF injection attempts
   - Implement strict HTTP method whitelisting

4. **ADFS Hardening**
   - Review ADFS authentication flow
   - Implement path traversal protection
   - Validate all query parameters
   - Enable ADFS logging and monitoring

5. **Network Segmentation**
   - Place ADFS behind additional security layers
   - Implement geo-blocking if applicable
   - Enable rate limiting per IP
   - Monitor for suspicious patterns

### Long-term Improvements

1. **Web Application Firewall Tuning**
   - Enable OWASP Core Rule Set
   - Configure custom rules for HTTPAPI quirks
   - Implement request normalization
   - Add anomaly detection

2. **Security Monitoring**
   - Log all authentication attempts
   - Monitor for path traversal patterns
   - Alert on encoding manipulation
   - Track failed authentication rates

3. **Architecture Review**
   - Consider modern authentication alternatives
   - Evaluate OAuth 2.0 / OIDC migration
   - Implement zero-trust architecture
   - Add additional reverse proxy layer

## Technical Details

### Vulnerable Components
- **Microsoft HTTPAPI 2.0** - Kernel-mode HTTP driver
- **ADFS (Active Directory Federation Services)** - Federation server
- **Cloudflare WAF** - Currently bypassed by encoding techniques

### Attack Vectors Confirmed
1. UTF-8 overlong encoding bypass
2. Mixed encoding attacks
3. Path traversal via normalization
4. CRLF injection in query parameters
5. HTTP verb tampering
6. Null byte injection

### References
- CVE-2015-1635: HTTP.sys Remote Code Execution
- CVE-2017-7269: IIS 6.0 WebDAV Buffer Overflow  
- CVE-2023-23392: HTTP.sys Request Smuggling
- CVE-2023-44487: HTTP/2 Rapid Reset
- CVE-2021-42306: ADFS Security Feature Bypass

## Payload File Location
Custom Microsoft HTTPAPI bypass payloads: `payloads/microsoft-httpapi-bypass.json`

## Next Steps

1. **Immediate**: Verify patch levels on production ADFS server
2. **Short-term**: Update WAF rules and test mitigation
3. **Long-term**: Plan ADFS security architecture review

---

**Note**: This scan was conducted for authorized security testing purposes only. All findings should be addressed according to your organization's vulnerability management process.
