# LLM Mode Improvements

## Summary
Implemented automatic optimization for LLM/GenAI security testing to prevent timeouts and rate limiting issues.

## Changes Made

### 1. Auto-Adjusted Defaults for LLM Mode (`src/main.rs`)
- **Before**: Used web app defaults (concurrency=10, delay=100ms) for all scans
- **After**: Automatically detects `--llm-mode` and adjusts defaults:
  - Concurrency: `10` → `3` (reduces load on LLM endpoints)
  - Delay: `100ms` → `500ms` (gives LLM more time between requests)
- Users can still override with `--concurrency` and `--delay` flags

### 2. Increased Timeout for LLM Mode (`src/http.rs`)
- **Before**: Fixed 30-second timeout for all requests
- **After**: Dynamic timeout based on mode:
  - Web app mode: `30 seconds`
  - LLM mode: `60 seconds` (LLM inference takes longer)

### 3. Added Rate Limit Retry Logic (`src/http.rs`)
- **Before**: Failed immediately on 429 (rate limit) responses
- **After**: Automatically retries with exponential backoff:
  - Max retries: `3`
  - Backoff: `1s, 2s, 4s` (exponential)
  - Logs retry attempts for visibility

### 4. Updated Help Documentation (`src/main.rs`)
- Updated CLI help text to reflect automatic optimizations
- Made it clear that LLM mode "just works" with optimal settings
- Users can still override if they have specific requirements

## Technical Details

### Code Changes

#### `src/main.rs`
```rust
// Changed CLI args to Option types to detect user overrides
concurrency: Option<usize>,  // was: usize with default_value = "10"
delay: Option<u64>,          // was: u64 with default_value = "100"

// Auto-adjust defaults based on llm_mode
if args.llm_mode {
    config.concurrency = args.concurrency.unwrap_or(3);
    config.delay_ms = args.delay.unwrap_or(500);
} else {
    config.concurrency = args.concurrency.unwrap_or(10);
    config.delay_ms = args.delay.unwrap_or(100);
}
```

#### `src/http.rs`
```rust
// Dynamic timeout based on mode
let timeout_secs = if config.llm_mode { 60 } else { 30 };

// Retry loop for rate limiting
for retry_count in 0..=max_retries {
    // Send request...
    if status == 429 && retry_count < max_retries {
        let backoff_ms = 1000 * 2_u64.pow(retry_count as u32);
        tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
        continue;
    }
    return Ok(response);
}
```

## Benefits

1. **Prevents Hanging**: 60-second timeout prevents indefinite hangs on slow LLM responses
2. **Reduces Rate Limiting**: Lower concurrency (3 vs 10) and higher delay (500ms vs 100ms) reduce 429 errors
3. **Automatic Recovery**: Retry logic with exponential backoff handles temporary rate limits
4. **Better User Experience**: Works out-of-the-box without requiring advanced configuration
5. **Maintains Flexibility**: Users can still override settings if needed

## Testing

### Before Improvements
```bash
# This would hang or fail with rate limiting
./target/release/waf-scan https://mcp.simpleportchecker.com/mcp --llm-mode
# Result: Timeout or 429 rate limit errors
```

### After Improvements
```bash
# Now works automatically with optimal settings
./target/release/waf-scan https://mcp.simpleportchecker.com/mcp --llm-mode
# Result: Successful scan with concurrency=3, delay=500ms, timeout=60s

# Can still override if needed
./target/release/waf-scan https://example.com/api --llm-mode --concurrency 5 --delay 1000
# Result: Uses custom settings (concurrency=5, delay=1000ms)
```

## Backward Compatibility

✅ **Fully backward compatible**
- Existing commands without `--llm-mode` use the same defaults as before
- Existing commands WITH explicit `--concurrency` or `--delay` respect user overrides
- No breaking changes to CLI interface or behavior

## Version

These improvements are included in version `0.1.5`.
