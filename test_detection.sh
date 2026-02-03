#!/bin/bash
cat << 'CONSENT' | ./target/release/waf-scan "$@"
I ACCEPT
CONSENT
