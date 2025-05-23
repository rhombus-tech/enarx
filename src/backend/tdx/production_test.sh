#!/bin/bash
# Production readiness test script for TDX implementation
# This script validates that the TDX attestation code is in a production-ready state
# by checking for common issues and verifying the implementation.

set -e  # Exit on any error
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'  # No Color

echo -e "${YELLOW}Starting TDX Production Readiness Testing${NC}"
echo "======================================================"

# Determine OS type and set paths accordingly
if [[ "$OSTYPE" == "darwin"* ]]; then
    IS_MAC=1
    echo "Detected macOS environment"
else
    IS_MAC=0
    echo "Detected Linux environment"
fi

# Navigate to project root based on script location
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
ATTESTATION_FILE="$PROJECT_ROOT/src/backend/tdx/attestation.rs"

echo "Project root: $PROJECT_ROOT"
echo "Attestation file: $ATTESTATION_FILE"

if [ ! -f "$ATTESTATION_FILE" ]; then
    echo -e "${RED}Could not find attestation.rs file at $ATTESTATION_FILE${NC}"
    exit 1
fi

# Check for required dependencies
echo -e "\n${YELLOW}Checking for required system dependencies:${NC}"
check_dependency() {
    if command -v $1 &> /dev/null; then
        echo -e "${GREEN}✓ $1 found${NC}"
    else
        echo -e "${YELLOW}⚠ $1 not found - may be needed for production${NC}"
        MISSING_DEPS=1
    fi
}

# System dependencies
check_dependency "curl"      # For PCS API
check_dependency "jq"        # For JSON processing

# Check for Intel QVL library availability
echo -e "\n${YELLOW}Checking for Intel QVL libraries:${NC}"
if [ $IS_MAC -eq 1 ]; then
    echo -e "${YELLOW}⚠ Running on macOS, skipping library check${NC}"
    echo "   For production: Intel QVL libraries must be installed on Linux systems"
else
    if ldconfig -p | grep libsgx_dcap_quoteverify > /dev/null; then
        echo -e "${GREEN}✓ Intel QVL verification library found${NC}"
    else
        echo -e "${YELLOW}⚠ Intel QVL library not found - will test in fallback mode${NC}"
        echo "   For production: apt install libsgx-dcap-quote-verify"
    fi
fi

# Check for placeholder values in the code
echo -e "\n${YELLOW}Checking for simulation and placeholder values:${NC}"
grep_check() {
    local pattern="$1"
    local desc="$2"
    
    if grep -n "$pattern" "$ATTESTATION_FILE" > /dev/null; then
        echo -e "${RED}✗ Found $desc - not production ready${NC}"
        grep -n --color=always "$pattern" "$ATTESTATION_FILE" | head -3
        FOUND_PLACEHOLDERS=1
    else
        echo -e "${GREEN}✓ No $desc found${NC}"
    fi
}

# Common placeholder patterns to check
grep_check "TODO" "TODOs"
grep_check "FIXME" "FIXMEs"
grep_check "simulation" "simulation code"
grep_check "\"AAAAAAAAAAAAAAAA\"" "hardcoded base64 values"
grep_check "0x4141414141414141" "hardcoded hex values"
grep_check "dummy_" "dummy test functions/variables"
grep_check "panic!" "panic statements (should use proper error handling)"
grep_check "unwrap()" "unwrap calls without error handling"
grep_check "expect(" "expect calls without error handling"

# Validate parameter validation
echo -e "\n${YELLOW}Checking for parameter validation patterns:${NC}"
validation_check() {
    local pattern="$1"
    local expected="$2"
    local count=$(grep -c "$pattern" "$ATTESTATION_FILE" || echo 0)
    
    if [ "$count" -ge "$expected" ]; then
        echo -e "${GREEN}✓ Found $count occurrences of $pattern validation${NC}"
    else
        echo -e "${RED}✗ Only found $count occurrences of $pattern validation, expected at least $expected${NC}"
        MISSING_VALIDATION=1
    fi
}

# Check for common validation patterns
validation_check "if .* > MAX_REASONABLE" 2
validation_check "if .* == 0 {" 3
validation_check "Error::new(ErrorKind::" 2
validation_check "bail!" 3
validation_check "ensure!" 1
validation_check "context" 3

# Check dual-format parameter handling
echo -e "\n${YELLOW}Checking for dual-format parameter handling:${NC}"
if grep -n "from_le_bytes" "$ATTESTATION_FILE" > /dev/null && grep -n "let length =" "$ATTESTATION_FILE" > /dev/null; then
    echo -e "${GREEN}✓ Found dual-format parameter handling pattern${NC}" 
else
    echo -e "${RED}✗ Missing dual-format parameter handling${NC}"
    MISSING_PATTERNS=1
fi

# Check for error logging
echo -e "\n${YELLOW}Checking for proper error logging:${NC}"
log_check() {
    local pattern="$1"
    local expected="$2"
    local count=$(grep -c "$pattern" "$ATTESTATION_FILE" || echo 0)
    
    if [ "$count" -ge "$expected" ]; then
        echo -e "${GREEN}✓ Found $count $pattern statements${NC}"
    else
        echo -e "${RED}✗ Only found $count $pattern statements, expected at least $expected${NC}"
        MISSING_LOGGING=1
    fi
}

log_check "error!" 3
log_check "warn!" 3
log_check "debug!" 5
log_check "info!" 2

# Check for FMSPC extraction logic (which was fixed)
echo -e "\n${YELLOW}Checking for proper FMSPC extraction logic:${NC}"
if grep -n "extract_fmspc" "$ATTESTATION_FILE" > /dev/null; then
    FMSPC_IMPLEMENTATION=$(grep -A 20 "fn extract_fmspc" "$ATTESTATION_FILE")
    if [[ "$FMSPC_IMPLEMENTATION" == *"hardcoded"* ]] || [[ "$FMSPC_IMPLEMENTATION" == *"placeholder"* ]]; then
        echo -e "${RED}✗ FMSPC extraction still uses hardcoded/placeholder values${NC}"
        FOUND_PLACEHOLDERS=1
    else
        echo -e "${GREEN}✓ FMSPC extraction appears to use real parsing logic${NC}"
    fi
else
    echo -e "${RED}✗ Could not find FMSPC extraction function${NC}"
    MISSING_FUNCTIONS=1
fi

# Check for verification methods
echo -e "\n${YELLOW}Checking for dual verification paths:${NC}"
if grep -n "verify_with_intel_qvl" "$ATTESTATION_FILE" > /dev/null; then
    echo -e "${GREEN}✓ Found Intel QVL verification path${NC}"
else
    echo -e "${RED}✗ Missing Intel QVL verification path${NC}"
    MISSING_FUNCTIONS=1
fi

if grep -n "verify_measurement_with_accumulator" "$ATTESTATION_FILE" > /dev/null; then
    echo -e "${GREEN}✓ Found accumulator verification path${NC}"
else
    echo -e "${RED}✗ Missing accumulator verification path${NC}"
    MISSING_FUNCTIONS=1
fi

# Summarize findings
echo -e "\n${YELLOW}Production Readiness Summary:${NC}"
echo "=============================="

if [ -n "$FOUND_PLACEHOLDERS" ] || [ -n "$MISSING_VALIDATION" ] || \
   [ -n "$MISSING_PATTERNS" ] || [ -n "$MISSING_LOGGING" ] || [ -n "$MISSING_FUNCTIONS" ]; then
    echo -e "${RED}✗ Code is NOT fully production-ready${NC}"
    
    [ -n "$FOUND_PLACEHOLDERS" ] && echo -e "  - ${RED}Contains placeholders or simulation code${NC}"
    [ -n "$MISSING_VALIDATION" ] && echo -e "  - ${RED}Insufficient parameter validation${NC}"
    [ -n "$MISSING_PATTERNS" ] && echo -e "  - ${RED}Missing dual-format parameter handling${NC}"
    [ -n "$MISSING_LOGGING" ] && echo -e "  - ${RED}Insufficient error logging${NC}"
    [ -n "$MISSING_FUNCTIONS" ] && echo -e "  - ${RED}Missing critical functions${NC}"
    
    echo -e "\n${YELLOW}Recommendations to address issues:${NC}"
    echo "1. Replace any placeholder values with real implementations"
    echo "2. Add proper parameter validation (bounds checking, null checks, etc.)"
    echo "3. Implement or fix dual-format parameter handling"
    echo "4. Add comprehensive error logging"
    echo "5. Implement missing functionality"
    
    exit 1
else
    echo -e "${GREEN}✓ TDX implementation appears production-ready!${NC}"
    echo -e "\n${YELLOW}Next steps for validation:${NC}"
    echo "1. Test on actual TDX hardware when available"
    echo "2. Verify with Intel PCS API using valid API keys"
    echo "3. Test accumulator verification with known measurements"
    echo "4. Conduct performance comparison between QVL and accumulator paths"
    
    exit 0
fi
