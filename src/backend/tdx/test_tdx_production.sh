#!/bin/bash
# Production readiness test script for TDX implementation
# This script validates that the TDX attestation code is in a production-ready state
# by checking for common issues, verifying dependencies, and doing basic validation.

set -e  # Exit on any error
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'  # No Color

echo -e "${YELLOW}Starting TDX Production Readiness Testing${NC}"
echo "======================================================"

# Navigate to project root
cd "$(dirname "$0")/../../../.."
PROJECT_ROOT=$(pwd)

# Check for required dependencies
echo -e "\n${YELLOW}Checking for required system dependencies:${NC}"
check_dependency() {
    if command -v $1 &> /dev/null; then
        echo -e "${GREEN}✓ $1 found${NC}"
    else
        echo -e "${RED}✗ $1 not found - required for production TDX${NC}"
        MISSING_DEPS=1
    fi
}

# System dependencies
check_dependency "ldconfig"  # For checking shared libs
check_dependency "curl"      # For PCS API
check_dependency "jq"        # For JSON processing

# Check Intel QVL library availability
echo -e "\n${YELLOW}Checking for Intel QVL libraries:${NC}"
if ldconfig -p | grep libsgx_dcap_quoteverify > /dev/null; then
    echo -e "${GREEN}✓ Intel QVL verification library found${NC}"
else
    echo -e "${YELLOW}⚠ Intel QVL library not found - will test in fallback mode${NC}"
    echo "   For production: apt install libsgx-dcap-quote-verify"
fi

# Check for placeholder values in the code
echo -e "\n${YELLOW}Checking for simulation and placeholder values:${NC}"
grep_check() {
    local pattern="$1"
    local desc="$2"
    local file="$PROJECT_ROOT/src/backend/tdx/attestation.rs"
    
    if grep -n "$pattern" "$file" > /dev/null; then
        echo -e "${RED}✗ Found $desc - not production ready${NC}"
        grep -n --color=always "$pattern" "$file" | head -3
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
grep_check "unwrap()" "unwrap calls (should use proper error handling)"
grep_check "expect(" "expect calls (should use proper error handling)"

# Validate parameter validation
echo -e "\n${YELLOW}Checking for parameter validation patterns:${NC}"
validation_check() {
    local pattern="$1"
    local expected="$2"
    local file="$PROJECT_ROOT/src/backend/tdx/attestation.rs"
    local count=$(grep -c "$pattern" "$file")
    
    if [ "$count" -ge "$expected" ]; then
        echo -e "${GREEN}✓ Found $count occurrences of $pattern validation${NC}"
    else
        echo -e "${RED}✗ Only found $count occurrences of $pattern validation, expected at least $expected${NC}"
        MISSING_VALIDATION=1
    fi
}

# Check for common validation patterns
validation_check "if .* > MAX_REASONABLE" 5
validation_check "if .* == 0 {" 5
validation_check "Error::new(ErrorKind::" 5
validation_check "bail!" 5
validation_check "ensure!" 3
validation_check "context" 5

# Check dual-format parameter handling
echo -e "\n${YELLOW}Checking for dual-format parameter handling:${NC}"
file="$PROJECT_ROOT/src/backend/tdx/attestation.rs"
if grep -n "from_le_bytes" "$file" > /dev/null && grep -n "let length =" "$file" > /dev/null; then
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
    local file="$PROJECT_ROOT/src/backend/tdx/attestation.rs"
    local count=$(grep -c "$pattern" "$file")
    
    if [ "$count" -ge "$expected" ]; then
        echo -e "${GREEN}✓ Found $count $pattern statements${NC}"
    else
        echo -e "${RED}✗ Only found $count $pattern statements, expected at least $expected${NC}"
        MISSING_LOGGING=1
    fi
}

log_check "error!" 5
log_check "warn!" 5
log_check "debug!" 8
log_check "info!" 3

# Test compilation with TDX features
echo -e "\n${YELLOW}Testing compilation with TDX features:${NC}"
if cargo check --features=tdx; then
    echo -e "${GREEN}✓ Code compiles with TDX features${NC}"
else
    echo -e "${RED}✗ Code fails to compile with TDX features${NC}"
    COMPILE_FAILURE=1
fi

# Summarize findings
echo -e "\n${YELLOW}Production Readiness Summary:${NC}"
echo "=============================="

if [ -n "$MISSING_DEPS" ] || [ -n "$FOUND_PLACEHOLDERS" ] || [ -n "$MISSING_VALIDATION" ] || \
   [ -n "$MISSING_PATTERNS" ] || [ -n "$MISSING_LOGGING" ] || [ -n "$COMPILE_FAILURE" ]; then
    echo -e "${RED}✗ Code is NOT fully production-ready${NC}"
    
    [ -n "$MISSING_DEPS" ] && echo -e "  - ${RED}Missing required dependencies${NC}"
    [ -n "$FOUND_PLACEHOLDERS" ] && echo -e "  - ${RED}Contains placeholders or simulation code${NC}"
    [ -n "$MISSING_VALIDATION" ] && echo -e "  - ${RED}Insufficient parameter validation${NC}"
    [ -n "$MISSING_PATTERNS" ] && echo -e "  - ${RED}Missing dual-format parameter handling${NC}"
    [ -n "$MISSING_LOGGING" ] && echo -e "  - ${RED}Insufficient error logging${NC}"
    [ -n "$COMPILE_FAILURE" ] && echo -e "  - ${RED}Code does not compile with TDX features${NC}"
    
    echo -e "\n${YELLOW}Recommendations to address issues:${NC}"
    echo "1. Install any missing dependencies"
    echo "2. Replace any placeholder values with real implementations"
    echo "3. Add proper parameter validation (bounds checking, null checks, etc.)"
    echo "4. Implement or fix dual-format parameter handling"
    echo "5. Add comprehensive error logging"
    echo "6. Fix compilation issues"
    
    exit 1
else
    echo -e "${GREEN}✓ TDX implementation appears production-ready!${NC}"
    echo -e "\n${YELLOW}Recommendations for further validation:${NC}"
    echo "1. Test on actual TDX hardware when available"
    echo "2. Perform security audit of the implementation"
    echo "3. Test with Intel PCS API using valid API keys"
    echo "4. Verify TCB handling with different expiry scenarios"
    echo "5. Test accumulator verification with known measurements"
    
    exit 0
fi
