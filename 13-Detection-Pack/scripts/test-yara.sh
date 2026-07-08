#!/bin/bash
# Automated YARA test runner for Coinhive cryptominer rules
# Usage: ./test-yara.sh
# Depends on: yara (>= 4.x), 04-YARA/yara-coinhive-miner.yar

set -euo pipefail

YARA_RULE="../../04-YARA/yara-coinhive-miner.yar"
SAMPLES_DIR="../test-samples"
PASS=0
FAIL=0
TOTAL=0

if ! command -v yara &> /dev/null; then
    echo "ERROR: yara not found. Install with: sudo apt install -y yara"
    exit 1
fi

if [ ! -f "$YARA_RULE" ]; then
    echo "ERROR: YARA rule file not found at $YARA_RULE"
    exit 1
fi

echo "=== YARA Coinhive Detection Test Suite ==="
echo "Rule: $YARA_RULE"
echo ""

# Test 1: coinhive-test.js -> should match Coinhive_JS_Miner_Generic
echo -n "[TEST] coinhive-test.js -> Coinhive_JS_Miner_Generic ... "
TOTAL=$((TOTAL + 1))
RESULT=$(yara "$YARA_RULE" "$SAMPLES_DIR/coinhive-test.js" 2>&1 || true)
if echo "$RESULT" | grep -q "Coinhive_JS_Miner_Generic"; then
    echo "PASS"
    PASS=$((PASS + 1))
else
    echo "FAIL (expected Coinhive_JS_Miner_Generic)"
    echo "  Output: $RESULT"
    FAIL=$((FAIL + 1))
fi

# Test 2: coinhive-test-ws.js -> should match Coinhive_JS_Miner_Generic
echo -n "[TEST] coinhive-test-ws.js -> Coinhive_JS_Miner_Generic ... "
TOTAL=$((TOTAL + 1))
RESULT=$(yara "$YARA_RULE" "$SAMPLES_DIR/coinhive-test-ws.js" 2>&1 || true)
if echo "$RESULT" | grep -q "Coinhive_JS_Miner_Generic"; then
    echo "PASS"
    PASS=$((PASS + 1))
else
    echo "FAIL (expected Coinhive_JS_Miner_Generic)"
    echo "  Output: $RESULT"
    FAIL=$((FAIL + 1))
fi

# Test 3: coinhive-injected.html -> should match Coinhive_JS_Miner_Generic + Coinhive_JS_Miner_Injected_In_HTML
echo -n "[TEST] coinhive-injected.html -> Coinhive_JS_Miner_Generic + Coinhive_JS_Miner_Injected_In_HTML ... "
TOTAL=$((TOTAL + 1))
RESULT=$(yara "$YARA_RULE" "$SAMPLES_DIR/coinhive-injected.html" 2>&1 || true)
if echo "$RESULT" | grep -q "Coinhive_JS_Miner_Generic" && echo "$RESULT" | grep -q "Coinhive_JS_Miner_Injected_In_HTML"; then
    echo "PASS"
    PASS=$((PASS + 1))
else
    echo "FAIL (expected both Coinhive_JS_Miner_Generic and Coinhive_JS_Miner_Injected_In_HTML)"
    echo "  Output: $RESULT"
    FAIL=$((FAIL + 1))
fi

# Test 4: generic-miner.js -> should match Generic_Browser_Cryptominer_Behavior
echo -n "[TEST] generic-miner.js -> Generic_Browser_Cryptominer_Behavior ... "
TOTAL=$((TOTAL + 1))
RESULT=$(yara "$YARA_RULE" "$SAMPLES_DIR/generic-miner.js" 2>&1 || true)
if echo "$RESULT" | grep -q "Generic_Browser_Cryptominer_Behavior"; then
    echo "PASS"
    PASS=$((PASS + 1))
else
    echo "FAIL (expected Generic_Browser_Cryptominer_Behavior)"
    echo "  Output: $RESULT"
    FAIL=$((FAIL + 1))
fi

# Test 5: benign.js -> should match nothing (negative test)
echo -n "[TEST] benign.js -> (none) ... "
TOTAL=$((TOTAL + 1))
RESULT=$(yara "$YARA_RULE" "$SAMPLES_DIR/benign.js" 2>&1 || true)
if [ -z "$RESULT" ]; then
    echo "PASS"
    PASS=$((PASS + 1))
else
    echo "FAIL (expected no match)"
    echo "  Output: $RESULT"
    FAIL=$((FAIL + 1))
fi

# Test 6: normal.html -> should match nothing (negative test)
echo -n "[TEST] normal.html -> (none) ... "
TOTAL=$((TOTAL + 1))
RESULT=$(yara "$YARA_RULE" "$SAMPLES_DIR/normal.html" 2>&1 || true)
if [ -z "$RESULT" ]; then
    echo "PASS"
    PASS=$((PASS + 1))
else
    echo "FAIL (expected no match)"
    echo "  Output: $RESULT"
    FAIL=$((FAIL + 1))
fi

# Summary
echo ""
echo "=== Results: $PASS/$TOTAL passed, $FAIL failed ==="
if [ $FAIL -gt 0 ]; then
    exit 1
fi
