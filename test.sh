#!/bin/bash

BIN="./ft_ping"
TARGET="8.8.8.8"
DOMAIN="google.com"

PASS_COUNT=0
FAIL_COUNT=0

function run_test() {
    DESCRIPTION="$1"
    shift
    CMD="$@"
    
    echo -n "[TEST] $DESCRIPTION... "

    if eval "$CMD" >/dev/null 2>&1; then
        echo -e "\e[32mPASS\e[0m"
        PASS_COUNT=$((PASS_COUNT+1))
    else
        echo -e "\e[31mFAIL\e[0m"
        echo "       ↳ Command: $CMD"
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
}

function run() {
    echo "===== Running tests on: $BIN ====="
    echo ""

    # Basic tests
    run_test "Basic ping to IP" $BIN $TARGET -w 1
    run_test "Basic ping to domain" $BIN $DOMAIN -w 1

    # Options
    run_test "Option -n (numeric only)" $BIN -n $DOMAIN -w 1
    run_test "Option -v (verbose)" $BIN -v $TARGET -w 1
    run_test "Option -r (bypass routing)" $BIN -r $TARGET -w 1
    run_test "Option --ttl=1 (TTL set)" $BIN --ttl 1 $TARGET -w 1
    run_test "Option -s 32 (payload size)" $BIN -s 32 $TARGET -w 1
    run_test "Option -p ab (custom padding)" $BIN -p ab $TARGET -w 1
    run_test "Option -W 1 (packet timeout)" $BIN -W 1 $TARGET -w 1
    run_test "Option -w 2 (global timeout)" $BIN -w 2 $TARGET

    # Help / usage
    run_test "Help option -?" $BIN -\?

    # Invalid input
    run_test "Invalid domain" $BIN invalid.invalid.test
    run_test "Invalid IP" $BIN 999.999.999.999
    run_test "Invalid hex in -p" $BIN -p gh $TARGET
    run_test "Odd-length hex in -p" $BIN -p fff $TARGET
    run_test "Too long hex in -p" $BIN -p ffffffffffffffffffffffffffffffff $TARGET
    run_test "Missing argument to -w" $BIN -w
    run_test "Missing argument to -l" $BIN -l

    # Root-only options (run only if root)
    if [ "$EUID" -eq 0 ]; then
        run_test "Flood mode -f (root)" $BIN -f -w 1 $TARGET
        run_test "Preload -l 5 (root)" $BIN -l 5 $TARGET -w 1
        run_test "Flood + Preload" $BIN -f -l 10 $TARGET -w 1
    else
        echo -e "[INFO] Skipping root-only tests (not running as root)"
    fi

    echo ""
    echo "===== Test Summary ====="
    echo -e "✅ Passed: \e[32m$PASS_COUNT\e[0m"
    echo -e "❌ Failed: \e[31m$FAIL_COUNT\e[0m"
}

run
