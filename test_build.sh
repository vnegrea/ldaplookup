#!/bin/bash
#
# ╔═══════════════════════════════════════════════════════════════════════════╗
# ║                              ⚠️  WARNING ⚠️                                ║
# ║                                                                           ║
# ║  This script is for CI/BUILD TESTING ONLY.                                ║
# ║                                                                           ║
# ║  DO NOT modify this script to use real credentials.                       ║
# ║  DO NOT commit this script with real passwords or server URLs.            ║
# ║                                                                           ║
# ║  Test values MUST contain "test", "example", "localhost", or "127.0.0.1"  ║
# ║  The script will abort if it detects non-test values.                     ║
# ╚═══════════════════════════════════════════════════════════════════════════╝
#
# Purpose: Verify the build process works by feeding test data via heredoc.
# Does NOT test LDAP functionality (no real server connection).
#
# Tests both credential modes:
#   1. Legacy embedded (mode 2) — password baked into the binary
#   2. Sealed credentials (mode 1) — build without password, seal on "target"

set -e

# ============================================================================
# TEST VALUES - These must contain "test", "example", "localhost" or "127.0.0.1"
# ============================================================================
TEST_URL="ldaps://ldap.test.example.com"
TEST_USER_BASE="ou=People,dc=test,dc=example,dc=com"
TEST_GROUP_BASE="ou=Groups,dc=test,dc=example,dc=com"
TEST_BIND_DN="cn=testbind,dc=test,dc=example,dc=com"
TEST_PASSWORD="testpassword123"

# ============================================================================
# SAFETY CHECKS - Abort if values look like real credentials
# ============================================================================
check_test_value() {
    local value="$1"
    local name="$2"
    local lower_value=$(echo "$value" | tr '[:upper:]' '[:lower:]')

    if [[ "$lower_value" != *"test"* && "$lower_value" != *"example"* && \
          "$lower_value" != *"localhost"* && "$lower_value" != *"127.0.0.1"* ]]; then
        echo ""
        echo "❌ SAFETY CHECK FAILED"
        echo "   $name does not contain 'test', 'example', 'localhost', or '127.0.0.1'"
        echo "   Value: $value"
        echo ""
        echo "   This script is for testing only. Do not use real credentials."
        echo ""
        exit 1
    fi
}

# ============================================================================
# HELPER - Verify build artifacts exist
# ============================================================================
check_build_artifacts() {
    if [[ -f "ldaplookup" ]]; then
        echo "✅ ldaplookup binary created ($(stat -c%s ldaplookup) bytes)"
    else
        echo "❌ ldaplookup binary not created"
        exit 1
    fi

    if [[ -L "ldaplookupg" ]]; then
        echo "✅ ldaplookupg symlink created"
    else
        echo "❌ ldaplookupg symlink not created"
        exit 1
    fi

    if [[ -f ".garble_seed" ]]; then
        echo "✅ .garble_seed created"
    else
        echo "❌ .garble_seed not created"
        exit 1
    fi
}

# ============================================================================
# HELPER - Run standard binary tests (usage + mock lookup)
# ============================================================================
run_binary_tests() {
    echo ""
    echo "--- Test: No arguments (expect usage) ---"
    USAGE_OUTPUT=$(./ldaplookup 2>&1 || true)
    echo "$USAGE_OUTPUT"
    if [[ "$USAGE_OUTPUT" == *"Usage:"* ]]; then
        echo "✅ Usage displayed correctly"
    else
        echo "❌ Unexpected output"
        exit 1
    fi

    echo ""
    echo "--- Test: Mock lookup (expect LDAP error - this is normal) ---"
    LOOKUP_OUTPUT=$(./ldaplookup testuser 2>&1 || true)
    echo "$LOOKUP_OUTPUT"
    if [[ "$LOOKUP_OUTPUT" == *"LDAP"* || "$LOOKUP_OUTPUT" == *"failed"* || "$LOOKUP_OUTPUT" == *"Error"* ]]; then
        echo "✅ Binary executes and attempts LDAP connection (error expected with test data)"
    else
        echo "❌ Unexpected output"
        exit 1
    fi
}

echo "=== CI Build Test ==="
echo "Performing safety checks..."

check_test_value "$TEST_URL" "TEST_URL"
check_test_value "$TEST_PASSWORD" "TEST_PASSWORD"

echo "Safety checks passed."
echo ""

# Back up existing seed if present (protect production seeds)
SEED_BACKED_UP=false
if [[ -f ".garble_seed" ]]; then
    cp .garble_seed .garble_seed.backup
    SEED_BACKED_UP=true
    trap 'if [[ "$SEED_BACKED_UP" == "true" ]]; then mv .garble_seed.backup .garble_seed 2>/dev/null; fi' EXIT
    echo "Note: Existing .garble_seed backed up (will be restored after test)"
fi

# ============================================================================
# TEST 1: Legacy embedded credentials (mode 2)
# ============================================================================
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  TEST 1: Legacy Embedded (mode 2)       ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Clean up any previous test artifacts
rm -f ldaplookup ldaplookupg .garble_seed

# Build with mode 2 (legacy) — password embedded in binary
# Order: disclaimer, url, user_base, group_base, bind_dn, cred_mode(2=legacy),
#        password, hostname_lock(n), confirm_no_host(y), path_lock(n), confirm_no_path(y), new_seed(y)
cat <<EOF | ./build.sh
yes
${TEST_URL}
${TEST_USER_BASE}
${TEST_GROUP_BASE}
${TEST_BIND_DN}
2
${TEST_PASSWORD}
n
y
n
y
y
EOF

echo ""
echo "=== Mode 2: Build Results ==="
check_build_artifacts
run_binary_tests

echo ""
echo "=== Mode 2: All Tests PASSED ==="

# Clean up mode 2 artifacts
echo ""
echo "Cleaning up mode 2 artifacts..."
rm -f ldaplookup ldaplookupg .garble_seed
echo "Removed: ldaplookup, ldaplookupg, .garble_seed"

# ============================================================================
# TEST 2: Sealed credentials (mode 1)
# ============================================================================
echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  TEST 2: Sealed Credentials (mode 1)    ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Build with mode 1 (sealed) — no password prompt in build.sh
# Order: disclaimer, url, user_base, group_base, bind_dn, cred_mode(1=sealed),
#        hostname_lock(n), confirm_no_host(y), path_lock(n), confirm_no_path(y), new_seed(y)
cat <<EOF | ./build.sh
yes
${TEST_URL}
${TEST_USER_BASE}
${TEST_GROUP_BASE}
${TEST_BIND_DN}
1
n
y
n
y
y
EOF

echo ""
echo "=== Mode 1: Build Results ==="
check_build_artifacts

# Seal credentials on this machine
# term.ReadPassword requires a real terminal, so we use python3 pty to simulate one
echo ""
echo "--- Test: Sealing credentials (--seal) ---"
SEAL_OUTPUT=$(echo "${TEST_PASSWORD}" | python3 -c "
import pty, os, sys, time
password = sys.stdin.buffer.read()
pid, fd = pty.fork()
if pid == 0:
    os.execvp('./ldaplookup', ['./ldaplookup', '--seal'])
else:
    time.sleep(0.5)
    os.write(fd, password)
    os.write(fd, b'\n')
    time.sleep(1)
    output = b''
    while True:
        try:
            data = os.read(fd, 4096)
            if not data:
                break
            output += data
        except OSError:
            break
    os.waitpid(pid, 0)
    sys.stdout.buffer.write(output)
" 2>&1)
echo "$SEAL_OUTPUT"

# Find the .seal file (named <binary_path>.seal)
SEAL_FILE=$(readlink -f ./ldaplookup).seal
if [[ -f "$SEAL_FILE" ]]; then
    echo "✅ Seal file created: $SEAL_FILE"
else
    echo "❌ Seal file not created"
    exit 1
fi

# Run standard binary tests — binary decrypts sealed creds and attempts LDAP
run_binary_tests

echo ""
echo "=== Mode 1: All Tests PASSED ==="

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║  ALL TESTS PASSED                       ║"
echo "╚══════════════════════════════════════════╝"
echo ""

# Clean up test artifacts (trap will restore original seed on exit)
echo "Cleaning up test artifacts..."
rm -f ldaplookup ldaplookupg .garble_seed "$SEAL_FILE"
echo "Removed: ldaplookup, ldaplookupg, .garble_seed, seal file"
if [[ "$SEED_BACKED_UP" == "true" ]]; then
    echo "Restoring original .garble_seed..."
fi

exit 0
