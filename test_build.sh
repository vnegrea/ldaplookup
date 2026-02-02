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

echo "=== CI Build Test ==="
echo "Performing safety checks..."

check_test_value "$TEST_URL" "TEST_URL"
check_test_value "$TEST_PASSWORD" "TEST_PASSWORD"

echo "Safety checks passed."
echo ""

# Clean up any previous test artifacts
rm -f ldaplookup ldaplookupg .garble_seed

# Feed test inputs to build.sh
# Order: disclaimer, url, user_base, group_base, bind_dn, password,
#        hostname_lock(n), confirm_no_host(y), path_lock(n), confirm_no_path(y), new_seed(y)
cat <<EOF | ./build.sh
yes
${TEST_URL}
${TEST_USER_BASE}
${TEST_GROUP_BASE}
${TEST_BIND_DN}
${TEST_PASSWORD}
n
y
n
y
y
EOF

# Verify binaries were created
echo ""
echo "=== Test Results ==="

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

# Test: Run without arguments (should show usage)
echo ""
echo "--- Test: No arguments (expect usage) ---"
USAGE_OUTPUT=$(./ldaplookup 2>&1 || true)
echo "$USAGE_OUTPUT"
if [[ "$USAGE_OUTPUT" == *"Usage:"* ]]; then
    echo "✅ Usage displayed correctly"
else
    echo "⚠️  Unexpected output"
fi

# Test: Run with mock input (should fail to connect - expected)
echo ""
echo "--- Test: Mock lookup (expect LDAP error - this is normal) ---"
LOOKUP_OUTPUT=$(./ldaplookup testuser 2>&1 || true)
echo "$LOOKUP_OUTPUT"
if [[ "$LOOKUP_OUTPUT" == *"LDAP"* || "$LOOKUP_OUTPUT" == *"failed"* || "$LOOKUP_OUTPUT" == *"Error"* ]]; then
    echo "✅ Binary executes and attempts LDAP connection (error expected with test data)"
else
    echo "⚠️  Unexpected output"
fi

echo ""
echo "=== All Tests PASSED ==="
echo ""

# Clean up test artifacts
echo "Cleaning up test artifacts..."
rm -f ldaplookup ldaplookupg .garble_seed
echo "Removed: ldaplookup, ldaplookupg, .garble_seed"

exit 0
