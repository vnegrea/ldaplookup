#!/bin/bash
set -e

GARBLE="${HOME}/go/bin/garble"

if [[ ! -x "$GARBLE" ]]; then
    echo "garble not found. Installing..."
    go install mvdan.cc/garble@latest
fi

# Security disclaimer
echo ""
echo "⚠️  SECURITY NOTICE"
echo "This tool embeds LDAP credentials directly in the binary."
echo "Consider Kerberos/GSSAPI if your environment supports it."
echo "See README.md for details on when this tool is appropriate."
echo ""
echo -n "Type 'yes' to confirm you understand the security implications: "
read ACCEPT_DISCLAIMER
if [[ "$ACCEPT_DISCLAIMER" != "yes" && "$ACCEPT_DISCLAIMER" != "Yes" ]]; then
    echo "Build cancelled."
    exit 0
fi
echo ""

# LDAP Server Configuration
echo -n "Enter LDAP server URL (e.g., ldaps://ldap.umich.edu): "
read LDAP_SERVER
if [[ -z "$LDAP_SERVER" ]]; then
    echo "Error: LDAP server cannot be empty"
    exit 1
fi

echo -n "Enter user search base (e.g., ou=People,dc=umich,dc=edu): "
read USER_SEARCH_BASE
if [[ -z "$USER_SEARCH_BASE" ]]; then
    echo "Error: user search base cannot be empty"
    exit 1
fi

echo -n "Enter group search base (e.g., ou=User Groups,ou=Groups,dc=umich,dc=edu): "
read GROUP_SEARCH_BASE
if [[ -z "$GROUP_SEARCH_BASE" ]]; then
    echo "Error: group search base cannot be empty"
    exit 1
fi

# Bind Credentials
echo -n "Enter bind DN: "
read BIND_DN
if [[ -z "$BIND_DN" ]]; then
    echo "Error: bind DN cannot be empty"
    exit 1
fi

echo -n "Enter bind password: "
read -s LDAP_PASSWORD
echo ""
if [[ -z "$LDAP_PASSWORD" ]]; then
    echo "Error: password cannot be empty"
    exit 1
fi

# Hostname lock configuration
ALLOWED_HOSTS=""
DNS_SERVER=""

echo ""
echo "Note: Hostname lock requires exact matching. Use FQDN (e.g., myserver.umich.edu)."
echo "      Run 'hostname -f' on target systems to verify the format they will report."

while true; do
    echo -n "Enable hostname lock? (Y/n): "
    read ENABLE_HOST_LOCK

    if [[ ! "$ENABLE_HOST_LOCK" =~ ^[Nn] ]]; then
        echo -n "Enter DNS server for verification (e.g., 10.0.0.1): "
        read DNS_SERVER
        if [[ -z "$DNS_SERVER" ]]; then
            echo "Error: DNS server cannot be empty when hostname lock is enabled"
            exit 1
        fi
        
        echo "Enter allowed hostnames using FQDN (e.g., myserver.umich.edu,server2.umich.edu)"
        echo "   Tip: Run 'hostname -f' on target systems to verify the exact hostname format"
        echo -n "> "
        read ALLOWED_HOSTS
        if [[ -z "$ALLOWED_HOSTS" ]]; then
            echo "Error: allowed hostnames cannot be empty when hostname lock is enabled"
            exit 1
        fi
        
        echo "Hostname lock enabled for: $ALLOWED_HOSTS"
        break
    else
        echo "⚠️  Warning: Disabling hostname lock significantly reduces security if the binary is obtained by unauthorized parties."
        echo -n "Are you sure you want to continue without hostname lock? (y/N): "
        read CONFIRM_NO_HOST
        if [[ "$CONFIRM_NO_HOST" =~ ^[Yy] ]]; then
            break
        fi
        # Loop back to ask again
    fi
done

# Path lock configuration
ALLOWED_PATH=""

while true; do
    echo -n "Enable path lock? (Y/n): "
    read ENABLE_PATH_LOCK

    if [[ ! "$ENABLE_PATH_LOCK" =~ ^[Nn] ]]; then
        echo -n "Enter allowed deployment path (e.g., /opt/ldaplookup): "
        read ALLOWED_PATH
        if [[ -z "$ALLOWED_PATH" ]]; then
            echo "Error: allowed path cannot be empty when path lock is enabled"
            exit 1
        fi
        
        echo "Path lock enabled for: $ALLOWED_PATH"
        break
    else
        echo "⚠️  Warning: Disabling path lock significantly reduces security if the binary is obtained by unauthorized parties."
        echo -n "Are you sure you want to continue without path lock? (y/N): "
        read CONFIRM_NO_PATH
        if [[ "$CONFIRM_NO_PATH" =~ ^[Yy] ]]; then
            break
        fi
        # Loop back to ask again
    fi
done

# Seed management for consistent binary fingerprints
SEED_FILE=".garble_seed"
echo -n "Generate new obfuscation seed? (y/N): "
read CHANGE_SEED

if [[ "$CHANGE_SEED" =~ ^[Yy] ]]; then
    SEED="$(openssl rand -hex 16)"
    echo "$SEED" > "$SEED_FILE"
    echo "New seed generated."
elif [[ -f "$SEED_FILE" ]]; then
    SEED="$(cat "$SEED_FILE")"
    echo "Using existing seed."
else
    SEED="$(openssl rand -hex 16)"
    echo "$SEED" > "$SEED_FILE"
    echo "No existing seed. Generated new one."
fi

go mod tidy

echo "Building hardened obfuscated binary with garble..."

# XOR obfuscation function (pure bash)
xor_encode() {
    local str="$1" key="$2"
    local i result=""
    for ((i=0; i<${#str}; i++)); do
        local sc=$(printf '%d' "'${str:i:1}")
        local kc=$(printf '%d' "'${key:i%${#key}:1}")
        result+=$(printf '%02x' $((sc ^ kc)))
    done
    echo "$result"
}

# Generate random key for obfuscation
OBF_KEY=$(openssl rand -hex 16)

# Obfuscate sensitive values
OBF_PASSWORD=$(xor_encode "$LDAP_PASSWORD" "$OBF_KEY")
OBF_HOSTS=$(xor_encode "$ALLOWED_HOSTS" "$OBF_KEY")
OBF_PATH=$(xor_encode "$ALLOWED_PATH" "$OBF_KEY")

export GOGARBLE='*'
CGO_ENABLED=0 "$GARBLE" -literals -tiny -seed="$SEED" build \
  -trimpath \
  -ldflags="-s -w -buildid= -X 'main.ldapServer=${LDAP_SERVER}' -X 'main.bindDN=${BIND_DN}' -X 'main.userSearchBase=${USER_SEARCH_BASE}' -X 'main.groupSearchBase=${GROUP_SEARCH_BASE}' -X 'main.bindPWEnc=${OBF_PASSWORD}' -X 'main.obfKey=${OBF_KEY}' -X 'main.dnsServer=${DNS_SERVER}' -X 'main.allowedHostsEnc=${OBF_HOSTS}' -X 'main.allowedPathEnc=${OBF_PATH}'" \
  -o ldaplookup .

ln -sf ldaplookup ldaplookupg

unset LDAP_SERVER BIND_DN USER_SEARCH_BASE GROUP_SEARCH_BASE LDAP_PASSWORD DNS_SERVER ALLOWED_HOSTS ALLOWED_PATH OBF_KEY OBF_PASSWORD OBF_HOSTS OBF_PATH

echo ""
echo "Done! Binaries created: ./ldaplookup (users) and ./ldaplookupg (groups)"
