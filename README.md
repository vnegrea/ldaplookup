# ldaplookup

A hardened, self-contained LDAP lookup tool with embedded credentials. Produces a statically linked binary with no external dependencies.

## Features

- **Zero dependencies**: Single static binary with no runtime libraries required (no libldap, no ldapsearch)
- **Portable**: Runs on any Linux system without installation
- **Secure credential handling**: Credentials are obfuscated and embedded at build time, never exposed in process tables or environment variables
- **Deployment locks**: Restrict execution to specific hostnames and paths, rendering the binary useless if copied elsewhere ([see details](#runtime-locks))
- **Tamper protection**: Built-in resistance to debugging and analysis ([see details](#tamper-protection))
- **Dual mode**: Use `ldaplookup` for users, `ldaplookupg` for groups
- **Smart lookups**: Numeric input automatically searches by uidNumber/gidNumber

## ⚠️ When to Use This Tool

This tool embeds LDAP credentials directly in the binary. Before using it, consider these alternatives:

**Preferred alternatives:**
- **Kerberos/GSSAPI**: Uses ticket-based authentication with no stored secrets. If your environment supports Kerberos, this is the recommended approach.
- **Secrets management platforms**: Enterprise solutions offer better audit trails, credential rotation, and access controls.

**When this tool may be appropriate:**
- Parallel automation across many systems where secrets management platforms may hit rate limits or cause latency
- LDAP services that do not support GSSAPI authentication
- Environments without centralized secrets infrastructure
- Situations where a self-contained, dependency-free binary is required

**This tool is not:**
- A replacement for proper secrets management
- Immune to reverse engineering (obfuscation ≠ encryption)
- Suitable for public or untrusted systems

**Recommendation:** Always enable hostname and path locks to maximize protection.

## 🔒 Hardening

### Build-time Obfuscation

Go produces native machine-code binaries. This can raise the effort to reverse engineer compared to shipping source or readily decompilable artifacts, but it does not prevent reverse engineering. This tool adds another layer using [garble](https://github.com/burrowers/garble), a build wrapper that obfuscates Go binaries by randomizing symbol names, obscuring string literals, and stripping/altering metadata.

The build uses flags from garble, Go's build system, the Go linker, and environment variables:

| Flag | Source | Purpose |
|------|--------|---------|
| `-literals` | garble | Obfuscate string literals, preventing simple string extraction |
| `-tiny` | garble | Strip debug info and runtime panic/trace output, hindering analysis |
| `-seed` | garble | Use deterministic randomization for reproducible builds |
| `-trimpath` | go build | Remove local filesystem paths from binary |
| `-buildid=` | go linker | Remove Go build ID to hinder version fingerprinting |
| `GOGARBLE='*'` | env var | Obfuscate all packages including dependencies |

### Runtime Locks

**Hostname lock:** Restricts execution to specific servers using DNS verification.
1. At build time, specify a trusted DNS server IP and allowed hostnames
2. At runtime, the binary queries the trusted DNS server to resolve its own hostname and verifies it matches the allowed list

Using a DNS server you control is critical. It prevents attackers from spoofing hostname resolution on a compromised system. If verification fails, [tamper protection](#tamper-protection) is triggered.

**Important:** Hostname matching is exact. Use the **FQDN** (e.g., `myserver.umich.edu`) not just the short name.

To check what your system will return, run: `hostname -f`

You can provide multiple FQDNs (comma-separated) for systems with multiple hostnames: `server1.umich.edu,server2.umich.edu`

**Path lock:** Restricts execution to a specific deployment directory.
1. At build time, specify the allowed deployment path (e.g., `/opt/ldaplookup`)
2. At runtime, the binary verifies its executable path matches the allowed location

This prevents the binary from being copied elsewhere and executed. If verification fails, [tamper protection](#tamper-protection) is triggered.

### Tamper Protection

Built-in tamper resistance protects against analysis and unauthorized use. When combined with hostname and path locks, protection is significantly enhanced.

### Best Practices
- Use `chmod 110` and open up as needed
- Use a dedicated LDAP service account with read-only permissions
- Deploy only to trusted, access-controlled systems
- Rotate credentials if a binary is compromised

## 📦 Installing Go Locally (Linux)

**Note:** If you already have Go installed and configured (`go version` works), skip this section. The build scripts will install garble automatically.

If Go is not available system-wide and you prefer not to install it globally, use the included helper script:

```bash
./install-go-local.sh      # Downloads and installs Go + garble
source ~/myGo/env.sh       # Activate in current terminal
./test_build.sh            # Verify build works
./build.sh                 # Build with real credentials
```

The script installs to `~/myGo/` and creates an environment file. To make permanent, add `source ~/myGo/env.sh` to your `~/.bashrc`.

## Build

```bash
./build.sh
```

You'll be prompted for:
- Security disclaimer acknowledgment (type 'yes' to continue)
- LDAP server URL (e.g., `ldaps://ldap.umich.edu`)
- User search base (e.g., `ou=People,dc=umich,dc=edu`)
- Group search base (e.g., `ou=User Groups,ou=Groups,dc=umich,dc=edu`)
- Bind DN (full Distinguished Name, e.g., `cn=App01,ou=Applications,o=services` — not just `cn=App01`)
- Bind password
- Hostname lock (enabled by default)
- Path lock (enabled by default)
- Whether to generate a new obfuscation seed

### Testing the Build

To verify the build process works without real credentials:

```bash
./test_build.sh
```

This script builds with dummy test data, verifies the binary is created and executes, then cleans up.

### Deployment

The build produces `ldaplookup` and a symlink `ldaplookupg`. To deploy:

```bash
# Copy the binary to target
cp ldaplookup /path/to/destination/

# Create the symlink for group lookups
ln -s ldaplookup /path/to/destination/ldaplookupg
```

The binary detects its invocation name. When called as `ldaplookupg`, it queries groups instead of users.

### Obfuscation Seed

The build script prompts whether to generate a new obfuscation seed. The seed controls how garble randomizes the obfuscation. The same seed produces the same obfuscated output.

**When to keep the existing seed (answer N):**
- Rebuilding with the same credentials
- You want the binary hash to remain consistent
- Avoiding detection as a "new" binary by endpoint security tools

**When to generate a new seed (answer Y):**
- Credentials have changed
- You want protection against differential analysis (comparing two binaries to identify patterns)
- Deploying to a new environment where a fresh fingerprint is acceptable

**Trade-off:** A new seed produces a completely different binary, which provides better protection against reverse engineering through comparison. However, endpoint detection and response (EDR) tools may flag it as an unknown binary until it's re-baselined in your environment.

The seed is stored in `.garble_seed` (gitignored) and reused on subsequent builds unless you choose to regenerate it.

## Usage

```bash
# User lookup by uid
./ldaplookup <uid>

# User lookup by uidNumber (auto-detected)
./ldaplookup 12345

# Group lookup by name
./ldaplookupg <groupname>

# Group lookup by gidNumber (auto-detected)
./ldaplookupg 1001

# Specific attributes
./ldaplookup <uid> uid displayName uidNumber
./ldaplookupg <groupname> cn gidNumber memberUid
```

### Examples

```bash
# Get all attributes for user
./ldaplookup jsmith

# Get specific user attributes
./ldaplookup jsmith uid uidNumber mail

# Get group by name
./ldaplookupg staff

# Get group by gidNumber
./ldaplookupg 1001
```

## Requirements

- Go 1.25.5+
- [garble](https://github.com/burrowers/garble): `go install mvdan.cc/garble@latest`
- openssl (for seed generation)
