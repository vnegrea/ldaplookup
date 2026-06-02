package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Build-time configuration (set via -ldflags)
var (
	ldapServer      string
	bindDN          string
	userSearchBase  string
	groupSearchBase string
	bindPWEnc       string // XOR encoded
	obfKey          string // XOR key
	dnsServer       string // optional: hostname lock DNS server
	allowedHostsEnc string // optional: XOR encoded
	allowedPathEnc  string // optional: XOR encoded
)

// xorDecode decodes a hex-encoded XOR string into a byte slice.
// Returning []byte (instead of string) lets the password call site zero
// the buffer after use; config callers convert back with string(...).
func xorDecode(hexStr, key string) []byte {
	if hexStr == "" || key == "" {
		return nil
	}
	result := make([]byte, len(hexStr)/2)
	for i := 0; i < len(hexStr); i += 2 {
		var b byte
		fmt.Sscanf(hexStr[i:i+2], "%02x", &b)
		result[i/2] = b ^ key[i/2%len(key)]
	}
	return result
}

var validUserAttrs = map[string]bool{
	"uid":         true,
	"displayName": true,
	"uidNumber":   true,
	"gidNumber":   true,
	"mail":        true,
}

var validGroupAttrs = map[string]bool{
	"cn":        true,
	"gidNumber": true,
	"memberUid": true,
}

// secureExit removes the running binary and any symlinks to it, then exits.
// Resolves the actual executable path (via EvalSymlinks) instead of relying
// on hardcoded filenames, and only deletes symlinks in the same directory
// whose target is this binary.
func secureExit() {
	execPath, err := os.Executable()
	if err == nil {
		execPath, _ = filepath.EvalSymlinks(execPath)
		dir := filepath.Dir(execPath)

		// Remove symlinks in the same directory that point to this binary
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			full := filepath.Join(dir, e.Name())
			if target, err := os.Readlink(full); err == nil {
				abs, _ := filepath.Abs(filepath.Join(dir, target))
				if abs == execPath {
					os.Remove(full)
				}
			}
		}

		os.Remove(execPath)
	}
	os.Exit(1)
}

// getHostnameFQDN returns the fully qualified domain name using stdlib only.
// Avoids shelling to hostname/hostnamectl, which would expose us to PATH
// hijacking on hosts where $PATH is attacker-controlled.
func getHostnameFQDN() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}

	// Forward+reverse DNS to promote a short name to an FQDN
	if addrs, err := net.LookupHost(hostname); err == nil && len(addrs) > 0 {
		if names, err := net.LookupAddr(addrs[0]); err == nil && len(names) > 0 {
			fqdn := strings.TrimSuffix(names[0], ".")
			if fqdn != "" && !strings.HasPrefix(fqdn, "localhost") {
				return fqdn
			}
		}
	}
	return hostname
}

// checkHostnameLock validates hostname against allowed list and DNS
func checkHostnameLock() bool {
	allowedHosts := string(xorDecode(allowedHostsEnc, obfKey))
	if dnsServer == "" || allowedHosts == "" {
		return true
	}

	currentHost := getHostnameFQDN()
	allowed := strings.Split(allowedHosts, ",")

	found := false
	for _, h := range allowed {
		if strings.TrimSpace(h) == currentHost {
			found = true
			break
		}
	}
	if !found {
		return false
	}

	// Verify hostname resolves via specified DNS server
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 5 * time.Second}
			return d.DialContext(ctx, "udp", dnsServer+":53")
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ips, err := resolver.LookupHost(ctx, currentHost)
	return err == nil && len(ips) > 0
}

// checkPathLock validates binary is running from allowed directory
func checkPathLock() bool {
	allowedPath := string(xorDecode(allowedPathEnc, obfKey))
	if allowedPath == "" {
		return true
	}

	execPath, err := os.Executable()
	if err != nil {
		return false
	}

	execDir := filepath.Dir(execPath)
	
	// Normalize paths (remove trailing slashes)
	execDir = strings.TrimSuffix(execDir, "/")
	normalizedAllowed := strings.TrimSuffix(allowedPath, "/")
	
	return execDir == normalizedAllowed
}

// checkTracerPid checks /proc/self/status for a non-zero TracerPid
func checkTracerPid() bool {
	file, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "TracerPid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] != "0" {
				return true
			}
			break
		}
	}
	return false
}

// checkDebugger uses heuristics to detect debugging. These are defense-in-depth
// speed bumps, not cryptographic guarantees. PTRACE_TRACEME is deliberately NOT
// used: a successful TRACEME call permanently marks the process as traced by
// its parent, and the next runtime-delivered signal (SIGURG for goroutine
// preemption, GC signals, etc.) halts the process in signal-delivery-stop with
// no tracer to release it. The TracerPid check below catches the realistic
// threat (gdb, strace, lldb, ltrace, perf trace) without that side effect.
func checkDebugger() bool {
	// Method 1: TracerPid - catches ptrace-based debuggers (gdb, strace)
	if checkTracerPid() {
		return true
	}

	// Method 2: Timing - single-stepping causes measurable delay
	start := time.Now()
	sum := 0
	for i := 0; i < 1000; i++ {
		sum += i
	}
	_ = sum
	if time.Since(start) > 50*time.Millisecond {
		return true
	}

	return false
}

func main() {
	if checkDebugger() {
		secureExit()
	}

	if !checkHostnameLock() || !checkPathLock() {
		secureExit()
	}

	bindPW := xorDecode(bindPWEnc, obfKey)
	if ldapServer == "" || bindDN == "" || userSearchBase == "" || groupSearchBase == "" || len(bindPW) == 0 {
		fmt.Fprintf(os.Stderr, "Error: binary was not built with required values.\n")
		fmt.Fprintf(os.Stderr, "Use build.sh to create a properly configured binary.\n")
		os.Exit(1)
	}

	// Detect mode from binary name
	isGroupMode := strings.HasSuffix(os.Args[0], "g")

	var searchBase, nameAttr, numAttr string
	var validAttrs map[string]bool

	if isGroupMode {
		searchBase = groupSearchBase
		nameAttr = "cn"
		numAttr = "gidNumber"
		validAttrs = validGroupAttrs
	} else {
		searchBase = userSearchBase
		nameAttr = "uid"
		numAttr = "uidNumber"
		validAttrs = validUserAttrs
	}

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <%s> [attr...]\n", os.Args[0], nameAttr)
		fmt.Fprintf(os.Stderr, "Numeric IDs are auto-detected and search by %s.\n", numAttr)
		fmt.Fprintf(os.Stderr, "If no attributes specified, returns full record.\n")
		os.Exit(1)
	}

	identifier := os.Args[1]
	requestedAttrs := os.Args[2:]

	// Auto-detect numeric identifier
	var filter string
	if _, err := strconv.Atoi(identifier); err == nil {
		filter = fmt.Sprintf("(%s=%s)", numAttr, ldap.EscapeFilter(identifier))
	} else {
		filter = fmt.Sprintf("(%s=%s)", nameAttr, ldap.EscapeFilter(identifier))
	}

	// Only validate if specific attributes were requested
	for _, attr := range requestedAttrs {
		if !validAttrs[attr] {
			fmt.Fprintf(os.Stderr, "Invalid attribute: %s\n", attr)
			os.Exit(1)
		}
	}

	// Configure TLS
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS12,
	}

	// Connect to LDAP server
	conn, err := ldap.DialURL(ldapServer, ldap.DialWithTLSConfig(tlsConfig))
	if err != nil {
		fmt.Fprintf(os.Stderr, "LDAP connect failed: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	// Bind with service account
	err = conn.Bind(bindDN, string(bindPW))
	// Zero the password buffer immediately after the bind call consumes it.
	// The string(...) cast above creates a short-lived copy the LDAP library
	// reads; the long-lived buffer we control is wiped here.
	for i := range bindPW {
		bindPW[i] = 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "LDAP bind failed: %v\n", err)
		os.Exit(1)
	}

	// Build and execute search
	searchRequest := ldap.NewSearchRequest(
		searchBase,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,     // SizeLimit - only expect 1 result
		10,    // TimeLimit in seconds
		false, // TypesOnly
		filter,
		requestedAttrs, // Empty slice returns all attributes
		nil,
	)

	result, err := conn.Search(searchRequest)
	if err != nil {
		fmt.Fprintf(os.Stderr, "LDAP search failed: %v\n", err)
		os.Exit(1)
	}

	if len(result.Entries) == 0 {
		label := "User"
		if isGroupMode {
			label = "Group"
		}
		fmt.Fprintf(os.Stderr, "%s not found: %s\n", label, identifier)
		os.Exit(1)
	}

	// Output results
	entry := result.Entries[0]
	if len(requestedAttrs) == 0 {
		// Full record - print everything returned
		for _, attr := range entry.Attributes {
			for _, value := range attr.Values {
				fmt.Printf("%s: %s\n", attr.Name, value)
			}
		}
	} else {
		// Specific attributes requested
		for _, attr := range requestedAttrs {
			fmt.Printf("%s: %s\n", attr, entry.GetAttributeValue(attr))
		}
	}
}
