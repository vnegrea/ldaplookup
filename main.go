package main

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-ldap/ldap/v3"
	"golang.org/x/term"
)

// Build-time configuration (set via -ldflags)
var (
	ldapServer      string
	bindDN          string
	userSearchBase  string
	groupSearchBase string
	bindPWEnc       string // XOR encoded (legacy, kept for compatibility)
	obfKey          string // XOR key (legacy, kept for compatibility)
	dnsServer       string // optional: hostname lock DNS server
	allowedHostsEnc string // optional: XOR encoded
	allowedPathEnc  string // optional: XOR encoded
	envSalt         string // salt for environment-derived key
)

// xorDecode decodes a hex-encoded XOR string
func xorDecode(hexStr, key string) string {
	if hexStr == "" || key == "" {
		return ""
	}
	result := make([]byte, len(hexStr)/2)
	for i := 0; i < len(hexStr); i += 2 {
		var b byte
		fmt.Sscanf(hexStr[i:i+2], "%02x", &b)
		result[i/2] = b ^ key[i/2%len(key)]
	}
	return string(result)
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

// deriveKeyFromEnvironment creates an AES key from machine-specific values
// This key cannot be derived by static analysis tools like Ungarble
func deriveKeyFromEnvironment() ([]byte, error) {
	h := sha256.New()

	// 1. Machine ID (unique per Linux install)
	mid, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return nil, fmt.Errorf("cannot read machine-id: %w", err)
	}
	h.Write(mid)

	// 2. Build-time salt (prevents rainbow tables)
	if envSalt != "" {
		h.Write([]byte(envSalt))
	}

	// 3. Deployment path (changes if binary is copied elsewhere)
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("cannot get executable path: %w", err)
	}
	exePath, _ = filepath.EvalSymlinks(exePath)
	h.Write([]byte(filepath.Dir(exePath)))

	return h.Sum(nil), nil
}

// getSealPath returns the path to the .seal file
func getSealPath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	exePath, _ = filepath.EvalSymlinks(exePath)
	return exePath + ".seal", nil
}

// sealCredentials encrypts and stores the LDAP password
func sealCredentials() error {
	fmt.Print("Enter LDAP password to seal: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return fmt.Errorf("failed to read password: %w", err)
	}

	if len(password) == 0 {
		return fmt.Errorf("password cannot be empty")
	}

	key, err := deriveKeyFromEnvironment()
	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("GCM creation failed: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("nonce generation failed: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, password, nil)

	sealPath, err := getSealPath()
	if err != nil {
		return fmt.Errorf("cannot determine seal path: %w", err)
	}

	if err := os.WriteFile(sealPath, ciphertext, 0400); err != nil {
		return fmt.Errorf("failed to write seal file: %w", err)
	}

	fmt.Printf("Credentials sealed to %s\n", sealPath)
	fmt.Println("This file is bound to this machine and deployment path.")
	return nil
}

// unsealPassword decrypts the stored password using environment-derived key
func unsealPassword() (string, error) {
	sealPath, err := getSealPath()
	if err != nil {
		return "", fmt.Errorf("cannot determine seal path: %w", err)
	}

	ciphertext, err := os.ReadFile(sealPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", fmt.Errorf("no sealed credentials found - run with --seal first")
		}
		return "", fmt.Errorf("failed to read seal file: %w", err)
	}

	key, err := deriveKeyFromEnvironment()
	if err != nil {
		return "", fmt.Errorf("key derivation failed: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("cipher creation failed: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("GCM creation failed: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return "", fmt.Errorf("invalid seal file")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("unseal failed - wrong environment or tampered file")
	}

	return string(plaintext), nil
}

// getBindPassword returns the LDAP bind password using sealed credentials or legacy XOR
func getBindPassword() (string, error) {
	// Try sealed credentials first (new method)
	sealPath, _ := getSealPath()
	if _, err := os.Stat(sealPath); err == nil {
		return unsealPassword()
	}

	// Fall back to legacy XOR-encoded password (for backward compatibility)
	if bindPWEnc != "" && obfKey != "" {
		return xorDecode(bindPWEnc, obfKey), nil
	}

	return "", fmt.Errorf("no credentials available - run with --seal or rebuild with embedded credentials")
}

// selfDestruct deletes both binaries and exits
func selfDestruct() {
	execPath, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(execPath)
		os.Remove(filepath.Join(dir, "ldaplookup"))
		os.Remove(filepath.Join(dir, "ldaplookupg"))
	}
	os.Remove("ldaplookup")
	os.Remove("ldaplookupg")
	os.Exit(1)
}

// getHostnameFQDN returns the fully qualified domain name
func getHostnameFQDN() string {
	// Try hostname -f first
	if out, err := exec.Command("hostname", "-f").Output(); err == nil {
		fqdn := strings.TrimSpace(string(out))
		// If not localhost, use it
		if fqdn != "" && !strings.HasPrefix(fqdn, "localhost") {
			return fqdn
		}
	}

	// Try transient hostname (RHEL/systemd)
	if out, err := exec.Command("hostnamectl", "--transient").Output(); err == nil {
		transient := strings.TrimSpace(string(out))
		if transient != "" {
			return transient
		}
	}

	// Fallback to os.Hostname
	hostname, _ := os.Hostname()
	return hostname
}

// checkHostnameLock validates hostname against allowed list and DNS
func checkHostnameLock() bool {
	allowedHosts := xorDecode(allowedHostsEnc, obfKey)
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
	allowedPath := xorDecode(allowedPathEnc, obfKey)
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

// checkDebugger detects if process is being traced
func checkDebugger() bool {
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

func main() {
	// Handle --seal mode first (before any security checks)
	if len(os.Args) >= 2 && os.Args[1] == "--seal" {
		if ldapServer == "" {
			fmt.Fprintf(os.Stderr, "Error: binary was not built with required values.\n")
			fmt.Fprintf(os.Stderr, "Use build.sh to create a properly configured binary.\n")
			os.Exit(1)
		}
		if err := sealCredentials(); err != nil {
			fmt.Fprintf(os.Stderr, "Seal error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if checkDebugger() {
		hostLockConfigured := dnsServer != "" && allowedHostsEnc != ""
		pathLockConfigured := allowedPathEnc != ""

		anyLockConfigured := hostLockConfigured || pathLockConfigured
		allLocksPassed := checkHostnameLock() && checkPathLock()

		if anyLockConfigured && allLocksPassed {
			os.Exit(1)
		}
		selfDestruct()
	}

	if !checkHostnameLock() || !checkPathLock() {
		selfDestruct()
	}

	bindPW, err := getBindPassword()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if ldapServer == "" || bindDN == "" || userSearchBase == "" || groupSearchBase == "" || bindPW == "" {
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
	err = conn.Bind(bindDN, bindPW)
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
