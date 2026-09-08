package main

import (
	"bufio"
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	baseURL             = "https://keys.sshpub.com"
	upgradeAPIBaseURL   = "https://sshpub.com"
	maxResponseBodySize = 256 * 1024
)

//go:embed VERSION
var versionFile string

var (
	usernamePattern    = regexp.MustCompile(`^[a-z0-9-]{1,16}$`)
	devicePattern      = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
	version            = strings.TrimSpace(versionFile)
	installSource      = "direct"
	errRemoveCancelled = errors.New("remove cancelled")
)

var allowedAlgorithms = map[string]struct{}{
	"ssh-ed25519":                        {},
	"ssh-rsa":                            {},
	"ecdsa-sha2-nistp256":                {},
	"ecdsa-sha2-nistp384":                {},
	"ecdsa-sha2-nistp521":                {},
	"sk-ssh-ed25519@openssh.com":         {},
	"sk-ecdsa-sha2-nistp256@openssh.com": {},
}

type target struct {
	Username string
	Devices  []string
}

type publicKey struct {
	Line      string
	Algorithm string
	KeyData   string
	Comment   string
	Device    string
	Identity  string
}

type keyLine struct {
	Raw string
	Key *publicKey
}

type addResult struct {
	Added  []string
	Exists []string
}

type removeOptions struct {
	Force       bool
	Confirm     io.Reader
	Prompt      io.Writer
	Interactive bool
}

type removePlan struct {
	Kept                []string
	Removed             []string
	RemainingValidKeys  int
	WouldRemoveAnyValid bool
}

type apiKeyResponse struct {
	Username string       `json:"username"`
	Keys     []apiKeyItem `json:"keys"`
}

type apiErrorResponse struct {
	Error string `json:"error"`
}

type apiKeyItem struct {
	Device    string `json:"device"`
	PublicKey string `json:"public_key"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr, authorizedKeysPath, baseURL); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer, pathFunc func() (string, error), apiBase string) error {
	if len(args) == 0 {
		printHelp(stdout)
		return nil
	}
	switch args[0] {
	case "help", "--help", "-h":
		if len(args) != 1 {
			return errors.New("help does not accept arguments")
		}
		printHelp(stdout)
		return nil
	case "version", "--version":
		if len(args) != 1 {
			return errors.New("version does not accept arguments")
		}
		fmt.Fprintf(stdout, "sshpub %s\n", version)
		return nil
	case "upgrade":
		if len(args) != 1 {
			return errors.New("upgrade does not accept arguments")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return runUpgrade(ctx, http.DefaultClient, stdout, upgradeAPIBaseURL)
	case "add":
		if len(args) != 2 {
			return errors.New("usage: sshpub add <user|user/device[,device...]>")
		}
		t, err := parseTarget(args[1])
		if err != nil {
			return err
		}
		path, err := pathFunc()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		result, err := addKeys(ctx, http.DefaultClient, apiBase, path, t)
		if err != nil {
			return err
		}
		printAddResult(stdout, result)
		fmt.Fprintln(stdout)
		printCurrentAuthorizedKeysTitle(stdout, path)
		fmt.Fprintln(stdout)
		return listKeys(stdout, path)
	case "remove":
		if len(args) < 2 || len(args) > 3 {
			return errors.New("usage: sshpub remove <user|user/device[,device...]> [--force]")
		}
		force := false
		if len(args) == 3 {
			if args[2] != "--force" {
				return errors.New("usage: sshpub remove <user|user/device[,device...]> [--force]")
			}
			force = true
		}
		t, err := parseTarget(args[1])
		if err != nil {
			return err
		}
		path, err := pathFunc()
		if err != nil {
			return err
		}
		removed, err := removeKeysWithOptions(path, t, removeOptions{
			Force:       force,
			Confirm:     os.Stdin,
			Prompt:      stdout,
			Interactive: isInteractive(os.Stdin),
		})
		if err != nil {
			if errors.Is(err, errRemoveCancelled) {
				return nil
			}
			return err
		}
		printRemoveResult(stdout, removed)
		fmt.Fprintln(stdout)
		printCurrentAuthorizedKeysTitle(stdout, path)
		fmt.Fprintln(stdout)
		return listKeys(stdout, path)
	case "list":
		if len(args) != 1 {
			return errors.New("list does not accept arguments")
		}
		path, err := pathFunc()
		if err != nil {
			return err
		}
		return listKeys(stdout, path)
	default:
		return fmt.Errorf("unknown command: %s", args[0])
	}
}

func printHelp(w io.Writer) {
	fmt.Fprint(w, `SSH Pub

Usage:
  sshpub add <user>
  sshpub add <user>/<device[,device...]>

  sshpub remove <user>
  sshpub remove <user>/<device[,device...]>

  sshpub list
  sshpub version
  sshpub upgrade

https://sshpub.com
`)
}

type upgradeResponse struct {
	Upgrade bool   `json:"upgrade"`
	Latest  string `json:"latest"`
}

func runUpgrade(ctx context.Context, client *http.Client, stdout io.Writer, apiBase string) error {
	if installSource == "package" {
		fmt.Fprintln(stdout, "This installation is managed by your package manager.")
		fmt.Fprintln(stdout, "Use your system package manager to upgrade sshpub.")
		return nil
	}
	if installSource != "direct" {
		return fmt.Errorf("unknown install source: %s", installSource)
	}
	resp, err := checkUpgrade(ctx, client, apiBase, version)
	if err != nil {
		return err
	}
	if !resp.Upgrade {
		fmt.Fprintf(stdout, "sshpub is up to date (%s).\n", version)
		return nil
	}
	fmt.Fprintf(stdout, "A new version is available: %s\n\n", resp.Latest)
	fmt.Fprintln(stdout, "Upgrade with:")
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "curl -fsSL https://sshpub.com/install.sh | sh")
	return nil
}

func checkUpgrade(ctx context.Context, client *http.Client, apiBase, currentVersion string) (upgradeResponse, error) {
	endpoint := strings.TrimRight(apiBase, "/") + "/api/cli/upgrade?version=" + url.QueryEscape(currentVersion)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return upgradeResponse{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return upgradeResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return upgradeResponse{}, fmt.Errorf("sshpub server returned HTTP %d", resp.StatusCode)
	}
	limited := &io.LimitedReader{R: resp.Body, N: maxResponseBodySize + 1}
	body, err := io.ReadAll(limited)
	if err != nil {
		return upgradeResponse{}, err
	}
	if len(body) > maxResponseBodySize {
		return upgradeResponse{}, errors.New("server response exceeds 256 KiB")
	}
	var out upgradeResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return upgradeResponse{}, errors.New("invalid JSON returned by server")
	}
	if out.Latest == "" {
		return upgradeResponse{}, errors.New("invalid upgrade response")
	}
	return out, nil
}

func parseTarget(value string) (target, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || strings.ContainsAny(value, "?#") || strings.HasPrefix(value, "/") || strings.HasSuffix(value, "/") || strings.Contains(value, "//") {
		return target{}, errors.New("invalid target")
	}
	parts := strings.Split(value, "/")
	if len(parts) > 2 {
		return target{}, errors.New("invalid target")
	}
	if !usernamePattern.MatchString(parts[0]) {
		return target{}, errors.New("invalid username")
	}
	t := target{Username: parts[0]}
	if len(parts) == 1 {
		return t, nil
	}
	devices := strings.Split(parts[1], ",")
	seen := make(map[string]struct{}, len(devices))
	for _, device := range devices {
		if !devicePattern.MatchString(device) {
			return target{}, errors.New("invalid device")
		}
		if _, ok := seen[device]; ok {
			return target{}, fmt.Errorf("duplicate device: %s", device)
		}
		seen[device] = struct{}{}
		t.Devices = append(t.Devices, device)
	}
	return t, nil
}

func addKeys(ctx context.Context, client *http.Client, apiBase, path string, t target) (addResult, error) {
	body, err := downloadKeys(ctx, client, apiBase, t)
	if err != nil {
		return addResult{}, err
	}
	keys, err := parseServerKeys(body, t)
	if err != nil {
		return addResult{}, err
	}
	if err := validateReturnedDevices(keys, t); err != nil {
		return addResult{}, err
	}
	current, err := readAuthorizedKeys(path)
	if err != nil {
		return addResult{}, err
	}
	existing := make(map[string]struct{})
	for _, line := range current {
		if line.Key != nil {
			existing[line.Key.Identity] = struct{}{}
		}
	}
	result := addResult{}
	var additions []string
	for _, key := range keys {
		if _, ok := existing[key.Identity]; ok {
			result.Exists = append(result.Exists, t.Username+"/"+key.Device)
			continue
		}
		existing[key.Identity] = struct{}{}
		result.Added = append(result.Added, t.Username+"/"+key.Device)
		additions = append(additions, key.Line)
	}
	if len(additions) == 0 {
		return result, nil
	}
	original, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return addResult{}, err
	}
	next := appendAuthorizedKeyLines(original, additions)
	if err := writeAtomic(path, next); err != nil {
		return addResult{}, err
	}
	return result, nil
}

func downloadKeys(ctx context.Context, client *http.Client, apiBase string, t target) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, buildAPIURL(apiBase, t), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", cliUserAgent())
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	limited := &io.LimitedReader{R: resp.Body, N: maxResponseBodySize + 1}
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(body) > maxResponseBodySize {
		return nil, errors.New("server response exceeds 256 KiB")
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if message := serverErrorMessage(body); message != "" {
			return nil, errors.New(sanitizeServerError(message))
		}
		return nil, fmt.Errorf("sshpub server returned HTTP %d", resp.StatusCode)
	}
	return body, nil
}

func cliUserAgent() string {
	if version == "" {
		return "SSH Pub CLI"
	}
	return "SSH Pub CLI/" + version
}

func serverErrorMessage(body []byte) string {
	var resp apiErrorResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return ""
	}
	return strings.TrimSpace(resp.Error)
}

func sanitizeServerError(message string) string {
	message = strings.TrimSpace(message)
	if message == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range message {
		if r == '\n' || r == '\t' || (r >= 0x20 && r != 0x7f) {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

func buildAPIURL(apiBase string, t target) string {
	u := strings.TrimRight(apiBase, "/") + "/" + url.PathEscape(t.Username)
	if len(t.Devices) == 0 {
		return u
	}
	escaped := make([]string, 0, len(t.Devices))
	for _, device := range t.Devices {
		escaped = append(escaped, url.PathEscape(device))
	}
	return u + "/" + strings.Join(escaped, ",")
}

func parseServerKeys(data []byte, t target) ([]*publicKey, error) {
	lines, err := publicKeyLinesFromAPIResponse(data, t)
	if err != nil {
		return nil, err
	}
	keys := make([]*publicKey, 0, len(lines))
	seen := make(map[string]struct{})
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		key, err := parsePublicKeyLine(line, true)
		if err != nil {
			return nil, errors.New("invalid SSH public key returned by server")
		}
		username, device, ok := splitSSHComment(key.Comment)
		if !ok || username != t.Username {
			return nil, fmt.Errorf("unexpected SSH Pub key comment: %s", key.Comment)
		}
		key.Device = device
		if _, ok := seen[key.Identity]; ok {
			return nil, errors.New("duplicate SSH public key returned by server")
		}
		seen[key.Identity] = struct{}{}
		keys = append(keys, key)
	}
	return keys, nil
}

func publicKeyLinesFromAPIResponse(data []byte, t target) ([]string, error) {
	var resp apiKeyResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, errors.New("invalid JSON returned by server")
	}
	if resp.Username != "" && strings.ToLower(resp.Username) != t.Username {
		return nil, fmt.Errorf("unexpected response username: %s", resp.Username)
	}
	lines := make([]string, 0, len(resp.Keys))
	for _, item := range resp.Keys {
		if item.Device != "" && item.Device != strings.ToLower(strings.TrimSpace(item.Device)) {
			return nil, fmt.Errorf("invalid response device: %s", item.Device)
		}
		if item.Device != "" && !devicePattern.MatchString(item.Device) {
			return nil, fmt.Errorf("invalid response device: %s", item.Device)
		}
		line := strings.TrimSpace(item.PublicKey)
		if line == "" {
			return nil, errors.New("empty public key returned by server")
		}
		lines = append(lines, line)
	}
	return lines, nil
}

func validateReturnedDevices(keys []*publicKey, t target) error {
	if len(t.Devices) == 0 {
		return nil
	}
	got := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		got[key.Device] = struct{}{}
	}
	want := make(map[string]struct{}, len(t.Devices))
	for _, device := range t.Devices {
		want[device] = struct{}{}
	}
	var extra []string
	for device := range got {
		if _, ok := want[device]; !ok {
			extra = append(extra, device)
		}
	}
	sort.Strings(extra)
	if len(extra) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "requested %d devices, but unexpected keys were returned", len(t.Devices))
		fmt.Fprintf(&b, "\nUnexpected: %s", joinQualified(t.Username, extra))
		return errors.New(b.String())
	}
	return nil
}

func parsePublicKeyLine(line string, serverStrict bool) (*publicKey, error) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.ContainsAny(trimmed, "\r\n") {
		return nil, errors.New("invalid ssh public key")
	}
	if strings.Contains(trimmed, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		return nil, errors.New("private keys are not accepted")
	}
	pub, comment, options, rest, err := ssh.ParseAuthorizedKey([]byte(trimmed))
	if err != nil {
		return nil, err
	}
	if len(options) > 0 {
		return nil, errors.New("authorized_keys options are not accepted")
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return nil, errors.New("trailing data is not accepted")
	}
	fields := strings.Fields(trimmed)
	if serverStrict && len(fields) != 3 {
		return nil, errors.New("server keys must have algorithm, key data, and comment")
	}
	if len(fields) < 2 || fields[0] != pub.Type() {
		return nil, errors.New("invalid ssh public key")
	}
	if _, ok := allowedAlgorithms[pub.Type()]; !ok {
		return nil, fmt.Errorf("unsupported ssh public key algorithm: %s", pub.Type())
	}
	if strings.Contains(pub.Type(), "-cert-v01@openssh.com") {
		return nil, errors.New("OpenSSH certificates are not supported")
	}
	return &publicKey{
		Line:      trimmed,
		Algorithm: pub.Type(),
		KeyData:   fields[1],
		Comment:   comment,
		Identity:  pub.Type() + " " + string(pub.Marshal()),
	}, nil
}

func splitSSHComment(comment string) (string, string, bool) {
	parts := strings.Split(comment, "/")
	if len(parts) != 3 || parts[0] != "sshpub.com" {
		return "", "", false
	}
	if !usernamePattern.MatchString(parts[1]) || !devicePattern.MatchString(parts[2]) {
		return "", "", false
	}
	return parts[1], parts[2], true
}

func readAuthorizedKeys(path string) ([]keyLine, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	raw := splitPreserveLines(string(data))
	out := make([]keyLine, 0, len(raw))
	for _, line := range raw {
		entry := keyLine{Raw: line}
		if key, err := parsePublicKeyLine(line, false); err == nil {
			entry.Key = key
		}
		out = append(out, entry)
	}
	return out, nil
}

func removeKeys(path string, t target) ([]string, error) {
	return removeKeysWithOptions(path, t, removeOptions{})
}

func removeKeysWithOptions(path string, t target, opts removeOptions) ([]string, error) {
	original, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	plan := planRemoveKeys(original, t)
	if len(plan.Removed) == 0 {
		return nil, nil
	}
	if plan.WouldRemoveAnyValid && plan.RemainingValidKeys == 0 && !opts.Force {
		if !opts.Interactive {
			return nil, errors.New("refusing to remove all SSH keys from authorized_keys without --force")
		}
		ok, err := confirmRemoveAllKeys(opts, path)
		if err != nil {
			return nil, err
		}
		if !ok {
			if opts.Prompt != nil {
				fmt.Fprintln(opts.Prompt, "Remove cancelled. authorized_keys was not changed.")
			}
			return nil, errRemoveCancelled
		}
	}
	if err := writeAtomic(path, []byte(strings.Join(plan.Kept, "\n"))); err != nil {
		return nil, err
	}
	return uniqueSorted(plan.Removed), nil
}

func planRemoveKeys(original []byte, t target) removePlan {
	lines := splitPreserveLines(string(original))
	removeAllDevices := len(t.Devices) == 0
	deviceSet := make(map[string]struct{}, len(t.Devices))
	for _, device := range t.Devices {
		deviceSet[device] = struct{}{}
	}
	plan := removePlan{}
	keepLine := func(line string) {
		plan.Kept = append(plan.Kept, line)
		if isEffectiveAuthorizedKeyLine(line) {
			plan.RemainingValidKeys++
		}
	}
	for _, line := range lines {
		key, err := parsePublicKeyLine(line, false)
		if err != nil {
			keepLine(line)
			continue
		}
		username, device, ok := splitSSHComment(key.Comment)
		if !ok || username != t.Username {
			keepLine(line)
			continue
		}
		if removeAllDevices {
			plan.Removed = append(plan.Removed, username+"/"+device)
			plan.WouldRemoveAnyValid = true
			continue
		}
		if _, ok := deviceSet[device]; ok {
			plan.Removed = append(plan.Removed, username+"/"+device)
			plan.WouldRemoveAnyValid = true
			continue
		}
		keepLine(line)
	}
	return plan
}

func isEffectiveAuthorizedKeyLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.ContainsAny(trimmed, "\r\n") {
		return false
	}
	if strings.Contains(trimmed, "-----BEGIN OPENSSH PRIVATE KEY-----") {
		return false
	}
	pub, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(trimmed))
	if err != nil {
		return false
	}
	if len(bytes.TrimSpace(rest)) > 0 {
		return false
	}
	return !strings.Contains(pub.Type(), "-cert-v01@openssh.com")
}

func confirmRemoveAllKeys(opts removeOptions, path string) (bool, error) {
	if opts.Confirm == nil {
		return false, errors.New("confirmation input is unavailable")
	}
	if opts.Prompt != nil {
		fmt.Fprintf(opts.Prompt, "Warning: this operation will remove all SSH keys from: %s\n", path)
		fmt.Fprintln(opts.Prompt, "You may lose SSH access to this account.")
		fmt.Fprintln(opts.Prompt)
		fmt.Fprint(opts.Prompt, "Continue? [y/N]: ")
	}
	line, err := bufio.NewReader(opts.Confirm).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	return strings.EqualFold(strings.TrimSpace(line), "y"), nil
}

func isInteractive(file *os.File) bool {
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func listKeys(w io.Writer, path string) error {
	lines, err := readAuthorizedKeys(path)
	if err != nil {
		return err
	}
	fmt.Fprintln(w, "SOURCE   NAME              TYPE                 KEY")
	for _, line := range lines {
		if line.Key == nil {
			continue
		}
		source := "LOCAL"
		name := strings.TrimSpace(line.Key.Comment)
		if username, device, ok := splitSSHComment(line.Key.Comment); ok {
			source = "SSHPUB"
			name = username + "/" + device
		}
		if name == "" {
			name = "-"
		}
		fmt.Fprintf(w, "%-8s %-17s %-20s %s\n", source, name, displayAlgorithm(line.Key.Algorithm), compactKeyData(line.Key.KeyData))
	}
	return nil
}

func compactKeyData(keyData string) string {
	keyData = strings.TrimSpace(keyData)
	if len(keyData) <= 28 {
		return keyData
	}
	return keyData[:12] + "..." + keyData[len(keyData)-12:]
}

func authorizedKeysPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "authorized_keys"), nil
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".authorized_keys.tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func appendAuthorizedKeyLines(original []byte, additions []string) []byte {
	var out []byte
	out = append(out, original...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	for _, line := range additions {
		out = append(out, line...)
		out = append(out, '\n')
	}
	return out
}

func splitPreserveLines(data string) []string {
	data = strings.TrimSuffix(data, "\n")
	data = strings.TrimSuffix(data, "\r")
	if data == "" {
		return nil
	}
	return strings.Split(strings.ReplaceAll(data, "\r\n", "\n"), "\n")
}

func printAddResult(w io.Writer, result addResult) {
	sort.Strings(result.Added)
	sort.Strings(result.Exists)
	if len(result.Added) == 0 {
		fmt.Fprintln(w, "No keys added.")
		if len(result.Exists) > 0 {
			fmt.Fprintln(w, "All requested keys already exist.")
		}
		return
	}
	fmt.Fprintf(w, "Added %d %s:\n\n", len(result.Added), plural("key", len(result.Added)))
	for _, name := range result.Added {
		fmt.Fprintln(w, name)
	}
	if len(result.Exists) > 0 {
		fmt.Fprint(w, "\nAlready exists:\n\n")
		for _, name := range result.Exists {
			fmt.Fprintln(w, name)
		}
	}
}

func printRemoveResult(w io.Writer, removed []string) {
	if len(removed) == 0 {
		fmt.Fprintln(w, "No matching SSH Pub keys found.")
		return
	}
	fmt.Fprintf(w, "Removed %d %s:\n\n", len(removed), plural("key", len(removed)))
	for _, name := range removed {
		fmt.Fprintln(w, name)
	}
}

func printCurrentAuthorizedKeysTitle(w io.Writer, path string) {
	fmt.Fprintf(w, "Current authorized_keys: %s\n", path)
}

func plural(word string, n int) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var out []string
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func joinQualified(username string, devices []string) string {
	values := make([]string, 0, len(devices))
	for _, device := range devices {
		values = append(values, username+"/"+device)
	}
	return strings.Join(values, ", ")
}

func displayAlgorithm(algorithm string) string {
	switch algorithm {
	case "ssh-ed25519":
		return "ED25519"
	case "ssh-rsa":
		return "RSA"
	case "ecdsa-sha2-nistp256":
		return "ECDSA-P256"
	case "ecdsa-sha2-nistp384":
		return "ECDSA-P384"
	case "ecdsa-sha2-nistp521":
		return "ECDSA-P521"
	default:
		return algorithm
	}
}
