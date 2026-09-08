package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		input   string
		user    string
		devices []string
	}{
		{"alice", "alice", nil},
		{"alice/pc", "alice", []string{"pc"}},
		{"alice/MacBook-Pro", "alice", []string{"macbook-pro"}},
		{"alice/pc,iphone", "alice", []string{"pc", "iphone"}},
		{"ALICE1/git", "alice1", []string{"git"}},
		{"alice/git", "alice", []string{"git"}},
		{"1234/git", "1234", []string{"git"}},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseTarget(tt.input)
			if err != nil {
				t.Fatalf("parseTarget() error = %v", err)
			}
			if got.Username != tt.user || strings.Join(got.Devices, ",") != strings.Join(tt.devices, ",") {
				t.Fatalf("parseTarget() = %#v", got)
			}
		})
	}
}

func TestParseTargetRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{"/alice", "alice_dev", "abcdefghijklmnopq", "alice/work_pc", "alice/abcdefghijklmnopqrstuvwxyzabcdefg", "alice/", "alice//pc", "alice/../admin", "alice?x=1", "alice#foo", "alice/pc/", "alice/pc,pc"} {
		t.Run(input, func(t *testing.T) {
			if _, err := parseTarget(input); err == nil {
				t.Fatalf("parseTarget(%q) expected error", input)
			}
		})
	}
}

func TestBuildAPIURL(t *testing.T) {
	got := buildAPIURL("https://keys.sshpub.com", mustTarget(t, "alice1/git"))
	want := "https://keys.sshpub.com/alice1/git"
	if got != want {
		t.Fatalf("buildAPIURL() = %q, want %q", got, want)
	}
}

func TestParsePublicKeyLineAcceptsSupportedKeys(t *testing.T) {
	for _, line := range []string{
		testKey(t, "ed25519", "sshpub.com/alice/pc"),
		testKey(t, "rsa", "sshpub.com/alice/pc"),
		testKey(t, "ecdsa256", "sshpub.com/alice/pc"),
		testKey(t, "ecdsa384", "sshpub.com/alice/pc"),
		testKey(t, "ecdsa521", "sshpub.com/alice/pc"),
		"sk-ecdsa-sha2-nistp256@openssh.com AAAAInNrLWVjZHNhLXNoYTItbmlzdHAyNTZAb3BlbnNzaC5jb20AAAAIbmlzdHAyNTYAAABBBGRNqlFgED/pf4zXz8IzqA6CALNwYcwgd4MQDmIS1GOtn1SySFObiuyJaOlpqkV5FeEifhxfIC2ejKKtNyO4CysAAAAEc3NoOg== sshpub.com/alice/pc",
		"sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIJjzc2a20RjCvN/0ibH6UpGuN9F9hDvD7x182bOesNhHAAAABHNzaDo= sshpub.com/alice/pc",
	} {
		t.Run(strings.Fields(line)[0], func(t *testing.T) {
			if _, err := parsePublicKeyLine(line, true); err != nil {
				t.Fatalf("parsePublicKeyLine() error = %v", err)
			}
		})
	}
}

func TestAllowedAlgorithmsExcludeUnsupportedExperimentalKeys(t *testing.T) {
	if _, ok := allowedAlgorithms["ssh-mldsa44-ed25519@openssh.com"]; ok {
		t.Fatalf("experimental ML-DSA key should not be allowed")
	}
}

func TestParsePublicKeyLineRejectsInvalidKeyData(t *testing.T) {
	for _, line := range []string{
		"ssh-ed25519 not-base64 sshpub.com/alice/pc",
		"ssh-ed25519 AAAA sshpub.com/alice/pc",
	} {
		if _, err := parsePublicKeyLine(line, true); err == nil {
			t.Fatalf("parsePublicKeyLine(%q) expected error", line)
		}
	}
}

func TestParsePublicKeyLineRejectsAuthorizedKeysOptions(t *testing.T) {
	valid := testKey(t, "ed25519", "sshpub.com/alice/pc")
	for _, prefix := range []string{`command="echo no" `, `from="10.0.0.1" `, `permitopen="host:22" `, `environment="A=B" `} {
		if _, err := parsePublicKeyLine(prefix+valid, true); err == nil {
			t.Fatalf("parsePublicKeyLine() expected options error for %q", prefix)
		}
	}
}

func TestCommentValidation(t *testing.T) {
	if _, _, ok := splitSSHComment("sshpub.com/alice/pc"); !ok {
		t.Fatalf("expected valid SSH Pub comment")
	}
	for _, comment := range []string{"alice/pc", "alice@pc", "foo", "sshpub.com//pc", "sshpub.com/alice/mac/book"} {
		if _, _, ok := splitSSHComment(comment); ok {
			t.Fatalf("splitSSHComment(%q) expected invalid", comment)
		}
	}
}

func TestSingleDeviceAddRejectsTwoKeys(t *testing.T) {
	path := authorizedKeysFixture(t, "")
	server := keyServer(t, apiBody("alice", "pc", testKey(t, "ed25519", "sshpub.com/alice/pc"), "phone", testKey(t, "rsa", "sshpub.com/alice/phone")))
	defer server.Close()
	_, err := addKeys(context.Background(), server.Client(), server.URL, path, mustTarget(t, "alice/pc"))
	if err == nil {
		t.Fatalf("addKeys expected error")
	}
	assertFile(t, path, "")
}

func TestMultiDeviceAddValidation(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"all returned", apiBody("alice", "pc", testKey(t, "ed25519", "sshpub.com/alice/pc"), "iphone", testKey(t, "rsa", "sshpub.com/alice/iphone")), false},
		{"missing", apiBody("alice", "pc", testKey(t, "ed25519", "sshpub.com/alice/pc")), false},
		{"all missing", apiBody("alice"), false},
		{"extra", apiBody("alice", "pc", testKey(t, "ed25519", "sshpub.com/alice/pc"), "iphone", testKey(t, "rsa", "sshpub.com/alice/iphone"), "macbook", testKey(t, "ecdsa256", "sshpub.com/alice/macbook")), true},
		{"uppercase response device", apiBody("alice", "MacBook", testKey(t, "ed25519", "sshpub.com/alice/macbook")), true},
		{"duplicate key", duplicateServerKey(t), true},
		{"wrong device", apiBody("alice", "pc", testKey(t, "ed25519", "sshpub.com/alice/pc"), "macbook", testKey(t, "rsa", "sshpub.com/alice/macbook")), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := authorizedKeysFixture(t, "")
			server := keyServer(t, tt.body)
			defer server.Close()
			_, err := addKeys(context.Background(), server.Client(), server.URL, path, mustTarget(t, "alice/pc,iphone"))
			if (err != nil) != tt.wantErr {
				t.Fatalf("addKeys() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestUserAddRejectsOtherUsername(t *testing.T) {
	path := authorizedKeysFixture(t, "")
	server := keyServer(t, apiBody("alice", "pc", testKey(t, "ed25519", "sshpub.com/bob/pc")))
	defer server.Close()
	if _, err := addKeys(context.Background(), server.Client(), server.URL, path, mustTarget(t, "alice")); err == nil {
		t.Fatalf("addKeys expected username error")
	}
	assertFile(t, path, "")
}

func TestResponseSizeLimit(t *testing.T) {
	server := keyServer(t, strings.Repeat("x", maxResponseBodySize+1))
	defer server.Close()
	_, err := downloadKeys(context.Background(), server.Client(), server.URL, mustTarget(t, "alice"))
	if err == nil {
		t.Fatalf("downloadKeys expected response size error")
	}
}

func TestDownloadKeysUsesServerJSONError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"The requested public keys do not exist or are not available through the SSH Pub CLI."}`))
	}))
	defer server.Close()

	_, err := downloadKeys(context.Background(), server.Client(), server.URL, mustTarget(t, "list"))
	if err == nil {
		t.Fatalf("downloadKeys expected error")
	}
	want := "The requested public keys do not exist or are not available through the SSH Pub CLI."
	if err.Error() != want {
		t.Fatalf("downloadKeys error = %q, want %q", err.Error(), want)
	}
}

func TestDownloadKeysSanitizesServerJSONError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"bad\u001b[31m message\u007f"}`))
	}))
	defer server.Close()

	_, err := downloadKeys(context.Background(), server.Client(), server.URL, mustTarget(t, "list"))
	if err == nil {
		t.Fatalf("downloadKeys expected error")
	}
	if got, want := err.Error(), "bad[31m message"; got != want {
		t.Fatalf("downloadKeys error = %q, want %q", got, want)
	}
}

func TestDownloadKeysFallsBackToHTTPStatusForNonJSONError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`not found`))
	}))
	defer server.Close()

	_, err := downloadKeys(context.Background(), server.Client(), server.URL, mustTarget(t, "list"))
	if err == nil {
		t.Fatalf("downloadKeys expected error")
	}
	if got, want := err.Error(), "sshpub server returned HTTP 404"; got != want {
		t.Fatalf("downloadKeys error = %q, want %q", got, want)
	}
}

func TestDownloadKeysSendsSSHPubUserAgent(t *testing.T) {
	var gotUserAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUserAgent = r.Header.Get("User-Agent")
		_, _ = w.Write([]byte(apiBody("alice", "pc", testKey(t, "ed25519", "sshpub.com/alice/pc"))))
	}))
	defer server.Close()

	if _, err := downloadKeys(context.Background(), server.Client(), server.URL, mustTarget(t, "alice/pc")); err != nil {
		t.Fatalf("downloadKeys error = %v", err)
	}
	if !strings.Contains(gotUserAgent, "SSH Pub") {
		t.Fatalf("User-Agent = %q, want SSH Pub keyword", gotUserAgent)
	}
}

func TestDeduplicateByPublicKeyBody(t *testing.T) {
	existing := testKey(t, "ed25519", "old-comment")
	returned := replaceComment(existing, "sshpub.com/alice/pc")
	path := authorizedKeysFixture(t, existing+"\n")
	server := keyServer(t, apiBody("alice", "pc", returned))
	defer server.Close()
	result, err := addKeys(context.Background(), server.Client(), server.URL, path, mustTarget(t, "alice/pc"))
	if err != nil {
		t.Fatalf("addKeys() error = %v", err)
	}
	if len(result.Added) != 0 || len(result.Exists) != 1 {
		t.Fatalf("result = %#v", result)
	}
	assertFile(t, path, existing+"\n")
}

func TestAddAtomicBehaviorOnInvalidKey(t *testing.T) {
	original := "# keep\n\n" + testKey(t, "ed25519", "local") + "\n"
	path := authorizedKeysFixture(t, original)
	server := keyServer(t, apiBody("alice", "pc", testKey(t, "rsa", "sshpub.com/alice/pc"), "iphone", "ssh-ed25519 bad sshpub.com/alice/iphone"))
	defer server.Close()
	if _, err := addKeys(context.Background(), server.Client(), server.URL, path, mustTarget(t, "alice/pc,iphone")); err == nil {
		t.Fatalf("addKeys expected error")
	}
	assertFile(t, path, original)
}

func TestRemove(t *testing.T) {
	alicePC := testKey(t, "ed25519", "sshpub.com/alice/pc")
	alicePhone := testKey(t, "rsa", "sshpub.com/alice/iphone")
	bobPC := testKey(t, "ecdsa256", "sshpub.com/bob/pc")
	local := testKey(t, "ecdsa384", "john@work")
	original := strings.Join([]string{"# keep", "", alicePC, alicePhone, bobPC, local}, "\n") + "\n"
	tests := []struct {
		name       string
		target     string
		notContain []string
		contain    []string
	}{
		{"user", "alice", []string{alicePC, alicePhone}, []string{"# keep", "", bobPC, local}},
		{"single", "alice/pc", []string{alicePC}, []string{"# keep", "", alicePhone, bobPC, local}},
		{"multi", "alice/pc,iphone", []string{alicePC, alicePhone}, []string{"# keep", "", bobPC, local}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := authorizedKeysFixture(t, original)
			if _, err := removeKeys(path, mustTarget(t, tt.target)); err != nil {
				t.Fatalf("removeKeys() error = %v", err)
			}
			got := readFile(t, path)
			for _, value := range tt.notContain {
				if strings.Contains(got, value) {
					t.Fatalf("file still contains removed line %q", value)
				}
			}
			for _, value := range tt.contain {
				if !strings.Contains(got, value) {
					t.Fatalf("file lost kept content %q\n%s", value, got)
				}
			}
		})
	}
}

func TestRunAddPrintsCurrentAuthorizedKeys(t *testing.T) {
	local := testKey(t, "rsa", "john@work")
	alicePC := testKey(t, "ed25519", "sshpub.com/alice/pc")
	path := authorizedKeysFixture(t, local+"\n")
	server := keyServer(t, apiBody("alice", "pc", alicePC))
	defer server.Close()

	var out bytes.Buffer
	err := run([]string{"add", "alice/pc"}, &out, io.Discard, func() (string, error) {
		return path, nil
	}, server.URL)
	if err != nil {
		t.Fatalf("run add error = %v", err)
	}
	text := out.String()
	for _, want := range []string{
		"Added 1 key:",
		"alice/pc",
		"Current authorized_keys: " + path,
		"SOURCE   NAME              TYPE                 KEY",
		"LOCAL",
		"john@work",
		"SSHPUB",
		"alice/pc",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("add output missing %q:\n%s", want, text)
		}
	}
}

func TestRunRemovePrintsCurrentAuthorizedKeys(t *testing.T) {
	alicePC := testKey(t, "ed25519", "sshpub.com/alice/pc")
	bobPC := testKey(t, "rsa", "sshpub.com/bob/pc")
	local := testKey(t, "ecdsa256", "john@work")
	path := authorizedKeysFixture(t, strings.Join([]string{alicePC, bobPC, local}, "\n")+"\n")

	var out bytes.Buffer
	err := run([]string{"remove", "alice/pc"}, &out, io.Discard, func() (string, error) {
		return path, nil
	}, "https://example.invalid")
	if err != nil {
		t.Fatalf("run remove error = %v", err)
	}
	text := out.String()
	for _, want := range []string{
		"Removed 1 key:",
		"alice/pc",
		"Current authorized_keys: " + path,
		"SOURCE   NAME              TYPE                 KEY",
		"SSHPUB",
		"bob/pc",
		"LOCAL",
		"john@work",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("remove output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, compactKeyData(strings.Fields(alicePC)[1])) {
		t.Fatalf("remove output still lists removed key:\n%s", text)
	}
}

func TestRemoveRefusesToClearAllKeysNonInteractive(t *testing.T) {
	alicePC := testKey(t, "ed25519", "sshpub.com/alice/pc")
	original := alicePC + "\n# keep comment\n"
	path := authorizedKeysFixture(t, original)

	_, err := removeKeysWithOptions(path, mustTarget(t, "alice"), removeOptions{})
	if err == nil {
		t.Fatalf("removeKeysWithOptions expected error")
	}
	if !strings.Contains(err.Error(), "without --force") {
		t.Fatalf("error = %v", err)
	}
	assertFile(t, path, original)
}

func TestRemoveAllowsClearingSSHPubKeysWhenOptionLocalKeyRemains(t *testing.T) {
	alicePC := testKey(t, "ed25519", "sshpub.com/alice/pc")
	localWithOptions := `from="10.0.0.1" ` + testKey(t, "rsa", "john@work")
	original := alicePC + "\n" + localWithOptions + "\n"
	path := authorizedKeysFixture(t, original)

	removed, err := removeKeysWithOptions(path, mustTarget(t, "alice"), removeOptions{})
	if err != nil {
		t.Fatalf("removeKeysWithOptions error = %v", err)
	}
	if got, want := strings.Join(removed, ","), "alice/pc"; got != want {
		t.Fatalf("removed = %q, want %q", got, want)
	}
	assertFile(t, path, localWithOptions)
}

func TestRemoveCancelledDoesNotChangeFile(t *testing.T) {
	alicePC := testKey(t, "ed25519", "sshpub.com/alice/pc")
	original := alicePC + "\n"
	path := authorizedKeysFixture(t, original)

	var prompt bytes.Buffer
	_, err := removeKeysWithOptions(path, mustTarget(t, "alice"), removeOptions{
		Confirm:     strings.NewReader("\n"),
		Prompt:      &prompt,
		Interactive: true,
	})
	if !errors.Is(err, errRemoveCancelled) {
		t.Fatalf("removeKeysWithOptions error = %v, want cancelled", err)
	}
	assertFile(t, path, original)
	text := prompt.String()
	for _, want := range []string{
		"Warning: this operation will remove all SSH keys from: " + path,
		"You may lose SSH access to this account.",
		"Continue? [y/N]:",
		"Remove cancelled. authorized_keys was not changed.",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("prompt output missing %q:\n%s", want, text)
		}
	}
}

func TestRemoveConfirmedClearsAllKeys(t *testing.T) {
	alicePC := testKey(t, "ed25519", "sshpub.com/alice/pc")
	path := authorizedKeysFixture(t, alicePC+"\n")

	removed, err := removeKeysWithOptions(path, mustTarget(t, "alice"), removeOptions{
		Confirm:     strings.NewReader("y\n"),
		Prompt:      io.Discard,
		Interactive: true,
	})
	if err != nil {
		t.Fatalf("removeKeysWithOptions error = %v", err)
	}
	if got, want := strings.Join(removed, ","), "alice/pc"; got != want {
		t.Fatalf("removed = %q, want %q", got, want)
	}
	assertFile(t, path, "")
}

func TestRemoveForceClearsAllKeysWithoutConfirmation(t *testing.T) {
	alicePC := testKey(t, "ed25519", "sshpub.com/alice/pc")
	path := authorizedKeysFixture(t, alicePC+"\n")

	removed, err := removeKeysWithOptions(path, mustTarget(t, "alice"), removeOptions{
		Force: true,
	})
	if err != nil {
		t.Fatalf("removeKeysWithOptions error = %v", err)
	}
	if got, want := strings.Join(removed, ","), "alice/pc"; got != want {
		t.Fatalf("removed = %q, want %q", got, want)
	}
	assertFile(t, path, "")
}

func TestListSourcesAndKeyData(t *testing.T) {
	sshpubKey := testKey(t, "ed25519", "sshpub.com/alice/pc")
	localKey := testKey(t, "rsa", "john@work")
	path := authorizedKeysFixture(t, sshpubKey+"\n"+localKey+"\n")
	var out bytes.Buffer
	if err := listKeys(&out, path); err != nil {
		t.Fatalf("listKeys() error = %v", err)
	}
	text := out.String()
	for _, want := range []string{"SSHPUB", "alice/pc", "LOCAL", "john@work", "KEY", "..."} {
		if !strings.Contains(text, want) {
			t.Fatalf("list output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "FINGERPRINT") || strings.Contains(text, "SHA256:") {
		t.Fatalf("list output must not show fingerprints:\n%s", text)
	}
}

func TestUpgradeDirectModeCallsUpgradeAPI(t *testing.T) {
	oldVersion, oldSource := version, installSource
	version, installSource = "0.1.3", "direct"
	defer func() {
		version, installSource = oldVersion, oldSource
	}()

	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if r.URL.Path != "/api/cli/upgrade" {
			t.Fatalf("path = %q, want /api/cli/upgrade", r.URL.Path)
		}
		if got := r.URL.Query().Get("version"); got != "0.1.3" {
			t.Fatalf("version query = %q, want 0.1.3", got)
		}
		_, _ = w.Write([]byte(`{"upgrade":true,"latest":"0.1.4"}`))
	}))
	defer server.Close()

	var out bytes.Buffer
	if err := runUpgrade(context.Background(), server.Client(), &out, server.URL); err != nil {
		t.Fatalf("runUpgrade() error = %v", err)
	}
	if !called {
		t.Fatalf("expected upgrade API request")
	}
	text := out.String()
	for _, want := range []string{"A new version is available: 0.1.4", "curl -fsSL https://sshpub.com/install.sh | sh"} {
		if !strings.Contains(text, want) {
			t.Fatalf("upgrade output missing %q:\n%s", want, text)
		}
	}
}

func TestUpgradePackageModeDoesNotCallUpgradeAPI(t *testing.T) {
	oldSource := installSource
	installSource = "package"
	defer func() {
		installSource = oldSource
	}()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("package mode must not call upgrade API")
	}))
	defer server.Close()

	var out bytes.Buffer
	if err := runUpgrade(context.Background(), server.Client(), &out, server.URL); err != nil {
		t.Fatalf("runUpgrade() error = %v", err)
	}
	text := out.String()
	if !strings.Contains(text, "This installation is managed by your package manager.") {
		t.Fatalf("package output missing package manager message:\n%s", text)
	}
	if strings.Contains(text, "curl -fsSL https://sshpub.com/install.sh | sh") {
		t.Fatalf("package output must not include direct install command:\n%s", text)
	}
}

func TestUpgradeDirectModeUpToDate(t *testing.T) {
	oldVersion, oldSource := version, installSource
	version, installSource = "0.1.3", "direct"
	defer func() {
		version, installSource = oldVersion, oldSource
	}()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"upgrade":false,"latest":"0.1.3"}`))
	}))
	defer server.Close()

	var out bytes.Buffer
	if err := runUpgrade(context.Background(), server.Client(), &out, server.URL); err != nil {
		t.Fatalf("runUpgrade() error = %v", err)
	}
	if got, want := out.String(), "sshpub is up to date (0.1.3).\n"; got != want {
		t.Fatalf("output = %q, want %q", got, want)
	}
}

func TestFileContentPreservedOnAdd(t *testing.T) {
	comment := "# keep this"
	blank := ""
	local := testKey(t, "ed25519", "local")
	other := testKey(t, "rsa", "sshpub.com/bob/pc")
	path := authorizedKeysFixture(t, strings.Join([]string{comment, blank, local, other}, "\n")+"\n")
	server := keyServer(t, apiBody("alice", "pc", testKey(t, "ecdsa256", "sshpub.com/alice/pc")))
	defer server.Close()
	if _, err := addKeys(context.Background(), server.Client(), server.URL, path, mustTarget(t, "alice/pc")); err != nil {
		t.Fatalf("addKeys() error = %v", err)
	}
	got := readFile(t, path)
	for _, want := range []string{comment, "\n\n", local, other, "sshpub.com/alice/pc"} {
		if !strings.Contains(got, want) {
			t.Fatalf("file missing %q:\n%s", want, got)
		}
	}
}

func testKey(t *testing.T, kind, comment string) string {
	t.Helper()
	var pub ssh.PublicKey
	var err error
	switch kind {
	case "ed25519":
		key, _, genErr := ed25519.GenerateKey(rand.Reader)
		err = genErr
		if err == nil {
			pub, err = ssh.NewPublicKey(key)
		}
	case "rsa":
		key, genErr := rsa.GenerateKey(rand.Reader, 2048)
		err = genErr
		if err == nil {
			pub, err = ssh.NewPublicKey(&key.PublicKey)
		}
	case "ecdsa256":
		pub = ecdsaPublicKey(t, elliptic.P256())
	case "ecdsa384":
		pub = ecdsaPublicKey(t, elliptic.P384())
	case "ecdsa521":
		pub = ecdsaPublicKey(t, elliptic.P521())
	default:
		t.Fatalf("unknown key kind %q", kind)
	}
	if err != nil {
		t.Fatalf("generate %s key: %v", kind, err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))) + " " + comment
}

func ecdsaPublicKey(t *testing.T, curve elliptic.Curve) ssh.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("generate ecdsa key: %v", err)
	}
	pub, err := ssh.NewPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("new ssh public key: %v", err)
	}
	return pub
}

func replaceComment(line, comment string) string {
	fields := strings.Fields(line)
	return fmt.Sprintf("%s %s %s", fields[0], fields[1], comment)
}

func duplicateServerKey(t *testing.T) string {
	t.Helper()
	key := testKey(t, "ed25519", "sshpub.com/alice/pc")
	return apiBody("alice", "pc", key, "iphone", replaceComment(key, "sshpub.com/alice/iphone"))
}

func apiBody(username string, deviceAndKeys ...string) string {
	var b strings.Builder
	fmt.Fprintf(&b, `{"username":%q,"keys":[`, username)
	for i := 0; i < len(deviceAndKeys); i += 2 {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"device":%q,"public_key":%q}`, deviceAndKeys[i], deviceAndKeys[i+1])
	}
	b.WriteString(`]}`)
	return b.String()
}

func mustTarget(t *testing.T, input string) target {
	t.Helper()
	got, err := parseTarget(input)
	if err != nil {
		t.Fatalf("parseTarget(%q): %v", input, err)
	}
	return got
}

func keyServer(t *testing.T, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
}

func authorizedKeysFixture(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	return string(data)
}

func assertFile(t *testing.T, path, want string) {
	t.Helper()
	if got := readFile(t, path); got != want {
		t.Fatalf("file content = %q, want %q", got, want)
	}
}
