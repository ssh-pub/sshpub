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
		source  string
		user    string
		devices []string
	}{
		{"alice", "", "alice", nil},
		{"alice/pc", "", "alice", []string{"pc"}},
		{"alice/MacBook-Pro", "", "alice", []string{"macbook-pro"}},
		{"alice/pc,iphone", "", "alice", []string{"pc", "iphone"}},
		{"ALICE1/git", "", "alice1", []string{"git"}},
		{"alice/git", "", "alice", []string{"git"}},
		{"1234/git", "", "1234", []string{"git"}},
		{"github/Alice", "github", "alice", nil},
		{"github/alice-1", "github", "alice-1", nil},
		{"gitlab/Alice.Name", "gitlab", "alice.name", nil},
		{"gitlab/alice_1", "gitlab", "alice_1", nil},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := parseTarget(tt.input)
			if err != nil {
				t.Fatalf("parseTarget() error = %v", err)
			}
			if got.Source != tt.source || got.Username != tt.user || strings.Join(got.Devices, ",") != strings.Join(tt.devices, ",") {
				t.Fatalf("parseTarget() = %#v", got)
			}
		})
	}
}

func TestParseTargetRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{"/alice", "alice_dev", "abcdefghijklmnopq", "alice/work_pc", "alice/abcdefghijklmnopqrstuvwxyzabcdefg", "alice/", "alice//pc", "alice/../admin", "alice?x=1", "alice#foo", "alice/pc/", "alice/pc,pc", "github/alice/1", "github/alice,pc", "github/alice_", "github/-alice", "github/alice-", "github/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "gitlab/-alice"} {
		t.Run(input, func(t *testing.T) {
			if _, err := parseTarget(input); err == nil {
				t.Fatalf("parseTarget(%q) expected error", input)
			}
		})
	}
}

func TestProviderUsernameValidation(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		username string
		valid    bool
	}{
		{"github basic", "github", "alice", true},
		{"github hyphen", "github", "alice-test", true},
		{"github single", "github", "a", true},
		{"github digits", "github", "alice123", true},
		{"github double hyphen", "github", "alice--test", false},
		{"github leading hyphen", "github", "-alice", false},
		{"github trailing hyphen", "github", "alice-", false},
		{"github underscore", "github", "alice_test", false},
		{"github dot", "github", "alice.test", false},
		{"github too long", "github", strings.Repeat("a", 40), false},
		{"gitlab basic", "gitlab", "alice", true},
		{"gitlab dot", "gitlab", "alice.test", true},
		{"gitlab underscore", "gitlab", "alice_test", true},
		{"gitlab hyphen", "gitlab", "alice-test", true},
		{"gitlab short valid", "gitlab", "ab", true},
		{"gitlab single invalid", "gitlab", "a", false},
		{"gitlab leading dot", "gitlab", ".alice", false},
		{"gitlab leading hyphen", "gitlab", "-alice", false},
		{"gitlab leading underscore", "gitlab", "_alice", false},
		{"gitlab trailing dot", "gitlab", "alice.", false},
		{"gitlab trailing hyphen", "gitlab", "alice-", false},
		{"gitlab trailing underscore", "gitlab", "alice_", false},
		{"gitlab too long", "gitlab", strings.Repeat("a", 256), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseTarget(tt.provider + "/" + tt.username)
			if tt.valid && err != nil {
				t.Fatalf("parseTarget() error = %v", err)
			}
			if !tt.valid && err == nil {
				t.Fatalf("parseTarget() expected error")
			}
		})
	}
}

func TestProviderUsernameValidationMatchesCommentParsing(t *testing.T) {
	for _, tt := range []struct {
		provider string
		username string
	}{
		{"github", "alice"},
		{"github", "alice-test"},
		{"github", "alice--test"},
		{"github", "alice_test"},
		{"gitlab", "alice"},
		{"gitlab", "alice.test"},
		{"gitlab", "alice_"},
		{"gitlab", "a"},
	} {
		t.Run(tt.provider+"/"+tt.username, func(t *testing.T) {
			_, parseErr := parseTarget(tt.provider + "/" + tt.username)
			_, _, commentOK := splitProviderComment("sshpub.com/" + tt.provider + "/" + tt.username)
			if (parseErr == nil) != commentOK {
				t.Fatalf("parseTarget valid=%v splitProviderComment ok=%v", parseErr == nil, commentOK)
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
	err := run([]string{"remove", "alice/pc", "--yes"}, &out, io.Discard, func() (string, error) {
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

func TestRemoveRequiresConfirmationByDefault(t *testing.T) {
	alicePC := testKey(t, "ed25519", "sshpub.com/alice/pc")
	original := alicePC + "\n# keep comment\n"
	path := authorizedKeysFixture(t, original)

	_, err := removeKeysWithOptions(path, mustTarget(t, "alice"), removeOptions{})
	if err == nil {
		t.Fatalf("removeKeysWithOptions expected error")
	}
	assertFile(t, path, original)
}

func TestRemoveAllowsClearingSSHPubKeysWhenOptionLocalKeyRemains(t *testing.T) {
	alicePC := testKey(t, "ed25519", "sshpub.com/alice/pc")
	localWithOptions := `from="10.0.0.1" ` + testKey(t, "rsa", "john@work")
	original := alicePC + "\n" + localWithOptions + "\n"
	path := authorizedKeysFixture(t, original)

	removed, err := removeKeysWithOptions(path, mustTarget(t, "alice"), removeOptions{Force: true})
	if err != nil {
		t.Fatalf("removeKeysWithOptions error = %v", err)
	}
	if got, want := strings.Join(removed, ","), "alice/pc"; got != want {
		t.Fatalf("removed = %q, want %q", got, want)
	}
	assertFile(t, path, localWithOptions+"\n")
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
		"1 key will be removed:",
		"SOURCE   NAME",
		"Remove 1 key for alice? [y/N]:",
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

func TestRunRemoveRejectsForceArgument(t *testing.T) {
	var out bytes.Buffer
	err := run([]string{"remove", "alice/pc", "--force"}, &out, io.Discard, func() (string, error) {
		return authorizedKeysFixture(t, ""), nil
	}, "https://example.invalid")
	if err == nil || !strings.Contains(err.Error(), "usage: sshpub remove") {
		t.Fatalf("run remove --force error = %v, want usage error", err)
	}
}

func TestListSourcesAndKeyData(t *testing.T) {
	sshpubKey := testKey(t, "ed25519", "sshpub.com/alice/pc")
	githubKey := testKey(t, "ed25519", "sshpub.com/github/alice")
	gitlabKey := testKey(t, "ed25519", "sshpub.com/gitlab/bob")
	localKey := testKey(t, "rsa", "john@work")
	path := authorizedKeysFixture(t, sshpubKey+"\n"+githubKey+"\n"+gitlabKey+"\n"+localKey+"\n")
	var out bytes.Buffer
	if err := listKeys(&out, path); err != nil {
		t.Fatalf("listKeys() error = %v", err)
	}
	text := out.String()
	for _, want := range []string{"SSHPUB", "alice/pc", "GITHUB", "alice", "GITLAB", "bob", "LOCAL", "john@work", "KEY", "..."} {
		if !strings.Contains(text, want) {
			t.Fatalf("list output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "FINGERPRINT") || strings.Contains(text, "SHA256:") {
		t.Fatalf("list output must not show fingerprints:\n%s", text)
	}
}

func TestSSHPubDeviceAddUpdatesRotatedKey(t *testing.T) {
	oldKey := testKey(t, "ed25519", "sshpub.com/alice/pc")
	newKey := testKey(t, "rsa", "sshpub.com/alice/pc")
	path := authorizedKeysFixture(t, oldKey+"\n")
	server := keyServer(t, apiBody("alice", "pc", newKey))
	defer server.Close()

	result, err := addKeys(context.Background(), server.Client(), server.URL, path, mustTarget(t, "alice/pc"))
	if err != nil {
		t.Fatalf("addKeys() error = %v", err)
	}
	if got, want := strings.Join(result.Updated, ","), "alice/pc"; got != want {
		t.Fatalf("Updated = %q, want %q", got, want)
	}
	got := readFile(t, path)
	if strings.Contains(got, oldKey) || !strings.Contains(got, newKey) {
		t.Fatalf("rotation did not replace key:\n%s", got)
	}
}

func TestProviderAddGitHubAddsMultipleKeysWithSameComment(t *testing.T) {
	keyA := withoutComment(testKey(t, "ed25519", "ignored"))
	keyB := withoutComment(testKey(t, "rsa", "ignored"))
	keyC := withoutComment(testKey(t, "ecdsa256", "ignored"))
	path := authorizedKeysFixture(t, "")
	server := providerServer(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Accept"); got != "application/vnd.github+json" {
			t.Fatalf("Accept = %q", got)
		}
		if got := r.Header.Get("User-Agent"); !strings.HasPrefix(got, "sshpub/") {
			t.Fatalf("User-Agent = %q", got)
		}
		_, _ = w.Write([]byte(fmt.Sprintf(`[{"id":1,"key":%q},{"id":2,"key":%q},{"id":3,"key":%q}]`, keyA, keyB, keyC)))
	}, &githubAPIBaseURL)
	defer server.Close()

	result, err := addKeys(context.Background(), server.Client(), "", path, mustTarget(t, "github/alice"))
	if err != nil {
		t.Fatalf("addKeys() error = %v", err)
	}
	if len(result.Added) != 3 {
		t.Fatalf("Added = %#v, want 3 keys", result.Added)
	}
	var out bytes.Buffer
	printAddResult(&out, result)
	if !strings.Contains(out.String(), "Added 3 keys:") {
		t.Fatalf("add output should count 3 keys:\n%s", out.String())
	}
	got := readFile(t, path)
	if strings.Count(got, "sshpub.com/github/alice") != 3 {
		t.Fatalf("github comments not written for both keys:\n%s", got)
	}
}

func TestProviderAddGitLabReportsThreeAddedKeys(t *testing.T) {
	keyA := withoutComment(testKey(t, "ed25519", "ignored"))
	keyB := withoutComment(testKey(t, "rsa", "ignored"))
	keyC := withoutComment(testKey(t, "ecdsa256", "ignored"))
	path := authorizedKeysFixture(t, "")
	server := providerServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf(`[{"id":1,"key":%q,"usage_type":"auth"},{"id":2,"key":%q,"usage_type":"auth"},{"id":3,"key":%q,"usage_type":"auth_and_signing"}]`, keyA, keyB, keyC)))
	}, &gitlabAPIBaseURL)
	defer server.Close()

	result, err := addKeys(context.Background(), server.Client(), "", path, mustTarget(t, "gitlab/alice"))
	if err != nil {
		t.Fatalf("addKeys() error = %v", err)
	}
	var out bytes.Buffer
	printAddResult(&out, result)
	if !strings.Contains(out.String(), "Added 3 keys:") {
		t.Fatalf("add output should count 3 keys:\n%s", out.String())
	}
}

func TestProviderAddReportsRepeatedExistsByKey(t *testing.T) {
	for _, tt := range []struct {
		name       string
		target     string
		baseURLVar *string
		body       func([]string) string
	}{
		{
			name:       "github",
			target:     "github/alice",
			baseURLVar: &githubAPIBaseURL,
			body: func(keys []string) string {
				return fmt.Sprintf(`[{"id":1,"key":%q},{"id":2,"key":%q},{"id":3,"key":%q},{"id":4,"key":%q}]`, keys[0], keys[1], keys[2], keys[3])
			},
		},
		{
			name:       "gitlab",
			target:     "gitlab/alice",
			baseURLVar: &gitlabAPIBaseURL,
			body: func(keys []string) string {
				return fmt.Sprintf(`[{"id":1,"key":%q,"usage_type":"auth"},{"id":2,"key":%q,"usage_type":"auth"},{"id":3,"key":%q,"usage_type":"auth"},{"id":4,"key":%q,"usage_type":"auth"}]`, keys[0], keys[1], keys[2], keys[3])
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			existingA := withoutComment(testKey(t, "ed25519", "ignored"))
			existingB := withoutComment(testKey(t, "rsa", "ignored"))
			existingC := withoutComment(testKey(t, "ecdsa256", "ignored"))
			newKey := withoutComment(testKey(t, "ecdsa384", "ignored"))
			provider, username, _ := strings.Cut(tt.target, "/")
			path := authorizedKeysFixture(t, strings.Join([]string{
				existingA + " " + providerComment(provider, username),
				existingB + " " + providerComment(provider, username),
				existingC + " " + providerComment(provider, username),
			}, "\n")+"\n")
			server := providerServer(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(tt.body([]string{existingA, existingB, existingC, newKey})))
			}, tt.baseURLVar)
			defer server.Close()

			result, err := addKeys(context.Background(), server.Client(), "", path, mustTarget(t, tt.target))
			if err != nil {
				t.Fatalf("addKeys() error = %v", err)
			}
			if len(result.Exists) != 3 {
				t.Fatalf("Exists = %#v, want 3 keys", result.Exists)
			}
			var out bytes.Buffer
			printAddResult(&out, result)
			if strings.Count(out.String(), tt.target) != 4 {
				t.Fatalf("output should include 1 added and 3 exists entries for %s:\n%s", tt.target, out.String())
			}
		})
	}
}

func TestProviderAddDoesNotModifyExistingLocalComment(t *testing.T) {
	local := testKey(t, "ed25519", "My-Production-Server")
	path := authorizedKeysFixture(t, local+"\n")
	server := providerServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf(`[{"id":1,"key":%q}]`, withoutComment(local))))
	}, &githubAPIBaseURL)
	defer server.Close()

	result, err := addKeys(context.Background(), server.Client(), "", path, mustTarget(t, "github/alice"))
	if err != nil {
		t.Fatalf("addKeys() error = %v", err)
	}
	if len(result.Added) != 0 || len(result.Exists) != 1 {
		t.Fatalf("result = %#v", result)
	}
	assertFile(t, path, local+"\n")
}

func TestProviderAddGitLabFiltersSigningKeys(t *testing.T) {
	authKey := withoutComment(testKey(t, "ed25519", "ignored"))
	signingKey := withoutComment(testKey(t, "rsa", "ignored"))
	authAndSigningKey := withoutComment(testKey(t, "ecdsa256", "ignored"))
	path := authorizedKeysFixture(t, "")
	server := providerServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf(`[{"id":1,"title":"auth","key":%q,"usage_type":"auth"},{"id":2,"title":"sign","key":%q,"usage_type":"signing"},{"id":3,"title":"both","key":%q,"usage_type":"auth_and_signing"}]`, authKey, signingKey, authAndSigningKey)))
	}, &gitlabAPIBaseURL)
	defer server.Close()

	result, err := addKeys(context.Background(), server.Client(), "", path, mustTarget(t, "gitlab/alice"))
	if err != nil {
		t.Fatalf("addKeys() error = %v", err)
	}
	if len(result.Added) != 2 {
		t.Fatalf("Added = %#v, want 2 auth keys", result.Added)
	}
	got := readFile(t, path)
	if strings.Contains(got, strings.Fields(signingKey)[1]) || !strings.Contains(got, strings.Fields(authKey)[1]) || !strings.Contains(got, strings.Fields(authAndSigningKey)[1]) {
		t.Fatalf("gitlab usage filtering failed:\n%s", got)
	}
}

func TestProviderAddSigningOnlyReturnsNoKeys(t *testing.T) {
	key := withoutComment(testKey(t, "ed25519", "ignored"))
	path := authorizedKeysFixture(t, "")
	server := providerServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf(`[{"id":1,"key":%q,"usage_type":"signing"}]`, key)))
	}, &gitlabAPIBaseURL)
	defer server.Close()

	_, err := addKeys(context.Background(), server.Client(), "", path, mustTarget(t, "gitlab/alice"))
	if err == nil || !strings.Contains(err.Error(), "No SSH public keys found for gitlab/alice") {
		t.Fatalf("error = %v", err)
	}
	assertFile(t, path, "")
}

func TestProviderAddGitLabUnexpectedUsageTypeFailsClosed(t *testing.T) {
	for _, usage := range []string{"", "unknown"} {
		t.Run(usage, func(t *testing.T) {
			key := withoutComment(testKey(t, "ed25519", "ignored"))
			path := authorizedKeysFixture(t, "")
			server := providerServer(t, func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(fmt.Sprintf(`[{"id":1,"key":%q,"usage_type":%q}]`, key, usage)))
			}, &gitlabAPIBaseURL)
			defer server.Close()

			_, err := addKeys(context.Background(), server.Client(), "", path, mustTarget(t, "gitlab/alice"))
			if err == nil || !strings.Contains(err.Error(), "unexpected GitLab key usage_type") {
				t.Fatalf("error = %v, want unexpected usage_type", err)
			}
			assertFile(t, path, "")
		})
	}
}

func TestProviderAddDoesNotRemoveOldProviderKeys(t *testing.T) {
	oldKey := testKey(t, "ed25519", "sshpub.com/github/alice")
	newKey := withoutComment(testKey(t, "rsa", "ignored"))
	path := authorizedKeysFixture(t, oldKey+"\n")
	server := providerServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(fmt.Sprintf(`[{"id":1,"key":%q}]`, newKey)))
	}, &githubAPIBaseURL)
	defer server.Close()

	if _, err := addKeys(context.Background(), server.Client(), "", path, mustTarget(t, "github/alice")); err != nil {
		t.Fatalf("addKeys() error = %v", err)
	}
	got := readFile(t, path)
	if !strings.Contains(got, oldKey) || strings.Count(got, "sshpub.com/github/alice") != 2 {
		t.Fatalf("provider add should keep old provider key and add new one:\n%s", got)
	}
}

func TestProviderPaginationFailureDoesNotWrite(t *testing.T) {
	key := withoutComment(testKey(t, "ed25519", "ignored"))
	path := authorizedKeysFixture(t, "")
	server := providerServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "1" {
			next := "http://" + r.Host + strings.Replace(r.URL.String(), "page=1", "page=2", 1)
			w.Header().Set("Link", `<`+next+`>; rel="next"`)
			_, _ = w.Write([]byte(fmt.Sprintf(`[{"id":1,"key":%q}]`, key)))
			return
		}
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`bad gateway`))
	}, &githubAPIBaseURL)
	defer server.Close()

	if _, err := addKeys(context.Background(), server.Client(), "", path, mustTarget(t, "github/alice")); err == nil {
		t.Fatalf("addKeys expected pagination error")
	}
	assertFile(t, path, "")
}

func TestProviderInvalidJSONDoesNotWrite(t *testing.T) {
	path := authorizedKeysFixture(t, "")
	server := providerServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}, &githubAPIBaseURL)
	defer server.Close()

	if _, err := addKeys(context.Background(), server.Client(), "", path, mustTarget(t, "github/alice")); err == nil {
		t.Fatalf("addKeys expected invalid JSON error")
	}
	assertFile(t, path, "")
}

func TestProviderInvalidKeyDoesNotWrite(t *testing.T) {
	path := authorizedKeysFixture(t, "")
	server := providerServer(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"id":1,"key":"ssh-ed25519 bad"}]`))
	}, &githubAPIBaseURL)
	defer server.Close()

	if _, err := addKeys(context.Background(), server.Client(), "", path, mustTarget(t, "github/alice")); err == nil {
		t.Fatalf("addKeys expected invalid key error")
	}
	assertFile(t, path, "")
}

func TestRemoveDoesNotCrossSources(t *testing.T) {
	sshpubKey := testKey(t, "ed25519", "sshpub.com/alice/pc")
	githubKey := testKey(t, "rsa", "sshpub.com/github/alice")
	gitlabKey := testKey(t, "ecdsa256", "sshpub.com/gitlab/alice")
	path := authorizedKeysFixture(t, strings.Join([]string{sshpubKey, githubKey, gitlabKey}, "\n")+"\n")

	if _, err := removeKeys(path, mustTarget(t, "alice")); err != nil {
		t.Fatalf("removeKeys() error = %v", err)
	}
	got := readFile(t, path)
	if strings.Contains(got, sshpubKey) || !strings.Contains(got, githubKey) || !strings.Contains(got, gitlabKey) {
		t.Fatalf("remove alice crossed source boundaries:\n%s", got)
	}
}

func TestRemoveProviderSourceGroup(t *testing.T) {
	githubA := testKey(t, "ed25519", "sshpub.com/github/alice")
	githubB := testKey(t, "rsa", "sshpub.com/github/alice")
	githubOther := testKey(t, "ecdsa256", "sshpub.com/github/alice2")
	path := authorizedKeysFixture(t, strings.Join([]string{githubA, githubB, githubOther}, "\n")+"\n")

	removed, err := removeKeys(path, mustTarget(t, "github/alice"))
	if err != nil {
		t.Fatalf("removeKeys() error = %v", err)
	}
	if got, want := strings.Join(removed, ","), "github/alice,github/alice"; got != want {
		t.Fatalf("removed = %q, want %q", got, want)
	}
	got := readFile(t, path)
	if strings.Contains(got, githubA) || strings.Contains(got, githubB) || !strings.Contains(got, githubOther) {
		t.Fatalf("remove github/alice should delete exact source group only:\n%s", got)
	}
}

func TestRemoveConfirmationAnswers(t *testing.T) {
	for _, tt := range []struct {
		name    string
		answer  string
		wantRun bool
	}{
		{"enter", "\n", false},
		{"n", "n\n", false},
		{"yes", "yes\n", true},
		{"y uppercase", "Y\n", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key := testKey(t, "ed25519", "sshpub.com/alice/pc")
			path := authorizedKeysFixture(t, key+"\n")
			_, err := removeKeysWithOptions(path, mustTarget(t, "alice/pc"), removeOptions{
				Confirm:     strings.NewReader(tt.answer),
				Prompt:      io.Discard,
				Interactive: true,
			})
			if tt.wantRun && err != nil {
				t.Fatalf("removeKeysWithOptions error = %v", err)
			}
			if !tt.wantRun && !errors.Is(err, errRemoveCancelled) {
				t.Fatalf("error = %v, want cancel", err)
			}
			got := readFile(t, path)
			if tt.wantRun && strings.Contains(got, key) {
				t.Fatalf("key was not removed")
			}
			if !tt.wantRun && got != key+"\n" {
				t.Fatalf("file changed after cancel: %q", got)
			}
		})
	}
}

func TestRemoveTTYConfirmationAnswers(t *testing.T) {
	for _, tt := range []struct {
		name    string
		answer  string
		wantRun bool
	}{
		{"y", "y\n", true},
		{"enter", "\n", false},
		{"N", "N\n", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			key := testKey(t, "ed25519", "sshpub.com/alice/pc")
			path := authorizedKeysFixture(t, key+"\n")
			_, err := removeKeysWithOptions(path, mustTarget(t, "alice/pc"), removeOptions{
				Confirm:     strings.NewReader(tt.answer),
				Prompt:      io.Discard,
				Interactive: true,
			})
			if tt.wantRun && err != nil {
				t.Fatalf("removeKeysWithOptions error = %v", err)
			}
			if !tt.wantRun && !errors.Is(err, errRemoveCancelled) {
				t.Fatalf("error = %v, want cancel", err)
			}
			got := readFile(t, path)
			if tt.wantRun && strings.Contains(got, key) {
				t.Fatalf("key was not removed")
			}
			if !tt.wantRun && got != key+"\n" {
				t.Fatalf("file changed after cancel: %q", got)
			}
		})
	}
}

func TestRemoveNonTTYRequiresYes(t *testing.T) {
	key := testKey(t, "ed25519", "sshpub.com/alice/pc")
	path := authorizedKeysFixture(t, key+"\n")

	_, err := removeKeysWithOptions(path, mustTarget(t, "alice/pc"), removeOptions{
		Confirm:     strings.NewReader("y\n"),
		Prompt:      io.Discard,
		Interactive: false,
	})
	if err == nil || !strings.Contains(err.Error(), "confirmation requires an interactive terminal") {
		t.Fatalf("error = %v, want non-interactive confirmation error", err)
	}
	assertFile(t, path, key+"\n")
}

func TestRemoveYesSkipsConfirmation(t *testing.T) {
	key := testKey(t, "ed25519", "sshpub.com/alice/pc")
	path := authorizedKeysFixture(t, key+"\n")

	if _, err := removeKeysWithOptions(path, mustTarget(t, "alice/pc"), removeOptions{Force: true}); err != nil {
		t.Fatalf("removeKeysWithOptions error = %v", err)
	}
	assertFile(t, path, "")
}

func TestRunRemoveYesFlagsSkipConfirmation(t *testing.T) {
	for _, flag := range []string{"--yes", "-y"} {
		t.Run(flag, func(t *testing.T) {
			key := testKey(t, "ed25519", "sshpub.com/alice/pc")
			path := authorizedKeysFixture(t, key+"\n")
			var out bytes.Buffer
			err := run([]string{"remove", "alice/pc", flag}, &out, io.Discard, func() (string, error) {
				return path, nil
			}, "https://example.invalid")
			if err != nil {
				t.Fatalf("run remove %s error = %v", flag, err)
			}
			assertFile(t, path, "")
		})
	}
}

func TestRemovePreservesTrailingNewlineWhenNonEmpty(t *testing.T) {
	alicePC := testKey(t, "ed25519", "sshpub.com/alice/pc")
	bobPC := testKey(t, "ed25519", "sshpub.com/bob/pc")
	path := authorizedKeysFixture(t, alicePC+"\n"+bobPC+"\n")

	if _, err := removeKeys(path, mustTarget(t, "alice/pc")); err != nil {
		t.Fatalf("removeKeys() error = %v", err)
	}
	assertFile(t, path, bobPC+"\n")
}

func TestRemoveWarningOnlyWhenNoValidKeysRemain(t *testing.T) {
	alicePC := testKey(t, "ed25519", "sshpub.com/alice/pc")
	bobPC := testKey(t, "ed25519", "sshpub.com/bob/pc")

	t.Run("valid key remains", func(t *testing.T) {
		path := authorizedKeysFixture(t, alicePC+"\n"+bobPC+"\n")
		var prompt bytes.Buffer
		_, err := removeKeysWithOptions(path, mustTarget(t, "alice/pc"), removeOptions{
			Confirm:     strings.NewReader("\n"),
			Prompt:      &prompt,
			Interactive: true,
		})
		if !errors.Is(err, errRemoveCancelled) {
			t.Fatalf("error = %v, want cancel", err)
		}
		if strings.Contains(prompt.String(), "leave no valid SSH keys") {
			t.Fatalf("unexpected warning when another valid key remains:\n%s", prompt.String())
		}
	})

	t.Run("no valid keys remain", func(t *testing.T) {
		path := authorizedKeysFixture(t, alicePC+"\n")
		var prompt bytes.Buffer
		_, err := removeKeysWithOptions(path, mustTarget(t, "alice/pc"), removeOptions{
			Confirm:     strings.NewReader("\n"),
			Prompt:      &prompt,
			Interactive: true,
		})
		if !errors.Is(err, errRemoveCancelled) {
			t.Fatalf("error = %v, want cancel", err)
		}
		if !strings.Contains(prompt.String(), "Warning: this will leave no valid SSH keys in authorized_keys.") {
			t.Fatalf("missing final-key warning:\n%s", prompt.String())
		}
	})
}

func TestProviderRemoveWarningWhenNoValidKeysRemain(t *testing.T) {
	for _, tt := range []struct {
		name   string
		target string
		line   string
	}{
		{"github", "github/alice", testKey(t, "ed25519", "sshpub.com/github/alice")},
		{"gitlab", "gitlab/alice", testKey(t, "ed25519", "sshpub.com/gitlab/alice")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			path := authorizedKeysFixture(t, tt.line+"\n")
			var prompt bytes.Buffer
			_, err := removeKeysWithOptions(path, mustTarget(t, tt.target), removeOptions{
				Confirm:     strings.NewReader("\n"),
				Prompt:      &prompt,
				Interactive: true,
			})
			if !errors.Is(err, errRemoveCancelled) {
				t.Fatalf("error = %v, want cancel", err)
			}
			if !strings.Contains(prompt.String(), "Warning: this will leave no valid SSH keys in authorized_keys.") {
				t.Fatalf("missing provider final-key warning:\n%s", prompt.String())
			}
		})
	}
}

func TestRunRemoveYesLastKeySkipsConfirmAndExecutes(t *testing.T) {
	key := testKey(t, "ed25519", "sshpub.com/alice/pc")
	path := authorizedKeysFixture(t, key+"\n")
	var out bytes.Buffer
	err := run([]string{"remove", "alice/pc", "--yes"}, &out, io.Discard, func() (string, error) {
		return path, nil
	}, "https://example.invalid")
	if err != nil {
		t.Fatalf("run remove --yes error = %v", err)
	}
	assertFile(t, path, "")
	text := out.String()
	if strings.Contains(text, "[y/N]") {
		t.Fatalf("--yes must not prompt for confirmation:\n%s", text)
	}
	if !strings.Contains(text, "Removed 1 key:") {
		t.Fatalf("--yes should execute remove:\n%s", text)
	}
}

func TestPrintAddResultKeepsAddedExistsCountsAndDeduplicatesUpdated(t *testing.T) {
	var out bytes.Buffer
	printAddResult(&out, addResult{
		Added:   []string{"github/alice", "github/alice", "github/alice"},
		Updated: []string{"alice/mac", "alice/mac"},
		Exists:  []string{"github/bob", "github/bob", "github/bob"},
	})
	text := out.String()
	if !strings.Contains(text, "Added 3 keys") || strings.Count(text, "github/alice") != 3 {
		t.Fatalf("Added output should keep all 3 key entries:\n%s", text)
	}
	if strings.Count(text, "github/bob") != 3 {
		t.Fatalf("Exists output should keep all 3 key entries:\n%s", text)
	}
	if strings.Count(text, "alice/mac") != 1 {
		t.Fatalf("Updated output should be deduplicated:\n%s", text)
	}
	if !strings.Contains(text, "Updated 1 key") {
		t.Fatalf("Updated count should be deduplicated:\n%s", text)
	}
}

func TestRemoveNoMatchingKeysDoesNotPrompt(t *testing.T) {
	path := authorizedKeysFixture(t, "")
	var prompt bytes.Buffer
	removed, err := removeKeysWithOptions(path, mustTarget(t, "github/alice"), removeOptions{
		Confirm: strings.NewReader("y\n"),
		Prompt:  &prompt,
	})
	if err != nil {
		t.Fatalf("removeKeysWithOptions error = %v", err)
	}
	if len(removed) != 0 || prompt.Len() != 0 {
		t.Fatalf("removed=%#v prompt=%q", removed, prompt.String())
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

func TestUpgradeExternalModeDoesNotCallUpgradeAPI(t *testing.T) {
	oldSource := installSource
	installSource = "external"
	defer func() {
		installSource = oldSource
	}()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("external mode must not call upgrade API")
	}))
	defer server.Close()

	var out bytes.Buffer
	if err := runUpgrade(context.Background(), server.Client(), &out, server.URL); err != nil {
		t.Fatalf("runUpgrade() error = %v", err)
	}
	text := out.String()
	for _, want := range []string{
		"This build is not managed by SSH Pub.",
		"Upgrade it using the same method you used to install it.",
		"More information: https://sshpub.com",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("external output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "curl -fsSL https://sshpub.com/install.sh | sh") {
		t.Fatalf("external output must not include direct install command:\n%s", text)
	}
}

func TestUpgradeUnknownInstallSourceFailsClosed(t *testing.T) {
	oldSource := installSource
	installSource = "invalid"
	defer func() {
		installSource = oldSource
	}()

	var out bytes.Buffer
	err := runUpgrade(context.Background(), http.DefaultClient, &out, "https://example.invalid")
	if err == nil || err.Error() != "unknown install source: invalid" {
		t.Fatalf("runUpgrade() error = %v, want unknown install source", err)
	}
}

func TestInstallSourceIsPackageLevelStringVariable(t *testing.T) {
	oldSource := installSource
	installSource = "direct"
	if installSource != "direct" {
		t.Fatalf("installSource override failed")
	}
	installSource = oldSource
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

func providerServer(t *testing.T, handler http.HandlerFunc, baseURLVar *string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(handler)
	oldBaseURL := *baseURLVar
	*baseURLVar = server.URL
	t.Cleanup(func() {
		*baseURLVar = oldBaseURL
	})
	return server
}

func withoutComment(line string) string {
	fields := strings.Fields(line)
	return fields[0] + " " + fields[1]
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
