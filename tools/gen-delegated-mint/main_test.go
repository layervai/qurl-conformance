package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	conformance "github.com/layervai/qurl-conformance"
)

func TestRunAtPathPreservesSignedVectorsByDefault(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	before, err := conformance.ParseDelegatedMintIssueV1File(raw)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "vectors.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runAtPath(path, false); err != nil {
		t.Fatal(err)
	}
	afterRaw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	after, err := conformance.ParseDelegatedMintIssueV1File(afterRaw)
	if err != nil {
		t.Fatal(err)
	}
	beforeSigned := []conformance.DelegatedMintIssueV1Golden{
		before.Golden, before.RetryGolden, before.RefreshGolden, before.WrongEndpointSigned,
		before.NonceReuseSigned, before.AuthorityConflictSigned,
	}
	afterSigned := []conformance.DelegatedMintIssueV1Golden{
		after.Golden, after.RetryGolden, after.RefreshGolden, after.WrongEndpointSigned,
		after.NonceReuseSigned, after.AuthorityConflictSigned,
	}
	if !reflect.DeepEqual(afterSigned, beforeSigned) {
		t.Fatal("default generation changed a committed signed vector")
	}
}

func TestRunAtPathExplicitRotationChangesKIDsAndKeys(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatal(err)
	}
	before, err := conformance.ParseDelegatedMintIssueV1File(raw)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "vectors.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runAtPath(path, true); err != nil {
		t.Fatal(err)
	}
	afterRaw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	after, err := conformance.ParseDelegatedMintIssueV1File(afterRaw)
	if err != nil {
		t.Fatal(err)
	}
	if after.Golden.KID == before.Golden.KID || after.RefreshGolden.KID == before.RefreshGolden.KID {
		t.Fatal("explicit rotation reused a committed KID")
	}
	if after.Golden.PublicKeyDERB64URL == before.Golden.PublicKeyDERB64URL ||
		after.RefreshGolden.PublicKeyDERB64URL == before.RefreshGolden.PublicKeyDERB64URL {
		t.Fatal("explicit rotation reused a committed public key")
	}
	if after.Golden.KID == after.RefreshGolden.KID ||
		after.RetryGolden.KID != after.RefreshGolden.KID ||
		after.RetryGolden.PublicKeyDERB64URL != after.RefreshGolden.PublicKeyDERB64URL {
		t.Fatal("rotated initial and refresh key lineages are not distinct and stable")
	}
}

func TestNextRotationKID(t *testing.T) {
	t.Parallel()
	for input, want := range map[string]string{
		"issuer-2026-09":    "issuer-2026-09-r1",
		"issuer-2026-09-r1": "issuer-2026-09-r2",
	} {
		if got, err := nextRotationKID(input); err != nil || got != want {
			t.Errorf("nextRotationKID(%q) = %q, %v; want %q", input, got, err, want)
		}
	}
	if _, err := nextRotationKID(strings.Repeat("a", 64)); err == nil {
		t.Fatal("overlong rotated KID unexpectedly accepted")
	}
}
