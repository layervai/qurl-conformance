package main

import (
	"os"
	"path/filepath"
	"reflect"
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
