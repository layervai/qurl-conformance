package conformance

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// A preceding slash or @ remains a match so neither a full GitHub URL nor an
// npm scope can bypass this check.
var layerVRepositoryReference = regexp.MustCompile(`(?i)(?:^|[^\w])layervai/([a-z0-9](?:[a-z0-9._-]*[a-z0-9_-])?)`)

// Each entry was verified as public on 2026-09-06. Additions require the same
// check. A private repository must never be added to silence a failure.
var reviewedPublicLayerVRepositories = map[string]bool{
	"ops-routines-workflows": true,
	"qurl-conformance":       true,
	"qurl-go":                true,
	"qurl-typescript":        true,
}

func layerVRepositories(text string) []string {
	var repositories []string
	for _, match := range layerVRepositoryReference.FindAllStringSubmatch(text, -1) {
		repository := strings.TrimSuffix(strings.ToLower(match[1]), ".git")
		repositories = append(repositories, repository)
	}
	slices.Sort(repositories)
	return slices.Compact(repositories)
}

func unreviewedLayerVRepositories(text string) []string {
	var unreviewed []string
	for _, repository := range layerVRepositories(text) {
		if !reviewedPublicLayerVRepositories[repository] {
			unreviewed = append(unreviewed, repository)
		}
	}
	return unreviewed
}

func TestUnreviewedLayerVRepositoryFails(t *testing.T) {
	// Split the fixture so this test cannot permit its own forbidden value.
	fixture := "layervai/" + "unlisted-private-fixture"
	if got := unreviewedLayerVRepositories(fixture); !slices.Equal(got, []string{"unlisted-private-fixture"}) {
		t.Fatalf("unreviewed repositories = %v", got)
	}
}

func TestAllowlistedPrefixDoesNotHideUnreviewedRepository(t *testing.T) {
	// GitHub repository names may contain dots. Split the fixture so the test
	// does not itself add an unreviewed repository reference to public source.
	fixture := "layervai/qurl-conformance" + ".private"
	if got := unreviewedLayerVRepositories(fixture); !slices.Equal(got, []string{"qurl-conformance.private"}) {
		t.Fatalf("unreviewed repositories = %v", got)
	}
}

func reviewedCODEOWNERSTeamReference(path, matched string) bool {
	reviewedTeam := "@" + "layervai/" + "platform"
	return filepath.ToSlash(path) == ".github/CODEOWNERS" && strings.TrimSpace(matched) == reviewedTeam
}

func TestOnlyReviewedCODEOWNERSTeamReferenceIsExempt(t *testing.T) {
	fixture := "@" + "layervai/" + "platform"
	if got := unreviewedLayerVRepositories(fixture); !slices.Equal(got, []string{"platform"}) {
		t.Fatalf("scoped repository reference was not detected: %v", got)
	}
	if !reviewedCODEOWNERSTeamReference(".github/CODEOWNERS", fixture) {
		t.Fatal("reviewed CODEOWNERS team was not exempt")
	}
	if reviewedCODEOWNERSTeamReference("README.md", fixture) {
		t.Fatal("reviewed team was exempt outside CODEOWNERS")
	}
	privateScope := "@" + "layervai/" + "unlisted-private-scope"
	if got := unreviewedLayerVRepositories(privateScope); !slices.Equal(got, []string{"unlisted-private-scope"}) {
		t.Fatalf("unreviewed package scope was not detected: %v", got)
	}
	if reviewedCODEOWNERSTeamReference(".github/CODEOWNERS", privateScope) {
		t.Fatal("unreviewed CODEOWNERS scope was exempt")
	}
}

func TestPublicSourceNamesOnlyReviewedLayerVRepositories(t *testing.T) {
	seen := make(map[string]bool)
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			switch entry.Name() {
			case ".git", "node_modules", "dist", "build", "coverage":
				return filepath.SkipDir
			}
			return nil
		}
		if path == ".git" || !entry.Type().IsRegular() {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(body)
		for _, match := range layerVRepositoryReference.FindAllStringSubmatchIndex(text, -1) {
			repository := strings.TrimSuffix(strings.ToLower(text[match[2]:match[3]]), ".git")
			seen[repository] = true
			if !reviewedPublicLayerVRepositories[repository] && !reviewedCODEOWNERSTeamReference(path, text[match[0]:match[1]]) {
				t.Errorf("%s names an unreviewed LayerV repository %q", filepath.ToSlash(path), "layervai/"+repository)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for repository := range reviewedPublicLayerVRepositories {
		if !seen[repository] {
			t.Errorf("reviewed-public repository %q is not used", repository)
		}
	}
}
