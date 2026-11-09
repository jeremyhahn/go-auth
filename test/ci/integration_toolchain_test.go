package ci_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// golangBase matches a FROM line on the official golang image and captures the
// Go version in its tag, e.g. "FROM golang:1.27.0-bookworm AS build".
var golangBase = regexp.MustCompile(`(?im)^\s*FROM\s+(?:--platform=\S+\s+)?(?:docker\.io/)?(?:library/)?golang:(\d+\.\d+(?:\.\d+)?)\S*`)

// integrationDockerfiles returns every Dockerfile under pkg/, which is where
// each integration suite's image is defined.
func integrationDockerfiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(filepath.Join(repoRoot, "pkg"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasPrefix(d.Name(), "Dockerfile") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk pkg/: %v", err)
	}
	if len(files) == 0 {
		t.Fatal("found no Dockerfile under pkg/; the integration suites build their images from there")
	}
	return files
}

// The golang images set GOTOOLCHAIN=local, so an image older than the go
// directive cannot build the module at all. go-auth#25: 2c0f220 moved go.mod to
// 1.26.7 while all seven integration images stayed on golang:1.26.6, and every
// Docker-backed suite failed before running a test.
func TestIntegrationDockerfiles_GoVersionMatchesGoMod(t *testing.T) {
	want := goModVersion(t)
	for _, path := range integrationDockerfiles(t) {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, m := range golangBase.FindAllSubmatch(data, -1) {
			if got := string(m[1]); got != want {
				t.Errorf("%s: base image golang:%s != go.mod directive %s: the toolchain moves in one pass", path, got, want)
			}
		}
	}
}

func TestIntegrationWorkflow_GoVersionMatchesGoMod(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(repoRoot, ".github", "workflows", "integration.yml"))
	if err != nil {
		t.Fatalf("read integration.yml: %v", err)
	}
	var wf workflow
	if err := yaml.Unmarshal(data, &wf); err != nil {
		t.Fatalf("parse integration.yml: %v", err)
	}
	// Same rule as ci.yml: the pin may lead the directive by patch versions on
	// the same minor (Company Agent convention, m2289 (4)).
	if err := checkPinCoversDirective("integration.yml", wf.Env["GO_VERSION"], goModVersion(t)); err != nil {
		t.Fatal(err)
	}
}
