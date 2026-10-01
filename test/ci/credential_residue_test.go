package ci_test

// The credential-residue gate (go-auth#48, owner ruling on go-auth#3 §10.6).
//
// Every credential in this module lives in a go-enclave *enclave.MemoryEnclave,
// and plaintext leaves locked memory only where a call opens it. This test
// enumerates those calls in the module's non-test code under pkg/ and compares
// them, as a multiset of path:function sites, with the reviewed list in
// testdata/credential-residues.allow. A new site — or a removed one — fails
// with a diff, so the set of places plaintext can escape stays finite and
// cannot grow without a reviewer editing the list, and the list cannot
// silently keep a site that no longer exists.
//
// What counts as a site:
//
//   - x.WithBytes(fn) with exactly one argument, and x.OpenString() and
//     x.Open() with none. Those are go-enclave's plaintext-exposing methods
//     and their arities. Matching on name and arity rather than on the
//     receiver's type keeps this test free of a type-checker (pkg/pam and
//     pkg/pkcs11 have cgo files that cannot be type-checked without libpam
//     and the pkcs11 tag). The arity is what excludes the module's other
//     Open methods — SessionProvider.Open(ctx, cfg), SessionOpener.Open(ctx,
//     service, user), TPMProvider.Open(ctx, cfg) — which all take arguments.
//   - credential.WithTransientString(e, fn), the internal helper that lends a
//     credential to a string-only dependency. Its own WithBytes call is a site
//     too; the calls to it are counted separately because each is a distinct
//     residue.
//
// Every file is parsed regardless of build constraints, so the cgo-only sites
// are gated on a host that cannot compile them.
//
// Each allowlist line is "path:function ID", where ID is a residue ID from
// docs/security/credential-residues.md (R1, R2, ...) or "internal" for a
// borrow whose plaintext stays inside locked memory or the process's own
// crypto (an HMAC key, a constant-time compare). Every residue ID used must
// have a row in the register.

import (
	"bufio"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const (
	residueAllowlist = "testdata/credential-residues.allow"
	residueRegister  = "docs/security/credential-residues.md"
)

// plaintextMethods maps each plaintext-exposing go-enclave method to the
// number of arguments it takes.
var plaintextMethods = map[string]int{
	"WithBytes":  1,
	"OpenString": 0,
	"Open":       0,
}

// plaintextHelpers are package-qualified functions that lend plaintext.
var plaintextHelpers = map[string]bool{
	"credential.WithTransientString": true,
}

var residueIDPattern = regexp.MustCompile(`^(R[0-9]+|internal)$`)

func TestCredentialResidueAllowlist(t *testing.T) {
	got, err := collectPlaintextSites(filepath.Join(repoRoot, "pkg"))
	if err != nil {
		t.Fatalf("scan pkg/: %v", err)
	}
	want, ids := readResidueAllowlist(t, filepath.Join(repoRoot, "test", "ci", residueAllowlist))

	if diff := diffSiteCounts(want, got); diff != "" {
		t.Errorf("plaintext call sites in pkg/ differ from %s.\n"+
			"Each added site needs review and a residue ID (docs/security/credential-residues.md);\n"+
			"each removed site must be removed from the list.\n%s", residueAllowlist, diff)
	}

	register, err := os.ReadFile(filepath.Join(repoRoot, residueRegister))
	if err != nil {
		t.Fatalf("read the residue register: %v", err)
	}
	for id := range ids {
		if id == "internal" {
			continue
		}
		if !strings.Contains(string(register), "| "+id+" |") {
			t.Errorf("%s uses residue %s, which has no row in %s", residueAllowlist, id, residueRegister)
		}
	}
}

// TestCredentialResidueScannerFindsSites guards the gate against going blind:
// a scanner that matched nothing would compare an empty set with an empty
// list and pass forever. It runs the scanner over a fixture with known sites.
func TestCredentialResidueScannerFindsSites(t *testing.T) {
	dir := t.TempDir()
	src := `package fixture

type T struct{ e interface{} }

func (t *T) Use(e enclaveLike) {
	_ = e.WithBytes(func([]byte) error { return nil })
	_, _ = e.OpenString()
	_, _ = e.Open()
	_ = credential.WithTransientString(e, nil)
	_, _ = provider.Open(ctx, cfg) // not a site: takes arguments
	_ = e.EqualTo(nil)             // not a site: does not expose plaintext
}

func Free(e enclaveLike) {
	func() { _ = e.WithBytes(nil) }()
}
`
	if err := os.WriteFile(filepath.Join(dir, "fixture.go"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "fixture_test.go"), []byte("package fixture\n\nfunc x(e enclaveLike) { _ = e.WithBytes(nil) }\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := collectPlaintextSites(dir)
	if err != nil {
		t.Fatalf("scan fixture: %v", err)
	}
	want := map[string]int{
		filepath.ToSlash(filepath.Join(filepath.Base(dir), "fixture.go")) + ":T.Use": 4,
		filepath.ToSlash(filepath.Join(filepath.Base(dir), "fixture.go")) + ":Free":  1,
	}
	if diff := diffSiteCounts(want, got); diff != "" {
		t.Fatalf("scanner found the wrong sites:\n%s", diff)
	}
}

// collectPlaintextSites returns path:function -> number of plaintext-exposing
// calls, for every non-test .go file under root. Paths are relative to root's
// parent, so a scan of <repo>/pkg yields "pkg/...".
func collectPlaintextSites(root string) (map[string]int, error) {
	base := filepath.Dir(root)
	sites := map[string]int{}
	fset := token.NewFileSet()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if name := d.Name(); name == "testdata" || (strings.HasPrefix(name, ".") && path != root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			name := funcName(fn)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if isPlaintextCall(call) {
					sites[rel+":"+name]++
				}
				return true
			})
		}
		return nil
	})
	return sites, err
}

// isPlaintextCall reports whether call is one of the plaintext-exposing
// selector calls.
func isPlaintextCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	if pkg, ok := sel.X.(*ast.Ident); ok && plaintextHelpers[pkg.Name+"."+sel.Sel.Name] {
		return true
	}
	arity, ok := plaintextMethods[sel.Sel.Name]
	return ok && len(call.Args) == arity
}

// funcName renders a declaration as "Func" or "Recv.Method".
func funcName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	recv := fn.Recv.List[0].Type
	if star, ok := recv.(*ast.StarExpr); ok {
		recv = star.X
	}
	if generic, ok := recv.(*ast.IndexExpr); ok {
		recv = generic.X
	}
	if generic, ok := recv.(*ast.IndexListExpr); ok {
		recv = generic.X
	}
	if ident, ok := recv.(*ast.Ident); ok {
		return ident.Name + "." + fn.Name.Name
	}
	return fn.Name.Name
}

// readResidueAllowlist parses the allowlist into path:function -> count, and
// the set of residue IDs it uses. A site may appear on several lines, once per
// call.
func readResidueAllowlist(t *testing.T, path string) (map[string]int, map[string]bool) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open allowlist: %v", err)
	}
	defer f.Close()

	sites := map[string]int{}
	ids := map[string]bool{}
	scanner := bufio.NewScanner(f)
	for line := 1; scanner.Scan(); line++ {
		text := scanner.Text()
		if i := strings.Index(text, "#"); i >= 0 {
			text = text[:i]
		}
		fields := strings.Fields(text)
		if len(fields) == 0 {
			continue
		}
		if len(fields) != 2 || !strings.Contains(fields[0], ":") || !residueIDPattern.MatchString(fields[1]) {
			t.Errorf("%s:%d: want \"path:function ID\" with ID R<n> or internal, got %q", residueAllowlist, line, scanner.Text())
			continue
		}
		sites[fields[0]]++
		ids[fields[1]] = true
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read allowlist: %v", err)
	}
	return sites, ids
}

// diffSiteCounts describes how got differs from want, or returns "".
func diffSiteCounts(want, got map[string]int) string {
	keys := map[string]bool{}
	for k := range want {
		keys[k] = true
	}
	for k := range got {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)

	var b strings.Builder
	for _, k := range sorted {
		w, g := want[k], got[k]
		if g > w {
			fmt.Fprintf(&b, "  + %s (%d unlisted call(s): in the code, not in the list)\n", k, g-w)
		}
		if w > g {
			fmt.Fprintf(&b, "  - %s (%d listed call(s) no longer in the code)\n", k, w-g)
		}
	}
	return b.String()
}
