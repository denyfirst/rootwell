package architecture

import (
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

func TestWorkbenchHasNoNetworkOrProcessImports(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate architecture test")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	for _, directory := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, directory), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				return nil
			}

			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imported := range file.Imports {
				importPath, err := strconv.Unquote(imported.Path.Value)
				if err != nil {
					return err
				}
				relative, relErr := filepath.Rel(root, path)
				if relErr != nil {
					relative = path
				}
				allowedProbe := filepath.ToSlash(relative) == "cmd/rootwell-probe/main.go" &&
					(importPath == "net" || strings.HasPrefix(importPath, "net/"))
				allowedLoopbackServer := (filepath.ToSlash(relative) == "cmd/rootwelld/main.go" &&
					(importPath == "net" || importPath == "net/http")) ||
					(filepath.ToSlash(relative) == "cmd/rootwelld/gate.go" && importPath == "net/http")
				if forbiddenImport(importPath) && !allowedProbe && !allowedLoopbackServer {
					t.Errorf("forbidden Workbench import %q in %s", importPath, relative)
				}
				if importPath == "github.com/denyfirst/rootwell/internal/instanceaccess" &&
					!strings.HasPrefix(filepath.ToSlash(relative), "cmd/rootwelld/") {
					t.Errorf("installation access must remain outside the offline Workbench: %s", relative)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("scan %s: %v", directory, err)
		}
	}
}

func forbiddenImport(path string) bool {
	return path == "net" || strings.HasPrefix(path, "net/") || path == "os/exec" || path == "plugin" || path == "unsafe"
}
