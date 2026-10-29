package architecture

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRequestArchiveHasOnlyReviewedLocalConsumers(t *testing.T) {
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("architecture path")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(current), "..", ".."))
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			relative = filepath.ToSlash(relative)
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(n ast.Node) bool {
				id, ok := n.(*ast.Ident)
				if !ok {
					return true
				}
				switch id.Name {
				case "ArchiveClosedRequests", "ReadRequestArchive":
					if relative != "internal/inventorystore/request_archive.go" && relative != "internal/instanceaccess/request_archive_linux.go" {
						t.Error("unlocked request archive consumer", relative)
					}
				case "InventoryRequestArchive":
					if relative != "internal/instanceaccess/request_archive_linux.go" && relative != "internal/instanceaccess/request_archive_other.go" && relative != "cmd/rootwelld/history_archive_api.go" {
						t.Error("unreviewed request archive authority", relative)
					}
				case "archiveClosedRequestsAt":
					if relative != "internal/inventorystore/request_archive.go" {
						t.Error("runtime request archive clock override", relative)
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}
