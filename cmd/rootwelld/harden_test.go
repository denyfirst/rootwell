package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
)

// Every subcommand handles secrets, so hardening must come before anything
// else in run (audit RW-11).
func TestRunHardensTheProcessFirst(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "run" {
			continue
		}
		first, ok := fn.Body.List[0].(*ast.IfStmt)
		if !ok {
			t.Fatal("run must start by hardening the process")
		}
		assign, ok := first.Init.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			t.Fatal("run must start by hardening the process")
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if ident, isIdent := call.Fun.(*ast.Ident); !ok || !isIdent || ident.Name != "hardenProcess" {
			t.Fatal("run must start by hardening the process")
		}
		return
	}
	t.Fatal("run not found")
}
