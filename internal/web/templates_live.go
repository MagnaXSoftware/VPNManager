//go:build debug

package web

import (
	"io/fs"
	"os"
	"path"
)

var TemplatesFS fs.FS
var StaticFS fs.FS

func init() {
	dir := os.Getenv("ORCHESTRATOR_TEMPLATES_PATH")
	if dir == "" {
		panic("ORCHESTRATOR_TEMPLATES_PATH environment variable not set")
	}
	TemplatesFS = os.DirFS(dir)

	dir = os.Getenv("ORCHESTRATOR_STATIC_PATH")
	if dir == "" {
		dir = path.Join(os.Getenv("ORCHESTRATOR_TEMPLATES_PATH"), "..", "static")
	}
	StaticFS = os.DirFS(dir)
}
