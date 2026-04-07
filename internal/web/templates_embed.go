//go:build !debug

package web

import (
	"embed"
	"io/fs"
)

//go:embed all:templates all:static
var _embeddedFS embed.FS
var TemplatesFS = must(fs.Sub(_embeddedFS, "templates"))
var StaticFS = must(fs.Sub(_embeddedFS, "static"))

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
