package web

import (
	"context"
	"fmt"
	"html/template"
	"io"
	"strings"
)

type C map[string]any

type Engine interface {
	Render(io.Writer, string, any, context.Context) error
}

type stdlibEngine struct {
	templates *template.Template
}

type Crumb struct {
	Text, Link string
}

func crumbs(vals ...any) ([]Crumb, error) {
	if len(vals)%2 != 0 {
		return nil, fmt.Errorf("breadcrumbs must have an even number of values")
	}

	crumbs := make([]Crumb, len(vals)/2)
	for i := 0; i < len(vals); i += 2 {
		text, ok := vals[i].(string)
		if !ok {
			return nil, fmt.Errorf("breadcrumbs text must be a string")
		}
		crumbs[i/2] = Crumb{
			Text: text,
		}
		if link, ok := vals[i+1].(string); vals[i+1] != nil && ok {
			crumbs[i/2].Link = link
		}
	}

	return crumbs, nil
}

func join(sep string, vals ...string) string {
	return strings.Join(vals, sep)
}

func NewStdlibEngine() (Engine, error) {
	// wrap with custom: Stat,
	tmplts, err := template.New("").Funcs(template.FuncMap{
		"crumbs": crumbs,
		"join":   join,
	}).ParseFS(TemplatesFS, "*.html.tpl")
	if err != nil {
		return nil, err
	}

	return &stdlibEngine{
		templates: tmplts,
	}, nil
}

func (e *stdlibEngine) Render(w io.Writer, name string, data any, _ context.Context) error {
	tplName := strings.ReplaceAll(name, "/", "_") + ".html.tpl"
	return e.templates.ExecuteTemplate(w, tplName, data)
}
