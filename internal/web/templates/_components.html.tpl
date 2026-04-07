{{ define "breadcrumbs" }}
    <nav class="breadcrumbs pure-menu pure-menu-horizontal">
        <ol class="pure-menu-list">
            {{- range $i, $c := . }}
                {{ if $i }}<li class="pure-menu-item">&gt;</li>{{ end }}
                <li class="pure-menu-item">
                    {{- if .Link -}}
                        <a class="pure-menu-link" href="{{ .Link }}">{{ .Text }}</a>
                    {{- else -}}
                        <span class="pure-menu-text">{{ .Text }}</span>
                    {{- end -}}
                </li>
            {{- end }}
        </ol>
    </nav>
{{ end }}