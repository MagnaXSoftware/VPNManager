<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>{{ .Title }}</title>

    <link rel="stylesheet" href="/static/style.css">
</head>
<body>
<div class="page">

    <h1>{{ .Title }}</h1>

    {{ template "breadcrumbs" (crumbs "Tunnels" "/tunnels" .TunnelName (join "" "/tunnel/" .TunnelName) .Client.Name nil) }}

    <div class="grid">
        <div class="col">
            <div>
                <pre><code>{{ .Client.Export }}</code></pre>
            </div>
            <div class="grid text-center">
                <div class="col">
                    {{ if .Client.Disabled -}}
                        <form action="/tunnel/{{ .TunnelName }}/{{ .Client.Name }}/enable" method="POST"
                              class="pure-form"><input type="hidden" name="next"
                                                       value="/tunnel/{{ .TunnelName }}/{{ .Client.Name }}"><input
                                    type="submit" value="Enable" class="pure-button button-success"></form>
                    {{ else -}}
                        <form action="/tunnel/{{ .TunnelName }}/{{ .Client.Name }}/disable" method="POST"
                              class="pure-form"><input type="hidden" name="next"
                                                       value="/tunnel/{{ .TunnelName }}/{{ .Client.Name }}"><input
                                    type="submit" value="Disable" class="pure-button button-warning"></form>
                    {{- end }}
                </div>
                <div class="col">
                    <form action="/tunnel/{{ .TunnelName }}/{{ .Client.Name }}/remove" method="POST"
                          class="pure-form"><input type="submit" value="Remove" class="pure-button button-error"></form>
                </div>
            </div>
        </div>
        <div class="col">
            <img src="/tunnel/{{ .TunnelName }}/{{ .Client.Name }}/qr.png"
                 alt="configuration QR code for {{ .Client.Name }}">
        </div>
    </div>
</div>
</body>
</html>