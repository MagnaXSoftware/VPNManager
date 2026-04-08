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

    {{ template "breadcrumbs" (crumbs "Tunnels" nil) }}

    <div class="grid">
        <div class="col">
            <table class="pure-table">
                <thead>
                <tr>
                    <th>Tunnel</th>
                    <th>Clients</th>
                </tr>
                </thead>
                <tbody>
                {{ range $name, $tunnel := .Tunnels }}
                    <tr class="tunnel_row">
                    <td rowspan="{{ max (len $tunnel.Clients) 1 }}"><a
                                href="/tunnel/{{ $name }}">{{ $name }}</a><br><code>{{ $tunnel.Endpoint.String }}</code></td>
                    {{ range $i, $client := $tunnel.Clients }}
                        {{ if $i }}
                            </tr>
                            <tr>
                        {{ end }}
                        <td><a href="/tunnel/{{ $name }}/{{ $client.Name }}">{{ $client.Name }}</a>{{ if $client.Disabled }} <small class="muted">(DISABLED)</small>{{ end }}</td>
                    {{ else }}
                        <td></td>
                    {{ end }}
                    </tr>
                {{ end }}
                </tbody>
            </table>
        </div>
    </div>
</div>
</body>
</html>