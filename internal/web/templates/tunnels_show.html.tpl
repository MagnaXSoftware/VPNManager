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

    {{ template "breadcrumbs" (crumbs "Tunnels" "/tunnels" .TunnelName nil) }}


    <div class="grid">
        <div class="col">
            <pre><code>{{ .Tunnel.Server.Export }}</code></pre>
        </div>
        <div class="col">
            {{ $tunnelName := .TunnelName -}}
            <div id="add">
                <form action="/tunnel/{{ $tunnelName }}/create" method="POST" class="pure-form">
                    <!--suppress HtmlFormInputWithoutLabel -->
                    {{ if .Error -}}
                    <div class="modal danger">{{ .Error }}</div>
                    {{ end -}}
                    <input type="text" name="name" minlength="1" maxlength="15" placeholder="Client Name" required{{ if .FormValue }} value="{{ .FormValue }}"{{ end }}>
                    <button class="pure-button pure-button-primary" type="submit">Add</button>
                </form>
            </div>
            <div id="clients">
                <table class="pure-table-striped">
                    {{ range $client := .Tunnel.Clients }}
                        <tr>
                            <td><a href="/tunnel/{{ $tunnelName }}/{{ $client.Name }}">{{ $client.Name }}</a></td>
                            <td>
                                {{ if $client.Disabled -}}
                                    <form action="/tunnel/{{ $tunnelName }}/{{ $client.Name }}/enable" method="POST"
                                          class="pure-form"><input type="submit" value="Enable"
                                                                   class="pure-button button-success"></form>
                                {{ else -}}
                                    <form action="/tunnel/{{ $tunnelName }}/{{ $client.Name }}/disable" method="POST"
                                          class="pure-form"><input type="submit" value="Disable"
                                                                   class="pure-button button-warning"></form>
                                {{- end }}
                            </td>
                            <td>
                                <form action="/tunnel/{{ $tunnelName }}/{{ $client.Name }}/remove" method="POST"
                                      class="pure-form"><input type="submit" value="Remove"
                                                               class="pure-button button-error"></form>
                            </td>
                        </tr>
                    {{ end }}
                </table>
            </div>
        </div>
    </div>
</div>
</body>
</html>