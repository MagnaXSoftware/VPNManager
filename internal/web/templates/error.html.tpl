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
    {{ template "breadcrumbs" (crumbs "Tunnels" "/tunnels") }}
    <pre>{{ .Message }}</pre>
</div>
</body>
</html>