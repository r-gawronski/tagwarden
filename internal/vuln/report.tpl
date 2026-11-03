[{{- $f := true -}}{{- range . -}}{{- range .Vulnerabilities -}}{{- if $f }}{{ $f = false }}{{ else }},{{ end -}}
{"id":"{{ .VulnerabilityID | escapeString }}","pkg":"{{ .PkgName | escapeString }}","ver":"{{ .InstalledVersion | escapeString }}","fix":"{{ .FixedVersion | escapeString }}","sev":"{{ .Severity }}","status":"{{ .Status }}"}
{{- end -}}{{- end -}}]
