{{/*
Expand the name of the chart.
*/}}
{{- define "tagwarden.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "tagwarden.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Namespace for generated references.
Always uses the Helm release namespace.
*/}}
{{- define "tagwarden.namespaceName" -}}
{{- .Release.Namespace }}
{{- end }}

{{/*
Resource name with proper truncation for Kubernetes 63-character limit.
Takes a dict with:
  - .suffix: Resource name suffix (e.g., "metrics", "webhook")
  - .context: Template context (root context with .Values, .Release, etc.)
Dynamically calculates safe truncation to ensure total name length <= 63 chars.
*/}}
{{- define "tagwarden.resourceName" -}}
{{- $fullname := include "tagwarden.fullname" .context }}
{{- $suffix := .suffix }}
{{- $maxLen := sub 62 (len $suffix) | int }}
{{- if gt (len $fullname) $maxLen }}
{{- printf "%s-%s" (trunc $maxLen $fullname | trimSuffix "-") $suffix | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" $fullname $suffix | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{/*
ServiceAccount name to use.
When enabled, use the chart's ServiceAccount name.
When disabled, serviceAccount.name must be set; use "default" to pick the namespace default ServiceAccount.
*/}}
{{- define "tagwarden.serviceAccountName" -}}
{{- if .Values.serviceAccount.enabled }}
{{- include "tagwarden.resourceName" (dict "suffix" "controller-manager" "context" .) }}
{{- else }}
{{- required "serviceAccount.name is required when serviceAccount.enabled=false (set name: default explicitly to use the namespace default ServiceAccount)" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image reference from a dict with repository, tag and digest. Takes a dict with
.image and .context. The tag defaults to the chart appVersion.
*/}}
{{- define "tagwarden.image" -}}
{{- $ref := printf "%s:%s" .image.repository (.image.tag | default .context.Chart.AppVersion) }}
{{- with .image.digest }}{{ $ref = printf "%s@%s" $ref . }}{{ end }}
{{- $ref }}
{{- end }}

{{- define "tagwarden.managerImage" -}}
{{- include "tagwarden.image" (dict "image" .Values.manager.image "context" .) }}
{{- end }}

{{/*
Sync Job image: syncImage when its repository is set, else the manager image.
An empty syncImage.tag falls back to manager.image.tag, then appVersion.
*/}}
{{- define "tagwarden.syncImage" -}}
{{- if .Values.syncImage.repository }}
{{- $image := merge (dict "tag" (.Values.syncImage.tag | default .Values.manager.image.tag)) .Values.syncImage }}
{{- include "tagwarden.image" (dict "image" $image "context" .) }}
{{- else }}
{{- include "tagwarden.managerImage" . }}
{{- end }}
{{- end }}


{{/*
Trivy server name, image and labels. The Service name is what gated sync pods
and the manager reach.
*/}}
{{- define "tagwarden.trivyName" -}}
{{- include "tagwarden.resourceName" (dict "suffix" "trivy" "context" .) }}
{{- end }}

{{- define "tagwarden.trivyImage" -}}
{{- $image := .Values.trivy.image }}
{{- printf "%s:%s@%s" (required "trivy.image.repository is required" $image.repository) (required "trivy.image.tag is required" $image.tag) (required "trivy.image.digest is required" $image.digest) }}
{{- end }}

{{- define "tagwarden.trivySelectorLabels" -}}
app.kubernetes.io/name: {{ include "tagwarden.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: trivy
{{- end }}

{{- define "tagwarden.trivyLabels" -}}
{{ include "tagwarden.trivySelectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
{{- end }}

{{/*
Manager flags for the gate, empty unless trivy.enabled. The Trivy version is
the image tag.
*/}}
{{- define "tagwarden.trivyManagerArgs" -}}
{{- if .Values.trivy.enabled }}
- --trivy-image={{ include "tagwarden.trivyImage" . }}
- --trivy-version={{ .Values.trivy.image.tag }}
- --trivy-url=http://{{ include "tagwarden.trivyName" . }}.{{ .Release.Namespace }}.svc:4954
{{- end }}
{{- end }}
