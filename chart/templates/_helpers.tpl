{{- define "bridge.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "bridge.fullname" -}}
{{- if contains .Chart.Name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "bridge.selectorLabels" -}}
app.kubernetes.io/name: {{ include "bridge.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "bridge.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "bridge.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* The configuration with the ports the chart's container and service use */}}
{{- define "bridge.config" -}}
{{- mustMergeOverwrite (deepCopy .Values.config) (dict "listen" ":8080" "metrics_listen" ":9090") | toYaml }}
{{- end }}
