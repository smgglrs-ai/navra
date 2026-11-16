{{/* Standard naming. */}}
{{- define "navra.name" -}}
{{- default "navra" .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "navra.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "navra.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "navra.warmPoolName" -}}
{{- printf "%s-agents" (include "navra.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "navra.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels (release-scoped — multiple deployments coexist). */}}
{{- define "navra.labels" -}}
helm.sh/chart: {{ include "navra.chart" . }}
{{ include "navra.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "navra.selectorLabels" -}}
app.kubernetes.io/name: {{ include "navra.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/* Gateway image reference. */}}
{{- define "navra.image" -}}
{{- with .Values.image -}}
{{- if .registry -}}{{ .registry }}/{{ end }}{{ .repository }}:{{ .tag | default $.Chart.AppVersion }}
{{- end -}}
{{- end -}}

{{/* Agent image reference. */}}
{{- define "navra.agentImage" -}}
{{- with .Values.warmPool.image -}}
{{- if .registry -}}{{ .registry }}/{{ end }}{{ .repository }}:{{ .tag | default $.Chart.AppVersion }}
{{- end -}}
{{- end -}}
