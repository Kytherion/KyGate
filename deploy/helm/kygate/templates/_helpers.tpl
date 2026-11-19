{{- define "kygate.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}{{ .Release.Name | trunc 50 | trimSuffix "-" }}{{- else -}}{{ printf "%s-%s" .Release.Name .Chart.Name | trunc 50 | trimSuffix "-" }}{{- end -}}
{{- end -}}

{{- define "kygate.labels" -}}
app.kubernetes.io/name: kygate
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{- define "kygate.selector" -}}
app.kubernetes.io/name: kygate
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "kygate.serviceAccount" -}}
{{- if .Values.serviceAccount.create -}}{{ default (include "kygate.fullname" .) .Values.serviceAccount.name }}{{- else -}}{{ default "default" .Values.serviceAccount.name }}{{- end -}}
{{- end -}}

{{- define "kygate.image" -}}
{{ .Values.image.repository }}:{{ default .Chart.AppVersion .Values.image.tag }}
{{- end -}}

{{- define "kygate.storesSecret" -}}
{{- if .Values.dev.enabled -}}{{ include "kygate.fullname" . }}-dev-stores{{- else -}}{{ required "stores.existingSecret: a Secret with KYGATE_DATABASE_URL, KYGATE_COUNTERS_URL, KYGATE_CACHE_URL (or set dev.enabled for a trial)" .Values.stores.existingSecret }}{{- end -}}
{{- end -}}

{{- define "kygate.guardService" -}}{{ include "kygate.fullname" . }}-guard{{- end -}}

{{- define "kygate.guardTLSSecret" -}}
{{- if .Values.guard.tls.existingSecret -}}{{ .Values.guard.tls.existingSecret }}{{- else -}}{{ include "kygate.fullname" . }}-guard-tls{{- end -}}
{{- end -}}

{{/* Hardened pod and container settings, as restricted Pod Security asks. */}}
{{/* The images' users, by number: Kubernetes checks non-root against a UID. */}}
{{- define "kygate.podSecurity" -}}
runAsNonRoot: true
runAsUser: 10001
runAsGroup: 10001
fsGroup: 10001
seccompProfile: { type: RuntimeDefault }
{{- end -}}
{{- define "kygate.guardPodSecurity" -}}
runAsNonRoot: true
runAsUser: 10002
runAsGroup: 10002
fsGroup: 10002
seccompProfile: { type: RuntimeDefault }
{{- end -}}
{{- define "kygate.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
capabilities: { drop: [ALL] }
{{- end -}}

{{/* The environment every KyGate process shares: stores, master key, the
key-management service, provider keys, and the Guard link. */}}
{{- define "kygate.env" -}}
{{- $root := .root -}}
- name: KYGATE_ROLE
  value: {{ .role }}
{{- if and $root.Values.dev.enabled (not $root.Values.masterKey.existingSecret) }}
- name: KYGATE_MASTER_KEY
  valueFrom: { secretKeyRef: { name: {{ include "kygate.fullname" $root }}-dev-master-key, key: KYGATE_MASTER_KEY } }
{{- else }}
- name: {{ required "masterKey.secretKey: KYGATE_MASTER_KEY_WRAPPED (recommended) or KYGATE_MASTER_KEY" $root.Values.masterKey.secretKey }}
  valueFrom: { secretKeyRef: { name: {{ required "masterKey.existingSecret: the Secret that holds the master key (see 'kygate master-key new')" $root.Values.masterKey.existingSecret }}, key: {{ $root.Values.masterKey.secretKey }} } }
{{- end }}
{{- with $root.Values.kms.vaultAddr }}
- name: VAULT_ADDR
  value: {{ . | quote }}
{{- end }}
{{- with $root.Values.kms.vaultNamespace }}
- name: VAULT_NAMESPACE
  value: {{ . | quote }}
{{- end }}
{{- range $k, $v := $root.Values.kms.env }}
- name: {{ $k }}
  value: {{ $v | quote }}
{{- end }}
{{- range $k, $v := $root.Values.extraEnv }}
- name: {{ $k }}
  value: {{ $v | quote }}
{{- end }}
{{- if $root.Values.guard.enabled }}
- name: KYGATE_GUARD
  value: {{ include "kygate.guardService" $root }}:4002
- name: KYGATE_GUARD_TIMEOUT
  value: {{ $root.Values.guard.timeout | quote }}
{{- if $root.Values.guard.tls.enabled }}
- name: KYGATE_GUARD_TLS_CA
  value: /etc/kygate/guard-tls/ca.crt
- name: KYGATE_GUARD_TLS_CERT
  value: /etc/kygate/guard-tls/client.crt
- name: KYGATE_GUARD_TLS_KEY
  value: /etc/kygate/guard-tls/client.key
{{- end }}
{{- end }}
{{- end -}}

{{- define "kygate.envFrom" -}}
- secretRef: { name: {{ include "kygate.storesSecret" .root }} }
{{- range .root.Values.providers.envFromSecrets }}
- secretRef: { name: {{ . }} }
{{- end }}
{{- range .root.Values.kms.envFromSecrets }}
- secretRef: { name: {{ . }} }
{{- end }}
{{- end -}}

{{- define "kygate.guardTLSVolume" -}}
{{- if and .Values.guard.enabled .Values.guard.tls.enabled }}
- name: guard-tls
  secret: { secretName: {{ include "kygate.guardTLSSecret" . }}, defaultMode: 0400 }
{{- end }}
{{- end -}}
{{- define "kygate.guardTLSMount" -}}
{{- if and .Values.guard.enabled .Values.guard.tls.enabled }}
- { name: guard-tls, mountPath: /etc/kygate/guard-tls, readOnly: true }
{{- end }}
{{- end -}}
