{{/* Names and labels. */}}
{{- define "tutela.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "tutela.selectorLabels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "tutela.labels" -}}
{{ include "tutela.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version }}
{{- end -}}

{{/* The image, by digest when one is given. */}}
{{- define "tutela.image" -}}
{{- if .Values.image.digest -}}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) -}}
{{- end -}}
{{- end -}}

{{/* Required values, checked once: helm template and install fail with the reason. */}}
{{- define "tutela.check" -}}
{{- if not .Values.issuer -}}
{{- fail "issuer is required: tutelad's public https URL (TUTELA_ISSUER)" -}}
{{- end -}}
{{- if and (not .Values.devMode) (not (hasPrefix "https://" .Values.issuer)) -}}
{{- fail "issuer must be an https URL (devMode allows loopback http only)" -}}
{{- end -}}
{{- if not (regexMatch "^ten_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" .Values.tenant.id) -}}
{{- fail "tenant.id is required: ten_<uuidv7>, made once and never changed" -}}
{{- end -}}
{{- if not .Values.keycloak.realm -}}
{{- fail "keycloak.realm is required: the issuer of the tenant's Keycloak realm" -}}
{{- end -}}
{{- if not .Values.secrets.database.name -}}
{{- fail "secrets.database.name is required: a Secret with TUTELA_DATABASE_URL" -}}
{{- end -}}
{{- if not .Values.secrets.masterKey.name -}}
{{- fail "secrets.masterKey.name is required: a Secret with TUTELA_MASTER_KEY" -}}
{{- end -}}
{{- if not .Values.secrets.keyPepper.name -}}
{{- fail "secrets.keyPepper.name is required: a Secret with TUTELA_KEY_PEPPER" -}}
{{- end -}}
{{- if and .Values.bootstrap.enabled (not .Values.secrets.ownerDatabase.name) -}}
{{- fail "secrets.ownerDatabase.name is required by the bootstrap job (TUTELA_OWNER_DATABASE_URL)" -}}
{{- end -}}
{{- if and .Values.bootstrap.enabled (not .Values.tenant.owners) -}}
{{- fail "tenant.owners is required by the bootstrap job: the first owner's Keycloak user id" -}}
{{- end -}}
{{- if and .Values.console.enabled (not .Values.config.adminAcr) -}}
{{- fail "config.adminAcr is required with the Console (TUTELA_ADMIN_ACR)" -}}
{{- end -}}
{{- if and .Values.config.ledgerUrl (not .Values.secrets.ledgerToken.name) -}}
{{- fail "secrets.ledgerToken.name is required with config.ledgerUrl (TUTELA_LEDGER_TOKEN)" -}}
{{- end -}}
{{- if gt (int .Values.config.revisionCheckMs) 1000 -}}
{{- fail "config.revisionCheckMs must be at most 1000 for the documented 1.5 s revocation delay" -}}
{{- end -}}
{{- if lt (int .Values.replicaCount) 2 -}}
{{- fail "replicaCount must be at least 2 (Phase B: 2+ replicas)" -}}
{{- end -}}
{{- end -}}

{{/* The realm's JWKS. */}}
{{- define "tutela.jwksUri" -}}
{{- default (printf "%s/protocol/openid-connect/certs" (trimSuffix "/" .Values.keycloak.realm)) .Values.keycloak.jwksUri -}}
{{- end -}}

{{/* The Console's public host: console.host, ingress.host, or the issuer's host. */}}
{{- define "tutela.consoleHost" -}}
{{- if .Values.console.host -}}
{{- .Values.console.host -}}
{{- else if .Values.ingress.host -}}
{{- .Values.ingress.host -}}
{{- else -}}
{{- (urlParse .Values.issuer).host -}}
{{- end -}}
{{- end -}}

{{/* The first value of TUTELA_ADMIN_ACR: what the Console asks for. */}}
{{- define "tutela.stepUpAcr" -}}
{{- trim (first (splitList "," .Values.config.adminAcr)) -}}
{{- end -}}

{{/* Secret env entries shared by the service and the job. */}}
{{- define "tutela.secretEnv" -}}
- name: TUTELA_MASTER_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.masterKey.name }}
      key: {{ .Values.secrets.masterKey.key }}
- name: TUTELA_KEY_PEPPER
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.keyPepper.name }}
      key: {{ .Values.secrets.keyPepper.key }}
{{- if .Values.secrets.masterKeyPrevious.name }}
- name: TUTELA_MASTER_KEY_PREVIOUS
  valueFrom:
    secretKeyRef:
      name: {{ .Values.secrets.masterKeyPrevious.name }}
      key: {{ .Values.secrets.masterKeyPrevious.key }}
{{- end }}
{{- if .Values.secrets.databaseCA.name }}
- name: SSL_CERT_DIR
  value: /etc/tutela/database-ca
{{- end }}
{{- end -}}

{{/* The pod security context of every pod. */}}
{{- define "tutela.podSecurity" -}}
runAsNonRoot: true
runAsUser: 65532
runAsGroup: 65532
fsGroup: 65532
seccompProfile:
  type: RuntimeDefault
{{- end -}}

{{- define "tutela.containerSecurity" -}}
allowPrivilegeEscalation: false
readOnlyRootFilesystem: true
runAsNonRoot: true
capabilities:
  drop: ["ALL"]
{{- end -}}
