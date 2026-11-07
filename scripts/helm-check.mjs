// Checks the Helm chart (ADR-0056): `helm lint`, then `helm template` with the
// default values and with deploy/helm/tutela/ci/production-values.yaml, and
// asserts on the rendered manifests that every setting of deploy/tutelad.env
// and of the Console is set, that secrets are only referenced, and that the
// pods, the bootstrap job and the Keycloak client are what the notes for
// part 4c say. Wrong values must make `helm template` fail.
//
// `make helm` runs it. Without helm it says it is skipped, unless
// TUTELA_REQUIRE_HELM=1, which fails it, like the database tests.
import { execFileSync, spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

const CHART = "deploy/helm/tutela";
const PROD = `${CHART}/ci/production-values.yaml`;

if (spawnSync("helm", ["version", "--short"], { encoding: "utf8" }).status !== 0) {
  if (process.env.TUTELA_REQUIRE_HELM === "1") {
    console.error("helm check: helm is not installed and TUTELA_REQUIRE_HELM=1");
    process.exit(1);
  }
  console.log("skipped: helm is not installed (set TUTELA_REQUIRE_HELM=1 to fail instead)");
  process.exit(0);
}

let failures = 0;
let checks = 0;
function check(ok, what) {
  checks += 1;
  if (!ok) {
    failures += 1;
    console.error(`helm check: FAILED: ${what}`);
  }
}

function helm(args) {
  return execFileSync("helm", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

// ---------- The rendered manifests, one object per document ----------

function render(extra) {
  const text = helm(["template", "t", CHART, "--namespace", "tutela", ...extra]);
  return text
    .split(/^---$/m)
    .map((doc) => doc.trim())
    .filter((doc) => /^kind: /m.test(doc))
    .map((doc) => ({
      kind: doc.match(/^kind: (\S+)/m)[1],
      name: doc.match(/^ {2}name: (\S+)/m)[1],
      // Comments say what a setting is for; checks read the manifest only.
      text: doc
        .split("\n")
        .filter((line) => !/^\s*#/.test(line))
        .join("\n"),
    }));
}

function one(docs, kind, name) {
  const found = docs.filter((d) => d.kind === kind && (name === undefined || d.name === name));
  check(found.length === 1, `one ${kind}${name ? ` ${name}` : ""} (found ${found.length})`);
  return found[0] ?? { kind, name, text: "" };
}

// The `key: "value"` pairs of a ConfigMap's data.
function data(doc) {
  const out = new Map();
  const body = doc.text.split(/^data:$/m)[1] ?? "";
  for (const line of body.split("\n")) {
    const m = line.match(/^ {2}([A-Za-z0-9_.-]+): (.*)$/);
    if (m && m[2] !== "|") {
      out.set(m[1], JSON.parse(m[2].startsWith('"') ? m[2] : JSON.stringify(m[2])));
    }
  }
  return out;
}

// The text of a block scalar `key: |` of a ConfigMap's data.
function block(doc, key) {
  const lines = doc.text.split("\n");
  const start = lines.indexOf(`  ${key}: |`);
  if (start < 0) return "";
  const out = [];
  for (const line of lines.slice(start + 1)) {
    if (line !== "" && !line.startsWith("    ")) break;
    out.push(line.slice(4));
  }
  return out.join("\n");
}

// An env entry that comes from a Secret, never as a value.
function fromSecret(doc, name) {
  const re = new RegExp(`- name: ${name}\\n\\s+valueFrom:\\n\\s+secretKeyRef:`);
  return re.test(doc.text) && !new RegExp(`- name: ${name}\\n\\s+value:`).test(doc.text);
}

// ---------- What deploy/tutelad.env says every deployment sets ----------

const envFile = readFileSync("deploy/tutelad.env", "utf8");
const envValues = new Map();
const envKeys = new Set();
for (const line of envFile.split("\n")) {
  const set = line.match(/^([A-Z][A-Z0-9_]*)=(.*)$/);
  if (set) {
    envValues.set(set[1], set[2]);
    envKeys.add(set[1]);
  }
  for (const m of line.matchAll(/\b(TUTELA_[A-Z0-9_]+)=/g)) envKeys.add(m[1]);
}
// Secrets and the trust file come in another way; TUTELA_AUDIT_KEY never.
const NOT_IN_CONFIGMAP = new Set(["TUTELA_AUDIT_KEY", "TUTELA_LEDGER_TOKEN"]);
const CONSOLE = [
  "TUTELA_CONSOLE_DIR",
  "TUTELA_CONSOLE_ISSUER",
  "TUTELA_CONSOLE_CLIENT_ID",
  "TUTELA_ADMIN_ACR",
  "TUTELA_AUDIENCE",
  "TUTELA_REVISION_CHECK_MS",
  "TUTELA_CORS_ORIGINS",
];

function checkRender(label, docs, v) {
  const at = (what) => `${label}: ${what}`;
  check(!docs.some((d) => d.kind === "Secret"), at("the chart makes no Secret"));
  check(
    !docs.some((d) => d.text.includes("TUTELA_AUDIT_KEY")),
    at("TUTELA_AUDIT_KEY is never set"),
  );

  // The settings.
  const env = data(one(docs, "ConfigMap", "t-tutela-env"));
  for (const key of [...envKeys, ...CONSOLE]) {
    if (!NOT_IN_CONFIGMAP.has(key)) check(env.has(key), at(`the ConfigMap sets ${key}`));
  }
  for (const secret of ["TUTELA_DATABASE_URL", "TUTELA_MASTER_KEY", "TUTELA_KEY_PEPPER"]) {
    check(!env.has(secret), at(`${secret} is not in the ConfigMap`));
  }
  check(env.get("RUST_BACKTRACE") === "1", at("RUST_BACKTRACE=1"));
  check(env.get("RUST_LIB_BACKTRACE") === "0", at("RUST_LIB_BACKTRACE=0"));
  check(
    Number(env.get("TUTELA_REVISION_CHECK_MS")) <= 1000,
    at("TUTELA_REVISION_CHECK_MS <= 1000"),
  );
  check(env.get("TUTELA_ISSUER") === v.issuer, at("TUTELA_ISSUER is the issuer"));
  check(env.get("TUTELA_CONSOLE_DIR") === "/srv/tutela/console", at("the Console is on"));
  check(env.get("TUTELA_CONSOLE_ISSUER") === v.realm, at("TUTELA_CONSOLE_ISSUER is the realm"));
  check(env.get("TUTELA_ADMIN_ACR") !== "", at("TUTELA_ADMIN_ACR is set with the Console"));
  if (v.defaults) {
    // The chart's defaults are the env file's values.
    for (const [key, value] of envValues) {
      if (key !== "TUTELA_CONSOLE_DIR") {
        check(env.get(key) === value, at(`${key} defaults to ${value} as in deploy/tutelad.env`));
      }
    }
  }

  // The trust file: the realm as the notes for part 4c say.
  const trust = block(one(docs, "ConfigMap", "t-tutela-trust"), "trust.toml");
  const realm = trust.split("[[issuer]]")[1] ?? "";
  check(realm.includes(`iss = "${v.realm}"`), at("the trust file names the realm"));
  for (const line of ['algs = ["RS256"]', "external = true", "allow_typ_jwt = true"]) {
    check(realm.includes(line), at(`the realm's issuer has ${line}`));
  }
  check(realm.includes(`tenants = ["${v.tenant}"]`), at("the realm's issuer has the one tenant"));

  // The service's pods.
  const deploy = one(docs, "Deployment", "t-tutela");
  const replicas = Number(deploy.text.match(/^ {2}replicas: (\d+)/m)?.[1]);
  check(replicas >= 2, at(`2+ replicas (${replicas})`));
  for (const line of [
    "runAsNonRoot: true",
    "readOnlyRootFilesystem: true",
    "allowPrivilegeEscalation: false",
    'drop: ["ALL"]',
    "type: RuntimeDefault",
    "automountServiceAccountToken: false",
    "path: /healthz",
    "path: /readyz",
    "readinessProbe:",
    "livenessProbe:",
    "startupProbe:",
    "resources:",
    "name: t-tutela-env",
    "mountPath: /etc/tutela/trust",
  ]) {
    check(deploy.text.includes(line), at(`the Deployment has ${line}`));
  }
  for (const secret of ["TUTELA_DATABASE_URL", "TUTELA_MASTER_KEY", "TUTELA_KEY_PEPPER"]) {
    check(fromSecret(deploy, secret), at(`the Deployment takes ${secret} from a Secret`));
  }
  check(/checksum\/config: [0-9a-f]{64}/.test(deploy.text), at("a changed setting rolls the pods"));
  const svc = one(docs, "Service", "t-tutela");
  check(/name: http\n\s+port: 8080/.test(svc.text), at("the Service has the API port"));
  check(!svc.text.includes("9090"), at("the ops port stays off the Service"));
  check(
    /maxUnavailable: 1/.test(one(docs, "PodDisruptionBudget").text),
    at("a PodDisruptionBudget"),
  );
  const policies = docs.filter((d) => d.kind === "NetworkPolicy").map((d) => d.name);
  check(
    policies.includes("t-tutela") && policies.includes("t-tutela-bootstrap"),
    at("NetworkPolicies"),
  );

  // The bootstrap job.
  const job = one(docs, "Job", "t-tutela-bootstrap");
  check(
    job.text.includes('"helm.sh/hook": pre-install,pre-upgrade'),
    at("the job is a pre-install, pre-upgrade hook"),
  );
  check(
    job.text.includes('args: ["bootstrap", "--plan", "/etc/tutela/bootstrap/plan.json"]'),
    at("the job runs tutelad bootstrap"),
  );
  for (const secret of ["TUTELA_OWNER_DATABASE_URL", "TUTELA_MASTER_KEY", "TUTELA_KEY_PEPPER"]) {
    check(fromSecret(job, secret), at(`the job takes ${secret} from a Secret`));
  }
  for (const name of ["TUTELA_SERVICE_ROLE", "TUTELA_ISSUER", "TUTELA_KEY_PEPPER_VERSION"]) {
    check(job.text.includes(`- name: ${name}\n`), at(`the job sets ${name}`));
  }
  check(
    job.text.includes("readOnlyRootFilesystem: true"),
    at("the job's root filesystem is read-only"),
  );
  const plan = JSON.parse(block(one(docs, "ConfigMap", "t-tutela-bootstrap"), "plan.json") || "{}");
  check(plan.tenant?.id === v.tenant, at("the plan names the tenant"));
  check(
    (plan.tenant?.admin_upstream ?? []).every((o) => o.startsWith(`${v.realm}=`)) &&
      (plan.tenant?.admin_upstream ?? []).length > 0,
    at("the plan's first owners are accounts of the realm"),
  );
  check((plan.apps ?? []).length === v.apps, at(`the plan makes ${v.apps} apps`));
  check(
    (plan.webhooks ?? []).length === v.webhooks,
    at(`the plan registers ${v.webhooks} webhooks`),
  );
  const role = one(docs, "Role", "t-tutela-bootstrap").text;
  check(!/resources: \["(?!secrets)/.test(role), at("the job's Role is for Secrets only"));
  check(
    !/verbs:.*"(list|watch|delete|patch|\*)"/.test(role),
    at("the job's Role cannot list, watch, delete or patch"),
  );

  // The Console's Keycloak client (the notes for part 4c).
  const imported = JSON.parse(
    block(one(docs, "ConfigMap", "t-tutela-keycloak-client"), "partial-import.json") || "{}",
  );
  const c = imported.clients?.[0] ?? {};
  check(c.clientId === v.clientId, at("the client id"));
  check(c.publicClient === true, at("a public client"));
  check(c.standardFlowEnabled === true, at("the standard flow"));
  check(c.implicitFlowEnabled === false, at("no implicit flow"));
  check(c.directAccessGrantsEnabled === false, at("no direct access grants"));
  check(c.serviceAccountsEnabled === false, at("no service account"));
  // Keycloak's default full scope puts every client the person has a role
  // of into `aud` ("account" for the realm's default roles): two audiences,
  // which tutelad refuses (CONTRACTS.md 4.6, ADR-0057).
  check(c.fullScopeAllowed === false, at("no full scope: the one audience is TUTELA_AUDIENCE"));
  check(c.attributes?.["pkce.code.challenge.method"] === "S256", at("PKCE S256 required"));
  check(
    JSON.stringify(c.redirectUris) === JSON.stringify([`https://${v.host}/console/callback`]),
    at("the redirect URI"),
  );
  check(
    JSON.stringify(c.webOrigins) === JSON.stringify([`https://${v.host}`]),
    at("the web origin"),
  );
  check(
    c.attributes?.["post.logout.redirect.uris"] === `https://${v.host}/console/`,
    at("the post-logout redirect URI"),
  );
  const audience = (c.protocolMappers ?? []).find(
    (m) => m.protocolMapper === "oidc-audience-mapper",
  );
  check(
    audience?.config?.["included.custom.audience"] === env.get("TUTELA_AUDIENCE"),
    at("the audience mapper adds TUTELA_AUDIENCE"),
  );
  check(
    audience?.config?.["access.token.claim"] === "true",
    at("the audience is in the access token"),
  );
  const loa = JSON.parse(c.attributes?.["acr.loa.map"] ?? "{}");
  const stepUp = env.get("TUTELA_ADMIN_ACR").split(",")[0].trim();
  check(
    Number.isInteger(loa[stepUp]),
    at(`the ACR-to-LoA map names ${stepUp}, the first TUTELA_ADMIN_ACR`),
  );
}

// ---------- Lint, then the two renders ----------

for (const args of [[CHART], [CHART, "-f", PROD]]) {
  const r = spawnSync("helm", ["lint", ...args], { encoding: "utf8" });
  check(r.status === 0, `helm lint ${args.join(" ")}\n${r.stdout}${r.stderr}`);
}

checkRender("default values", render([]), {
  defaults: true,
  issuer: "https://tutela.example.com",
  realm: "https://keycloak.example.com/realms/example",
  tenant: "ten_01a1b4a2-0000-7000-8000-000000000000",
  clientId: "tutela-console",
  host: "tutela.example.com",
  apps: 0,
  webhooks: 0,
});

const prod = render(["-f", PROD]);
checkRender("production values", prod, {
  defaults: false,
  issuer: "https://tutela.acme.test",
  realm: "https://keycloak.acme.internal/realms/acme",
  tenant: "ten_01a1b4b0-1234-7abc-8def-0123456789ab",
  clientId: "tutela-console",
  host: "tutela.acme.test",
  apps: 2,
  webhooks: 1,
});
{
  const at = (what) => `production values: ${what}`;
  const deploy = one(prod, "Deployment", "t-tutela");
  check(deploy.text.includes("image: ghcr.io/f8fvwgzc/tutelad@sha256:"), at("the image by digest"));
  check(fromSecret(deploy, "TUTELA_LEDGER_TOKEN"), at("TUTELA_LEDGER_TOKEN from a Secret"));
  check(
    fromSecret(deploy, "TUTELA_MASTER_KEY_PREVIOUS"),
    at("TUTELA_MASTER_KEY_PREVIOUS from a Secret"),
  );
  check(
    /- name: SSL_CERT_DIR\n\s+value: \/etc\/tutela\/database-ca/.test(deploy.text),
    at("the database's CA added"),
  );
  const env = data(one(prod, "ConfigMap", "t-tutela-env"));
  check(
    env.get("TUTELA_CORS_ORIGINS") === "https://crm.acme.test,https://admin.acme.test",
    at("the CORS origins"),
  );
  const trust = block(one(prod, "ConfigMap", "t-tutela-trust"), "trust.toml");
  check(
    trust.startsWith('private_hosts = ["keycloak.acme.internal"]'),
    at("the realm's host is private, once"),
  );
  check(
    trust.includes("workloads = true") && trust.includes('name = "symphony"'),
    at("extra issuers and audiences"),
  );
  const ingress = one(prod, "Ingress", "t-tutela").text;
  check(/path: \/\n\s+pathType: Prefix/.test(ingress), at("the ingress routes every path"));
  check(ingress.includes("secretName: tutela-tls"), at("the ingress has TLS"));
  check(
    !/content-security-policy|configuration-snippet|server-snippet/i.test(ingress),
    at("the ingress adds no header"),
  );
}

// ---------- Wrong values fail ----------

for (const [why, set] of [
  ["one replica", ["--set", "replicaCount=1"]],
  ["a slow revision check", ["--set", "config.revisionCheckMs=2000"]],
  ["no tenant id", ["--set", "tenant.id="]],
  [
    "a tenant id that is not a uuidv7",
    ["--set", "tenant.id=ten_01a1b4a2-0000-4000-8000-000000000000"],
  ],
  ["no realm", ["--set", "keycloak.realm="]],
  ["an http issuer", ["--set", "issuer=http://tutela.example.com"]],
  ["the Console without TUTELA_ADMIN_ACR", ["--set", "config.adminAcr="]],
  ["a ledger without its token", ["--set", "config.ledgerUrl=https://l.example.com/append"]],
  ["no first owner", ["--set", "tenant.owners=null"]],
]) {
  const r = spawnSync("helm", ["template", "t", CHART, ...set], { encoding: "utf8" });
  check(r.status !== 0, `helm template refuses ${why}`);
}

if (failures > 0) {
  console.error(`helm check: ${failures} of ${checks} checks failed`);
  process.exit(1);
}
console.log(
  `helm check: ${checks} checks passed (lint, default and production values, wrong values refused)`,
);
