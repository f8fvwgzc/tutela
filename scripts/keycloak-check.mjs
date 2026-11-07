// Tests tutelad's token exchange and the Console's sign-in against a real
// Keycloak 26 (#87, ADR-0057). It starts the pinned Keycloak image on
// loopback in dev mode, makes the tenant's realm (the step-up browser flow,
// people with known passwords and TOTP secrets) and imports the Console's
// client from the Helm chart's partial-import JSON, as a realm admin would
// (ADR-0056 item 9), so the test also proves that JSON. Then it runs two
// Rust tests against it with a fixture file:
//   - crates/tutelad/tests/keycloak.rs: real access tokens exchanged at
//     POST /oauth2/token (TUTELA_KEYCLOAK_FIXTURE);
//   - crates/tutelad/tests/console_e2e.rs: the Phase B exit check in
//     Playwright's Chromium, signing in at Keycloak's own login and OTP
//     pages (TUTELA_E2E_KEYCLOAK_FIXTURE).
// The container is removed at the end; the image stays.
//
// `make keycloak` runs it. It pulls an image and starts a container, so it
// is skipped unless TUTELA_REQUIRE_KEYCLOAK=1; with it set, anything
// missing (docker, helm, the image, the database) fails it. Both tests need
// TUTELA_TEST_DATABASE_URL like every database test, and the built Console
// (`make js-build`).
//
//   node scripts/keycloak-check.mjs          # the checks
//   node scripts/keycloak-check.mjs --keep   # only the realm: prints the
//                                            # fixture, leaves Keycloak running
import { execFileSync, spawnSync } from "node:child_process";
import { randomBytes, randomUUID } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";

// Keycloak 26.8.1, the image rebuild of 2026-10-23 (the newest 26.x tag
// older than a week on 2026-11-07), pinned by its manifest-list digest
// (linux/amd64 and linux/arm64). ADR-0057.
const IMAGE =
  "quay.io/keycloak/keycloak:26.8.1-1@sha256:a78d6b79572168cb25886b80a8b5b8d4ed4390743e3eecb810538683e209dd6b";
const CHART = "deploy/helm/tutela";
// The chart renders https redirect URIs for console.host. Nothing listens
// at this host: the Rust test reads the code from the redirect's Location.
const CHART_HOST = "127.0.0.1:9";
const STEP_UP_ACR = "mfa";
const STEP_UP_LEVEL = 2;
const keep = process.argv.includes("--keep");

function fail(what) {
  console.error(`keycloak check: ${what}`);
  process.exit(1);
}

if (process.env.TUTELA_REQUIRE_KEYCLOAK !== "1" && !keep) {
  console.log(
    "skipped: the test against a real Keycloak pulls an image and starts a container " +
      "(set TUTELA_REQUIRE_KEYCLOAK=1 to run it, and fail when it cannot)",
  );
  process.exit(0);
}

function run(cmd, args, opts = {}) {
  return spawnSync(cmd, args, { encoding: "utf8", ...opts });
}

if (run("docker", ["version", "--format", "{{.Server.Version}}"]).status !== 0) {
  fail("docker is not running");
}
if (run("helm", ["version", "--short"]).status !== 0) fail("helm is not installed");

// A public image needs no credentials. Pull with an empty Docker config, so
// a credential helper that hangs cannot stop it (ADR-0055).
if (run("docker", ["image", "inspect", IMAGE]).status !== 0) {
  const config = mkdtempSync(join(tmpdir(), "tutela-docker-"));
  console.log(`keycloak check: pulling ${IMAGE}`);
  const pulled = run("docker", ["pull", IMAGE], {
    env: { ...process.env, DOCKER_CONFIG: config },
    stdio: "inherit",
  });
  rmSync(config, { recursive: true, force: true });
  if (pulled.status !== 0) fail(`could not pull ${IMAGE}`);
}

/** A free loopback port (the container binds it right after). */
function freePort() {
  return new Promise((resolve, reject) => {
    const s = createServer();
    s.once("error", reject);
    s.listen(0, "127.0.0.1", () => {
      const { port } = s.address();
      s.close(() => resolve(port));
    });
  });
}

/** 20 characters of the base32 alphabet: Keycloak keys the TOTP HMAC with its bytes. */
function totpSecret() {
  const abc = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  return Array.from(randomBytes(20), (b) => abc[b % 32]).join("");
}

function password() {
  return randomBytes(18).toString("base64url");
}

function person(username, first, last) {
  return {
    id: randomUUID(),
    username,
    first,
    last,
    password: password(),
    totp: totpSecret(),
  };
}

function userOf(realm, p) {
  return {
    id: p.id,
    username: p.username,
    email: `${p.username}@example.test`,
    emailVerified: true,
    firstName: p.first,
    lastName: p.last,
    enabled: true,
    // What a person made in the admin console or by sign-up holds.
    realmRoles: [`default-roles-${realm}`],
    credentials: [
      { type: "password", value: p.password, temporary: false },
      {
        type: "otp",
        userLabel: "test authenticator",
        secretData: JSON.stringify({ value: p.totp }),
        credentialData: JSON.stringify({
          subType: "totp",
          digits: 6,
          counter: 0,
          period: 30,
          algorithm: "HmacSHA1",
        }),
      },
    ],
  };
}

function step(authenticator, requirement, priority, config) {
  return {
    authenticator,
    authenticatorFlow: false,
    requirement,
    priority,
    userSetupAllowed: false,
    ...(config ? { authenticatorConfig: config } : {}),
  };
}

function subflow(flowAlias, requirement, priority) {
  return { flowAlias, authenticatorFlow: true, requirement, priority, userSetupAllowed: false };
}

function flow(alias, topLevel, authenticationExecutions) {
  return { alias, providerId: "basic-flow", topLevel, builtIn: false, authenticationExecutions };
}

/**
 * The tenant's realm as its admin sets it up (JS-SDK.md, "Configure
 * Keycloak for it"): access tokens of 5 minutes, and Keycloak's step-up
 * browser flow: the SSO cookie, or level 1 (password), then level 2 (OTP)
 * when a client asks for it. The level-2 max age of 300 s matches the life
 * of an admin token.
 */
function realmOf(name, people) {
  return {
    realm: name,
    enabled: true,
    accessTokenLifespan: 300,
    otpPolicyType: "totp",
    otpPolicyAlgorithm: "HmacSHA1",
    otpPolicyDigits: 6,
    otpPolicyPeriod: 30,
    otpPolicyLookAheadWindow: 1,
    otpPolicyCodeReusable: false,
    browserFlow: "tutela browser",
    authenticationFlows: [
      flow("tutela browser", true, [
        step("auth-cookie", "ALTERNATIVE", 10),
        subflow("tutela levels", "ALTERNATIVE", 20),
      ]),
      flow("tutela levels", false, [
        subflow("tutela level 1", "CONDITIONAL", 10),
        subflow("tutela level 2", "CONDITIONAL", 20),
      ]),
      flow("tutela level 1", false, [
        step("conditional-level-of-authentication", "REQUIRED", 10, "tutela loa 1"),
        step("auth-username-password-form", "REQUIRED", 20, "tutela amr pwd"),
      ]),
      flow("tutela level 2", false, [
        step("conditional-level-of-authentication", "REQUIRED", 10, "tutela loa 2"),
        step("auth-otp-form", "REQUIRED", 20, "tutela amr otp"),
      ]),
    ],
    authenticatorConfig: [
      { alias: "tutela loa 1", config: { "loa-condition-level": "1", "loa-max-age": "36000" } },
      {
        alias: "tutela loa 2",
        config: { "loa-condition-level": String(STEP_UP_LEVEL), "loa-max-age": "300" },
      },
      // What the AMR mapper (when a client has one) says for each form.
      { alias: "tutela amr pwd", config: { "default.reference.value": "pwd" } },
      { alias: "tutela amr otp", config: { "default.reference.value": "otp" } },
    ],
    users: people.map((p) => userOf(name, p)),
  };
}

/** The Console's client from the chart, as `helm template` renders it. */
function chartClient(realmIssuer) {
  const out = execFileSync(
    "helm",
    [
      "template",
      "t",
      CHART,
      "--show-only",
      "templates/keycloak-client.yaml",
      "--set",
      "devMode=true",
      "--set",
      "issuer=http://127.0.0.1:9",
      "--set",
      "tenant.id=ten_01a1b4a2-0000-7000-8000-000000000000",
      "--set",
      `keycloak.realm=${realmIssuer}`,
      "--set",
      `keycloak.stepUpLevel=${STEP_UP_LEVEL}`,
      "--set",
      `config.adminAcr=${STEP_UP_ACR}`,
      "--set",
      `console.host=${CHART_HOST}`,
    ],
    { encoding: "utf8" },
  );
  const lines = out.split("\n");
  const at = lines.findIndex((l) => l.trim() === "partial-import.json: |");
  if (at < 0) fail("the chart rendered no partial-import.json");
  const body = [];
  for (const l of lines.slice(at + 1)) {
    if (!l.startsWith("    ") && l.trim() !== "") break;
    body.push(l.slice(4));
  }
  return JSON.parse(body.join("\n"));
}

/** A test client of the realm: standard flow, one audience mapper, maybe the AMR mapper. */
function testClient(clientId, audience, fullScopeAllowed, amr = false) {
  const mapper = (name, protocolMapper, config) => ({
    name,
    protocol: "openid-connect",
    protocolMapper,
    config: { ...config, "access.token.claim": "true", "id.token.claim": "false" },
  });
  return {
    clientId,
    publicClient: true,
    standardFlowEnabled: true,
    directAccessGrantsEnabled: false,
    fullScopeAllowed,
    redirectUris: [`https://${CHART_HOST}/console/callback`],
    attributes: {
      "pkce.code.challenge.method": "S256",
      "acr.loa.map": JSON.stringify({ [STEP_UP_ACR]: STEP_UP_LEVEL }),
    },
    protocolMappers: [
      mapper("audience", "oidc-audience-mapper", { "included.custom.audience": audience }),
      ...(amr ? [mapper("amr", "oidc-amr-mapper", {})] : []),
    ],
  };
}

const port = await freePort();
const base = `http://127.0.0.1:${port}`;
const name = `tutela-keycloak-${process.pid}`;
const admin = { username: "admin", password: password() };
const dir = mkdtempSync(join(tmpdir(), "tutela-keycloak-"));
const fixturePath = join(dir, "fixture.json");
let started = false;
let failed = false;

function cleanup() {
  if (started && (!keep || failed)) run("docker", ["rm", "-f", name]);
  if (!keep) rmSync(dir, { recursive: true, force: true });
}
for (const sig of ["SIGINT", "SIGTERM"]) {
  process.on(sig, () => {
    cleanup();
    process.exit(1);
  });
}

async function http(method, path, token, body) {
  const headers = {};
  if (token) headers.authorization = `Bearer ${token}`;
  if (body !== undefined) headers["content-type"] = "application/json";
  const r = await fetch(`${base}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await r.text();
  if (!r.ok) throw new Error(`${method} ${path}: ${r.status} ${text.slice(0, 300)}`);
  return text === "" ? null : JSON.parse(text);
}

async function main() {
  const up = run("docker", [
    "run",
    "-d",
    "--rm",
    "--name",
    name,
    "--label",
    "org.f8fvwgzc.tutela.test=keycloak",
    "-p",
    `127.0.0.1:${port}:8080`,
    "-e",
    `KC_BOOTSTRAP_ADMIN_USERNAME=${admin.username}`,
    "-e",
    `KC_BOOTSTRAP_ADMIN_PASSWORD=${admin.password}`,
    // The issuer is spelled exactly as tutelad's trust file has it.
    "-e",
    `KC_HOSTNAME=${base}`,
    IMAGE,
    "start-dev",
  ]);
  if (up.status !== 0) throw new Error(`docker run: ${up.stderr}`);
  started = true;

  const deadline = Date.now() + 180_000;
  let ready = null;
  while (Date.now() < deadline) {
    ready = await fetch(`${base}/realms/master`).catch(() => null);
    if (ready?.ok) break;
    await new Promise((r) => setTimeout(r, 1000));
  }
  if (!ready?.ok) {
    const logs = run("docker", ["logs", "--tail", "40", name]);
    throw new Error(`Keycloak did not start in 180 s\n${logs.stdout}${logs.stderr}`);
  }
  const t = await fetch(`${base}/realms/master/protocol/openid-connect/token`, {
    method: "POST",
    body: new URLSearchParams({
      grant_type: "password",
      client_id: "admin-cli",
      username: admin.username,
      password: admin.password,
    }),
  }).then((r) => r.json());
  const token = t.access_token;
  if (typeof token !== "string") throw new Error("no admin token");
  // Keycloak's tokens carry its clock: after a sleep, Docker's VM clock
  // has been minutes behind the Mac's. Keycloak sends no Date header, so
  // read the admin token's iat.
  const iat = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString()).iat;
  const skew = Math.round(iat - Date.now() / 1000);
  if (!Number.isFinite(skew) || Math.abs(skew) > 20) {
    throw new Error(`the container's clock is ${String(skew)} s off the host's: restart Docker`);
  }
  console.log(`keycloak check: Keycloak is up at ${base} (clock skew ${String(skew)} s)`);

  const owner = person("olivia", "Olivia", "Owner");
  const member = person("max", "Max", "Member");
  const stranger = person("olivia", "Olivia", "Elsewhere");
  await http("POST", "/admin/realms", token, realmOf("tutela", [owner, member]));
  await http("POST", "/admin/realms", token, realmOf("elsewhere", [stranger]));

  const issuer = `${base}/realms/tutela`;
  const imported = await http("POST", "/admin/realms/tutela/partialImport", token, {
    ...chartClient(issuer),
  });
  if (imported?.added !== 1) {
    throw new Error(`the chart's client was not imported: ${JSON.stringify(imported)}`);
  }
  const consoleClient = chartClient(issuer).clients[0];
  // A client whose one audience is another service's.
  await http("POST", "/admin/realms/tutela/clients", token, {
    ...testClient("tutela-test-other-api", "crm-api", false),
  });
  // The chart's client with Keycloak's default full scope: every client
  // role of the person adds its client to `aud`.
  await http("POST", "/admin/realms/tutela/clients", token, {
    ...testClient("tutela-test-full-scope", "tutela-authz", true),
  });
  // The chart's client with the AMR mapper.
  await http("POST", "/admin/realms/tutela/clients", token, {
    ...testClient("tutela-test-amr", "tutela-authz", false, true),
  });
  // Another realm with the Console's client, not in tutelad's trust file.
  await http("POST", "/admin/realms/elsewhere/clients", token, consoleClient);

  const fixture = {
    url: base,
    admin,
    step_up_acr: STEP_UP_ACR,
    redirect_uri: consoleClient.redirectUris[0],
    realm: { issuer, client_id: consoleClient.clientId, admin_path: "/admin/realms/tutela" },
    elsewhere: { issuer: `${base}/realms/elsewhere`, client_id: consoleClient.clientId },
    other_api_client: "tutela-test-other-api",
    full_scope_client: "tutela-test-full-scope",
    amr_client: "tutela-test-amr",
    people: Object.fromEntries(
      [
        ["owner", owner],
        ["member", member],
        ["stranger", stranger],
      ].map(([k, p]) => [
        k,
        {
          username: p.username,
          password: p.password,
          totp: p.totp,
          sub: p.id,
          name: `${p.first} ${p.last}`,
        },
      ]),
    ),
  };
  writeFileSync(fixturePath, JSON.stringify(fixture, null, 2), { mode: 0o600 });
  if (keep) {
    console.log(`keycloak check: realm ready; fixture ${fixturePath}; container ${name}`);
    return;
  }

  const cargo = process.env.CARGO ?? "cargo";
  const test = (file, env) => {
    const r = spawnSync(
      cargo,
      ["test", "-p", "tutelad", "--all-features", "--locked", "--test", file, "--", "--nocapture"],
      { stdio: "inherit", env: { ...process.env, ...env } },
    );
    if (r.status !== 0) throw new Error(`the ${file} test failed against Keycloak`);
  };
  test("keycloak", { TUTELA_KEYCLOAK_FIXTURE: fixturePath });
  test("console_e2e", { TUTELA_CONSOLE_E2E: "1", TUTELA_E2E_KEYCLOAK_FIXTURE: fixturePath });
  console.log("keycloak check: token exchange and the Console's browser check pass");
}

try {
  await main();
} catch (e) {
  console.error(`keycloak check: ${e instanceof Error ? e.message : String(e)}`);
  failed = true;
  cleanup();
  process.exit(1);
}
cleanup();
