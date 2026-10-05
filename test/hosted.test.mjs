// Hosted-mode checks against a fake NITRO endpoint. Run: npm run build && npm test
// Needs openssl on PATH to mint a throwaway self-signed certificate.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { createServer } from "node:https";
import { X509Certificate } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assertSafeArg } from "../dist/ssh.js";

const MCP_PORT = 18080;
const nitroCalls = [];
let nitro;
let app;
let appLog = "";

function principal(roles, scp = "NetScaler.Access") {
  const claims = [{ typ: "http://schemas.microsoft.com/identity/claims/scope", val: scp }, ...roles.map((r) => ({ typ: "roles", val: r }))];
  return Buffer.from(JSON.stringify({ auth_typ: "aad", role_typ: "roles", claims })).toString("base64");
}

async function rpc(method, params, roles = ["NetScaler.Reader"], scp, path = "/mcp") {
  const headers = { "Content-Type": "application/json", Accept: "application/json, text/event-stream" };
  if (roles) headers["X-MS-CLIENT-PRINCIPAL"] = principal(roles, scp);
  headers["X-MS-CLIENT-PRINCIPAL-NAME"] = "tester@example.com";
  const res = await fetch(`http://127.0.0.1:${MCP_PORT}${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
  });
  return { status: res.status, body: res.headers.get("content-type")?.includes("json") ? await res.json() : await res.text() };
}

before(async () => {
  const dir = mkdtempSync(join(tmpdir(), "ns-mcp-test-"));
  execFileSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=fake-ns",
    "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem")], { stdio: "ignore" });
  const cert = readFileSync(join(dir, "cert.pem"));
  const fingerprint = new X509Certificate(cert).fingerprint256;

  let backupName = "";
  nitro = createServer({ key: readFileSync(join(dir, "key.pem")), cert }, (req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
    const body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString()) : undefined;
    nitroCalls.push({ method: req.method, url: req.url, pass: req.headers["x-nitro-pass"], body });
    res.setHeader("Content-Type", "application/json");
    if (body?.servicegroup?.servicegroupname === "hang") return; // never answers: the client times out
    if (req.url.includes("/config/hangget")) return;
    if (/[?&]filter=[^&]*%3A/i.test(req.url)) { // NITRO 13.1 and 14.1 reject an encoded ':' in filter
      res.statusCode = 400;
      return res.end(JSON.stringify({ errorcode: -1, message: "Invalid filter in query parameters", severity: "ERROR" }));
    }
    if (req.url.includes("responderpolicy/nope") || req.url.includes("vpnvserver_responderpolicy_binding/gw3")) {
      res.statusCode = 500;
      return res.end(JSON.stringify({ errorcode: 258, message: "No such resource", severity: "ERROR" }));
    }
    if (req.url.includes("sslvserver_binding/vs_broken")) {
      res.statusCode = 500;
      return res.end(JSON.stringify({ errorcode: 1, message: "boom", severity: "ERROR" }));
    }
    if (body?.systembackup) backupName = body.systembackup.filename;
    if (body?.nsacl) { // block_ip_acl retried after an outcome-unknown add: the ACL is already there
      res.statusCode = 409;
      return res.end(JSON.stringify({ errorcode: 273, message: "Resource already exists", severity: "ERROR" }));
    }
    if (req.url.includes("authenticationauthnprofile/missing")) {
      res.statusCode = 404;
      return res.end(JSON.stringify({ errorcode: 258, message: "No such resource", severity: "ERROR" }));
    }
    res.end(JSON.stringify({ errorcode: 0, message: "Done", hanode: [{ state: "PRIMARY" }], nsversion: { version: "NS13.1" },
      ping: [{ response: "3 packets transmitted, 3 packets received" }],
      vpnvserver: req.url.includes("vpnvserver/gw2") ? [{ name: "gw2", authnprofile: "missing" }] : [{ name: "gw1", authnprofile: "prof1" }, { name: "gw2" }, { name: "gw3" }],
      nsacl: [{ aclname: "mcp_block_203_0_113_7", aclaction: "DENY", state: "ENABLED", srcipval: "203.0.113.7", kernelstate: "APPLIED" }],
      authenticationvserver: [{ name: "aaa1" }], authenticationauthnprofile: [{ name: "prof1", authnvsname: "aaa1" }],
      nsrunningconfig: { response: "add lb vserver v HTTP\n".repeat(300) },
      systemfile: req.url.includes("filename:big") ? [{ filecontent: Buffer.from("x".repeat(150_000)).toString("base64") }] : undefined,
      vpnvserver_responderpolicy_binding: req.url.includes("/gw1") ? [{ policy: "block_saml", priority: 10, bindpoint: "REQUEST" }] : [],
      authenticationvserver_responderpolicy_binding: [],
      responderpolicy: [{ name: "block_saml", logaction: "log_saml" }],
      auditmessageaction: [{ name: "log_saml", loglevel1: "INFORMATIONAL", logtonewnslog: "NO" }],
      auditsyslogparams: { userdefinedauditlog: "YES", loglevel: ["ALERT", "CRITICAL"] },
      auditnslogparams: { userdefinedauditlog: "NO", loglevel: ["ALL"] },
      systemsession: [{ sid: 101, username: "bob", clientipaddress: "203.0.113.5", currentconn: false }, { sid: 7, username: "api", currentconn: true }],
      servicegroup_servicegroupmember_binding: [{ servicegroupname: "web", servername: "web1", port: 443, state: "DISABLED", ip: "10.1.1.1" }],
      systembackup: backupName ? [{ filename: `${backupName}.tgz`, level: "basic" }] : [],
      sslparameter: { defaultprofile: "DISABLED" },
      sslvserver: [{ vservername: "vs_old", ssl3: "DISABLED", tls1: "ENABLED", tls11: "DISABLED", tls12: "ENABLED", tls13: "DISABLED" }, { vservername: "vs_broken", tls12: "ENABLED" }],
      sslvserver_binding: req.url.includes("sslvserver_binding/vs_broken") ? undefined : [{ sslvserver_sslciphersuite_binding: [{ ciphername: "SSL3-DES-CBC3-SHA" }, { ciphername: "DEFAULT" }], sslvserver_sslcertkey_binding: [{ certkeyname: "www" }] }],
      sslcertkey: [{ certkey: "www", daystoexpiration: 12, linkcertkeyname: "", issuer: "CN=Some CA", subject: "CN=www" }],
      authenticationvserver_authenticationpolicy_binding: req.url.includes("authenticationvserver_authenticationpolicy_binding/aaa1") ? [{ policy: "ap_saml", priority: "100" }] : undefined,
      authenticationpolicy: req.url.includes("authenticationpolicy/ap_saml") ? [{ name: "ap_saml", rule: "true", action: "saml1" }] : undefined,
      authenticationsamlaction: req.url.includes("authenticationsamlaction/saml1") ? [{ name: "saml1", samlredirecturl: "https://idp.example/sso" }] : undefined,
      authenticationldapaction: [{ name: "l1", ldapbinddnpassword: "s3cret-bind", passwdchange: "ENABLED", _nextgenapiresource: "x" }],
      systemuser: [{ username: "backdoor", externalauth: "DISABLED", logging: "ENABLED" }],
      systemcmdpolicy: [{ policyname: "allow_all", action: "ALLOW", cmdspec: ".*" }],
      systemuser_systemcmdpolicy_binding: [{ username: "backdoor", policyname: "allow_all" }],
      nsip: [{ ipaddress: "10.0.0.9", type: "SNIP", mgmtaccess: "ENABLED", restrictaccess: "DISABLED", gui: "ENABLED" }] }));
    });
  });
  await new Promise((r) => nitro.listen(0, "127.0.0.1", r));
  const nitroAddr = `127.0.0.1:${nitro.address().port}`;

  app = spawn(process.execPath, ["dist/index.js"], {
    env: {
      PATH: process.env.PATH,
      MCP_TRANSPORT: "http",
      WEBSITE_AUTH_ENABLED: "True",
      PORT: String(MCP_PORT),
      NETSCALER_TARGETS: "lab,bad",
      NS_LAB_NSIP: nitroAddr, NS_LAB_USER: "api", NS_LAB_PASS: "lab-secret", NS_LAB_TLS_SHA256: fingerprint, NS_LAB_TIMEOUT: "1500",
      NS_LAB_ADMIN_USER: "api-admin", NS_LAB_ADMIN_PASS: "lab-admin-secret",
      NS_LAB_SSH_USER: "nsconmsg", NS_LAB_SSH_PASS: "x", NS_LAB_FORENSICS_USER: "forensics", NS_LAB_FORENSICS_PASS: "x", NS_LAB_SSH_SHA256: "AAAA",
      NS_BAD_NSIP: nitroAddr, NS_BAD_USER: "api", NS_BAD_PASS: "bad-secret", NS_BAD_TLS_SHA256: "AA".repeat(32),
    },
  });
  app.stdout.on("data", (d) => (appLog += d));
  app.stderr.on("data", (d) => (appLog += d));
  for (let i = 0; i < 50 && !appLog.includes("listening"); i++) await new Promise((r) => setTimeout(r, 100));
  assert.ok(appLog.includes("listening"), `app did not start: ${appLog}`);
});

after(() => {
  app?.kill();
  nitro?.close();
});

test("refuses to start without App Service authentication", () => {
  let failed = false;
  try {
    execFileSync(process.execPath, ["dist/index.js"], { env: { PATH: process.env.PATH, MCP_TRANSPORT: "http" }, stdio: "pipe" });
  } catch (err) {
    failed = true;
    assert.match(String(err.stderr), /WEBSITE_AUTH_ENABLED/);
  }
  assert.ok(failed);
});

test("rejects callers without the scope or a role", async () => {
  assert.equal((await rpc("tools/list", {}, null)).status, 403);
  assert.equal((await rpc("tools/list", {}, [])).status, 403);
  assert.equal((await rpc("tools/list", {}, ["NetScaler.Reader"], "Other.Scope")).status, 403);
  assert.equal((await rpc("tools/list", {}, undefined, undefined, "/mcp/lab")).status, 404);
});

test("Reader sees 53 tools, Admin sees all 73", async () => {
  const readerTools = (await rpc("tools/list", {})).body.result.tools;
  const reader = readerTools.map((t) => t.name);
  const admin = (await rpc("tools/list", {}, ["NetScaler.Admin"])).body.result.tools.map((t) => t.name);
  for (const t of readerTools) {
    assert.deepEqual(t.inputSchema.properties.appliance.enum, ["lab", "bad"], `${t.name} lacks the appliance choice`);
    assert.ok(t.inputSchema.required.includes("appliance"));
  }
  assert.equal(reader.length, 53);
  assert.equal(admin.length, 73);
  for (const t of ["force_ha_failover", "force_ha_sync", "save_config", "get_system_file", "drain_service_group_member", "create_backup", "kill_admin_session", "nitro_write", "get_core_backtrace", "search_core", "capture_aaad_debug"]) {
    assert.ok(!reader.includes(t), `${t} visible to Reader`);
    assert.ok(admin.includes(t), `${t} missing for Admin`);
  }
});

test("Reader cannot call an admin tool by name, and nothing reaches the appliance", async () => {
  const before = nitroCalls.length;
  for (const name of ["force_ha_sync", "save_config", "get_system_file", "nitro_write"]) {
    const { body } = await rpc("tools/call", { name, arguments: { appliance: "lab" } });
    assert.ok(body.error || body.result?.isError, `${name} was not refused`);
  }
  assert.equal(nitroCalls.length, before);
});

test("pinned read reaches the appliance with its credentials", async () => {
  const { body } = await rpc("tools/call", { name: "get_ha_status", arguments: { appliance: "lab" } });
  assert.ok(!body.result.isError, JSON.stringify(body));
  assert.ok(nitroCalls.some((c) => c.pass === "lab-secret"));
});

test("Reader tools use the read account, admin tools the admin account", async () => {
  let from = nitroCalls.length;
  await rpc("tools/call", { name: "get_ha_status", arguments: { appliance: "lab" } }, ["NetScaler.Admin"]);
  assert.ok(nitroCalls.length > from);
  assert.ok(nitroCalls.slice(from).every((c) => c.pass === "lab-secret"));
  from = nitroCalls.length;
  const { body } = await rpc("tools/call", { name: "save_config", arguments: { appliance: "lab" } }, ["NetScaler.Admin"]);
  assert.ok(!body.result.isError, JSON.stringify(body));
  assert.ok(nitroCalls.length > from);
  assert.ok(nitroCalls.slice(from).every((c) => c.pass === "lab-admin-secret"));
});

test("an admin tool on a target with no admin account is refused before any request", async () => {
  const from = nitroCalls.length;
  const { body } = await rpc("tools/call", { name: "save_config", arguments: { appliance: "bad" } }, ["NetScaler.Admin"]);
  assert.ok(body.result.isError);
  assert.match(body.result.content[0].text, /not configured for bad/);
  assert.equal(nitroCalls.length, from);
});

test("tools carry read-only or destructive hints", async () => {
  const tools = (await rpc("tools/list", {}, ["NetScaler.Admin"])).body.result.tools;
  const hint = (n) => tools.find((t) => t.name === n).annotations;
  assert.equal(hint("get_ha_status").readOnlyHint, true);
  assert.equal(hint("nitro_write").destructiveHint, true);
  assert.equal(hint("capture_aaad_debug").destructiveHint, true);
});

test("fingerprint mismatch fails before credentials are sent", async () => {
  const { body } = await rpc("tools/call", { name: "get_ha_status", arguments: { appliance: "bad" } });
  assert.match(JSON.stringify(body), /fingerprint mismatch/);
  assert.ok(!nitroCalls.some((c) => c.pass === "bad-secret"));
});

test("failover with the wrong expected primary is refused and audited", async () => {
  const posts = nitroCalls.filter((c) => c.method === "POST").length;
  const { body } = await rpc("tools/call",
    { name: "force_ha_failover", arguments: { appliance: "lab", confirm: "yes", expected_primary: "10.0.0.99" } }, ["NetScaler.Admin"]);
  assert.ok(body.result.isError);
  assert.match(body.result.content[0].text, /refused/);
  assert.equal(nitroCalls.filter((c) => c.method === "POST").length, posts);
  await new Promise((r) => setTimeout(r, 100));
  assert.match(appLog, /"audit":"attempt".*"tool":"force_ha_failover".*"appliance":"lab"/);
  assert.match(appLog, /"audit":"result".*"outcome":"error: Failover refused/);
});

test("nitro_get redacts secret fields and refuses dangerous resources and args", async () => {
  const { body } = await rpc("tools/call",
    { name: "nitro_get", arguments: { appliance: "lab", namespace: "config", resource: "authenticationldapaction" } });
  const text = body.result.content[0].text;
  assert.ok(!text.includes("s3cret-bind"), text);
  assert.match(text, /"ldapbinddnpassword": "\[redacted\]"/);
  assert.match(text, /"passwdchange": "ENABLED"/);
  assert.ok(!text.includes("_nextgenapiresource"));

  const before = nitroCalls.length;
  for (const a of [{ resource: "systemfile" }, { resource: "techsupport" }, { namespace: "stat", resource: "lbvserver", args: "clearstats:basic" }]) {
    const r = await rpc("tools/call", { name: "nitro_get", arguments: { appliance: "lab", namespace: "config", ...a } });
    assert.ok(r.body.result?.isError, JSON.stringify(r.body));
  }
  for (const a of [{ resource: "../config/nsip" }, { resource: "nsip", name: "../x" }, { resource: "aaauser", filter: "password:guess" }, { resource: "nsip", filter: "ipaddress:203.0.113.4&x=y" }]) {
    const r = await rpc("tools/call", { name: "nitro_get", arguments: { appliance: "lab", namespace: "config", ...a } });
    assert.ok(r.body.error || r.body.result?.isError, JSON.stringify(a));
  }
  assert.equal(nitroCalls.length, before);
});

test("security reads flag a hidden superuser and an exposed SNIP", async () => {
  const audit = (await rpc("tools/call", { name: "audit_admin_access", arguments: { appliance: "lab" } })).body.result.content[0].text;
  const user = JSON.parse(audit).users.find((u) => u.username === "backdoor");
  assert.ok(user.flags.includes("SUPERUSER-EQUIVALENT"), audit);
  assert.match(audit, /"policyname": "allow_all"/);
  const exposure = (await rpc("tools/call", { name: "check_management_exposure", arguments: { appliance: "lab" } })).body.result.content[0].text;
  assert.match(exposure, /10\.0\.0\.9 \(SNIP\): management access enabled without restrictaccess/);
  assert.match(exposure, /plain HTTP/);
});

test("assertSafeArg rejects shell metacharacters", () => {
  for (const bad of ["a;b", "a\nb", "$(id)", "`id`", "a|b", "a b"]) {
    assert.throws(() => assertSafeArg(bad, "arg"), undefined, bad);
  }
  assert.doesNotThrow(() => assertSafeArg("tcp_err_rst", "arg"));
});

const call = async (name, args, roles = ["NetScaler.Admin"]) =>
  (await rpc("tools/call", { name, arguments: { appliance: "lab", ...args } }, roles)).body;
const posts = () => nitroCalls.filter((c) => c.method === "POST");

test("test_reachability sends a capped ping, a numeric traceroute, and rejects option-shaped hosts", async () => {
  const n = posts().length;
  const ok = await call("test_reachability", { mode: "ping", host: "10.1.1.1", source_ip: "10.0.0.9" }, ["NetScaler.Reader"]);
  assert.match(ok.result.content[0].text, /3 packets transmitted/);
  const sent = posts().at(-1);
  assert.match(sent.url, /\/config\/ping$/);
  assert.deepEqual(sent.body, { ping: { hostName: "10.1.1.1", c: 3, t: 5, S: "10.0.0.9" } });
  await call("test_reachability", { mode: "traceroute", host: "10.1.1.1", max_hops: 3 }, ["NetScaler.Reader"]);
  assert.deepEqual(posts().at(-1).body, { traceroute: { host: "10.1.1.1", n: true, m: 3, w: 2, q: 1 } });
  for (const host of ["-c 99 10.1.1.1", "a b", "host\r\nx", "h\u00e9st.example", "-flood"]) {
    const r = await call("test_reachability", { mode: "ping", host }, ["NetScaler.Reader"]);
    assert.ok(r.error || r.result?.isError, host);
  }
  assert.equal(posts().length, n + 2);
});

test("filters reach NITRO with a literal ':' and a failed read is not reported as all UP", async () => {
  const r = await call("list_down_services", {}, ["NetScaler.Reader"]);
  assert.ok(!r.result.isError, r.result.content[0].text);
  assert.ok(nitroCalls.some((c) => c.url.includes("/config/service?filter=svrstate:DOWN&attrs=name,ipaddress")));
  const s = await call("list_services", { state_filter: "OUT OF SERVICE" }, ["NetScaler.Reader"]);
  assert.ok(!s.result.isError, s.result.content[0].text);
  assert.ok(nitroCalls.some((c) => c.url.includes("filter=svrstate:OUT%20OF%20SERVICE")));
});

test("drain_service_group_member sends member-only payloads and reports observed state", async () => {
  const off = await call("drain_service_group_member", { servicegroup: "web", server: "web1", port: 443, action: "disable", delay: 30 });
  assert.match(off.result.content[0].text, /"state": "DISABLED"/);
  let sent = posts().at(-1);
  assert.match(sent.url, /servicegroup\?action=disable$/);
  assert.deepEqual(sent.body, { servicegroup: { servicegroupname: "web", servername: "web1", port: 443, graceful: "YES", delay: 30 } });
  await call("drain_service_group_member", { servicegroup: "web", server: "web1", port: 443, action: "enable" });
  sent = posts().at(-1);
  assert.deepEqual(sent.body, { servicegroup: { servicegroupname: "web", servername: "web1", port: 443 } });
  for (const bad of [{ server: "" }, { port: 0 }, { port: 1.5 }, { port: 70000 }]) {
    const r = await call("drain_service_group_member", { servicegroup: "web", server: "web1", port: 443, action: "disable", ...bad });
    assert.ok(r.error || r.result?.isError, JSON.stringify(bad));
  }
});

test("create_backup names the file and reads back that exact backup", async () => {
  const r = await call("create_backup", { comment: "pre-change" });
  const out = JSON.parse(r.result.content[0].text);
  assert.match(out.filename, /^mcp_\d{14}_[0-9a-f]{6}$/);
  assert.equal(out.outcome, "created");
  assert.equal(out.backup.filename, `${out.filename}.tgz`);
  const sent = posts().at(-1);
  assert.match(sent.url, /systembackup\?action=create$/);
  assert.deepEqual(sent.body, { systembackup: { filename: out.filename, level: "basic", comment: "pre-change" } });
});

test("kill_admin_session checks the session first and never sends all", async () => {
  const n = posts().length;
  for (const [args, why] of [[{ sid: 999, username: "bob" }, /no management session/], [{ sid: 101, username: "eve" }, /belongs to 'bob'/], [{ sid: 7, username: "api" }, /own session/]]) {
    const r = await call("kill_admin_session", args);
    assert.ok(r.result.isError);
    assert.match(r.result.content[0].text, why);
  }
  for (const sid of [0, -1, 1.5]) {
    const r = await call("kill_admin_session", { sid, username: "bob" });
    assert.ok(r.error || r.result?.isError, String(sid));
  }
  assert.equal(posts().length, n);
  const ok = await call("kill_admin_session", { sid: 101, username: "bob" });
  assert.ok(!ok.result.isError, JSON.stringify(ok));
  assert.deepEqual(posts().at(-1).body, { systemsession: { sid: 101 } });
  assert.match(posts().at(-1).url, /systemsession\?action=kill$/);
});

test("audit_ssl_posture flags old TLS, weak ciphers and certs, and reports a failed read as incomplete", async () => {
  const out = JSON.parse((await call("audit_ssl_posture", {}, ["NetScaler.Reader"])).result.content[0].text);
  assert.equal(out.reads_complete, false);
  assert.match(out.stopped_because, /vs_broken: boom/);
  assert.ok(out.assessment_limits.length >= 3);
  const f = out.vservers[0].findings.join("\n");
  assert.match(f, /old protocols enabled: tls1/);
  assert.match(f, /weak ciphers bound: SSL3-DES-CBC3-SHA/);
  assert.match(f, /expires in 12 days/);
  assert.match(f, /no linked intermediate/);
  assert.ok(!f.includes("DEFAULT"));
});

test("a write with no reply is reported as outcome unknown and sent once", async () => {
  const n = posts().length;
  const r = await call("drain_service_group_member", { servicegroup: "hang", server: "s", port: 80, action: "disable" });
  assert.ok(r.result.isError);
  assert.match(r.result.content[0].text, /Outcome unknown/);
  assert.equal(posts().length, n + 1);
});

test("a read with no reply is retried, a write is not", async () => {
  const before = nitroCalls.filter((c) => c.url.includes("/config/hangget")).length;
  const r = await call("nitro_get", { namespace: "config", resource: "hangget" }, ["NetScaler.Reader"]);
  assert.ok(r.result.isError);
  assert.equal(nitroCalls.filter((c) => c.url.includes("/config/hangget")).length - before, 3);
});

test("nitro_write previews without sending, applies on request, and keeps secrets out of output and audit", async () => {
  const n = nitroCalls.length;
  const args = { operation: "set", resource: "authenticationldapaction", name: "l1", payload: { ldapbinddnpassword: "n3w-s3cret", serverip: "10.0.0.5" } };
  const pv = await call("nitro_write", args);
  const pvText = pv.result.content[0].text;
  assert.match(pvText, /"method": "PUT"/);
  assert.match(pvText, /\/nitro\/v1\/config\/authenticationldapaction\/l1/);
  assert.ok(!pvText.includes("n3w-s3cret"), pvText);
  assert.equal(nitroCalls.length, n);

  const live = await call("nitro_write", { ...args, preview: false });
  assert.ok(!live.result.isError, JSON.stringify(live));
  const sent = nitroCalls.at(-1);
  assert.equal(sent.method, "PUT");
  assert.match(sent.url, /\/config\/authenticationldapaction\/l1$/);
  assert.deepEqual(sent.body, { authenticationldapaction: args.payload });
  assert.match(live.result.content[0].text, /save_config/);
  await new Promise((r) => setTimeout(r, 100));
  assert.ok(!appLog.includes("n3w-s3cret"), "payload secret reached the audit log");

  const refused = await call("nitro_write", { operation: "action", resource: "systemsession", action: "kill", payload: { all: true }, preview: false });
  assert.ok(refused.result.isError);
  assert.equal(nitroCalls.length, n + 1);
});

test("check_policy_coverage names the gateway and auth vservers a policy is missing from", async () => {
  const out = JSON.parse((await call("check_policy_coverage", { type: "responder", policy: "block_saml" }, ["NetScaler.Reader"])).result.content[0].text);
  assert.deepEqual(out.not_bound_on, ["gateway gw2", "authentication aaa1"]);
  assert.deepEqual(out.unverified, ["gateway gw3"]);
  assert.equal(out.incomplete, true);
  const nope = await call("check_policy_coverage", { type: "responder", policy: "nope" }, ["NetScaler.Reader"]);
  assert.ok(nope.result.isError);
  assert.match(nope.result.content[0].text, /No responder policy named 'nope'/);
  assert.equal(out.vservers.find((v) => v.vserver === "gw1").priority, 10);
});

test("check_log_actions flags a log action no log will accept", async () => {
  const out = JSON.parse((await call("check_log_actions", {}, ["NetScaler.Reader"])).result.content[0].text);
  const f = out.findings[0];
  assert.equal(f.logaction, "log_saml");
  assert.match(f.global_syslog, /excludes INFORMATIONAL/);
  assert.match(f.global_nslog, /userdefinedauditlog is off/);
});

test("a refused admin call is an error, and the audit records it as one", async () => {
  const { body } = await rpc("tools/call", { name: "block_ip_acl", arguments: { appliance: "lab", target: "10.1.1.1" } }, ["NetScaler.Admin"]);
  assert.ok(body.result.isError);
  await new Promise((r) => setTimeout(r, 100));
  assert.match(appLog, /"audit":"result".*"outcome":"error: Refused: '10\.1\.1\.1'/);
});

test("block_ip_acl retried after its ACL was created goes on to apply", async () => {
  const from = nitroCalls.length;
  const { body } = await rpc("tools/call", { name: "block_ip_acl", arguments: { appliance: "lab", target: "203.0.113.7" } }, ["NetScaler.Admin"]);
  assert.ok(!body.result.isError, JSON.stringify(body));
  assert.match(body.result.content[0].text, /Blocked 203\.0\.113\.7: ACL mcp_block_203_0_113_7 was already in place and applied/);
  assert.ok(nitroCalls.slice(from).some((c) => c.method === "POST" && c.url.includes("/nsacls?action=apply")));
});

test("node=peer with no peer configured is an error; a standalone appliance is not", async () => {
  const peer = (await rpc("tools/call", { name: "get_syslog", arguments: { appliance: "lab", node: "peer" } })).body.result;
  assert.ok(peer.isError);
  assert.match(peer.content[0].text, /no peer NSIP/);
  for (const name of ["get_ha_status", "get_crash_state"]) {
    const r = (await rpc("tools/call", { name, arguments: { appliance: "lab" } })).body.result;
    assert.ok(!r.isError, `${name}: ${JSON.stringify(r)}`);
  }
});

test("diagnose_auth follows a Gateway's authentication profile, resolves advanced policy actions of any type, and keeps what it has when the profile is missing", async () => {
  const ok = JSON.parse((await rpc("tools/call", { name: "diagnose_auth", arguments: { appliance: "lab", vserver_name: "gw1" } })).body.result.content[0].text);
  assert.equal(ok.nfactor_auth_vserver.authnprofile, "prof1");
  assert.equal(ok.nfactor_auth_vserver.vserver[0].name, "aaa1");
  assert.deepEqual(ok.nfactor_auth_vserver.action_configs.saml1, { type: "authenticationsamlaction", config: [{ name: "saml1", samlredirecturl: "https://idp.example/sso" }] });
  assert.ok(nitroCalls.some((c) => c.url.includes("vpnvserver_authenticationpolicy_binding/gw1")));
  const broken = (await rpc("tools/call", { name: "diagnose_auth", arguments: { appliance: "lab", vserver_name: "gw2" } })).body.result;
  assert.ok(!broken.isError);
  const out = JSON.parse(broken.content[0].text);
  assert.match(out.authnprofile_error, /missing/);
  assert.equal(out.vserver[0].name, "gw2");
});

test("search_config caps matches, and any long result is cut with the note first", async () => {
  const search = (await rpc("tools/call", { name: "search_config", arguments: { appliance: "lab", query: "add lb" } })).body.result.content[0].text;
  assert.match(search, /^300 matching line\(s\) for 'add lb'\. Showing the first 200; 100 more/);
  const file = (await rpc("tools/call", { name: "get_system_file", arguments: { appliance: "lab", filename: "big", filelocation: "/var/log" } }, ["NetScaler.Admin"])).body.result.content[0].text;
  assert.match(file, /^\[Output cut at 100,000 of 150,/);
  assert.ok(file.length < 100_300);
});
