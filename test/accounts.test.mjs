// Account split, forensic command shapes and SSH capture modes. Run: npm run build && npm test

import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createServer } from "node:net";
import ssh2 from "ssh2";
import { NitroClient } from "../dist/client.js";
import { runSshCommand } from "../dist/ssh.js";
import { readFileSync } from "node:fs";
import { NSCONMSG_POLICY } from "../dist/tools/nsconmsg.js";
import { FORENSIC_POLICY, backtraceCommand, searchCommand, CAPTURE_COMMAND, LIST_CORES_COMMAND, extractHits } from "../dist/tools/forensics.js";

const config = {
  nsip: "127.0.0.1:1", peerNsip: "127.0.0.1:2", username: "ro", password: "x", adminUser: "", adminPass: "",
  protocol: "http", timeout: 500, sshUser: "", sshPass: "", forensicsUser: "", forensicsPass: "",
  sshPort: 22, sshTimeout: 2000, tlsSha256: [], sshSha256: [],
};

test("the read-only client refuses writes locally, peer clients included, but allows ping", async () => {
  for (const c of [new NitroClient(config, true), new NitroClient(config, true).forNode("127.0.0.1:3")]) {
    await assert.rejects(c.post("lbvserver", { lbvserver: {} }), /Refused: .*read-only/);
    await assert.rejects(c.delete("nsacl", "x"), /Refused/);
    await assert.rejects(c.post("ping", { ping: {} }), (err) => !/Refused/.test(err.message));
  }
  await assert.rejects(new NitroClient(config).post("lbvserver", { lbvserver: {} }), (err) => !/Refused/.test(err.message));
});

test("forensic commands match the published policy, and nothing else does", () => {
  const policy = new RegExp(FORENSIC_POLICY);
  for (const cmd of [backtraceCommand("3/nsaaad-41203"), backtraceCommand("nsaaad-994"), searchCommand("3/nsaaad-41203", "idp.test.local", 5), searchCommand("nsaaad-994", "idp.test.local", 5), CAPTURE_COMMAND, LIST_CORES_COMMAND]) {
    assert.ok(policy.test(cmd), cmd);
  }
  assert.equal(backtraceCommand("3/nsaaad-41203"), "shell gdb -nx -batch -ex bt /netscaler/nsaaad /var/core/3/nsaaad-41203");
  for (const bad of [
    "shell gdb -nx -batch -ex bt /netscaler/nsaaad /var/core/1/nsppe-1",
    "shell gdb -nx -batch -ex bt /netscaler/nsaaad /var/core/nsppe-1",
    "shell gdb -nx -batch -ex bt /netscaler/nsaaad /var/core/../nsaaad-1",
    "shell gdb -nx -batch -ex shell /netscaler/nsaaad /var/core/1/nsaaad-1",
    "shell cat /tmp/aaad.debug /etc/master.passwd",
    "shell grep -a -o -b -E -m 5 [[:print:]]{0,128}-r[[:print:]]{0,128} /var/core/1/nsaaad-1",
    "shell grep -a -o -b -E -m 5 [[:print:]]{0,128}x;id[[:print:]]{0,128} /var/core/1/nsaaad-1",
    "shell grep -a -o -b -E -m 5 .{0,128}abc.{0,128} /var/core/1/nsaaad-1",
    "shell id",
    "shell ls -lR /",
  ]) assert.ok(!policy.test(bad), bad);
});

test("search hits are parsed from grep -o -b lines and CLI chatter is dropped", () => {
  const out = " Done\r\n1024:<saml:Issuer>https://idp.test.local</saml:Issuer>\r\n88:PPPP\r\nERROR: \r\n";
  assert.deepEqual(extractHits(out), [
    { offset: 1024, text: "<saml:Issuer>https://idp.test.local</saml:Issuer>" },
    { offset: 88, text: "PPPP" },
  ]);
});

test("the nsconmsg policy admits the four command shapes and nothing else, and is the one published", () => {
  const policy = new RegExp(NSCONMSG_POLICY);
  for (const cmd of [
    "shell nsconmsg -K /var/nslog/newnslog -d event -s disptime=1", "shell nsconmsg -K /var/nslog/newnslog.12 -d event",
    "shell nsconmsg -K /var/nslog/newnslog -d current -g tcp_err", "shell nsconmsg -K /var/nslog/newnslog -d current",
    "shell nsconmsg -K /var/nslog/newnslog -d stats", "shell nsconmsg -d oldconmsg -s ConLb=2",
  ]) assert.ok(policy.test(cmd), cmd);
  for (const bad of [
    "shell nsconmsg -K /var/nslog/newnslog.1.tar.gz -d stats", "shell nsconmsg -K /var/nslog/.. -d stats",
    "shell nsconmsg -K /var/nslog/x/newnslog -d stats", "shell nsconmsg -K /var/nslog/newnslog -d stats -O /tmp/x",
    "shell nsconmsg -K /nsconfig/ns.conf -d stats", "shell nsconmsg -K /var/nslog/newnslog -d current -g a;id", "shell id",
  ]) assert.ok(!policy.test(bad), bad);
  assert.ok(readFileSync("docs/local-mode.md", "utf8").includes(`ALLOW "${NSCONMSG_POLICY}"`), "docs/local-mode.md does not publish NSCONMSG_POLICY");
});

test("bad numbers in the timeout and port settings refuse to start", () => {
  const env = { PATH: process.env.PATH, NETSCALER_NSIP: "127.0.0.1", NETSCALER_USER: "ro", NETSCALER_PASS: "x" };
  for (const [name, value] of [["NETSCALER_TIMEOUT", "1000ms"], ["NETSCALER_TIMEOUT", "3000000000"], ["NETSCALER_SSH_PORT", "70000"], ["NETSCALER_SSH_TIMEOUT", "0"]]) {
    assert.throws(() => execFileSync(process.execPath, ["dist/index.js"], { env: { ...env, [name]: value }, stdio: "pipe" }),
      (err) => new RegExp(`${name} must be a whole number`).test(String(err.stderr)), `${name}=${value}`);
  }
});

test("half an account pair refuses to start", () => {
  const env = { PATH: process.env.PATH, NETSCALER_NSIP: "127.0.0.1", NETSCALER_USER: "ro", NETSCALER_PASS: "x" };
  assert.throws(() => execFileSync(process.execPath, ["dist/index.js"], { env: { ...env, NETSCALER_ADMIN_USER: "rw" }, stdio: "pipe" }), (err) => /NETSCALER_ADMIN_PASS/.test(String(err.stderr)));
});

/** A one-command SSH server: `shell cat /tmp/aaad.debug` streams a line every 50 ms, `flood` writes 2 MB. */
async function fakeSsh(t) {
  const hostKey = ssh2.utils.generateKeyPairSync("ed25519").private;
  const server = new ssh2.Server({ hostKeys: [hostKey] }, (client) => {
    client.on("authentication", (ctx) => (ctx.method === "password" && ctx.password === "pw" ? ctx.accept() : ctx.reject()));
    client.on("session", (accept) => accept().on("exec", (acceptExec, _reject, info) => {
      const stream = acceptExec();
      if (info.command === "flood") {
        stream.write(Buffer.alloc(2 * 1024 * 1024, 0x61));
        return;
      }
      const timer = setInterval(() => stream.write("aaad line\n"), 50);
      timer.unref();
      stream.on("close", () => clearInterval(timer));
    }));
    client.on("error", () => {});
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  t.after(() => server.close());
  return { ...config, sshPort: server.address().port };
}

test("a capture window returns what was read, a byte cap stops the read, a plain timeout fails", async (t) => {
  const cfg = await fakeSsh(t);
  const account = { user: "forensics", pass: "pw" };
  const win = await runSshCommand(cfg, account, "127.0.0.1", CAPTURE_COMMAND, { timeoutMs: 600, window: true });
  assert.equal(win.cut, "window");
  assert.match(win.stdout, /aaad line/);
  const capped = await runSshCommand(cfg, account, "127.0.0.1", "flood", { timeoutMs: 5000, maxBytes: 64 * 1024 });
  assert.equal(capped.cut, "bytes");
  assert.ok(capped.stdout.length >= 64 * 1024 && capped.stdout.length < 2 * 1024 * 1024);
  await assert.rejects(runSshCommand(cfg, account, "127.0.0.1", CAPTURE_COMMAND, { timeoutMs: 400 }), /timed out/);
});

test("a capture window that ends before the command starts is a failure, not an empty capture", async (t) => {
  const silent = createServer(() => {}); // accepts TCP, never speaks SSH
  await new Promise((r) => silent.listen(0, "127.0.0.1", r));
  t.after(() => silent.close());
  silent.unref();
  const cfg = { ...config, sshPort: silent.address().port, sshTimeout: 2000 };
  await assert.rejects(runSshCommand(cfg, { user: "f", pass: "pw" }, "127.0.0.1", CAPTURE_COMMAND, { timeoutMs: 300, window: true }), /timed out/);
});

test("local mode serves several appliances from NETSCALER_TARGETS, each with its own accounts", async () => {
  const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
  const { StdioClientTransport } = await import("@modelcontextprotocol/sdk/client/stdio.js");
  const env = {
    PATH: process.env.PATH, NETSCALER_TARGETS: "east,west",
    NS_EAST_NSIP: "127.0.0.1:1", NS_EAST_USER: "ro", NS_EAST_PASS: "x", NS_EAST_ADMIN_USER: "rw", NS_EAST_ADMIN_PASS: "y", NS_EAST_PROTOCOL: "http",
    NS_WEST_NSIP: "127.0.0.1:2", NS_WEST_USER: "ro", NS_WEST_PASS: "x", NS_WEST_PROTOCOL: "http",
  };
  const client = new Client({ name: "t", version: "0" });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: ["dist/index.js"], env, stderr: "ignore" }));
  try {
    const tools = (await client.listTools()).tools;
    const save = tools.find((t) => t.name === "save_config");
    assert.ok(save, "admin tool missing although east has an admin account");
    assert.deepEqual(save.inputSchema.properties.appliance.enum, ["east", "west"]);
    assert.ok(!tools.some((t) => t.name === "search_core"), "forensic tools offered with no forensics account");
    const r = await client.callTool({ name: "save_config", arguments: { appliance: "west" } });
    assert.ok(r.isError);
    assert.match(r.content[0].text, /not configured for west/);
  } finally {
    await client.close();
  }
});

test("run_nsconmsg refuses rotated archives, which nsconmsg would decompress on the appliance", async () => {
  const { Client } = await import("@modelcontextprotocol/sdk/client/index.js");
  const { StdioClientTransport } = await import("@modelcontextprotocol/sdk/client/stdio.js");
  const env = { PATH: process.env.PATH, NETSCALER_NSIP: "127.0.0.1:1", NETSCALER_USER: "ro", NETSCALER_PASS: "x", NETSCALER_PROTOCOL: "http", NETSCALER_SSH_USER: "s", NETSCALER_SSH_PASS: "s" };
  const client = new Client({ name: "t", version: "0" });
  await client.connect(new StdioClientTransport({ command: process.execPath, args: ["dist/index.js"], env, stderr: "ignore" }));
  try {
    for (const logfile of ["/var/nslog/newnslog.3.tar.gz", "/var/nslog/newnslog.1.tar"]) {
      const r = await client.callTool({ name: "run_nsconmsg", arguments: { mode: "stats", logfile } });
      assert.ok(r.isError, logfile);
      assert.match(r.content[0].text, /rotated archive/);
    }
    for (const logfile of ["/var/nslog/..", "/var/nslog/x/newnslog", "/var/nslog/ns.log"]) {
      const r = await client.callTool({ name: "run_nsconmsg", arguments: { mode: "stats", logfile } });
      assert.ok(r.isError, logfile);
      assert.match(r.content[0].text, /must be \/var\/nslog\/newnslog/);
    }
  } finally {
    await client.close();
  }
});
