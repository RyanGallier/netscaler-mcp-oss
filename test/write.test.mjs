// nitro_write request planning and config paging. Run: npm run build && npm test

import { test } from "node:test";
import assert from "node:assert/strict";
import { planWrite } from "../dist/tools/generic.js";
import { pageText } from "../dist/tools/system.js";

const ops = ["add", "set", "unset", "rm", "bind", "unbind", "action"];

test("each operation maps to the NITRO method, path, query and body", () => {
  const cases = [
    [{ operation: "add", resource: "lbvserver", payload: { name: "lb1", servicetype: "HTTP" } }, { method: "POST", path: "lbvserver", body: { lbvserver: { name: "lb1", servicetype: "HTTP" } } }],
    [{ operation: "set", resource: "lbvserver", name: "lb 1", payload: { lbmethod: "ROUNDROBIN" } }, { method: "PUT", path: "lbvserver/lb%201", body: { lbvserver: { lbmethod: "ROUNDROBIN" } } }],
    [{ operation: "set", resource: "nsparam", payload: { timezone: "GMT" } }, { method: "PUT", path: "nsparam", body: { nsparam: { timezone: "GMT" } } }],
    [{ operation: "unset", resource: "lbvserver", payload: { name: "lb1", comment: true } }, { method: "POST", path: "lbvserver", query: "action=unset", body: { lbvserver: { name: "lb1", comment: true } } }],
    [{ operation: "action", resource: "sslcertkey", action: "link", payload: { certkey: "www", linkcertkeyname: "ca" } }, { method: "POST", path: "sslcertkey", query: "action=link", body: { sslcertkey: { certkey: "www", linkcertkeyname: "ca" } } }],
    [{ operation: "rm", resource: "lbvserver", name: "lb1" }, { method: "DELETE", path: "lbvserver/lb1", query: undefined }],
    [{ operation: "bind", resource: "lbvserver_service_binding", name: "lb1", payload: { name: "lb1", servicename: "s1" } }, { method: "PUT", path: "lbvserver_service_binding/lb1", body: { lbvserver_service_binding: { name: "lb1", servicename: "s1" } } }],
    [{ operation: "unbind", resource: "lbvserver_service_binding", name: "lb1", args: "servicename:s1" }, { method: "DELETE", path: "lbvserver_service_binding/lb1", query: "args=servicename:s1" }],
    [{ operation: "unbind", resource: "cmpglobal_cmppolicy_binding", args: "policyname:p1" }, { method: "DELETE", path: "cmpglobal_cmppolicy_binding", query: "args=policyname:p1" }],
  ];
  for (const [input, want] of cases) assert.deepEqual(JSON.parse(JSON.stringify(planWrite(input))), JSON.parse(JSON.stringify(want)), JSON.stringify(input));
});

test("refused resources are refused for every operation", () => {
  for (const resource of ["reboot", "shutdown", "install", "systembackup", "nsconfig", "routerdynamicrouting", "systemfile", "nsencryptionkey", "nsencryptionparams", "nshmackey", "sslhsmkey", "cluster", "clusterinstance", "clusternode", "systemsession", "aaasession", "vpnicaconnection", "vpnpcoipconnection", "rdpconnections"]) {
    for (const operation of ops) {
      const r = planWrite({ operation, resource, name: "x", payload: { a: 1 }, args: "a:b", action: "kill" });
      assert.ok("refused" in r && r.refused.startsWith(resource), `${operation} ${resource}`);
    }
  }
});

test("the argument matrix refuses wrong shapes and hostile input", () => {
  const bad = [
    { operation: "unset", resource: "lbvserver", name: "lb1", payload: { name: "lb1", comment: true } },
    { operation: "action", resource: "lbvserver", name: "lb1", action: "enable", payload: { name: "lb1" } },
    { operation: "add", resource: "lbvserver", name: "lb1", payload: { name: "lb1" } },
    { operation: "rm", resource: "lbvserver" },
    { operation: "set", resource: "lbvserver", payload: { lbmethod: "ROUNDROBIN" } },
    { operation: "set", resource: "inatparam", payload: { nat46v6prefix: "x" } },
    { operation: "unbind", resource: "lbvserver_service_binding", name: "lb1" },
    { operation: "unbind", resource: "cmpglobal_cmppolicy_binding" },
    { operation: "set", resource: "lbvserver", name: "", payload: { a: 1 } },
    ...["a/b", "a?b", "a#b", "a%2fb", "..", ".", "a\nb"].map((name) => ({ operation: "rm", resource: "lbvserver", name })),
    ...["servicename:s1%2Cport:80", "servicename:a+b", "servicename:a\rb", "password:x"].map((args) => ({ operation: "unbind", resource: "lbvserver_service_binding", name: "lb1", args })),
    { operation: "action", resource: "lbvserver", action: "Enable", payload: { name: "lb1" } },
    { operation: "action", resource: "lbvserver", payload: { name: "lb1" } },
    { operation: "add", resource: "lbvserver", action: "enable", payload: { name: "lb1" } },
    { operation: "action", resource: "lbvserver", action: "kill", payload: { all: true } },
    { operation: "rm", resource: "lbvserver", name: "lb1", payload: { a: 1 } },
    { operation: "add", resource: "lbvserver", payload: {} },
  ];
  for (const input of bad) assert.ok("refused" in planWrite(input), JSON.stringify(input));
});

test("config pages concatenate exactly, end on line breaks and always advance", () => {
  const text = "line one\n" + "x".repeat(2500) + "\nsmile \u{1F600} end\n";
  const read = (max) => {
    let out = "", offset = 0, sha;
    for (let i = 0; i < 100; i++) {
      const page = pageText(text, offset, max, sha);
      const nl = page.indexOf("\n");
      const meta = JSON.parse(page.slice(0, nl));
      out += page.slice(nl + 1);
      sha = meta.sha256;
      if (meta.next_offset === undefined) return out;
      assert.ok(meta.next_offset > offset);
      offset = meta.next_offset;
    }
    throw new Error("did not finish");
  };
  assert.equal(read(1000), text);
  const cut = "a".repeat(999) + "\u{1F600}" + "b".repeat(10);
  const first = pageText(cut, 0, 1000);
  assert.equal(JSON.parse(first.slice(0, first.indexOf("\n"))).next_offset, 1001);
  assert.equal(pageText("", 0, 1000), JSON.stringify({ offset: 0, total_chars: 0, sha256: JSON.parse(pageText("", 0, 1000).split("\n")[0]).sha256 }) + "\n");
  const sha = JSON.parse(first.split("\n")[0]).sha256;
  assert.throws(() => pageText(cut, 1000, 1000, sha), /not a page boundary/);
  assert.throws(() => pageText(cut, 5000, 1000, sha), /not a page boundary/);
  assert.throws(() => pageText(cut, 10, 1000), /expected_sha256 is required/);
  assert.throws(() => pageText(cut + "changed", 10, 1000, sha), /changed since the first page/);
});
