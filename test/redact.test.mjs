// Redaction of CLI text and NITRO records, and the allowsAll superuser heuristic. Run: npm run build && npm test
import { test } from "node:test";
import assert from "node:assert/strict";
import { redact, redactText, redactForensic } from "../dist/redact.js";

test("redactText masks secrets and leaves everything else alone", () => {
  const cases = [
    ["add authentication ldapAction l -ldapBindDnPassword 9f3c -encrypted -encryptmethod ENCMTHD_3", "add authentication ldapAction l -ldapBindDnPassword [redacted] -encrypted -encryptmethod ENCMTHD_3"],
    ['add authentication radiusAction r -radKey "my secret" -encrypted', "add authentication radiusAction r -radKey [redacted] -encrypted"],
    ['set lb monitor m HTTP -password "ab\\"cd" -secure YES', "set lb monitor m HTTP -password [redacted] -secure YES"],
    ["add aaa user bob -password\nadd lb vserver v HTTP", "add aaa user bob -password\nadd lb vserver v HTTP"],
    ["SET AAA USER BOB -PASSWORD hunter2", "SET AAA USER BOB -PASSWORD [redacted]"],
    ["add system user nsroot  5a1b2c -encrypted -hashmethod SHA512", "add system user nsroot  [redacted] -encrypted -hashmethod SHA512"],
    ["-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----", "-----BEGIN PRIVATE KEY----- [redacted] -----END PRIVATE KEY-----"],
    ["import ssl certFile c https://bob:hunter2@example.com/c.pem", "import ssl certFile c https://bob:[redacted]@example.com/c.pem"],
    ["add ssl certKey c -cert c.pem -key c.key -passwordExpiry 5", "add ssl certKey c -cert c.pem -key c.key -passwordExpiry 5"],
    ["bind ssl vserver v -sslProfile p", "bind ssl vserver v -sslProfile p"],
    ["add ssl certKey c1 -cert c1.pfx -key c1.pfx -inform PFX 7a9b3c -encrypted -encryptmethod ENCMTHD_3 -kek -suffix 2023_07_22 -expiryMonitor DISABLED", "add ssl certKey c1 -cert c1.pfx -key c1.pfx -inform PFX [redacted] -encrypted -encryptmethod ENCMTHD_3 -kek -suffix 2023_07_22 -expiryMonitor DISABLED"],
    ['add ssl certKey c2 -cert c2.pfx -inform PFX "a b c" -encrypted', "add ssl certKey c2 -cert c2.pfx -inform PFX [redacted] -encrypted"],
    ["set ns rpcNode 10.0.0.2 -password 9a9a -encrypted -srcIP 10.0.0.1", "set ns rpcNode 10.0.0.2 -password [redacted] -encrypted -srcIP 10.0.0.1"],
    ["add snmp community s3cr3t ALL", "add snmp community [redacted] ALL"],
    ['ns CMD_EXECUTED User nsroot - Command "rm snmp community s3cr3t" - Status "Done"', 'ns CMD_EXECUTED User nsroot - Command "rm snmp community [redacted]" - Status "Done"'],
    ['ns CMD_EXECUTED Command "add system user bob 4f5e -encrypted"', 'ns CMD_EXECUTED Command "add system user bob [redacted] -encrypted"'],
    ["servicename:s1,password:hunter2", "servicename:s1,password:[redacted]"],
    ["show snmp community", "show snmp community"],
    ["password: hunter2", "password: [redacted]"],
    ['password:"top secret",user:a', "password:[redacted],user:a"],
    ['Command "set aaa user a -password topsecret"', 'Command "set aaa user a -password [redacted]"'],
    ["add system user bob hunter2 -externalAuth DISABLED", "add system user bob [redacted] -externalAuth DISABLED"],
    ["add system user bob -externalAuth DISABLED", "add system user bob -externalAuth DISABLED"],
    ["add ssl certKey c -cert c.pfx -inform PFX plainpass", "add ssl certKey c -cert c.pfx -inform PFX [redacted]"],
    ["add ssl certKey c -cert c.pfx -inform PFX -expiryMonitor ENABLED", "add ssl certKey c -cert c.pfx -inform PFX -expiryMonitor ENABLED"],
    ["add lb monitor m HTTP -encryptmethod x", "add lb monitor m HTTP -encryptmethod x"],
  ];
  for (const [input, want] of cases) assert.equal(redactText(input), want, input);
});

test("redact masks secret-named fields only", () => {
  const out = redact({ lbmonitor: [{ monitorname: "m", snmpcommunity: "public", password: "", secure: "YES", key: "/nsconfig/ssl/k.pem", otpsecret: "extensionAttribute1" }] });
  assert.deepEqual(out.lbmonitor[0], { monitorname: "m", snmpcommunity: "[redacted]", password: "", secure: "YES", key: "/nsconfig/ssl/k.pem", otpsecret: "extensionAttribute1" });
});

test("redactForensic masks form-encoded secrets that redactText leaves", () => {
  const line = "POST /nf/auth/doAuthentication.do login=bob&passwd=hunter2&passwd1=otp99 newPassword=s3cret client_secret=abc pwd=x";
  assert.equal(redactText(line), line);
  assert.equal(redactForensic(line), "POST /nf/auth/doAuthentication.do login=bob&passwd=[redacted]&passwd1=[redacted] newPassword=[redacted] client_secret=[redacted] pwd=[redacted]");
  assert.equal(redactForensic("passwdchange=ENABLED"), "passwdchange=ENABLED");
  const cases = [
    ["Authorization: Basic dXNlcjpodW50ZXIy\r\nHost: gw", "Authorization: Basic [redacted]\r\nHost: gw"],
    ["authorization:Bearer eyJhbGciOi.x.y next", "authorization:Bearer [redacted] next"],
    ["Cookie: NSC_AAAC=abc123def; NSC_TMAS=xyz; other=keep", "Cookie: NSC_AAAC=[redacted]; NSC_TMAS=[redacted]; other=keep"],
    ["Proxy-Authorization: NTLM TlRMTVNTUAAB end", "Proxy-Authorization: NTLM [redacted] end"],
    ["Set-Cookie: NSC_app_prod-1=ffffffff0909; path=/", "Set-Cookie: NSC_app_prod-1=[redacted]; path=/"],
    ['{"newPassword":"x1","adminPasswd":"x2"}', '{"newPassword":"[redacted]","adminPasswd":"[redacted]"}'],
    ['{"user":"bob","password":"hun\\"ter2","client_secret":"abc","passwd1":"9","note":"ok"}', '{"user":"bob","password":"[redacted]","client_secret":"[redacted]","passwd1":"[redacted]","note":"ok"}'],
    ['"passwdchange": "ENABLED"', '"passwdchange": "ENABLED"'],
  ];
  for (const [input, want] of cases) assert.equal(redactForensic(input), want, input);
});

test("redactText stays linear on a 200 KB word run and still masks URL credentials", () => {
  const started = Date.now();
  redactText("a".repeat(200_000));
  assert.ok(Date.now() - started < 1000, `took ${Date.now() - started} ms`);
  assert.equal(redactText("ldaps://admin:pw@10.0.0.1:636 x=sftp://u:p@h/f"), "ldaps://admin:[redacted]@10.0.0.1:636 x=sftp://u:[redacted]@h/f");
});

test("redact masks a secret-named field whatever its type", () => {
  assert.deepEqual(redact({ password: 12345678, psk: ["a"], communityname: { v: 1 }, passphrase: "", comment: "ok" }),
    { password: "[redacted]", psk: "[redacted]", communityname: "[redacted]", passphrase: "", comment: "ok" });
});

test("allowsAll catches match-everything ALLOW policies only", async () => {
  const { allowsAll } = await import("../dist/tools/security.js");
  for (const spec of [".*", "^.*$", "^(.*)$", ".+", " .* ", "^.*"]) assert.ok(allowsAll({ action: "ALLOW", cmdspec: spec }, "p"), spec);
  for (const spec of ["^show .*", "(^show)|(^stat)", "^shell nsconmsg.*"]) assert.ok(!allowsAll({ action: "ALLOW", cmdspec: spec }, "p"), spec);
  assert.ok(!allowsAll({ action: "DENY", cmdspec: ".*" }, "p"));
  assert.ok(allowsAll(undefined, "superuser"));
});
