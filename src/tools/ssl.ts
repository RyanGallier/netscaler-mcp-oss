/**
 * SSL certificate and profile management tools.
 */

import { type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { asRows, type NitroClient } from "../client.js";

type Row = Record<string, unknown>;
const WEAK_CIPHER = /RC4|3DES|DES-CBC|NULL|EXP-|EXPORT|MD5/i;
const OLD_PROTOCOLS = ["ssl2", "ssl3", "tls1", "tls11"] as const;
const MAX_VSERVERS = 200;
const MAX_GETS = 600;
const DEADLINE_MS = 40_000; // a read started near the deadline can still take ~20 s, so this lands under a 60 s client timeout
const ASSESSMENT_LIMITS = [
  "Built-in cipher groups (e.g. DEFAULT) are listed by name, not expanded, so weak ciphers inside them are not flagged.",
  "Which settings apply (vserver or SSL profile) is inferred from sslparameter defaultprofile and the bound profile, and is unverified on live appliances.",
  "Missing-intermediate is a heuristic: a server cert with no linked CA cert whose issuer differs from its subject.",
];

/** Findings for one SSL vserver from its effective settings, bound cipher names and cert bindings. */
function sslFindings(settings: Row, cipherNames: string[], bindings: Row[], certs: Map<string, Row>): string[] {
  const findings: string[] = [];
  const enabled = (k: string) => settings[k] === "ENABLED";
  const old = OLD_PROTOCOLS.filter(enabled);
  if (old.length) findings.push(`old protocols enabled: ${old.join(", ")}`);
  if (!enabled("tls12") && !enabled("tls13")) findings.push("neither TLS 1.2 nor TLS 1.3 enabled");
  const weak = cipherNames.filter((c) => WEAK_CIPHER.test(c));
  if (weak.length) findings.push(`weak ciphers bound: ${weak.join(", ")}`);
  for (const b of bindings) {
    const c = certs.get(String(b.certkeyname));
    if (!c) continue;
    const days = Number(c.daystoexpiration);
    if (c.status === "Expired" || (Number.isFinite(days) && days <= 0)) findings.push(`cert ${c.certkey} has EXPIRED`);
    else if (Number.isFinite(days) && days < 30) findings.push(`cert ${c.certkey} expires in ${days} days`);
    if (!b.ca && !c.linkcertkeyname && c.issuer !== c.subject) findings.push(`cert ${c.certkey} has no linked intermediate (heuristic)`);
  }
  return findings;
}

export function registerSSLTools(server: McpServer, client: NitroClient) {
  server.tool(
    "list_ssl_certificates",
    "List all installed SSL certificates with name, subject, issuer, expiry date, days until expiration, and status. Sorted by days-to-expiration ascending so expiring certs appear first.",
    {
      expiring_within_days: z
        .number()
        .optional()
        .describe("Only show certs expiring within this many days. Omit to show all."),
    },
    async (args) => {
      const response = await client.get("config", "sslcertkey", {
        attrs: "certkey,subject,issuer,clientcertnotbefore,clientcertnotafter,daystoexpiration,status,serial",
      });

      let certs = (response as Record<string, unknown>).sslcertkey as
        | Record<string, unknown>[]
        | undefined;

      if (!certs) {
        return { content: [{ type: "text" as const, text: "No SSL certificates found." }] };
      }

      // Filter by expiry if requested
      if (args.expiring_within_days) {
        const threshold = args.expiring_within_days as number;
        certs = certs.filter((c) => {
          const days = parseInt(String(c.daystoexpiration ?? "99999"), 10);
          return days <= threshold;
        });
      }

      // Sort by days to expiration ascending
      certs.sort((a, b) => {
        const dA = parseInt(String(a.daystoexpiration ?? "99999"), 10);
        const dB = parseInt(String(b.daystoexpiration ?? "99999"), 10);
        return dA - dB;
      });

      const summary = `${certs.length} certificate(s) found.`;

      return {
        content: [
          { type: "text" as const, text: `${summary}\n\n${JSON.stringify(certs, null, 2)}` },
        ],
      };
    }
  );

  server.tool(
    "get_ssl_certificate",
    "Get detailed information about a specific SSL certificate including its full subject, issuer chain, validity dates, and all virtual servers it is bound to.",
    {
      certkey_name: z.string().describe("The cert-key pair name as shown in list_ssl_certificates."),
    },
    async (args) => {
      const name = args.certkey_name as string;

      const [certConfig, bindings] = await Promise.allSettled([
        client.get("config", `sslcertkey/${encodeURIComponent(name)}`),
        client.get("config", `sslcertkey_sslvserver_binding/${encodeURIComponent(name)}`),
      ]);

      const result: Record<string, unknown> = {};

      if (certConfig.status === "fulfilled") {
        result.certificate = (certConfig.value as Record<string, unknown>).sslcertkey;
      }
      if (bindings.status === "fulfilled") {
        result.bound_to_vservers =
          (bindings.value as Record<string, unknown>).sslcertkey_sslvserver_binding;
      } else {
        result.bound_to_vservers = [];
      }

      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "list_ssl_profiles",
    "List all SSL profiles with their protocol versions and cipher settings. Whether enhanced (default) profiles are in use is defaultprofile in nitro_get config sslparameter; the 13.1 default is DISABLED.",
    {},
    async () => {
      const response = await client.get("config", "sslprofile", {
        attrs: "name,sslprofiletype,ssl3,tls1,tls11,tls12,tls13,denysslreneg,ersa",
      });

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify((response as Record<string, unknown>).sslprofile, null, 2),
          },
        ],
      };
    }
  );

  server.tool(
    "get_ssl_vserver_config",
    "Get the SSL configuration for a specific virtual server: bound certificate, SSL profile, protocol versions, cipher suites, and OCSP/CRL settings.",
    {
      vserver_name: z.string().describe("The virtual server name."),
    },
    async (args) => {
      const name = args.vserver_name as string;

      const [sslConfig, certBinding, cipherBinding] = await Promise.allSettled([
        client.get("config", `sslvserver/${encodeURIComponent(name)}`),
        client.get("config", `sslvserver_sslcertkey_binding/${encodeURIComponent(name)}`),
        client.get("config", `sslvserver_sslciphersuite_binding/${encodeURIComponent(name)}`),
      ]);

      const result: Record<string, unknown> = {};

      if (sslConfig.status === "fulfilled") {
        result.ssl_settings = (sslConfig.value as Record<string, unknown>).sslvserver;
      }
      if (certBinding.status === "fulfilled") {
        result.certificates =
          (certBinding.value as Record<string, unknown>).sslvserver_sslcertkey_binding;
      }
      if (cipherBinding.status === "fulfilled") {
        result.ciphers =
          (cipherBinding.value as Record<string, unknown>).sslvserver_sslciphersuite_binding;
      }

      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "update_ssl_certificate",
    "Update (replace) an existing SSL certificate and key. The cert and key files must already be uploaded to /nsconfig/ssl/ on the NetScaler. This updates the cert-key pair in place - all existing bindings are preserved.",
    {
      certkey_name: z
        .string()
        .describe("The existing cert-key pair name to update."),
      cert_file: z
        .string()
        .describe("Path to the certificate file on the NetScaler (e.g., /nsconfig/ssl/mycert.pem)."),
      key_file: z
        .string()
        .describe("Path to the private key file on the NetScaler (e.g., /nsconfig/ssl/mycert.key)."),
      no_domain_check: z
        .boolean()
        .optional()
        .default(false)
        .describe("Skip domain name validation (default: false)."),
    },
    async (args) => {
      const body: Record<string, unknown> = {
        certkey: args.certkey_name,
        cert: args.cert_file,
        key: args.key_file,
      };

      if (args.no_domain_check) {
        body.nodomaincheck = true;
      }

      await client.post("sslcertkey", { sslcertkey: body }, "update");

      return {
        content: [
          {
            type: "text" as const,
            text: `Certificate '${args.certkey_name}' updated successfully. Existing bindings are preserved. Run save_config to persist.`,
          },
        ],
      };
    }
  );

  server.tool(
    "audit_ssl_posture",
    "Sweep every SSL virtual server for weak settings: SSLv2/v3 or TLS 1.0/1.1 enabled, no TLS 1.2/1.3, weak ciphers (RC4, DES/3DES, NULL, export, MD5) bound by name, certs expiring within 30 days, and server certs with no linked intermediate. Reports evidence per vserver, never a clean bill: read assessment_limits. Stops at 200 vservers, 600 reads or about 40 s and says so.",
    {},
    async () => {
      const started = performance.now();
      let gets = 0;
      let stopped: string | undefined;
      const read = async (resource: string, attrs?: string): Promise<Row[]> => {
        if (stopped) return [];
        if (gets >= MAX_GETS) { stopped = `read budget of ${MAX_GETS} GETs reached`; return []; }
        if (performance.now() - started > DEADLINE_MS) { stopped = `${DEADLINE_MS / 1000} s time budget reached`; return []; }
        gets++;
        try {
          return asRows((await client.get("config", resource, attrs ? { attrs } : undefined))[resource.split("/")[0]]) as Row[];
        } catch (err) {
          stopped = `${resource}: ${err instanceof Error ? err.message : String(err)}`;
          return [];
        }
      };

      const defaultProfiles = (await read("sslparameter", "defaultprofile"))[0]?.defaultprofile === "ENABLED";
      const allVservers = await read("sslvserver");
      const vservers = allVservers.slice(0, MAX_VSERVERS);
      const capped = allVservers.length > MAX_VSERVERS ? `only the first ${MAX_VSERVERS} of ${allVservers.length} SSL vservers were checked` : undefined;
      const certs = new Map((await read("sslcertkey", "certkey,daystoexpiration,status,linkcertkeyname,issuer,subject,certificatetype")).map((c) => [String(c.certkey), c]));
      // 13.1 reports cipher groups under *_sslciphersuite_binding; individual ciphers may appear under *_sslcipher_binding.
      const cipherRows = (agg: Row | undefined, owner: string) =>
        [...((agg?.[`${owner}_sslciphersuite_binding`] as Row[]) ?? []), ...((agg?.[`${owner}_sslcipher_binding`] as Row[]) ?? [])];
      const profiles = new Map<string, { settings?: Row; ciphers: Row[] }>();

      const report = [];
      for (const vs of vservers) {
        if (stopped) break;
        const name = String(vs.vservername);
        const profileName = (vs.sslprofile as string | undefined) || (defaultProfiles ? "ns_default_ssl_profile_frontend" : undefined);
        let settings: Row = vs;
        const agg = (await read(`sslvserver_binding/${encodeURIComponent(name)}`))[0];
        let ciphers: Row[];
        if (profileName) {
          if (!profiles.has(profileName)) {
            profiles.set(profileName, {
              settings: (await read(`sslprofile/${encodeURIComponent(profileName)}`))[0],
              ciphers: cipherRows((await read(`sslprofile_binding/${encodeURIComponent(profileName)}`))[0], "sslprofile"),
            });
          }
          const p = profiles.get(profileName)!;
          settings = p.settings ?? vs;
          ciphers = p.ciphers;
        } else {
          ciphers = cipherRows(agg, "sslvserver");
        }
        const bindings = (agg?.sslvserver_sslcertkey_binding as Row[]) ?? [];

        if (stopped) break; // a half-read vserver would look clean
        const cipherNames = ciphers.map((c) => String(c.cipheraliasname ?? c.ciphername ?? ""));
        report.push({
          vserver: name,
          settings_from: profileName && profiles.get(profileName)?.settings ? `profile ${profileName}` : "vserver",
          protocols: Object.fromEntries(["ssl2", "ssl3", "tls1", "tls11", "tls12", "tls13"].map((k) => [k, settings[k]])),
          ciphers: cipherNames,
          certs: bindings.map((b) => b.certkeyname),
          findings: sslFindings(settings, cipherNames, bindings, certs),
        });
      }

      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            reads_complete: !stopped && !capped,
            ...((stopped || capped) && { stopped_because: [stopped, capped].filter(Boolean).join("; ") }),
            vservers_checked: report.length,
            vservers_with_findings: report.filter((r) => r.findings.length).length,
            default_profiles: defaultProfiles ? "ENABLED" : "DISABLED",
            assessment_limits: ASSESSMENT_LIMITS,
            vservers: report,
          }, null, 2),
        }],
      };
    }
  );
}
