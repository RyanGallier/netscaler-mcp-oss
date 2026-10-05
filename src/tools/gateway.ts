/**
 * Citrix Gateway (vpn vserver) tools: who is connected, and which session policies apply.
 */

import { type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { type NitroClient } from "../client.js";

type Row = Record<string, unknown>;

/** GET a config resource that may legitimately be empty; NITRO omits the key when there are no rows. */
async function rows(client: NitroClient, resource: string, key = resource): Promise<Row[]> {
  const res = await client.get("config", resource);
  return (res[key] as Row[] | undefined) ?? [];
}

// Session action fields that answer the usual Gateway questions (timeouts, ICA proxy, StoreFront, split tunnel).
const ACTION_FIELDS = [
  "sesstimeout", "forcedtimeout", "clientidletimeout", "icaproxy", "wihome", "storefronturl",
  "citrixreceiverhome", "splittunnel", "splitdns", "locallanaccess", "clientlessvpnmode",
  "defaultauthorizationaction", "sso", "ssocredential", "homepage", "transparentinterception",
  "clientchoices", "kcdaccount", "rdpclientprofilename",
];

export function registerGatewayTools(server: McpServer, client: NitroClient) {
  server.tool(
    "get_gateway_sessions",
    "List who is connected through Citrix Gateway: AAA sessions (one per logged-in user) and ICA connections (one per launched app or desktop, so a user can have several). Sessions carry no vserver name, so filter by user or by domain (the user's domain usually maps to the tenant, e.g. CONTOSO; for AAA sessions, which have no domain field, it matches the username). Use get_virtual_server_stats for per-vserver counts.",
    {
      user: z.string().optional().describe("Case-insensitive substring match on username."),
      domain: z.string().optional().describe("Case-insensitive substring match on the user's domain."),
    },
    async (args) => {
      const [aaa, ica, dtls] = await Promise.all([
        rows(client, "aaasession"),
        rows(client, "vpnicaconnection"),
        rows(client, "vpnicadtlsconnection"),
      ]);
      const u = (args.user as string | undefined)?.toLowerCase();
      const d = (args.domain as string | undefined)?.toLowerCase();
      const byUser = (r: Row) => !u || String(r.username ?? "").toLowerCase().includes(u);
      // AAA sessions have no domain field, so for them the domain filter matches the username (UPN suffix or DOMAIN\\user).
      const keep = (r: Row) => byUser(r) && (!d || String(r.domain ?? r.username ?? "").toLowerCase().includes(d));

      const icaAll: Row[] = [...ica.map((r) => ({ ...r, transport: "TCP" })), ...dtls.map((r) => ({ ...r, transport: "DTLS" }))].filter(keep);
      const perUser: Record<string, number> = {};
      for (const r of icaAll) {
        const key = `${r.domain ? `${r.domain}\\` : ""}${r.username ?? "?"}`;
        perUser[key] = (perUser[key] ?? 0) + 1;
      }
      const result = {
        aaa_sessions: aaa.filter(keep).map((r) => ({ username: r.username, groupname: r.groupname, client_ip: r.publicip ?? r.ipaddress, intranet_ip: r.intranetip ?? r.iip })),
        ica_connections: icaAll.map((r) => ({ username: r.username, domain: r.domain, transport: r.transport, client: `${r.srcip}:${r.srcport}`, vda: `${r.destip}:${r.destport}` })),
        ica_per_user: perUser,
      };
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "get_gateway_session_policies",
    "Show the session policies bound to one Citrix Gateway vserver, in priority order, with each policy's rule, hit count and the key settings of its session action (timeouts, ICA proxy, StoreFront / WI home, split tunnel, SSO, clientless mode). Answers 'why does this Gateway time out / not launch / go to the wrong StoreFront'.",
    {
      vserver: z.string().describe("The Gateway (vpn vserver) name, e.g. CONTOSO_AG."),
    },
    async (args) => {
      const vs = encodeURIComponent(args.vserver as string);
      const bindings = await rows(client, `vpnvserver_vpnsessionpolicy_binding/${vs}`, "vpnvserver_vpnsessionpolicy_binding");
      if (bindings.length === 0) {
        return { content: [{ type: "text" as const, text: `No session policies bound to ${args.vserver}.` }] };
      }
      const out = await Promise.all(
        bindings
          .sort((a, b) => Number(a.priority ?? 0) - Number(b.priority ?? 0))
          .map(async (b) => {
            const name = String(b.policy);
            const entry: Row = { priority: b.priority, policy: name, bindpoint: b.bindpoint };
            try {
              const pol = (await rows(client, `vpnsessionpolicy/${encodeURIComponent(name)}`, "vpnsessionpolicy"))[0] ?? {};
              entry.rule = pol.rule;
              entry.hits = pol.hits;
              entry.action = pol.action;
              const act = (await rows(client, `vpnsessionaction/${encodeURIComponent(String(pol.action))}`, "vpnsessionaction"))[0] ?? {};
              entry.settings = Object.fromEntries(ACTION_FIELDS.filter((f) => act[f] !== undefined).map((f) => [f, act[f]]));
            } catch (err) {
              entry.error = err instanceof Error ? err.message : String(err);
            }
            return entry;
          })
      );
      return { content: [{ type: "text" as const, text: JSON.stringify({ vserver: args.vserver, session_policies: out }, null, 2) }] };
    }
  );
}
