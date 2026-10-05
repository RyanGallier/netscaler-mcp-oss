/**
 * Network configuration and interface tools.
 */

import { isIP } from "node:net";
import { type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { type NitroClient } from "../client.js";

// ASCII hostname: labels of letters, digits and inner hyphens, 253 chars max. Rejects spaces, options and control characters.
const FQDN = /^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*\.?$/;
const ip = z.string().refine((v) => isIP(v) === 4, "must be an IPv4 address (IPv6 is not supported)");

export function registerNetworkTools(server: McpServer, client: NitroClient) {
  server.tool(
    "list_ip_addresses",
    "List all IP addresses configured on the NetScaler: NSIPs, VIPs, SNIPs, and MIPs with their type, VLAN, state, and traffic domain.",
    {},
    async () => {
      const response = await client.get("config", "nsip");
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify((response as Record<string, unknown>).nsip, null, 2),
          },
        ],
      };
    }
  );

  server.tool(
    "list_vlans",
    "List all VLANs configured on the NetScaler with their ID, bound interfaces, and bound IPs.",
    {},
    async () => {
      const response = await client.get("config", "vlan");
      const vlans = (response as Record<string, unknown>).vlan as
        | Record<string, unknown>[]
        | undefined;

      if (!vlans || vlans.length === 0) {
        return { content: [{ type: "text" as const, text: "No VLANs configured." }] };
      }

      // Fetch bindings for each VLAN
      const enriched = await Promise.all(
        vlans.map(async (vlan) => {
          const id = String(vlan.id ?? "");
          if (!id) return { ...vlan, bound_ips: [], bound_interfaces: [] };
          const [ipBindings, ifBindings] = await Promise.allSettled([
            client.get("config", `vlan_nsip_binding/${id}`),
            client.get("config", `vlan_interface_binding/${id}`),
          ]);

          return {
            ...vlan,
            bound_ips:
              ipBindings.status === "fulfilled"
                ? (ipBindings.value as Record<string, unknown>).vlan_nsip_binding
                : [],
            bound_interfaces:
              ifBindings.status === "fulfilled"
                ? (ifBindings.value as Record<string, unknown>).vlan_interface_binding
                : [],
          };
        })
      );

      return { content: [{ type: "text" as const, text: JSON.stringify(enriched, null, 2) }] };
    }
  );

  server.tool(
    "list_routes",
    "List all static routes configured on the NetScaler.",
    {},
    async () => {
      const response = await client.get("config", "route");
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify((response as Record<string, unknown>).route, null, 2),
          },
        ],
      };
    }
  );

  server.tool(
    "get_interface_stats",
    "Get interface statistics: throughput, errors, link state, speed, and duplex for all physical interfaces or a specific interface.",
    {
      interface_id: z
        .string()
        .optional()
        .describe("Interface ID (e.g., '1/1', '10/1'). Omit to list all interfaces."),
    },
    async (args) => {
      const id = args.interface_id as string | undefined;
      const resource = id ? `Interface/${encodeURIComponent(id)}` : "Interface";

      const response = await client.get("stat", resource);
      // NITRO returns interface stats under "Interface" key (capital I)
      const stats = response.Interface ?? response.interface;
      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(stats, null, 2),
          },
        ],
      };
    }
  );

  server.tool(
    "test_reachability",
    "Ping or traceroute FROM the NetScaler, optionally from a chosen source IP (e.g. a SNIP) and traffic domain. Answers 'can the appliance reach this backend, LDAP server or STA'. Fixed small probes: ping sends 3 packets and gives up after 5 s; traceroute stops at 6 hops (max), 1 probe per hop, 2 s wait (the NITRO minimum). Needs ping/traceroute allowed by the NITRO user's command policy (the built-in read-only policy does not). Output shape is unverified on builds other than the one tested.",
    {
      mode: z.enum(["ping", "traceroute"]).describe("ping for reachability and latency, traceroute for the path."),
      host: z.string().refine((v) => isIP(v) === 4 || (isIP(v) === 0 && FQDN.test(v)), "must be an IPv4 address or an ASCII hostname (IPv6 is not supported)").describe("Target IPv4 address or hostname."),
      source_ip: ip.optional().describe("Source IP on the appliance to send from, e.g. a SNIP. Omit to let routing choose."),
      traffic_domain: z.number().int().min(0).max(4094).optional().describe("Traffic domain ID. Omit for the default domain."),
      max_hops: z.number().int().min(1).max(6).default(6).describe("Traceroute only: maximum hops (1-6), kept inside the request timeout."),
    },
    async (args) => {
      const host = args.host as string;
      const td = args.traffic_domain as number | undefined;
      const src = args.source_ip as string | undefined;
      const resource = args.mode as string;
      const body = resource === "ping"
        ? { hostName: host, c: 3, t: 5, ...(src && { S: src }), ...(td !== undefined && { T: td }) }
        : { host, m: args.max_hops, w: 2, q: 1, ...(src && { s: src }), ...(td !== undefined && { T: td }) };
      let resp: Record<string, unknown>;
      try {
        resp = await client.post(resource, { [resource]: body });
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        const note = /^Outcome unknown/.test(msg) ? "Result indeterminate: the appliance did not answer in time. This is not proof the target is unreachable." : msg;
        return { content: [{ type: "text" as const, text: note }], isError: true };
      }
      const rows = resp[resource] as Record<string, unknown>[] | Record<string, unknown> | undefined;
      const output = (Array.isArray(rows) ? rows[0] : rows)?.response;
      const text = output
        ? String(output)
        : `The appliance accepted the ${resource} but returned no output text. Raw reply: ${JSON.stringify(resp)}`;
      return { content: [{ type: "text" as const, text }] };
    }
  );
}
