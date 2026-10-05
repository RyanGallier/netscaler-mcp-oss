/**
 * Virtual server management tools - LB, CS, VPN (Gateway), and GSLB.
 */

import { type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { type NitroClient } from "../client.js";

const VserverType = z
  .enum(["lb", "cs", "vpn", "gslb"])
  .describe("Virtual server type: lb (load balancing), cs (content switching), vpn (gateway), gslb (global server load balancing)");

/** Map vserver type to NITRO resource name. */
function vserverResource(type: string): string {
  switch (type) {
    case "lb": return "lbvserver";
    case "cs": return "csvserver";
    case "vpn": return "vpnvserver";
    case "gslb": return "gslbvserver";
    default: return "lbvserver";
  }
}

export function registerVServerTools(server: McpServer, client: NitroClient) {
  server.tool(
    "list_virtual_servers",
    "List all virtual servers of a given type with their name, IP, port, state (UP/DOWN/OFS), service type, and method. Supports filtering by state.",
    {
      type: VserverType,
      state_filter: z
        .enum(["UP", "DOWN", "OFS", ""])
        .optional()
        .describe("Filter by current state. Omit to return all."),
    },
    async (args) => {
      const resource = vserverResource(args.type as string);
      // Attributes each type actually has, per the NITRO spec.
      const attrs: Record<string, string> = {
        lbvserver: "name,ipv46,port,curstate,servicetype,lbmethod,td,statechangetimesec",
        csvserver: "name,ipv46,port,curstate,servicetype,td,statechangetimesec",
        vpnvserver: "name,ipv46,port,curstate,servicetype",
        gslbvserver: "name,curstate,servicetype,lbmethod,statechangetimesec",
      };
      const response = await client.get("config", resource, { attrs: attrs[resource] });
      let vservers = ((response as Record<string, unknown>)[resource] ?? []) as Record<string, unknown>[];
      // Filter here: the spec does not enumerate curstate, so out of service may read "OFS" or "OUT OF SERVICE".
      if (args.state_filter) {
        const want = args.state_filter as string;
        vservers = vservers.filter((v) => {
          const st = String(v.curstate ?? "").toUpperCase();
          return want === "OFS" ? st === "OFS" || st.startsWith("OUT OF SERVICE") : st === want;
        });
      }

      return { content: [{ type: "text" as const, text: JSON.stringify(vservers, null, 2) }] };
    }
  );

  server.tool(
    "get_virtual_server",
    "Get detailed configuration of a specific virtual server by name, including its common bindings (services and service groups, responder and rewrite policies, CS policies, Gateway session and STA bindings, GSLB services and domains) and SSL certificates.",
    {
      type: VserverType,
      name: z.string().describe("The virtual server name."),
    },
    async (args) => {
      const resource = vserverResource(args.type as string);
      const name = args.name as string;

      const configResponse = await client.get("config", `${resource}/${encodeURIComponent(name)}`);
      const vserver = (configResponse as Record<string, unknown>)[resource];

      // Fetch bindings in parallel
      const bindingTypes = getBindingTypes(args.type as string);
      const bindings: Record<string, unknown> = {};

      const results = await Promise.allSettled(
        bindingTypes.map(async (bt) => {
          // SSL cert bindings live on sslvserver, not the vserver-type-specific resource
          const bindingResource = bt === "sslcertkey"
            ? `sslvserver_sslcertkey_binding`
            : `${resource}_${bt}_binding`;
          const resp = await client.get(
            "config",
            `${bindingResource}/${encodeURIComponent(name)}`
          );
          return { type: bt, data: (resp as Record<string, unknown>)[bindingResource] };
        })
      );

      for (const r of results) {
        if (r.status === "fulfilled" && r.value.data) {
          bindings[r.value.type] = r.value.data;
        }
      }

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify({ config: vserver, bindings }, null, 2),
          },
        ],
      };
    }
  );

  server.tool(
    "get_virtual_server_stats",
    "Get real-time statistics for a specific virtual server: active connections, requests/sec, health percentage, bytes in/out, and hit counts.",
    {
      type: VserverType,
      name: z.string().describe("The virtual server name."),
    },
    async (args) => {
      const resource = vserverResource(args.type as string);
      const name = args.name as string;

      const response = await client.get("stat", `${resource}/${encodeURIComponent(name)}`);
      const stats = (response as Record<string, unknown>)[resource];

      return { content: [{ type: "text" as const, text: JSON.stringify(stats, null, 2) }] };
    }
  );

  server.tool(
    "enable_disable_vserver",
    "Enable or disable a virtual server. Disabling takes a vserver out of service (OFS state) - no new connections will be accepted. Existing connections are handled per the down-state flush setting.",
    {
      type: VserverType,
      name: z.string().describe("The virtual server name."),
      action: z.enum(["enable", "disable"]).describe("Whether to enable or disable."),
    },
    async (args) => {
      const resource = vserverResource(args.type as string);
      const name = args.name as string;
      const action = args.action as string;

      await client.post(resource, { [resource]: { name } }, action);

      return {
        content: [
          {
            type: "text" as const,
            text: `Virtual server '${name}' ${action}d successfully. Run get_virtual_server to verify state.`,
          },
        ],
      };
    }
  );
}

/** Common binding resource suffixes to check per vserver type. */
function getBindingTypes(type: string): string[] {
  switch (type) {
    case "lb":
      return [
        "service",
        "servicegroup",
        "responderpolicy",
        "rewritepolicy",
        "sslcertkey",
      ];
    case "cs":
      return [
        "cspolicy",
        "lbvserver",
        "responderpolicy",
        "rewritepolicy",
        "sslcertkey",
      ];
    case "vpn":
      return [
        "staserver",
        "vpnsessionpolicy",
        "aaapreauthenticationpolicy",
        "sslcertkey",
      ];
    case "gslb":
      return ["gslbservice", "domain"];
    default:
      return [];
  }
}
