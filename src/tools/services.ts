/**
 * Service and service group management tools.
 */

import { type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { type NitroClient } from "../client.js";

export function registerServiceTools(server: McpServer, client: NitroClient) {
  server.tool(
    "list_services",
    "List all services with name, IP, port, state (UP/DOWN/OUT OF SERVICE), service type, and whether health monitoring is on (use get_service for the bound monitors). Optionally filter by state to quickly find unhealthy backends.",
    {
      state_filter: z
        .enum(["UP", "DOWN", "OUT OF SERVICE", ""])
        .optional()
        .describe("Filter by service state. Omit to return all."),
    },
    async (args) => {
      const params: Record<string, string> = {
        attrs: "name,ipaddress,port,svrstate,servicetype,healthmonitor,statechangetimesec,tickssincelaststatechange",
      };
      if (args.state_filter) {
        params.filter = `svrstate:${args.state_filter}`;
      }

      const response = await client.get("config", "service", params);
      return {
        content: [
          { type: "text" as const, text: JSON.stringify((response as Record<string, unknown>).service, null, 2) },
        ],
      };
    }
  );

  server.tool(
    "get_service",
    "Get detailed configuration and current stats for a specific service by name, including bound monitors and their status.",
    {
      name: z.string().describe("The service name."),
    },
    async (args) => {
      const name = args.name as string;
      const [config, stats, monBindings] = await Promise.allSettled([
        client.get("config", `service/${encodeURIComponent(name)}`),
        client.get("stat", `service/${encodeURIComponent(name)}`),
        client.get("config", `service_lbmonitor_binding/${encodeURIComponent(name)}`),
      ]);

      const result: Record<string, unknown> = {};
      if (config.status === "fulfilled") {
        result.config = (config.value as Record<string, unknown>).service;
      }
      if (stats.status === "fulfilled") {
        result.stats = (stats.value as Record<string, unknown>).service;
      }
      if (monBindings.status === "fulfilled") {
        result.monitors = (monBindings.value as Record<string, unknown>).service_lbmonitor_binding;
      }

      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "list_service_groups",
    "List all service groups with member count, state, and service type.",
    {},
    async () => {
      const response = await client.get("config", "servicegroup", {
        attrs: "servicegroupname,servicetype,state,numofconnections,td",
      });

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify((response as Record<string, unknown>).servicegroup, null, 2),
          },
        ],
      };
    }
  );

  server.tool(
    "get_service_group_members",
    "List all members of a service group with their individual IP, port, state, and weight. Useful for checking backend health during maintenance.",
    {
      name: z.string().describe("The service group name."),
    },
    async (args) => {
      const name = args.name as string;
      const response = await client.get(
        "config",
        `servicegroup_servicegroupmember_binding/${encodeURIComponent(name)}`
      );

      return {
        content: [
          {
            type: "text" as const,
            text: JSON.stringify(
              (response as Record<string, unknown>).servicegroup_servicegroupmember_binding,
              null,
              2
            ),
          },
        ],
      };
    }
  );

  server.tool(
    "enable_disable_service",
    "Enable or disable a service. Disabling gracefully drains connections (per the service's down-state flush and graceful shutdown settings). Used during maintenance windows.",
    {
      name: z.string().describe("The service name."),
      action: z.enum(["enable", "disable"]).describe("Whether to enable or disable."),
      graceful: z
        .enum(["YES", "NO"])
        .optional()
        .default("YES")
        .describe("Graceful shutdown - wait for existing connections to close (default: YES)."),
      delay: z
        .number()
        .optional()
        .default(0)
        .describe("Delay in seconds before disabling (default: 0)."),
    },
    async (args) => {
      const name = args.name as string;
      const action = args.action as string;
      const body: Record<string, unknown> = { name };

      if (action === "disable") {
        body.graceful = args.graceful ?? "YES";
        if (args.delay) {
          body.delay = args.delay;
        }
      }

      await client.post("service", { service: body }, action);

      return {
        content: [
          {
            type: "text" as const,
            text: `Service '${name}' ${action}d successfully${action === "disable" ? ` (graceful: ${args.graceful ?? "YES"})` : ""}. Verify with get_service.`,
          },
        ],
      };
    }
  );

  server.tool(
    "enable_disable_server",
    "Enable or disable a backend server object. This affects ALL services bound to this server across all virtual servers. Use for full server maintenance.",
    {
      name: z.string().describe("The server name (not IP - use the named server object)."),
      action: z.enum(["enable", "disable"]).describe("Whether to enable or disable."),
    },
    async (args) => {
      const name = args.name as string;
      const action = args.action as string;

      await client.post("server", { server: { name } }, action);

      return {
        content: [
          {
            type: "text" as const,
            text: `Server '${name}' ${action}d successfully. All services bound to this server are affected.`,
          },
        ],
      };
    }
  );

  server.tool(
    "drain_service_group_member",
    "Enable or disable ONE member of a service group (server name + port), for example to drain one web server for patching without touching the rest of the pool or its other vservers. Disable is graceful by default and can wait up to an hour. Never disables a whole group.",
    {
      servicegroup: z.string().min(1).describe("The service group name."),
      server: z.string().min(1).describe("The member's server name as bound to the group (see get_service_group_members)."),
      port: z.number().int().min(1).max(65535).describe("The member's port."),
      action: z.enum(["enable", "disable"]).describe("Whether to enable or disable the member."),
      graceful: z.enum(["YES", "NO"]).default("YES").describe("Disable only: wait for existing connections to close (default YES)."),
      delay: z.number().int().min(0).max(3600).optional().describe("Disable only: seconds to wait before the member is disabled."),
    },
    async (args) => {
      const group = args.servicegroup as string;
      const server = args.server as string;
      const port = args.port as number;
      const action = args.action as string;
      const body: Record<string, unknown> = { servicegroupname: group, servername: server, port };
      if (action === "disable") {
        body.graceful = args.graceful;
        if (args.delay) body.delay = args.delay;
      }

      await client.post("servicegroup", { servicegroup: body }, action);

      let observed: unknown = "could not read the member back";
      try {
        const resp = await client.get("config", `servicegroup_servicegroupmember_binding/${encodeURIComponent(group)}`);
        const members = (resp.servicegroup_servicegroupmember_binding as Record<string, unknown>[] | undefined) ?? [];
        const m = members.find((r) => r.servername === server && Number(r.port) === port);
        observed = m ? { state: m.state, svrstate: m.svrstate, ip: m.ip } : "member not found in the group's bindings";
      } catch (err) {
        observed = `read-back failed: ${err instanceof Error ? err.message : String(err)}`;
      }
      return {
        content: [{
          type: "text" as const,
          text: JSON.stringify({
            action_accepted: `${action} ${group} ${server}:${port}`,
            observed_state: observed,
            note: action === "disable" ? "A graceful or delayed disable can still show ENABLED or draining until connections close or the delay ends." : undefined,
          }, null, 2),
        }],
      };
    }
  );
}
