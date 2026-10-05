/**
 * Troubleshooting tools - trace health chains, search config, policy analysis.
 */

import { type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { asRows, type NitroClient } from "../client.js";

const MAX_MATCHES = 200;

export function registerTroubleshootTools(server: McpServer, client: NitroClient) {
  server.tool(
    "trace_vserver_health",
    "Trace why a virtual server is DOWN or degraded. Walks the full dependency chain: vserver state → bound services/service groups → each member's state → bound monitors and their probe status. Returns the complete health picture in one call.",
    {
      type: z.enum(["lb", "cs", "vpn", "gslb"]).describe("Virtual server type."),
      name: z.string().describe("The virtual server name."),
    },
    async (args) => {
      const typeMap: Record<string, string> = {
        lb: "lbvserver", cs: "csvserver", vpn: "vpnvserver", gslb: "gslbvserver",
      };
      const resource = typeMap[args.type as string] ?? "lbvserver";
      const name = args.name as string;
      // Only LB and GSLB vservers bind services directly; CS points at LB vservers and VPN binds none.
      const chains: Record<string, Record<string, string>> = {
        lb: {
          svcBind: "lbvserver_service_binding", svc: "service", svcMon: "service_lbmonitor_binding",
          sgBind: "lbvserver_servicegroup_binding", sgMembers: "servicegroup_servicegroupmember_binding", sgMon: "servicegroup_lbmonitor_binding",
        },
        gslb: {
          svcBind: "gslbvserver_gslbservice_binding", svc: "gslbservice", svcMon: "gslbservice_lbmonitor_binding",
          sgBind: "gslbvserver_gslbservicegroup_binding", sgMembers: "gslbservicegroup_gslbservicegroupmember_binding", sgMon: "gslbservicegroup_lbmonitor_binding",
        },
      };
      const chain = chains[args.type as string];

      const result: Record<string, unknown> = {};

      // 1. Get vserver config and state
      try {
        const vsResp = await client.get("config", `${resource}/${encodeURIComponent(name)}`);
        const vs = (vsResp[resource] as Record<string, unknown>[] | undefined)?.[0] ?? vsResp[resource];
        result.vserver = vs;
      } catch (err) {
        return {
          content: [{
            type: "text" as const,
            text: `Cannot find ${resource} '${name}': ${err instanceof Error ? err.message : String(err)}`,
          }],
          isError: true,
        };
      }

      // 2. For CS vserver, also get the default LB vserver target
      if (args.type === "cs") {
        try {
          const csBindings = await client.get("config", `csvserver_lbvserver_binding/${encodeURIComponent(name)}`);
          result.default_lb_vserver = csBindings.csvserver_lbvserver_binding;
        } catch { /* no default lb binding */ }
      }

      // 3. Get bound services
      const services: Record<string, unknown>[] = [];

      if (chain) try {
        const svcBindings = await client.get("config", `${chain.svcBind}/${encodeURIComponent(name)}`);
        const bound = svcBindings[chain.svcBind] as Record<string, unknown>[] | undefined;
        if (bound) {
          for (const b of bound) {
            const svcName = (b.servicename ?? b.name) as string;
            if (!svcName) continue;

            const svcDetail: Record<string, unknown> = { binding: b };

            // Get service config + state
            try {
              const svcResp = await client.get("config", `${chain.svc}/${encodeURIComponent(svcName)}`);
              const svc = (svcResp[chain.svc] as Record<string, unknown>[] | undefined)?.[0] ?? svcResp[chain.svc];
              svcDetail.config = svc;
            } catch { /* service not found */ }

            // Get monitors bound to this service
            try {
              const monResp = await client.get("config", `${chain.svcMon}/${encodeURIComponent(svcName)}`);
              svcDetail.monitors = monResp[chain.svcMon];
            } catch { /* no monitors */ }

            services.push(svcDetail);
          }
        }
      } catch { /* no service bindings */ }

      // 4. Get bound service groups
      const serviceGroups: Record<string, unknown>[] = [];

      if (chain) try {
        const sgBindings = await client.get("config", `${chain.sgBind}/${encodeURIComponent(name)}`);
        const bound = sgBindings[chain.sgBind] as Record<string, unknown>[] | undefined;
        if (bound) {
          for (const b of bound) {
            const sgName = (b.servicegroupname ?? b.name) as string;
            if (!sgName) continue;

            const sgDetail: Record<string, unknown> = { binding: b };

            // Get service group members with their states
            try {
              const memberResp = await client.get("config", `${chain.sgMembers}/${encodeURIComponent(sgName)}`);
              sgDetail.members = memberResp[chain.sgMembers];
            } catch { /* no members */ }

            // Get monitors bound to service group
            try {
              const monResp = await client.get("config", `${chain.sgMon}/${encodeURIComponent(sgName)}`);
              sgDetail.monitors = monResp[chain.sgMon];
            } catch { /* no monitors */ }

            serviceGroups.push(sgDetail);
          }
        }
      } catch { /* no servicegroup bindings */ }

      result.services = services;
      result.service_groups = serviceGroups;

      // 5. Build a summary diagnosis
      const vs = result.vserver as Record<string, unknown> | undefined;
      const state = (vs?.curstate as string)?.toUpperCase() ?? "UNKNOWN";
      const diagLines: string[] = [`Virtual server '${name}' is ${state}`];

      if (state === "DOWN" || state === "OFS" || state === "OUT OF SERVICE") {
        const downServices = services.filter((s) => {
          const cfg = s.config as Record<string, unknown> | undefined;
          return cfg?.svrstate && (cfg.svrstate as string).toUpperCase() !== "UP";
        });
        if (downServices.length > 0) {
          diagLines.push(`${downServices.length} service(s) are DOWN:`);
          for (const s of downServices) {
            const cfg = s.config as Record<string, unknown>;
            diagLines.push(`  - ${cfg.servicename ?? cfg.name}: ${cfg.svrstate}`);
          }
        }
        if (!chain) {
          diagLines.push(args.type === "cs"
            ? "CS vservers have no services of their own; trace the target LB vservers (default_lb_vserver and the CS policy targets)."
            : "VPN vservers have no services; check the authentication and session policies instead (diagnose_auth).");
        } else if (services.length === 0 && serviceGroups.length === 0) {
          diagLines.push("No services or service groups are bound to this vserver.");
        }
      }

      return {
        content: [{
          type: "text" as const,
          text: `## Diagnosis\n${diagLines.join("\n")}\n\n## Full Trace\n${JSON.stringify(result, null, 2)}`,
        }],
      };
    }
  );

  server.tool(
    "search_config",
    "Search the running configuration for a text string. Returns up to 200 matching lines with context (the total count is always given). Use this to find where an IP, hostname, cert name, policy, or any string is referenced across the entire config.",
    {
      query: z.string().describe("Text to search for (case-insensitive)."),
      context_lines: z.number().int().min(0).max(20).optional().default(1).describe("Number of lines of context above and below each match (default: 1)."),
    },
    async (args) => {
      const response = await client.get("config", "nsrunningconfig");
      const config = (response.nsrunningconfig as Record<string, unknown>)?.response as string ?? "";

      if (!config) {
        return { content: [{ type: "text" as const, text: "Could not retrieve running config." }], isError: true };
      }

      const query = (args.query as string).toLowerCase();
      const contextLines = (args.context_lines as number) ?? 1;
      const lines = config.split("\n");
      const matches: string[] = [];
      const seen = new Set<number>();

      let hits = 0;
      for (let i = 0; i < lines.length; i++) {
        if (lines[i].toLowerCase().includes(query) && ++hits <= MAX_MATCHES) {
          const start = Math.max(0, i - contextLines);
          const end = Math.min(lines.length - 1, i + contextLines);

          for (let j = start; j <= end; j++) {
            if (!seen.has(j)) {
              seen.add(j);
              const prefix = j === i ? ">>> " : "    ";
              matches.push(`${prefix}${j + 1}: ${lines[j]}`);
            }
          }
          matches.push(""); // separator
        }
      }

      if (matches.length === 0) {
        return {
          content: [{ type: "text" as const, text: `No matches found for '${args.query}' in the running config.` }],
        };
      }

      const more = hits > MAX_MATCHES ? ` Showing the first ${MAX_MATCHES}; ${hits - MAX_MATCHES} more not shown, so use a more specific query.` : "";

      return {
        content: [{
          type: "text" as const,
          text: `${hits} matching line(s) for '${args.query}'.${more}\n\n${matches.join("\n")}`,
        }],
      };
    }
  );

  server.tool(
    "list_policies_with_hits",
    "List responder, rewrite, or CS policies with their hit counters, priority, expression, action, and which vservers they are bound to, including authentication vservers. Hit count = 0 on an expected policy immediately tells you traffic isn't matching.",
    {
      type: z.enum(["responder", "rewrite", "cs"]).describe("Policy type to list."),
    },
    async (args) => {
      const ptype = args.type as string;
      const resourceMap: Record<string, { policy: string; action: string }> = {
        responder: { policy: "responderpolicy", action: "responderaction" },
        rewrite: { policy: "rewritepolicy", action: "rewriteaction" },
        cs: { policy: "cspolicy", action: "csaction" },
      };

      const { policy: policyResource } = resourceMap[ptype];

      // Get all policies
      const policyResp = await client.get("config", policyResource);
      const policies = policyResp[policyResource] as Record<string, unknown>[] | undefined;

      if (!policies || policies.length === 0) {
        return {
          content: [{ type: "text" as const, text: `No ${ptype} policies found.` }],
        };
      }

      // responderpolicy_binding / rewritepolicy_binding do not include authentication vservers, so read those directly.
      const authBound: Record<string, Record<string, unknown>[]> = {};
      if (ptype !== "cs") {
        try {
          const avs = ((await client.get("config", "authenticationvserver")).authenticationvserver as Record<string, unknown>[] | undefined) ?? [];
          const key = `authenticationvserver_${policyResource}_binding`;
          await Promise.all(avs.map(async (v) => {
            try {
              const r = await client.get("config", `${key}/${encodeURIComponent(String(v.name))}`);
              for (const bnd of (r[key] as Record<string, unknown>[] | undefined) ?? []) {
                (authBound[String(bnd.policy)] ??= []).push({ authvserver: v.name, priority: bnd.priority, bindpoint: bnd.bindpoint });
              }
            } catch { /* nothing bound */ }
          }));
        } catch { /* no authentication vservers */ }
      }

      // Get stats (hit counters) for each policy
      const enriched = await Promise.all(
        policies.map(async (p) => {
          const pName = (p.name ?? p.policyname) as string;
          const detail: Record<string, unknown> = { ...p };

          // Get binding info to see where it's bound
          try {
            const bindResp = await client.get("config", `${policyResource}_binding/${encodeURIComponent(pName)}`);
            detail.bound_to = bindResp[`${policyResource}_binding`];
          } catch { /* not bound anywhere */ }
          if (authBound[pName]) detail.bound_to_auth_vservers = authBound[pName];

          // Get stats (there is no stat/cspolicy; CS hit counts are on the config object)
          if (policyResource !== "cspolicy") try {
            const statResp = await client.get("stat", `${policyResource}/${encodeURIComponent(pName)}`);
            detail.stats = (statResp[policyResource] as Record<string, unknown>[] | undefined)?.[0] ?? statResp[policyResource];
          } catch { /* no stats available */ }

          return detail;
        })
      );

      return {
        content: [{ type: "text" as const, text: JSON.stringify(enriched, null, 2) }],
      };
    }
  );

  server.tool(
    "check_policy_coverage",
    "For one responder or rewrite policy, list every Gateway (VPN) and authentication vserver and say whether the policy is bound to it, with priority and bind point. Use to prove a protective policy (e.g. an exploit block) is on every entry point; one missed vserver is a gap.",
    {
      type: z.enum(["responder", "rewrite"]).describe("Policy type."),
      policy: z.string().min(1).describe("Policy name."),
    },
    async (args) => {
      const res = `${args.type}policy`;
      const errors: string[] = [];
      const list = async (resource: string, key = resource.split("/")[0]) => {
        try { return ((await client.get("config", resource))[key] as Record<string, unknown>[] | undefined) ?? []; }
        catch (err) { errors.push(`${resource}: ${err instanceof Error ? err.message : String(err)}`); return []; }
      };
      try {
        await client.get("config", `${res}/${encodeURIComponent(args.policy)}`);
      } catch (err) {
        return { content: [{ type: "text" as const, text: `No ${args.type} policy named '${args.policy}' (${err instanceof Error ? err.message : String(err)}).` }], isError: true };
      }
      const rows = [];
      for (const kind of ["vpnvserver", "authenticationvserver"]) {
        for (const vs of await list(kind)) {
          const name = String(vs.name);
          const before = errors.length;
          const bound = (await list(`${kind}_${res}_binding/${encodeURIComponent(name)}`)).find((b) => b.policy === args.policy);
          const state = errors.length > before ? null : !!bound; // null: the binding read failed, so unknown
          rows.push({ vserver: name, type: kind === "vpnvserver" ? "gateway" : "authentication", bound: state, ...(bound && { priority: bound.priority, bindpoint: bound.bindpoint }) });
        }
      }
      const missing = rows.filter((r) => r.bound === false).map((r) => `${r.type} ${r.vserver}`);
      const unverified = rows.filter((r) => r.bound === null).map((r) => `${r.type} ${r.vserver}`);
      return { content: [{ type: "text" as const, text: JSON.stringify({
        ...(errors.length && { incomplete: true, errors }),
        policy: args.policy, vservers_checked: rows.length, not_bound_on: missing, ...(unverified.length && { unverified }), vservers: rows,
        note: "Global and LB/CS bindings are not checked here; see list_policies_with_hits.",
      }, null, 2) }] };
    }
  );

  server.tool(
    "check_log_actions",
    "Flag responder and rewrite log actions whose messages will not reach a log: for each policy with a logaction, checks the message action's level against the global syslog and nslog parameters and each syslog server action (user-defined audit logging on, and the level included). Reports per path rather than one verdict.",
    {},
    async () => {
      const errors: string[] = [];
      const list = async (resource: string) => {
        try { return asRows((await client.get("config", resource))[resource]); }
        catch (err) { errors.push(`${resource}: ${err instanceof Error ? err.message : String(err)}`); return []; }
      };
      const yes = (v: unknown) => ["YES", "TRUE", "ENABLED"].includes(String(v).toUpperCase());
      const levels = (v: unknown) => (Array.isArray(v) ? v : String(v ?? "").split(/[ ,]+/)).map((x) => String(x).toUpperCase()).filter(Boolean);
      const accepts = (path: Record<string, unknown> | undefined, level: string) => {
        if (!path) return "unknown (not readable)";
        if (!yes(path.userdefinedauditlog)) return "no: userdefinedauditlog is off";
        const l = levels(path.loglevel);
        return l.includes("ALL") || l.includes(level) ? "yes" : `no: loglevel ${l.join(",") || "unset"} excludes ${level}`;
      };
      const [resp, rew, actions, syslogParams, nslogParams, servers] = await Promise.all([
        list("responderpolicy"), list("rewritepolicy"), list("auditmessageaction"),
        list("auditsyslogparams"), list("auditnslogparams"), list("auditsyslogaction"),
      ]);
      const byName = new Map(actions.map((a) => [String(a.name), a]));
      const findings = [...resp.map((p) => ["responder", p] as const), ...rew.map((p) => ["rewrite", p] as const)]
        .filter(([, p]) => p.logaction)
        .map(([type, p]) => {
          const a = byName.get(String(p.logaction));
          if (!a) return { policy: p.name, type, logaction: p.logaction, problem: errors.some((e) => e.startsWith("auditmessageaction")) ? "unknown (action list unreadable)" : "log action not found" };
          // 13.1 returns the message action's level as loglevel1 (NITRO spec GET schema).
          const level = String(a.loglevel1 ?? a.loglevel ?? "").toUpperCase();
          return {
            policy: p.name, type, logaction: a.name, level,
            global_syslog: accepts(syslogParams[0], level),
            global_nslog: yes(a.logtonewnslog) ? "newnslog (logtonewnslog)" : accepts(nslogParams[0], level),
            syslog_servers: Object.fromEntries(servers.map((s) => [String(s.name), accepts(s, level)])),
          };
        });
      return { content: [{ type: "text" as const, text: JSON.stringify({
        ...(errors.length && { incomplete: true, errors }),
        policies_with_log_actions: findings.length, findings,
        note: "A syslog server action is only used if a syslog policy binds it globally or to the vserver; per-server results apply where it is bound.",
      }, null, 2) }] };
    }
  );

  server.tool(
    "get_monitor_details",
    "Get detailed configuration and probe status for a specific LB monitor. Shows the monitor type, interval, response codes, custom strings, and which services/service groups use it.",
    {
      name: z.string().describe("The monitor name."),
    },
    async (args) => {
      const name = args.name as string;

      const [config, bindings] = await Promise.allSettled([
        client.get("config", `lbmonitor/${encodeURIComponent(name)}`),
        client.get("config", `lbmonitor_binding/${encodeURIComponent(name)}`),
      ]);

      const result: Record<string, unknown> = {};

      if (config.status === "fulfilled") {
        result.config = config.value.lbmonitor;
      }
      if (bindings.status === "fulfilled") {
        result.bindings = bindings.value.lbmonitor_binding;
      }

      return {
        content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
      };
    }
  );

  server.tool(
    "list_down_services",
    "Quick diagnostic: list all services that are DOWN or OUT OF SERVICE, with IP, port, service type and last state change. Service group members are not included; use get_service_group_members or trace_vserver_health for those.",
    {},
    async () => {
      // Get all services that are DOWN
      let downServices: Record<string, unknown>[] = [];
      try {
        const resp = await client.get("config", "service", {
          filter: "svrstate:DOWN",
          attrs: "name,ipaddress,port,svrstate,servicetype,statechangetimesec",
        });
        downServices = (resp.service as Record<string, unknown>[]) ?? [];
      } catch { /* no down services */ }

      // Also check for OUT OF SERVICE
      let oosServices: Record<string, unknown>[] = [];
      try {
        const resp = await client.get("config", "service", {
          filter: "svrstate:OUT OF SERVICE",
          attrs: "name,ipaddress,port,svrstate,servicetype,statechangetimesec",
        });
        oosServices = (resp.service as Record<string, unknown>[]) ?? [];
      } catch { /* none */ }

      const allDown = [...downServices, ...oosServices];

      if (allDown.length === 0) {
        return {
          content: [{ type: "text" as const, text: "All services are UP. No down or out-of-service backends found." }],
        };
      }

      return {
        content: [{
          type: "text" as const,
          text: `${allDown.length} service(s) are DOWN or OUT OF SERVICE:\n\n${JSON.stringify(allDown, null, 2)}`,
        }],
      };
    }
  );
}
