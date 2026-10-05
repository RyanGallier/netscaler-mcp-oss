/**
 * Builds the McpServer. Shared by the stdio entry point (index.ts) and the
 * hosted HTTP entry point (http.ts), for one appliance or several.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z, type ZodRawShape } from "zod";
import { NitroClient } from "./client.js";
import { type Config } from "./config.js";
import { registerSystemTools } from "./tools/system.js";
import { registerHATools } from "./tools/ha.js";
import { registerVServerTools } from "./tools/vservers.js";
import { registerServiceTools } from "./tools/services.js";
import { registerSSLTools } from "./tools/ssl.js";
import { registerNetworkTools } from "./tools/network.js";
import { registerTroubleshootTools } from "./tools/troubleshoot.js";
import { registerAuthTools } from "./tools/auth.js";
import { registerDNSTools } from "./tools/dns.js";
import { registerNsconmsgTools } from "./tools/nsconmsg.js";
import { registerGatewayTools } from "./tools/gateway.js";
import { registerOpsTools } from "./tools/ops.js";
import { registerGenericTools } from "./tools/generic.js";
import { registerSecurityTools } from "./tools/security.js";
import { registerForensicsTools } from "./tools/forensics.js";

/**
 * Tools open to the Reader role; they run on the read-only NITRO account
 * (run_nsconmsg on its SSH account). The forensic tools (FORENSIC_TOOLS) use
 * their own SSH account and are gated by allowForensics. Everything else (the
 * NITRO writers, and get_system_file, which can read private keys under
 * /nsconfig/ssl) is admin-only, runs on the admin NITRO account, and is
 * registered only when allowAdmin is set. A tool missing from this list
 * defaults to admin-only.
 */
export const READER_TOOLS = new Set([
  "audit_admin_access",
  "audit_ssl_posture",
  "check_log_actions",
  "check_policy_coverage",
  "check_management_exposure",
  "diagnose_auth",
  "get_auth_objects",
  "get_auth_vserver_full",
  "get_config_diff",
  "get_crash_state",
  "get_dns_config",
  "get_gateway_session_policies",
  "get_gateway_sessions",
  "get_gslb_sync_status",
  "get_ha_status",
  "get_interface_stats",
  "get_monitor_details",
  "get_nslog_events",
  "get_running_config",
  "get_saved_config",
  "get_service",
  "get_service_group_members",
  "get_ssl_certificate",
  "get_ssl_vserver_config",
  "get_syslog",
  "get_system_info",
  "get_system_stats",
  "get_virtual_server",
  "get_virtual_server_stats",
  "list_cert_auth_policies",
  "list_dns_records",
  "list_down_services",
  "list_features",
  "list_gslb_services",
  "list_gslb_sites",
  "list_ip_addresses",
  "list_ldap_policies",
  "list_policies_with_hits",
  "list_radius_policies",
  "list_routes",
  "list_saml_policies",
  "list_service_groups",
  "list_services",
  "list_ssl_certificates",
  "list_ssl_profiles",
  "list_virtual_servers",
  "list_vlans",
  "nitro_get",
  "run_nsconmsg",
  "search_config",
  "test_reachability",
  "trace_nfactor_flow",
  "trace_vserver_health",
]);

/** Root forensic tools: admin tier, gated separately, run on the forensics SSH account. */
export const FORENSIC_TOOLS = new Set(["get_core_backtrace", "search_core", "capture_aaad_debug"]);

export type ToolHandler = (...args: any[]) => any;

export interface BuildOptions {
  allowAdmin: boolean;
  allowForensics: boolean;
  /** Wraps each admin-only tool handler, e.g. for audit logging. */
  wrapAdmin?: (name: string, handler: ToolHandler) => ToolHandler;
}

interface CapturedTool {
  description: string;
  schema: ZodRawShape;
  handler: ToolHandler;
}

/** Runs the tool modules against one appliance and account, and keeps what they register. */
function captureWith(config: Config, readOnly: boolean): Map<string, CapturedTool> {
  const tools = new Map<string, CapturedTool>();
  const recorder = {
    tool: (name: string, description: string, schema: ZodRawShape, handler: ToolHandler) => {
      if (tools.has(name)) throw new Error(`Tool ${name} registered twice`);
      tools.set(name, { description, schema, handler });
    },
  } as unknown as McpServer;
  const client = new NitroClient(config, readOnly);

  registerSystemTools(recorder, client, config);
  registerHATools(recorder, client, config);
  registerVServerTools(recorder, client);
  registerServiceTools(recorder, client);
  registerSSLTools(recorder, client);
  registerNetworkTools(recorder, client);
  registerTroubleshootTools(recorder, client);
  registerAuthTools(recorder, client);
  registerDNSTools(recorder, client);
  registerNsconmsgTools(recorder, config);
  registerGatewayTools(recorder, client);
  registerOpsTools(recorder, client);
  registerGenericTools(recorder, client);
  registerSecurityTools(recorder, client);
  registerForensicsTools(recorder, config);
  return tools;
}

/**
 * One appliance's tools, each bound to the account it needs: Reader tools to
 * the read-only NITRO account (forensic tools use their own SSH account),
 * other admin tools to the admin NITRO account. Admin tools are absent when
 * no admin account is set.
 */
function captureTools(config: Config): Map<string, CapturedTool> {
  const read = captureWith(config, true);
  const admin = config.adminUser
    ? captureWith({ ...config, username: config.adminUser, password: config.adminPass }, false)
    : new Map<string, CapturedTool>();
  const tools = new Map<string, CapturedTool>();
  for (const [name, tool] of read) {
    if (READER_TOOLS.has(name) || FORENSIC_TOOLS.has(name)) tools.set(name, tool);
    else if (admin.has(name)) tools.set(name, admin.get(name)!);
  }
  return tools;
}

export const MAX_TEXT = 100_000;

/**
 * Every tool result passes through here. List tools stringify the appliance's array, which NITRO omits when
 * there are no objects, and MCP rejects text-less content. Text past MAX_TEXT is cut, with the note first.
 */
function shapeResult(result: any): any {
  if (!Array.isArray(result?.content)) return result;
  return {
    ...result,
    content: result.content.map((c: any) => {
      if (c?.type !== "text") return c;
      if (typeof c.text !== "string") return { ...c, text: "[]" };
      if (c.text.length <= MAX_TEXT) return c;
      const note = `[Output cut at ${MAX_TEXT.toLocaleString("en-US")} of ${c.text.length.toLocaleString("en-US")} characters. Narrow the request (a filter, a name, or nitro_get with filter and attrs).]`;
      return { ...c, text: `${note}\n${c.text.slice(0, MAX_TEXT)}` };
    }),
  };
}

/**
 * One server for one or more appliances. With a single target the tools are
 * registered exactly as the modules define them. With several, every tool
 * gains a required `appliance` argument that picks the target.
 */
export function buildServer(targets: Map<string, Config>, opts: BuildOptions): McpServer {
  const server = new McpServer({ name: "netscaler", version: "0.1.0" });
  const names = [...targets.keys()];
  const perTarget = new Map(names.map((n) => [n, captureTools(targets.get(n)!)]));
  const applianceArg = z
    .enum(names as [string, ...string[]])
    .describe(
      "Which NetScaler: " +
        names.map((n) => `${n} (${[targets.get(n)!.nsip, targets.get(n)!.peerNsip].filter(Boolean).join(" + ")})`).join(", ") +
        ". If the request does not make it clear, ask the user which one."
    );

  // A tool is offered if any target has the account it needs.
  const all = new Map<string, CapturedTool>();
  for (const tools of perTarget.values()) for (const [name, tool] of tools) if (!all.has(name)) all.set(name, tool);

  for (const [name, tool] of all) {
    const admin = !READER_TOOLS.has(name);
    if (FORENSIC_TOOLS.has(name) ? !opts.allowForensics : admin && !opts.allowAdmin) continue;

    let schema = tool.schema;
    let handler: ToolHandler = async (...args: unknown[]) => shapeResult(await tool.handler(...args));
    if (names.length > 1) {
      schema = { ...tool.schema, appliance: applianceArg };
      handler = async ({ appliance, ...args }: { appliance: string }, extra: unknown) => {
        const target = perTarget.get(appliance)!.get(name);
        if (!target) {
          return { content: [{ type: "text" as const, text: `${name} needs an account that is not configured for ${appliance}.` }], isError: true };
        }
        return shapeResult(await target.handler(args, extra));
      };
    }
    if (admin && opts.wrapAdmin) handler = opts.wrapAdmin(name, handler);
    // Hints let MCP clients ask the user before every admin call.
    server.tool(name, tool.description, schema, admin ? { destructiveHint: true } : { readOnlyHint: true }, handler);
  }
  return server;
}
