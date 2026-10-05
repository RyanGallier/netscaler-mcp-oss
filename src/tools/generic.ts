/**
 * nitro_get: read any NITRO config or stat resource the curated tools do not cover.
 * GET only. Resources whose GET returns secrets, file contents, runs something or is
 * unbounded are refused; every response is redacted by the client.
 *
 * nitro_write: Admin-only add/set/unset/rm/bind/unbind/action on any NITRO config resource,
 * except whole-box, key-material and session-kill resources, which are refused outright.
 */

import { type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { type NitroClient } from "../client.js";
import { FIELD_SET, redact, redactText } from "../redact.js";

const REFUSED = new Map<string, string>([
  ["systemfile", "returns file contents, including private keys; use get_syslog or get_nslog_events"],
  ["techsupport", "a GET starts a techsupport collection"],
  ["routerdynamicrouting", "its args run routing CLI"],
  ["nsrunningconfig", "use get_running_config"],
  ["nssavedconfig", "use get_saved_config"],
  ["nsencryptionkey", "key material"],
  ["nsencryptionparams", "key material"],
  ["nshmackey", "key material"],
  ["sslhsmkey", "takes a password argument"],
  ["nsmigration", "can dump session state"],
  ["nsconnectiontable", "unbounded; use run_nsconmsg or a packet capture"],
  ["lsnsession", "unbounded"],
  ["cacheobject", "unbounded"],
]);
// Pairs of key:value separated by commas, the form NITRO uses for args and filter.
const PAIRS = /^[A-Za-z0-9_]+:[^,&#]*(,[A-Za-z0-9_]+:[^,&#]*)*$/;
const BAD_ARGS = /(^|,)(clearstats|commandstring|authtoken|password)\s*:/i;
const MAX_BYTES = 90_000;

/** Encode a query value but keep the ':' and ',' separators NITRO parses. */
const q = (v: string) => encodeURIComponent(v).replace(/%3A/gi, ":").replace(/%2C/gi, ",");

function strip(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(strip);
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).filter(([k]) => k !== "_nextgenapiresource").map(([k, v]) => [k, strip(v)])
    );
  }
  return value;
}

// Refused for every nitro_write operation. The operator's command policy is the real limit; this is an overlay.
const WRITE_REFUSED = new Map<string, string>([
  ...["reboot", "shutdown", "install"].map((r) => [r, "whole-box operation"] as [string, string]),
  ["systembackup", "use create_backup; restore is not offered"],
  ["nsconfig", "use save_config"],
  ["routerdynamicrouting", "runs routing CLI"],
  ["systemfile", "a file write can run code at boot (/nsconfig/rc.netscaler)"],
  ...["nsencryptionkey", "nsencryptionparams", "nshmackey", "sslhsmkey"].map((r) => [r, "key material"] as [string, string]),
  ...["cluster", "clusterinstance", "clusternode"].map((r) => [r, "cluster formation"] as [string, string]),
  ["systemsession", "use kill_admin_session"],
  ...["aaasession", "vpnicaconnection", "vpnpcoipconnection", "rdpconnections"].map((r) => [r, "use kill_gateway_session"] as [string, string]),
]);
// Resources with no name: global parameters and global bindings. Three *param resources are named collections.
const GLOBAL = /(param|params|parameter)$|global_\w+_binding$/;
const NAMED_PARAMS = new Set(["inatparam", "nat64param", "nsvpxparam"]);
const isGlobal = (r: string) => GLOBAL.test(r) && !NAMED_PARAMS.has(r);
const BAD_NAME = /[\u0000-\u001f\u007f/?#%]|\.\.|^\.$/;
const NOTE = "Effects may be immediate, and clear, flush, kill and apply actions cannot be undone. Configuration changes are in the running config only: run save_config to keep them across a reboot.";

type Op = "add" | "set" | "unset" | "rm" | "bind" | "unbind" | "action";
/** Which arguments each operation takes; anything else is refused. */
const MATRIX: Record<Op, { name: "required" | "global-optional" | "refused"; payload: boolean; args: boolean }> = {
  add: { name: "refused", payload: true, args: false },
  set: { name: "global-optional", payload: true, args: false },
  unset: { name: "refused", payload: true, args: false },
  action: { name: "refused", payload: true, args: false },
  rm: { name: "required", payload: false, args: true },
  bind: { name: "global-optional", payload: true, args: false },
  unbind: { name: "global-optional", payload: false, args: true },
};

/** Validates one nitro_write call and returns the request, or the reason it is refused. */
export function planWrite(a: { operation: Op; resource: string; name?: string; action?: string; payload?: Record<string, unknown>; args?: string }):
  { method: "POST" | "PUT" | "DELETE"; path: string; query?: string; body?: Record<string, unknown> } | { refused: string } {
  const why = WRITE_REFUSED.get(a.resource);
  if (why) return { refused: `${a.resource} is not writable through nitro_write (${why}).` };
  const rule = MATRIX[a.operation];
  if (a.name !== undefined) {
    if (rule.name === "refused") return { refused: `${a.operation} takes the object's identity from payload; do not pass name.` };
    if (a.name === "" || BAD_NAME.test(a.name)) return { refused: "name must be non-empty and cannot be '.' or contain control characters, '/', '?', '#', '%' or '..'." };
  } else if (rule.name === "required" || (rule.name === "global-optional" && !isGlobal(a.resource))) {
    return { refused: `${a.operation} on ${a.resource} needs a name.` };
  }
  if (a.payload !== undefined && !rule.payload) return { refused: `${a.operation} does not take a payload.` };
  if (rule.payload && (!a.payload || !Object.keys(a.payload).length)) return { refused: `${a.operation} needs a payload of NITRO fields.` };
  if (a.args !== undefined && !rule.args) return { refused: `${a.operation} does not take args.` };
  if (a.operation === "unbind" && !a.args) return { refused: "unbind needs args naming the bound entity, e.g. servicename:svc1." };
  if (a.args && (/[\u0000-\u001f%+]/.test(a.args) || !PAIRS.test(a.args))) return { refused: "args must be key:value pairs without control characters, '%' or '+'." };
  if (a.args && a.args.split(",").some((p) => FIELD_SET.has(p.split(":")[0].toLowerCase()))) return { refused: "args cannot carry a secret field." };
  if ((a.action !== undefined) !== (a.operation === "action")) return { refused: "action is required for operation=action and only there." };
  if (a.action !== undefined && !/^[a-z][a-z0-9]*$/.test(a.action)) return { refused: "action must be one lowercase NITRO verb, e.g. enable or link." };
  if (a.action === "kill" && a.payload && "all" in a.payload) return { refused: "kill with all is not offered." };

  const name = a.name !== undefined ? encodeURIComponent(a.name) : undefined;
  const body = a.payload ? { [a.resource]: a.payload } : undefined;
  const query = a.args ? `args=${q(a.args)}` : undefined;
  switch (a.operation) {
    case "add": return { method: "POST", path: a.resource, body };
    case "unset": return { method: "POST", path: a.resource, query: "action=unset", body };
    case "action": return { method: "POST", path: a.resource, query: `action=${a.action}`, body };
    case "set": case "bind": return { method: "PUT", path: name ? `${a.resource}/${name}` : a.resource, body };
    case "rm": case "unbind": return { method: "DELETE", path: name ? `${a.resource}/${name}` : a.resource, query };
  }
}

export function registerGenericTools(server: McpServer, client: NitroClient) {
  server.tool(
    "nitro_get",
    "Read any NITRO resource the other tools do not cover, e.g. config systemuser, systemcmdpolicy, systemsession, nsip, nsparam, auditsyslogaction, snmpmanager, ntpserver, appfwprofile, botprofile, nsacl, vpnparameter, lbvserver_binding (aggregate bindings need a name), or stat system, aaa, vpn, sslvserver. Resource names are the lowercase NITRO names (CLI 'show lb vserver' is lbvserver). Read-only; secrets are redacted. Prefer a curated tool when one exists.",
    {
      namespace: z.enum(["config", "stat"]).describe("config for configuration objects, stat for counters."),
      resource: z.string().regex(/^[a-z0-9_]+$/, "lowercase NITRO resource name").describe("NITRO resource name, e.g. systemuser or lbvserver_binding."),
      name: z.string().optional().describe("Object name. Required for _binding resources."),
      filter: z.string().regex(PAIRS).optional().describe("Exact-match filter, e.g. 'curstate:DOWN' or 'servicetype:SSL,port:443'."),
      attrs: z.string().regex(/^[a-z0-9_]+(,[a-z0-9_]+)*$/).optional().describe("Comma-separated fields to return, to keep output small."),
      args: z.string().regex(PAIRS).optional().describe("NITRO args, e.g. 'loggedin:true' or 'detail:true'."),
      max_rows: z.number().int().min(1).max(1000).default(100).describe("Rows returned per array (default 100)."),
    },
    async (args) => {
      const resource = args.resource as string;
      const why = REFUSED.get(resource);
      if (why) return { content: [{ type: "text" as const, text: `Refused: ${resource} (${why}).` }], isError: true };
      if (args.args && BAD_ARGS.test(args.args as string)) {
        return { content: [{ type: "text" as const, text: "Refused: clearstats, commandstring, authtoken and password args are not allowed (they reset counters, run commands or carry secrets)." }], isError: true };
      }

      // A filter or args key naming a secret field would turn exact-match into a guessing oracle.
      const keys = [args.filter, args.args].filter(Boolean).flatMap((v) => (v as string).split(",").map((p) => p.split(":")[0].toLowerCase()));
      if (keys.some((k) => FIELD_SET.has(k))) {
        return { content: [{ type: "text" as const, text: "Refused: filter and args cannot name a secret field." }], isError: true };
      }
      if (args.name && /\/|\.\./.test(args.name as string)) {
        return { content: [{ type: "text" as const, text: "Refused: name cannot contain '/' or '..'." }], isError: true };
      }

      const path = args.name ? `${resource}/${encodeURIComponent(args.name as string)}` : resource;
      const query = [
        args.filter && `filter=${q(args.filter as string)}`,
        args.attrs && `attrs=${q(args.attrs as string)}`,
        args.args && `args=${q(args.args as string)}`,
      ].filter(Boolean).join("&");
      const resp = await client.get(args.namespace as "config" | "stat", path, undefined, query || undefined);

      const maxRows = args.max_rows as number;
      const notes: string[] = [];
      const body: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(resp)) {
        if (k === "errorcode" || k === "message" || k === "severity") continue;
        if (Array.isArray(v) && v.length > maxRows) {
          notes.push(`${k}: showing ${maxRows} of ${v.length} rows; narrow with filter or raise max_rows.`);
          body[k] = strip(v.slice(0, maxRows));
        } else {
          body[k] = strip(v);
        }
      }

      let text = JSON.stringify(body, null, 2);
      if (text.length > MAX_BYTES) {
        text = text.slice(0, MAX_BYTES);
        notes.push(`Output truncated at ${MAX_BYTES} characters; use attrs, filter or max_rows.`);
      }
      return { content: [{ type: "text" as const, text: notes.length ? `${notes.join("\n")}\n\n${text}` : text }] };
    }
  );

  server.tool(
    "nitro_write",
    "Admin: change any NetScaler configuration through NITRO. operation add (POST, identity in payload), set (PUT one object, or a global parameter with no name), unset (payload names the object and the fields to unset, each true), rm (DELETE by name, optional args), bind (PUT a <object>_<target>_binding by owner name), unbind (DELETE a binding by owner name with args naming the bound entity), action (POST ?action=<verb> such as enable, disable, rename, link, apply, clear; identity in payload). Resource names are lowercase NITRO names (CLI 'add lb vserver' is lbvserver). preview defaults to true and returns the exact request without sending it; call again with preview false to apply. Whole-box operations, key material, file writes and session kills are refused; use the dedicated tools. Changes are unsaved until save_config.",
    {
      operation: z.enum(["add", "set", "unset", "rm", "bind", "unbind", "action"]),
      resource: z.string().regex(/^[a-z0-9_]+$/, "lowercase NITRO resource name").describe("e.g. lbvserver, sslvserver_sslcertkey_binding, nsparam."),
      name: z.string().optional().describe("Object or binding-owner name. Refused for add, unset and action; omit only for global parameters and global bindings."),
      action: z.string().optional().describe("operation=action only: the NITRO verb, e.g. enable, disable, rename, link."),
      payload: z.record(z.unknown()).optional().describe("NITRO fields as a JSON object, e.g. {\"name\":\"lb1\",\"servicetype\":\"HTTP\"}."),
      args: z.string().optional().describe("rm and unbind: key:value pairs, e.g. 'servicename:svc1' or 'ipaddress:10.0.0.5,port:80'."),
      preview: z.boolean().default(true).describe("true (default) shows the request without sending it."),
    },
    async (a) => {
      const plan = planWrite(a as Parameters<typeof planWrite>[0]);
      if ("refused" in plan) return { content: [{ type: "text" as const, text: `Refused: ${plan.refused}` }], isError: true };
      const url = `/nitro/v1/config/${plan.path}${plan.query ? `?${plan.query}` : ""}`;
      if (a.preview) {
        return { content: [{ type: "text" as const, text: JSON.stringify({ preview: true, method: plan.method, url, body: redact(plan.body) }, null, 2) + "\nNothing was sent. Call again with preview false to apply." }] };
      }
      try {
        const resp = plan.method === "PUT"
          ? await client.put(plan.path, plan.body!)
          : plan.method === "DELETE"
            ? await client.delete(plan.path, undefined, plan.query)
            : await client.post(plan.path, plan.body!, plan.query?.replace(/^action=/, ""));
        const { errorcode, message, severity, ...rest } = resp;
        return { content: [{ type: "text" as const, text: JSON.stringify({ applied: `${plan.method} ${url}`, reply: { errorcode, message, ...rest } }, null, 2) + `\n${NOTE}` }] };
      } catch (err) {
        return { content: [{ type: "text" as const, text: redactText(`${plan.method} ${url} failed: ${err instanceof Error ? err.message : String(err)}`) }], isError: true };
      }
    }
  );
}
