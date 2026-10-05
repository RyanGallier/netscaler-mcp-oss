/**
 * System information, stats, and config management tools.
 */

import { type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { gunzipSync } from "node:zlib";
import { createHash, randomBytes } from "node:crypto";
import { type NitroClient } from "../client.js";
import { NO_PEER, type Config } from "../config.js";
import { redactText } from "../redact.js";

/**
 * Decide how to render bytes pulled from the NetScaler filesystem.
 *
 * - If the bytes look like a gzip stream (magic `1f 8b`), gunzip and retry as text.
 * - If the resulting buffer is valid UTF-8 (no U+FFFD from replacement), return it as text.
 * - Otherwise, return a base64 blob so the caller can decode locally without data loss.
 *   Text is redacted; base64 output is not (get_system_file is admin-only).
 */
function renderFileBytes(raw: Buffer, filename: string): { body: string; note: string } {
  let buf = raw;
  let note = "";
  if (buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b) {
    try {
      buf = gunzipSync(buf);
      note = ` (gunzipped from ${raw.length} → ${buf.length} bytes)`;
    } catch (err) {
      return {
        body: raw.toString("base64"),
        note: ` (gzip decode failed: ${(err as Error).message}; returning base64, ${raw.length} bytes)`,
      };
    }
  }
  const text = buf.toString("utf-8");
  if (text.includes("\uFFFD")) {
    return {
      body: buf.toString("base64"),
      note: `${note} (binary; returning base64, ${buf.length} bytes)`,
    };
  }
  return { body: redactText(text), note: `${note} (${buf.length} bytes)` };
}

/**
 * Zod schema for the `node` parameter used by log-reading tools.
 * Kept as a constant so all three tools describe it identically.
 */
const nodeParam = z
  .enum(["primary", "peer"])
  .optional()
  .default("primary")
  .describe(
    "Which HA node to query: 'primary' (default) is the appliance's NSIP, 'peer' its configured peer NSIP. Useful for retrieving logs from the secondary node to compare against the primary."
  );

/** Resolve the right client for the requested node. Returns an error string if peer is requested but not configured. */
function pickClient(
  client: NitroClient,
  config: Config,
  node: "primary" | "peer"
): { client: NitroClient; nsip: string } | { error: string } {
  if (node === "peer") {
    if (!config.peerNsip) {
      return { error: NO_PEER };
    }
    return { client: client.forNode(config.peerNsip), nsip: config.peerNsip };
  }
  return { client, nsip: config.nsip };
}

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** Parse a NetScaler clock string like "Fri Oct  2 17:27:08 2026" (appliance clock is UTC). */
export function parseNsTime(s: unknown): { iso: string; epoch: number } | null {
  const m = /^\w{3}\s+(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\d{4})$/.exec(String(s ?? "").trim());
  const month = m ? MONTHS.indexOf(m[1]) : -1;
  if (!m || month < 0) return null;
  const ms = Date.UTC(+m[6], month, +m[2], +m[3], +m[4], +m[5]);
  return { iso: new Date(ms).toISOString(), epoch: ms / 1000 };
}

/** List one directory via NITRO systemfile (location only, no filename). */
export async function listDir(c: NitroClient, location: string): Promise<Record<string, unknown>[]> {
  const res = await c.get("config", "systemfile", undefined, `args=filelocation:${encodeURIComponent(location)}`);
  return (res.systemfile as Record<string, unknown>[] | undefined) ?? [];
}

/** Boot time for one node. Cores are listed by get_core_backtrace: the read account cannot see /var/core by design. */
async function crashState(c: NitroClient, nsip: string): Promise<Record<string, unknown>> {
  try {
    const ns = (await c.get("stat", "ns")).ns as Record<string, unknown> | undefined;
    return { nsip, starttime: ns?.starttime, boot: parseNsTime(ns?.starttime) };
  } catch (err) {
    return { nsip, status: "ERROR", error: err instanceof Error ? err.message : String(err) };
  }
}

const pageArgs = {
  offset: z.number().int().min(0).default(0).describe("Where to start: 0 for the first page, then next_offset from the previous page."),
  max_chars: z.number().int().min(1000).max(90_000).default(60_000).describe("Page size in characters (default 60,000, max 90,000)."),
  expected_sha256: z.string().regex(/^[0-9a-f]{64}$/).optional().describe("Required after the first page: the sha256 the first page returned, so a config that changed mid-read is caught."),
};

/** One page of config text, ending on a line break where possible; always advances. */
export function pageText(text: string, offset: number, maxChars: number, expected?: string): string {
  const sha256 = createHash("sha256").update(text, "utf8").digest("hex");
  if (offset > 0 && !expected) throw new Error("expected_sha256 is required after the first page; pass the sha256 the first page returned.");
  if (expected && expected !== sha256) throw new Error("The config changed since the first page. Start again at offset 0.");
  const isLow = (i: number) => i > 0 && i < text.length && /[\udc00-\udfff]/.test(text[i]);
  if (offset > text.length || isLow(offset)) throw new Error(`offset ${offset} is not a page boundary (total_chars ${text.length}).`);
  let end = Math.min(offset + maxChars, text.length);
  if (end < text.length) {
    const nl = text.lastIndexOf("\n", end - 1);
    if (nl >= offset) end = nl + 1;
    else if (isLow(end)) end++; // never split a surrogate pair on a hard cut
  }
  const meta = { offset, total_chars: text.length, sha256, ...(end < text.length && { next_offset: end }) };
  return `${JSON.stringify(meta)}\n${text.slice(offset, end)}`;
}

export function registerSystemTools(server: McpServer, client: NitroClient, config: Config) {
  server.tool(
    "get_crash_state",
    "Crash check for both HA nodes: last boot time (stat ns starttime; boot.iso and epoch assume the appliance clock is UTC, the default time zone; compare boot times with a tolerance of a minute or two, as they can shift by a second). An unexpected reboot on one node points at a crash; list and read the core files with get_core_backtrace (forensics account). A node that fails is reported with status ERROR instead of failing the call.",
    {},
    async () => {
      const nodes = [crashState(client, config.nsip)];
      if (config.peerNsip) nodes.push(crashState(client.forNode(config.peerNsip), config.peerNsip));
      const [primary, peer] = await Promise.all(nodes);
      return { content: [{ type: "text" as const, text: JSON.stringify({ primary, peer: peer ?? null }, null, 2) }] };
    }
  );

  server.tool(
    "get_system_info",
    "Get NetScaler system information: firmware version, hardware model and serial number, and the license (which features are licensed). For HA state use get_ha_status.",
    {},
    async () => {
      const [version, hardware, license] = await Promise.all([
        client.get("config", "nsversion"),
        client.get("config", "nshardware"),
        client.get("config", "nslicense"),
      ]);

      const result = {
        version: version.nsversion,
        hardware: hardware.nshardware,
        license: license.nslicense,
      };

      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "get_system_stats",
    "Get real-time system stats: CPU and management CPU usage, memory usage, throughput in and out (Mbps), HTTP requests and responses per second, current client TCP connections, and SSL transaction and session totals.",
    {},
    async () => {
      const [ns, http, tcp, ssl] = await Promise.all([
        client.get("stat", "ns"),
        client.get("stat", "protocolhttp"),
        client.get("stat", "protocoltcp"),
        client.get("stat", "ssl"),
      ]);

      const nsStats = ns.ns as Record<string, unknown> | undefined;
      const httpStats = http.protocolhttp as Record<string, unknown> | undefined;
      const tcpStats = tcp.protocoltcp as Record<string, unknown> | undefined;
      const sslStats = ssl.ssl as Record<string, unknown> | undefined;

      const result = {
        cpu_usage_pct: nsStats?.cpuusagepcnt,
        memory_usage_pct: nsStats?.memusagepcnt,
        mgmt_cpu_usage_pct: nsStats?.mgmtcpuusagepcnt,
        rx_mbps: nsStats?.rxmbitsrate,
        tx_mbps: nsStats?.txmbitsrate,
        http_requests_per_sec: httpStats?.httprequestsrate,
        http_responses_per_sec: httpStats?.httpresponsesrate,
        active_tcp_connections: tcpStats?.tcpcurclientconn,
        tcp_established: tcpStats?.tcpcurclientconnestablished,
        ssl_transactions: sslStats?.ssltottransactions,
        ssl_sessions: sslStats?.ssltotsessions,
      };

      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "get_running_config",
    "Retrieve the running configuration as text ('show running config'), redacted, one page at a time. The first line of each page is JSON with total_chars, sha256 and next_offset; call again with offset=next_offset and expected_sha256=sha256 until next_offset is absent. Use search_config to find specific lines without paging.",
    pageArgs,
    async (args) => {
      const response = await client.get("config", "nsrunningconfig");
      const config = (response.nsrunningconfig as Record<string, unknown>)?.response as string ?? "";
      try {
        return { content: [{ type: "text" as const, text: pageText(config, args.offset as number, args.max_chars as number, args.expected_sha256 as string | undefined) }] };
      } catch (err) {
        return { content: [{ type: "text" as const, text: (err as Error).message }], isError: true };
      }
    }
  );

  server.tool(
    "get_saved_config",
    "Retrieve the saved (startup) configuration as text, redacted, paged like get_running_config (follow next_offset with expected_sha256). For whether unsaved changes exist, use get_config_diff.",
    pageArgs,
    async (args) => {
      const response = await client.get("config", "nssavedconfig");
      const config = (response.nssavedconfig as Record<string, unknown>)?.textblob as string ?? "";
      try {
        return { content: [{ type: "text" as const, text: pageText(config, args.offset as number, args.max_chars as number, args.expected_sha256 as string | undefined) }] };
      } catch (err) {
        return { content: [{ type: "text" as const, text: (err as Error).message }], isError: true };
      }
    }
  );

  server.tool(
    "get_config_diff",
    "Check whether the running config has unsaved changes (lost on reboot). Uses the appliance's own changed-since-save flag; a text compare of running vs saved config always differs (devno suffixes, ordering, re-encrypted secrets).",
    {},
    async () => {
      const res = await client.get("config", "nsconfig");
      const c = (res.nsconfig as Record<string, unknown> | undefined) ?? {};
      const times = `Last changed: ${c.lastconfigchangedtime ?? "unknown"}. Last saved: ${c.lastconfigsavetime ?? "unknown"}.`;
      if (c.configchanged === undefined) {
        return { content: [{ type: "text" as const, text: `Unknown: nsconfig returned no configchanged field. ${times}` }] };
      }
      const text = String(c.configchanged).toLowerCase() === "true"
        ? `Running config has UNSAVED changes. They are lost on reboot unless saved (save ns config). ${times}`
        : `No unsaved changes - running config matches saved config. ${times}`;
      return { content: [{ type: "text" as const, text }] };
    }
  );

  server.tool(
    "save_config",
    "Save the running configuration to the startup config (equivalent to 'save ns config'). This persists all unsaved changes so they survive a reboot.",
    {},
    async () => {
      await client.post("nsconfig", { nsconfig: {} }, "save");
      return { content: [{ type: "text" as const, text: "Configuration saved successfully." }] };
    }
  );

  server.tool(
    "create_backup",
    "Take a system backup on the appliance before a change (create system backup). basic = config, certs and licences; full adds more of the filesystem and is larger. The tool names the file mcp_<UTC time>_<random> and returns that exact backup's details. Restore is deliberately not offered. A full backup can outlast the NITRO timeout: the result then says outcome unknown with the filename, so check the backup list before taking another.",
    {
      level: z.enum(["basic", "full"]).default("basic").describe("basic (default) or full."),
      comment: z.string().max(256).optional().describe("Why the backup was taken, e.g. the change ticket."),
    },
    async (args) => {
      const stamp = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
      const filename = `mcp_${stamp}_${randomBytes(3).toString("hex")}`;
      let postError: string | undefined;
      try {
        await client.post("systembackup", { systembackup: { filename, level: args.level, ...(args.comment ? { comment: args.comment } : {}) } }, "create");
      } catch (err) {
        postError = err instanceof Error ? err.message : String(err);
        if (!/^Outcome unknown/.test(postError)) {
          return { content: [{ type: "text" as const, text: `Backup ${filename} failed: ${postError}` }], isError: true };
        }
      }
      // Match on our own generated name; the appliance may add .tgz.
      let row: Record<string, unknown> | undefined;
      let readError: string | undefined;
      try {
        const rows = ((await client.get("config", "systembackup")).systembackup as Record<string, unknown>[] | undefined) ?? [];
        row = rows.find((r) => String(r.filename ?? "").startsWith(filename));
      } catch (err) {
        readError = err instanceof Error ? err.message : String(err);
      }
      const result = row
        ? { outcome: "created", filename, backup: row }
        : { outcome: postError ? "unknown" : "accepted", verification: "indeterminate", filename,
            note: postError ?? `The appliance accepted the request but ${readError ? `the read-back failed (${readError})` : "no backup with this name is listed yet"}. Check with nitro_get config systembackup before taking another.` };
      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }], ...(postError && !row ? { isError: true } : {}) };
    }
  );

  server.tool(
    "list_features",
    "List all NetScaler features and whether they are enabled or disabled.",
    {},
    async () => {
      const response = await client.get("config", "nsfeature");
      return {
        content: [{ type: "text" as const, text: JSON.stringify(response.nsfeature, null, 2) }],
      };
    }
  );

  server.tool(
    "get_syslog",
    "Retrieve NetScaler syslog/audit messages via the NITRO auditmessages API. Returns recent log entries including event messages, errors, warnings, auth failures, HA events, SSL errors, etc. Filter by severity level and/or search term. Use the 'node' parameter to query the peer HA node.",
    {
      severity: z
        .enum(["ALL", "EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFORMATIONAL", "DEBUG"])
        .optional()
        .describe("Filter by syslog severity level. Omit for all levels."),
      search: z
        .string()
        .optional()
        .describe("Text to search for in log messages (case-insensitive). E.g., 'SSL', 'HA', 'LDAP', 'certificate', 'failover'."),
      max_lines: z
        .number()
        .optional()
        .default(200)
        .describe("Maximum number of log messages to return (default: 200). NITRO max is 256."),
      node: nodeParam,
    },
    async (args) => {
      const picked = pickClient(client, config, (args.node as "primary" | "peer") ?? "primary");
      if ("error" in picked) {
        return { content: [{ type: "text" as const, text: picked.error }], isError: true };
      }
      const numMsgs = Math.min((args.max_lines as number) || 200, 256);

      // Build NITRO args string for auditmessages endpoint
      let argsStr = `numofmesgs:${numMsgs}`;
      if (args.severity) {
        argsStr += `,loglevel:${args.severity as string}`;
      }

      try {
        const response = await picked.client.get(
          "config", "auditmessages", undefined,
          `args=${argsStr}`
        );

        const messages = response.auditmessages as Record<string, unknown>[] | undefined;
        if (!messages || messages.length === 0) {
          return {
            content: [{ type: "text" as const, text: `No audit messages returned from ${picked.nsip}. Audit logging may not be configured.` }],
          };
        }

        // Extract the message text from each entry
        let lines = messages
          .map((m) => m.value as string)
          .filter((v) => v && v.trim());

        // Apply search filter if specified
        if (args.search) {
          const term = (args.search as string).toLowerCase();
          lines = lines.filter((l) => l.toLowerCase().includes(term));
        }

        return {
          content: [
            {
              type: "text" as const,
              text: `${lines.length} log entries from ${picked.nsip}:\n\n${lines.join("\n")}`,
            },
          ],
        };
      } catch (err) {
        return {
          content: [{
            type: "text" as const,
            text: `Failed to retrieve audit messages from ${picked.nsip}: ${err instanceof Error ? err.message : String(err)}`,
          }],
          isError: true,
        };
      }
    }
  );

  server.tool(
    "get_nslog_events",
    "Retrieve NetScaler system events via the NITRO nsevents API. Returns timestamped event entries - service UP/DOWN transitions, HA state changes, interface events, config changes, and other system events. More structured than syslog. Use the 'node' parameter to query the peer HA node.",
    {
      search: z
        .string()
        .optional()
        .describe("Text to search for in event entries (case-insensitive). E.g., 'SSL', 'HA', 'DOWN', 'failover', 'CONTOSO'."),
      max_events: z
        .number()
        .optional()
        .default(100)
        .describe("Maximum number of events to return (default: 100)."),
      node: nodeParam,
    },
    async (args) => {
      const picked = pickClient(client, config, (args.node as "primary" | "peer") ?? "primary");
      if ("error" in picked) {
        return { content: [{ type: "text" as const, text: picked.error }], isError: true };
      }
      try {
        const response = await picked.client.get("config", "nsevents");

        const events = response.nsevents as Record<string, unknown>[] | undefined;
        if (!events || events.length === 0) {
          return {
            content: [{ type: "text" as const, text: `No events returned from ${picked.nsip}.` }],
          };
        }

        // Format each event: timestamp + device + text
        let formatted = events.map((e) => {
          const time = e.time ? new Date((e.time as number) * 1000).toISOString() : "unknown";
          const dev = e.devname || "";
          const text = e.text || "";
          const code = e.eventcode || "";
          return `[${time}] [${dev}] (code:${code}) ${text}`;
        });

        // Apply search filter
        if (args.search) {
          const term = (args.search as string).toLowerCase();
          formatted = formatted.filter((l) => l.toLowerCase().includes(term));
        }

        const maxEvents = (args.max_events as number) || 100;
        const recent = formatted.slice(-maxEvents);

        return {
          content: [
            {
              type: "text" as const,
              text: `${recent.length} events from ${picked.nsip} (of ${formatted.length} matching):\n\n${recent.join("\n")}`,
            },
          ],
        };
      } catch (err) {
        return {
          content: [{
            type: "text" as const,
            text: `Failed to retrieve events from ${picked.nsip}: ${err instanceof Error ? err.message : String(err)}`,
          }],
          isError: true,
        };
      }
    }
  );

  server.tool(
    "get_system_file",
    "Read a file from the NetScaler filesystem via NITRO systemfile API. Returns the file content as text. Gzip files (e.g. rotated logs like ns.log.0.gz) are auto-decompressed. Binary files that are not valid UTF-8 after decompression are returned as base64. Large files may timeout. Use the 'node' parameter to read from the peer HA node.",
    {
      filename: z
        .string()
        .describe("Name of the file to read (e.g., 'ns.conf', 'ns.log', 'nsrunning.conf')."),
      filelocation: z
        .string()
        .describe("Directory path on the NetScaler (e.g., '/nsconfig', '/var/log', '/var/nslog', '/nsconfig/ssl')."),
      node: nodeParam,
    },
    async (args) => {
      const picked = pickClient(client, config, (args.node as "primary" | "peer") ?? "primary");
      if ("error" in picked) {
        return { content: [{ type: "text" as const, text: picked.error }], isError: true };
      }
      const filename = encodeURIComponent(args.filename as string);
      const location = encodeURIComponent(args.filelocation as string);

      try {
        const response = await picked.client.get(
          "config", "systemfile", undefined,
          `args=filename:${filename},filelocation:${location}`
        );

        const fileData = (response.systemfile as Record<string, unknown>[] | undefined)?.[0];

        if (!fileData?.filecontent) {
          return {
            content: [{ type: "text" as const, text: `File not found or empty on ${picked.nsip}: ${args.filelocation}/${args.filename}` }],
            isError: true,
          };
        }

        const raw = Buffer.from(fileData.filecontent as string, "base64");
        const { body, note } = renderFileBytes(raw, args.filename as string);

        return {
          content: [
            {
              type: "text" as const,
              text: `File: ${args.filelocation}/${args.filename} on ${picked.nsip}${note}\n\n${body}`,
            },
          ],
        };
      } catch (err) {
        return {
          content: [{
            type: "text" as const,
            text: `Failed to read file ${args.filelocation}/${args.filename} from ${picked.nsip}: ${err instanceof Error ? err.message : String(err)}`,
          }],
          isError: true,
        };
      }
    }
  );
}
