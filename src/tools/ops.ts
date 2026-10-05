/**
 * Admin incident tools: kick one Gateway user, block one source IP with an extended ACL, packet capture.
 * All are admin tools (they exist only with an admin account) and each is scoped so it cannot touch
 * anything it did not create.
 */

import { type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { asRows, type NitroClient } from "../client.js";
import { listDir, parseNsTime } from "./system.js";

const ACL_PREFIX = "mcp_block_";
// No leading zeros, so one address always maps to one ACL name.
const OCTET = "(25[0-5]|2[0-4]\\d|1\\d\\d|[1-9]?\\d)";
const IPV4 = new RegExp(`^${OCTET}(\\.${OCTET}){3}$`);
// /24s block_ip_acl refuses, e.g. the network this MCP reaches management from.
// NETSCALER_BLOCK_PROTECT="203.0.113.0/24,198.51.100.0/24"; blocking your own egress locks the MCP out.
// /24s only; malformed entries are dropped rather than guessed at.
const PROTECTED_NETS = (process.env.NETSCALER_BLOCK_PROTECT ?? "")
  .split(",")
  .map((n) => n.trim())
  .filter((n) => /^\d{1,3}(\.\d{1,3}){3}(\/24)?$/.test(n))
  .map((n) => n.split(".").slice(0, 3).join("."));

/** Public IPv4 only: blocking a private or loopback range on a shared pair can cut off management and back ends. */
function publicIp(ip: string): boolean {
  if (!IPV4.test(ip)) return false;
  const [a, b] = ip.split(".").map(Number);
  return !(a === 10 || a === 127 || a === 0 || a >= 224 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127));
}

/** "203.0.113.4" or "203.0.113.0/24" -> NITRO srcipval and a stable ACL name. */
function parseTarget(target: string): { srcipval: string; aclname: string } | null {
  const parts = target.trim().split("/");
  if (parts.length > 2) return null;
  const [ip, mask] = parts;
  if (!publicIp(ip) || PROTECTED_NETS.some((n) => ip.startsWith(`${n}.`))) return null;
  if (mask === undefined || mask === "32") return { srcipval: ip, aclname: `${ACL_PREFIX}${ip.replace(/\./g, "_")}` };
  if (mask !== "24") return null;
  const net = ip.split(".").slice(0, 3).join(".");
  return { srcipval: `${net}.0-${net}.255`, aclname: `${ACL_PREFIX}${net.replace(/\./g, "_")}_0_24` };
}

/**
 * Apply ns acls commits every pending ACL on the box, so refuse if anything we did not create is pending.
 * A missing kernelstate counts as pending (fail closed). Returns the refusal text, or null when clear.
 */
async function foreignPending(client: NitroClient): Promise<string | null> {
  const acls = ((await client.get("config", "nsacl")).nsacl as Record<string, unknown>[] | undefined) ?? [];
  const foreign = acls.filter((a) => !String(a.aclname).startsWith(ACL_PREFIX) && String(a.kernelstate ?? "").toUpperCase() !== "APPLIED");
  if (foreign.length === 0) return null;
  return `Refused, nothing changed: ${foreign.length} ACL(s) not created by this tool are pending (${foreign.map((a) => `${a.aclname}=${a.kernelstate ?? "unknown"}`).join(", ")}). Applying would commit them too. Resolve those first.`;
}

/** Apply after our change; on failure say plainly that the change is sitting un-applied. */
async function apply(client: NitroClient, what: string): Promise<string | null> {
  try {
    await client.post("nsacls", { nsacls: {} }, "apply");
    return null;
  } catch (err) {
    return `${what} is in the config but apply failed (${err instanceof Error ? err.message : String(err)}), so it is PENDING and the next 'apply ns acls' by anyone will commit it. Re-run to retry, or undo it.`;
  }
}

const text = (t: string, isError = false) => ({ content: [{ type: "text" as const, text: t }], ...(isError && { isError }) });

export function registerOpsTools(server: McpServer, client: NitroClient) {
  server.tool(
    "kill_gateway_session",
    "Log one user off everything on Citrix Gateway: their AAA session(s) plus any ICA, PCoIP and RDP connections, which otherwise stay up after the AAA session ends. One username per call; never kills all sessions. Usernames carry no domain, so a name that exists in two tenants on a shared appliance logs off both. The user can sign in again immediately.",
    { username: z.string().trim().min(1).regex(/^[^*?\\]+$/, "no wildcards").describe("Exact username as shown by get_gateway_sessions.") },
    async (args) => {
      const username = args.username as string;
      let aaaFailed = false;
      let killed = 0;
      const kinds: [string, string][] = [
        ["aaasession", "AAA sessions"], ["vpnicaconnection", "ICA connections"],
        ["vpnpcoipconnection", "PCoIP connections"], ["rdpconnections", "RDP connections"],
      ];
      const lines: string[] = [];
      for (const [resource, label] of kinds) {
        try {
          await client.post(resource, { [resource]: { username } }, "kill");
          // The appliance answers a PCoIP kill with success whether or not a connection existed.
          lines.push(`${label}: ${resource === "vpnpcoipconnection" ? "kill accepted (the appliance does not say whether any existed)" : "killed"}`);
          killed++;
        } catch (err) {
          if (resource === "aaasession") aaaFailed = true;
          lines.push(`${label}: not killed (${err instanceof Error ? err.message : String(err)})`);
        }
      }
      // No ICA/PCoIP/RDP connection is normal; a failed AAA kill is not, so it marks the call (and the hosted audit) as an error.
      const result = text(`${username}\n${lines.join("\n")}\nCheck get_gateway_sessions to confirm nothing remains.`);
      return aaaFailed || killed === 0 ? { ...result, isError: true } : result;
    }
  );

  server.tool(
    "block_ip_acl",
    `Drop all traffic from one public source IP (or one /24) at the NetScaler with an extended ACL named ${ACL_PREFIX}<a_b_c_d> (${ACL_PREFIX}<a_b_c>_0_24 for a /24), then apply ACLs. Refuses private/loopback ranges, and refuses to apply if any ACL this tool did not create is pending. Affects every vserver and the NSIP on the appliance, so never block an operator's IP; any /24 listed in NETSCALER_BLOCK_PROTECT is refused. With no priority, rules evaluate in creation order, so an earlier broader ALLOW still wins. The pending-ACL check is point-in-time, not a lock.`,
    {
      target: z.string().describe("Public IPv4 address, or an a.b.c.0/24 range."),
      priority: z.number().int().min(1).max(100000).optional().describe("ACL priority. Omit to evaluate in creation order."),
    },
    async (args) => {
      const t = parseTarget(args.target as string);
      if (!t) return text(`Refused: '${args.target}' is not a public IPv4 address or /24 (or it falls in a NETSCALER_BLOCK_PROTECT /24).`, true);
      const pending = await foreignPending(client);
      if (pending) return text(pending, true);
      const nsacl: Record<string, unknown> = { aclname: t.aclname, aclaction: "DENY", srcip: true, srcipop: "=", srcipval: t.srcipval, state: "ENABLED" };
      if (args.priority) nsacl.priority = args.priority;
      let existed = false;
      try {
        await client.post("nsacl", { nsacl });
      } catch (err) {
        // A retry after an outcome-unknown add finds our ACL already there: go on and apply it.
        const msg = err instanceof Error ? err.message : String(err);
        if (!/already exists/i.test(msg)) return text(/^Outcome unknown/.test(msg) ? `ACL ${t.aclname}: ${msg}` : `ACL ${t.aclname} not created: ${msg}`, true);
        // Apply it only if it is still the block this tool would create: an operator may have disabled or changed it.
        const have = asRows((await client.get("config", `nsacl/${encodeURIComponent(t.aclname)}`)).nsacl)[0] ?? {};
        if (have.aclaction !== "DENY" || have.state !== "ENABLED" || have.srcipval !== t.srcipval) {
          return text(`Refused, nothing changed: ACL ${t.aclname} already exists but is not an enabled DENY for ${t.srcipval} (action ${have.aclaction}, state ${have.state}, source ${have.srcipval}). Fix or remove it first.`, true);
        }
        existed = true;
      }
      const failed = await apply(client, `ACL ${t.aclname} (DENY ${t.srcipval})`);
      if (failed) return text(failed, true);
      return text(`Blocked ${t.srcipval}: ACL ${t.aclname} ${existed ? "was already in place" : "created"} and applied. Undo with unblock_ip_acl.`);
    }
  );

  server.tool(
    "unblock_ip_acl",
    `Remove an ACL created by block_ip_acl (name starts ${ACL_PREFIX}) and apply ACLs. Cannot remove any other ACL.`,
    { target: z.string().describe("The same IPv4 address or /24 that was blocked.") },
    async (args) => {
      const t = parseTarget(args.target as string);
      if (!t) return text(`Refused: '${args.target}' is not a public IPv4 address or /24.`, true);
      const pending = await foreignPending(client);
      if (pending) return text(pending, true);
      try {
        await client.delete("nsacl", t.aclname);
      } catch (err) {
        return text(`No ACL ${t.aclname} removed (${err instanceof Error ? err.message : String(err)}). Nothing changed.`, true);
      }
      const failed = await apply(client, `Removal of ACL ${t.aclname}`);
      if (failed) return text(failed, true);
      return text(`Unblocked ${t.srcipval}: ACL ${t.aclname} removed and ACLs applied.`);
    }
  );

  server.tool(
    "start_nstrace",
    "Start a packet capture limited to 1-4 VIP or client IPs. Writes one rolling file (nf=1) capped at the given size, so disk use stays bounded, but it does NOT stop by itself: call stop_nstrace when done. Trace lands under /var/nstrace on the appliance.",
    {
      ips: z.array(z.string()).min(1).max(4).describe("IPv4 addresses to capture (matches source or destination)."),
      minutes_per_file: z.number().int().min(1).max(60).optional().default(30).describe("Rollover interval for the single file (default 30)."),
      max_mb: z.number().int().min(10).max(2048).optional().default(500).describe("File size cap in MB (default 500)."),
      capture_ssl_keys: z.boolean().optional().default(false).describe("Also capture SSL master keys so the trace can be decrypted. The key file is sensitive: delete it with the trace."),
    },
    async (args) => {
      const ips = args.ips as string[];
      const bad = ips.filter((ip) => !IPV4.test(ip));
      if (bad.length) return text(`Refused: not IPv4: ${bad.join(", ")}.`, true);
      const filter = ips.map((ip) => `CONNECTION.IP.EQ(${ip})`).join(" || ");
      await client.post("nstrace", {
        nstrace: {
          filter, size: 0, nf: 1,
          time: (args.minutes_per_file as number) * 60,
          filesize: args.max_mb,
          capsslkeys: args.capture_ssl_keys ? "ENABLED" : "DISABLED",
        },
      }, "start");
      return text(`nstrace started for ${ips.join(", ")} (one rolling file, ${args.max_mb} MB cap${args.capture_ssl_keys ? ", SSL keys captured" : ""}). Call stop_nstrace when done.`);
    }
  );

  server.tool(
    "stop_nstrace",
    "Stop the running packet capture (box-wide: this stops any running nstrace, including one an operator started by hand). Lists the five most recent trace directories under /var/nstrace with their files (a .sslkeys file holds the TLS keys); match yours by time, then fetch small files such as the keys file with get_system_file.",
    {},
    async () => {
      await client.post("nstrace", { nstrace: {} }, "stop");
      let listing: string;
      try {
        const isDir = (f: Record<string, unknown>) => (f.filemode as string[] | undefined)?.includes("DIRECTORY");
        const epoch = (f: Record<string, unknown>) => parseNsTime(f.filemodifiedtime)?.epoch ?? 0;
        const dirs = (await listDir(client, "/var/nstrace")).filter(isDir).sort((a, b) => epoch(b) - epoch(a)).slice(0, 5);
        const rows = [];
        for (const d of dirs) {
          const files = (await listDir(client, `/var/nstrace/${d.filename}`)).map((f) => ({ file: f.filename, size: f.filesize }));
          rows.push({ dir: `/var/nstrace/${d.filename}`, modified: d.filemodifiedtime, files });
        }
        listing = rows.length ? JSON.stringify(rows, null, 2) : "No trace directories under /var/nstrace.";
      } catch (err) {
        listing = `Could not list /var/nstrace: ${err instanceof Error ? err.message : String(err)}`;
      }
      return text(`nstrace stopped.\n\n${listing}`);
    }
  );
}
