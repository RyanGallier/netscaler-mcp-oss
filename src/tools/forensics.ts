/**
 * Root forensic tools over SSH, for crash and attack investigation.
 *
 * Each tool sends one fixed command shape, built from validated tokens, as the
 * dedicated forensics account (NETSCALER_FORENSICS_USER, or NS_<NAME>_FORENSICS_USER
 * per target, CLI-only). That
 * account's command policy must allow exactly the shapes in FORENSIC_POLICY,
 * and those commands run as root on the appliance. Registered only when the
 * forensics account is configured; admin tier (audited in hosted mode).
 */

import { type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { NO_PEER, type Config } from "../config.js";
import { redactForensic } from "../redact.js";
import { runSshCommand } from "../ssh.js";

/** `<daemon>-<pid>` or `<n>/<daemon>-<pid>` under /var/core: 13.1 writes cores to both, per kern.corefile. */
const CORE = /^([0-9]{1,4}\/)?[a-z][a-z0-9_]{1,31}-[0-9]{1,7}$/;
/** Literal text to look for in a core; no leading dash, so grep never reads it as an option. */
const MARKER = /^[A-Za-z0-9_.:/=@][A-Za-z0-9_.:/=@-]{2,63}$/;

/** The command policy the forensics account needs, one alternative per tool. Published in docs/local-mode.md. */
export const FORENSIC_POLICY =
  "^shell (gdb -nx -batch -ex bt /netscaler/([a-z][a-z0-9_]{1,31}) /var/core/([0-9]{1,4}/)?\\2-[0-9]{1,7}" +
  "|grep -a -o -b -E -m [0-9]{1,2} \\[\\[:print:\\]\\]\\{0,128\\}[A-Za-z0-9_.:/=@][A-Za-z0-9_.:/=@-]{2,63}\\[\\[:print:\\]\\]\\{0,128\\} /var/core/([0-9]{1,4}/)?[a-z][a-z0-9_]{1,31}-[0-9]{1,7}" +
  "|cat /tmp/aaad\\.debug|ls -lR /var/core)$";

export function backtraceCommand(core: string): string {
  return `shell gdb -nx -batch -ex bt /netscaler/${core.split("/").pop()!.replace(/-[0-9]+$/, "")} /var/core/${core}`;
}

/** The window is printable characters only: the appliance CLI drops any output line holding other bytes. */
export function searchCommand(core: string, marker: string, maxLines: number): string {
  return `shell grep -a -o -b -E -m ${maxLines} [[:print:]]{0,128}${marker}[[:print:]]{0,128} /var/core/${core}`;
}

export const CAPTURE_COMMAND = "shell cat /tmp/aaad.debug";
/** Listed over SSH: NITRO shows an account only the /var/core entries it may download, and the read account may not. */
export const LIST_CORES_COMMAND = "shell ls -lR /var/core";

/** grep -o -b output lines ("offset:text"); anything else (CLI chatter) is dropped. */
export function extractHits(stdout: string): { offset: number; text: string }[] {
  return stdout
    .split(/\r?\n/)
    .map((line) => /^(\d+):(.*)$/.exec(line))
    .filter((m): m is RegExpExecArray => m !== null)
    .map((m) => ({ offset: Number(m[1]), text: m[2] }));
}

/** Drop the appliance CLI's own lines: " Done", and the bare "ERROR:" it prints when a command exits non-zero. */
export const cliOutput = (s: string) => s.split(/\r?\n/).filter((l) => !/^\s*Done\s*$/.test(l) && !/^ERROR:\s*$/.test(l)).join("\n").trim();

const text = (t: string, isError = false) => ({ content: [{ type: "text" as const, text: t }], ...(isError && { isError }) });

export function registerForensicsTools(server: McpServer, config: Config) {
  if (!config.forensicsUser) return;
  const account = { user: config.forensicsUser, pass: config.forensicsPass };
  const node = z.enum(["primary", "peer"]).optional().describe("Which HA node: primary (default) or peer.");
  const hostFor = (n?: string) => (n === "peer" ? config.peerNsip : config.nsip);
  const core = z.string().regex(CORE, "must look like nsaaad-1234 or 3/nsaaad-1234 (a core already compressed to .gz cannot be read in place)").describe("Core file from the core listing: <daemon>-<pid> or <n>/<daemon>-<pid>, e.g. nsaaad-41203 or 3/nsaaad-41203.");

  const run = async (n: string | undefined, command: string, opts: Parameters<typeof runSshCommand>[4]) => {
    const host = hostFor(n);
    if (!host) throw new Error(NO_PEER);
    return runSshCommand(config, account, host, command, opts);
  };

  server.tool(
    "get_core_backtrace",
    "Crash forensics. With no core: list /var/core (all daemons, ls -lR). With a core: run gdb on it as root and return the faulting stack (`bt`) of the crashing thread. Uses the forensics SSH account; runs at most 120 s.",
    { core: core.optional(), node },
    async (args) => {
      if (!args.core) {
        try {
          const r = await run(args.node, LIST_CORES_COMMAND, { timeoutMs: 30_000, maxBytes: 256 * 1024 });
          return text(`${cliOutput(r.stdout)}\n\nPass a core as <name> (top level) or <dir>/<name>. gdb reads only uncompressed cores named <daemon>-<pid>.`);
        } catch (err) {
          return text(`Listing failed: ${err instanceof Error ? err.message : String(err)}`, true);
        }
      }
      try {
        const r = await run(args.node, backtraceCommand(args.core), { timeoutMs: 120_000, maxBytes: 256 * 1024 });
        const out = redactForensic(`${cliOutput(r.stdout)}${r.stderr ? `\nstderr: ${r.stderr}` : ""}`);
        return text(r.cut ? `${out}\n[output cut at 256 KB]` : out);
      } catch (err) {
        return text(`gdb failed or timed out: ${err instanceof Error ? err.message : String(err)}`, true);
      }
    }
  );

  server.tool(
    "search_core",
    "Crash forensics: search a core file for a marker (an issuer, a NameID, a URL, a payload fragment; a . matches any character) as root and return each hit's byte offset with up to 128 readable characters either side (the context stops at the first unprintable byte). max_lines caps matching lines of the binary file (grep -m), not hits; output is capped at 64 KB. Uses the forensics SSH account; runs at most 120 s.",
    {
      core,
      marker: z.string().regex(MARKER, "3-64 characters from A-Z a-z 0-9 _ . : / = @ -, not starting with -").describe("Literal text to find."),
      max_lines: z.number().int().min(1).max(20).default(5).describe("Matching lines of the core to read (1-20)."),
      node,
    },
    async (args) => {
      try {
        const r = await run(args.node, searchCommand(args.core, args.marker, args.max_lines), { timeoutMs: 120_000, maxBytes: 64 * 1024 });
        const hits = extractHits(r.stdout);
        if (!hits.length) {
          const failed = r.stderr.trim() || /^(ERROR: \S|grep: )/m.test(r.stdout);
          return text(redactForensic(failed ? `Search did not run cleanly: ${r.stderr.trim() || cliOutput(r.stdout)}` : `No match for ${args.marker} in ${args.core}.`), !!failed);
        }
        const out = hits.map((h) => `@${h.offset}: ${h.text}`).join("\n");
        return text(redactForensic(r.cut ? `${out}\n[output cut at 64 KB]` : out));
      } catch (err) {
        return text(`Search failed or timed out: ${err instanceof Error ? err.message : String(err)}`, true);
      }
    }
  );

  server.tool(
    "capture_aaad_debug",
    "Capture the authentication daemon's debug stream (/tmp/aaad.debug: nFactor, LDAP, SAML, RADIUS decisions) for a fixed window, while you reproduce a logon. A second reader on the same pipe (another caller, or an operator's own cat) splits the stream, so a capture can miss lines. Output is redacted and capped at 1 MB read, 60,000 characters returned (the most recent). Uses the forensics SSH account.",
    {
      seconds: z.number().int().min(5).max(120).default(30).describe("How long to capture (5-120 s)."),
      filter: z.string().max(200).optional().describe("Case-insensitive substring; only lines containing it are returned."),
      node,
    },
    async (args) => {
      let r;
      try {
        r = await run(args.node, CAPTURE_COMMAND, { timeoutMs: args.seconds * 1000, maxBytes: 1024 * 1024, window: true });
      } catch (err) {
        return text(`Capture failed: ${err instanceof Error ? err.message : String(err)}`, true);
      }
      const want = args.filter?.toLowerCase();
      const lines = cliOutput(r.stdout).split("\n").filter((l) => l && (!want || l.toLowerCase().includes(want)));
      const body = redactForensic(lines.join("\n"));
      const shown = body.length > 60_000 ? body.slice(-60_000) : body;
      const note = r.cut === "bytes" ? "stopped at 1 MB" : r.cut === "window" ? `${args.seconds} s window` : `the command ended early (exit ${r.exitCode})${r.stderr.trim() ? `: ${redactForensic(r.stderr.trim())}` : ""}`;
      return text(`${lines.length} lines (${note}${shown.length < body.length ? ", showing the most recent 60,000 characters" : ""}). A second reader on the pipe would have split this stream.\n\n${shown}`);
    }
  );
}
