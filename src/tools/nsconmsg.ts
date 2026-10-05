/**
 * nsconmsg SSH tool - exposes the NetScaler `nsconmsg` CLI via a
 * single-shot SSH exec. Covers gaps NITRO REST does not expose:
 *   - per-PPE counter tree with -g pattern filter
 *   - live newnslog ring buffer (event stream, current/stats counters)
 *   - TCP RST reason-code counters (tcp_err_rst_*)
 *   - AAA/auth counter breakdowns
 *
 * Strict command whitelist - only the four forms below are allowed:
 *   nsconmsg -K <logfile> -d event [-s disptime=1]
 *   nsconmsg -K <logfile> -d current [-g <group>]
 *   nsconmsg -K <logfile> -d stats
 *   nsconmsg -d oldconmsg -s ConLb=2
 *
 * The `filter` param is applied client-side in JS after output is received,
 * NOT piped through a shell `grep`. This keeps the SSH exec a single literal
 * argv with no shell interpretation.
 *
 * Rotated counter logs (/var/nslog/newnslog.N.tar.gz) are refused: on 13.1
 * `nsconmsg -K <archive>` decompresses and extracts it in place under
 * /var/nslog (a 31 MB archive became a 244 MB .tar plus a directory), which a
 * read tool must not do. `-K pipe` does not read stdin on 13.1 either.
 */

import { type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { NO_PEER, type Config } from "../config.js";
import { runSshCommand, assertSafeArg } from "../ssh.js";
import { redactText } from "../redact.js";

const DEFAULT_LOGFILE = "/var/nslog/newnslog";
/** The only logs the tool opens; the published command policy allows the same names. */
const LOGFILE = /^\/var\/nslog\/newnslog(\.[0-9]{1,4})?$/;
/** The command policy the nsconmsg account needs: exactly the four forms below. Published in docs/local-mode.md. */
export const NSCONMSG_POLICY =
  "^shell nsconmsg (-K /var/nslog/newnslog(\\.[0-9]{1,4})? (-d event( -s disptime=1)?|-d current( -g [A-Za-z0-9_.-]+)?|-d stats)|-d oldconmsg -s ConLb=2)$";
const DEFAULT_MAX_LINES = 500;
const MAX_LINES_CAP = 5000;
const MAX_BODY_CHARS = 90_000;
const LIVE_WINDOW_MS = 15_000;

export function registerNsconmsgTools(server: McpServer, config: Config) {
  if (!config.sshUser) return;
  server.tool(
    "run_nsconmsg",
    "Run the NetScaler CLI `nsconmsg` command via SSH to pull per-PPE counters and live events from newnslog. Covers gaps the NITRO REST API does not expose: tcp_err_rst_* reason codes, detailed AAA/SAML counters, per-PPE breakdown. Reads the live /var/nslog/newnslog. Rotated archives (newnslog.N.tar.gz) are refused, because nsconmsg would decompress them on the appliance's disk. Uses the dedicated nsconmsg SSH account, whose command policy allows only nsconmsg.",
    {
      mode: z
        .enum(["event", "current", "stats", "oldconmsg"])
        .describe(
          "nsconmsg display mode. 'event' = newnslog event stream. 'current' = live counters (pairs with counter_group). 'stats' = full stats dump. 'oldconmsg' = legacy ConLb=2 view."
        ),
      counter_group: z
        .string()
        .optional()
        .describe(
          "Counter group pattern for mode=current (maps to `-g <group>`). Examples: 'aaa', 'tcp_err', 'saml', 'appfw', 'ssl_tot'. Alphanumerics, dash, underscore, dot only - no spaces or shell metacharacters."
        ),
      logfile: z
        .string()
        .optional()
        .describe(
          `newnslog file path for mode=event/current/stats (maps to -K). Default: ${DEFAULT_LOGFILE}. Only /var/nslog/newnslog or an uncompressed /var/nslog/newnslog.<n>; rotated archives (.tar.gz, .tar) are refused, because nsconmsg would decompress them in place.`
        ),
      disptime: z
        .boolean()
        .optional()
        .describe(
          "For mode=event, include event timestamps via `-s disptime=1`. Default: true."
        ),
      filter: z
        .string()
        .optional()
        .describe(
          "Case-insensitive substring to filter output lines after receipt (applied client-side, not piped to shell). E.g., 'errno', 'VRID', 'PPE-0'."
        ),
      max_lines: z
        .number()
        .int()
        .min(1)
        .optional()
        .describe(
          `Maximum output lines to return after filtering (default: ${DEFAULT_MAX_LINES}, cap: ${MAX_LINES_CAP}). Lines are taken from the end of the (filtered) output - i.e., most recent.`
        ),
      node: z
        .enum(["primary", "peer"])
        .optional()
        .describe(
          "Which HA node to SSH to: 'primary' (default) is the appliance's NSIP, 'peer' its configured peer NSIP."
        ),
      timeout_ms: z
        .number()
        .int()
        .min(5000)
        .max(600000)
        .optional()
        .describe(
          "mode=event and stats: the SSH command timeout (ms), default the configured SSH timeout (30000 unless changed); use more (e.g. 120000) for stats on a busy node. mode=current and oldconmsg are live displays that never end on their own: this is how long to watch them, default 15000. Range 5000-600000."
        ),
    },
    async (args) => {
      const nodeChoice = args.node ?? "primary";
      const host = nodeChoice === "peer" ? config.peerNsip : config.nsip;
      if (!host) {
        return {
          content: [
            {
              type: "text" as const,
              text: nodeChoice === "peer" ? NO_PEER : "Cannot target node 'primary': no NSIP is configured.",
            },
          ],
          isError: true,
        };
      }

      // Build the allowed command form strictly from validated args.
      // Prefix with `shell` because nsconmsg is a BSD binary at
      // /netscaler/nsconmsg - not a klish command. `shell <cmd>` passes
      // the full string to BSD and returns output non-interactively.
      // The remote cmdPolicy regex (if the account is hardened) must
      // match the full joined string starting with "shell nsconmsg".
      // Never interpolate user input into a shell string.
      const cmdParts: string[] = ["shell", "nsconmsg"];

      if (args.mode === "oldconmsg") {
        // Exactly one allowed form for oldconmsg.
        cmdParts.push("-d", "oldconmsg", "-s", "ConLb=2");
        if (args.counter_group || args.logfile || args.disptime !== undefined) {
          return errText(
            "mode=oldconmsg does not accept counter_group, logfile, or disptime."
          );
        }
      } else {
        const logfile = args.logfile ?? DEFAULT_LOGFILE;
        try {
          assertSafeArg(logfile, "logfile");
          if (/\.(tar|gz|tgz)$/i.test(logfile)) {
            throw new Error(`Refused: ${logfile} is a rotated archive. nsconmsg decompresses and extracts archives in place on the appliance's disk, so this read tool does not open them.`);
          }
          if (!LOGFILE.test(logfile)) {
            throw new Error(`logfile must be /var/nslog/newnslog or an uncompressed /var/nslog/newnslog.<n>: ${logfile}`);
          }
        } catch (e) {
          return errText((e as Error).message);
        }
        cmdParts.push("-K", logfile);

        if (args.mode === "event") {
          cmdParts.push("-d", "event");
          const wantDisptime = args.disptime ?? true;
          if (wantDisptime) cmdParts.push("-s", "disptime=1");
          if (args.counter_group) {
            return errText("mode=event does not accept counter_group.");
          }
        } else if (args.mode === "current") {
          cmdParts.push("-d", "current");
          if (args.counter_group) {
            try {
              assertSafeArg(args.counter_group, "counter_group");
              if (!/^[A-Za-z0-9_.-]+$/.test(args.counter_group)) throw new Error("counter_group allows letters, digits, '_', '.' and '-' only.");
            } catch (e) {
              return errText((e as Error).message);
            }
            cmdParts.push("-g", args.counter_group);
          }
        } else if (args.mode === "stats") {
          cmdParts.push("-d", "stats");
          if (args.counter_group) {
            return errText("mode=stats does not accept counter_group.");
          }
        }
      }

      // ssh2 exec takes a string; since no args contain spaces or shell
      // metacharacters (enforced by assertSafeArg), joining with single
      // spaces is safe and produces a deterministic command line.
      const command = cmdParts.join(" ");

      let result;
      try {
        // current and oldconmsg redraw until stopped, so they run as a capture window (lab-verified on 13.1-64.28).
        const live = args.mode === "current" || args.mode === "oldconmsg";
        result = await runSshCommand(config, { user: config.sshUser, pass: config.sshPass }, host, command,
          live ? { timeoutMs: args.timeout_ms ?? LIVE_WINDOW_MS, window: true, maxBytes: 4 * 1024 * 1024 } : { timeoutMs: args.timeout_ms });
      } catch (err) {
        return errText(
          `SSH exec failed against ${host}: ${
            err instanceof Error ? err.message : String(err)
          }`
        );
      }

      // Apply filter + max_lines client-side.
      const allLines = result.stdout.split(/\r?\n/);
      const filterLower = args.filter?.toLowerCase();
      const filtered = filterLower
        ? allLines.filter((l) => l.toLowerCase().includes(filterLower))
        : allLines;

      const cap = Math.min(args.max_lines ?? DEFAULT_MAX_LINES, MAX_LINES_CAP);
      const tail = filtered.length > cap ? filtered.slice(-cap) : filtered;

      const header = [
        `host: ${host} (${nodeChoice})`,
        `command: ${command}`,
        result.cut ? `stopped: ${result.cut === "window" ? "end of the watch window" : "4 MB read"}` : `exit: ${result.exitCode}${result.signal ? ` signal=${result.signal}` : ""}`,
        `lines: total=${allLines.length} filtered=${filtered.length} returned=${tail.length}`,
        result.stderr.trim() ? `stderr: ${redactText(result.stderr.trim())}` : "",
      ]
        .filter(Boolean)
        .join("\n");

      // Keep the most recent lines if the text is still long; the server-wide cap would keep the oldest.
      const joined = redactText(tail.join("\n"));
      const body = joined.length > MAX_BODY_CHARS ? joined.slice(-MAX_BODY_CHARS) : joined;

      return {
        content: [
          { type: "text" as const, text: `${header}${body.length < joined.length ? `\n(cut to the most recent ${MAX_BODY_CHARS.toLocaleString("en-US")} characters)` : ""}\n\n${body}` },
        ],
        ...(!result.cut && result.exitCode !== 0 && { isError: true }),
      };
    }
  );
}

function errText(msg: string) {
  return { content: [{ type: "text" as const, text: `Error: ${msg}` }], isError: true };
}
