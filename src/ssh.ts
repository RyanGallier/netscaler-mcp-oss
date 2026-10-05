/**
 * SSH runner for NetScaler CLI commands that NITRO REST does not expose.
 *
 * Primary use case: `nsconmsg` - per-PPE counter archaeology and historical
 * newnslog ring-buffer reads that the NITRO auditmessages/nsevents APIs do
 * not surface.
 *
 * Security posture:
 * - Each caller passes its own dedicated, CLI-only SSH account (nsconmsg or
 *   forensics), distinct from the NITRO accounts. The forensics policy allows
 *   exactly the shapes its tools build; the nsconmsg policy allows exactly the
 *   four nsconmsg shapes its tool builds.
 * - Host keys are pinned when sshSha256 is configured (required in hosted
 *   mode); otherwise any host key is accepted, matching local stdio use
 *   against known NSIPs on a trusted segment.
 * - One-shot exec per invocation (no persistent session, no shell).
 */

import { createHash } from "node:crypto";
import { Client } from "ssh2";
import { type Config } from "./config.js";

export interface SshResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: string | null;
  /** Set when the output was cut short: the capture window ended or the byte cap was hit. */
  cut?: "window" | "bytes";
}

export interface SshOptions {
  timeoutMs?: number;
  /** Close the connection and return what was read once stdout reaches this many bytes. */
  maxBytes?: number;
  /** Treat the timeout as the end of a capture window: return the output instead of failing. */
  window?: boolean;
}

export async function runSshCommand(
  config: Config,
  account: { user: string; pass: string },
  host: string,
  command: string,
  opts: SshOptions = {}
): Promise<SshResult> {
  if (!account.user || !account.pass) throw new Error("SSH account not configured.");

  const effectiveTimeout = opts.timeoutMs ?? config.sshTimeout;

  return new Promise<SshResult>((resolve, reject) => {
    const conn = new Client();
    let stdout = "";
    let stdoutBytes = 0;
    let stderr = "";
    let settled = false;
    let started = false; // the command is running; a window that ends before this is a connect failure

    // Closing the connection ends the remote command (verified for cat on 13.1).
    const stop = () => {
      try {
        conn.end();
      } catch {
        /* ignore */
      }
    };

    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      stop();
      if (opts.window && started) resolve({ stdout, stderr, exitCode: null, signal: null, cut: "window" });
      else reject(new Error(`SSH command timed out after ${effectiveTimeout}ms: ${command}`));
    }, effectiveTimeout);

    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn();
    };

    conn.on("ready", () => {
      conn.exec(command, (err, stream) => {
        if (err) {
          settle(() => {
            conn.end();
            reject(err);
          });
          return;
        }

        stream.on("close", (code: number | null, signal: string | null) => {
          settle(() => {
            conn.end();
            resolve({ stdout, stderr, exitCode: code, signal });
          });
        });

        started = true;
        stream.on("data", (data: Buffer) => {
          if (settled) return;
          stdout += data.toString("utf-8");
          stdoutBytes += data.length;
          if (opts.maxBytes && stdoutBytes >= opts.maxBytes) {
            settle(() => {
              stop();
              resolve({ stdout, stderr, exitCode: null, signal: null, cut: "bytes" });
            });
          }
        });

        stream.stderr.on("data", (data: Buffer) => {
          if (settled || stderr.length > 64 * 1024) return;
          stderr += data.toString("utf-8");
        });
      });
    });

    conn.on("error", (err) => {
      settle(() => reject(err));
    });

    conn.connect({
      host,
      port: config.sshPort,
      username: account.user,
      password: account.pass,
      readyTimeout: opts.window ? config.sshTimeout : effectiveTimeout,
      // ssh2 passes the raw host key; hash it to the ssh-keygen -l form.
      hostVerifier: (key: Buffer) =>
        config.sshSha256.length === 0 ||
        config.sshSha256.includes(createHash("sha256").update(key).digest("base64").replace(/=+$/, "")),
    });
  });
}

/**
 * Reject inputs that could break out of the intended single command.
 * NetScaler CLI accepts values with spaces (quoted), but we never forward
 * user input verbatim to a shell - each call is a one-shot exec with the
 * command we construct. Still, defense in depth: refuse metacharacters.
 */
export function assertSafeArg(value: string, label: string): void {
  // Block shell metachars, quote manipulation, newlines, and backtick.
  // Allow alphanumerics, dash, underscore, dot, slash, colon, equals, plus,
  // percent, comma, at - the set nsconmsg -g patterns and log paths need.
  const bad = /[;&|`$\n\r\\"'<>(){}\[\]*?!#~\s]/;
  if (bad.test(value)) {
    throw new Error(
      `Invalid characters in ${label}: ${JSON.stringify(value)} - metacharacters and whitespace are not permitted.`
    );
  }
}
