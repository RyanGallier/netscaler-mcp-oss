/**
 * Hosted mode: stateless Streamable HTTP behind App Service authentication.
 *
 * App Service authentication (Easy Auth) validates the Entra token and the
 * calling client before a request reaches this code, then injects the caller's
 * claims as X-MS-CLIENT-PRINCIPAL. This file only reads that header, so it
 * refuses to start unless the platform reports authentication enabled.
 *
 * One endpoint, POST /mcp, serving every appliance; with more than one, each
 * tool takes an `appliance` argument. Targets come from NETSCALER_TARGETS (e.g.
 * "prod,lab"), even for one appliance, each configured with the usual settings under an
 * NS_<TARGET>_ prefix (NS_PROD_NSIP, NS_PROD_PEER_NSIP, NS_PROD_USER, ...).
 */

import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { loadTargets, type Config } from "./config.js";
import { buildServer, type ToolHandler } from "./server.js";
import { redact } from "./redact.js";

const MAX_BODY_BYTES = 256 * 1024;
const SCOPE = "NetScaler.Access";
const READER_ROLE = "NetScaler.Reader";
const ADMIN_ROLE = "NetScaler.Admin";

interface Caller {
  name: string;
  oid: string;
  azp: string;
  roles: string[];
  scopes: string[];
}

interface ClientPrincipal {
  role_typ?: string;
  claims?: { typ: string; val: string }[];
}

function log(event: Record<string, unknown>): void {
  process.stdout.write(JSON.stringify({ ts: new Date().toISOString(), ...event }) + "\n");
}

function send(res: ServerResponse, status: number, message: string, headers: Record<string, string> = {}): void {
  res.writeHead(status, { "Content-Type": "text/plain", ...headers }).end(message);
}

/** Decode Easy Auth's principal header. Claim types may be short (scp) or URI-mapped (.../scope). */
export function readCaller(req: IncomingMessage): Caller | null {
  const header = req.headers["x-ms-client-principal"];
  if (typeof header !== "string") return null;
  try {
    const principal = JSON.parse(Buffer.from(header, "base64").toString("utf8")) as ClientPrincipal;
    const claims = principal.claims ?? [];
    const values = (...types: string[]) =>
      claims
        .filter((c) => types.some((t) => c.typ === t || c.typ.endsWith("/" + t)))
        .map((c) => c.val);
    const roleType = principal.role_typ ?? "roles";
    return {
      name: String(req.headers["x-ms-client-principal-name"] ?? ""),
      oid: values("oid", "objectidentifier")[0] ?? "",
      azp: values("azp", "appid")[0] ?? "",
      roles: claims.filter((c) => c.typ === roleType || c.typ === "roles").map((c) => c.val),
      scopes: values("scp", "scope").flatMap((v) => v.split(" ")),
    };
  } catch {
    return null;
  }
}

class BodyTooLarge extends Error {}

function readBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size <= MAX_BODY_BYTES) chunks.push(chunk);
    });
    req.on("end", () => {
      if (size > MAX_BODY_BYTES) return reject(new BodyTooLarge());
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch (err) {
        reject(err);
      }
    });
    req.on("error", reject);
  });
}

/** Writes an attempt line before each admin-only call and a result line after it. */
function auditAdmin(caller: Caller) {
  return (tool: string, handler: ToolHandler): ToolHandler =>
    async (...args: unknown[]) => {
      const op = randomUUID();
      const started = Date.now();
      log({ audit: "attempt", op, user: caller.name, oid: caller.oid, azp: caller.azp, tool, args: redact(args[0]) });
      let outcome = "ok";
      try {
        const result = await handler(...args);
        if (result?.isError) outcome = `error: ${result.content?.[0]?.text ?? "tool reported an error"}`;
        return result;
      } catch (err) {
        outcome = `error: ${err instanceof Error ? err.message : String(err)}`;
        throw err;
      } finally {
        log({ audit: "result", op, outcome, ms: Date.now() - started });
      }
    };
}

async function handle(req: IncomingMessage, res: ServerResponse, targets: Map<string, Config>): Promise<void> {
  if (!/^\/mcp\/?$/.test(new URL(req.url ?? "/", "http://localhost").pathname)) return send(res, 404, "Not found");
  if (req.method !== "POST") return send(res, 405, "Method not allowed", { Allow: "POST" });

  const caller = readCaller(req);
  const isAdmin = caller?.roles.includes(ADMIN_ROLE) ?? false;
  if (!caller || !caller.scopes.includes(SCOPE) || !(isAdmin || caller.roles.includes(READER_ROLE))) {
    log({ denied: true, user: caller?.name, roles: caller?.roles, scopes: caller?.scopes });
    return send(res, 403, "Forbidden: requires the NetScaler.Access scope and a NetScaler.Reader or NetScaler.Admin role");
  }

  let body: unknown;
  try {
    body = await readBody(req);
  } catch (err) {
    return err instanceof BodyTooLarge ? send(res, 413, "Request body too large") : send(res, 400, "Invalid JSON");
  }
  if (Array.isArray(body)) return send(res, 400, "JSON-RPC batches are not supported");

  const server = buildServer(targets, { allowAdmin: isAdmin, allowForensics: isAdmin, wrapAdmin: auditAdmin(caller) });
  const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
  res.on("close", () => {
    void transport.close();
    void server.close();
  });
  await server.connect(transport);
  await transport.handleRequest(req, res, body);
}

export function startHttp(): void {
  if (process.env.WEBSITE_AUTH_ENABLED?.toLowerCase() !== "true") {
    throw new Error("Hosted mode requires App Service authentication (WEBSITE_AUTH_ENABLED=True); X-MS-CLIENT-PRINCIPAL cannot be trusted without it.");
  }

  const targets = loadTargets();
  for (const [name, config] of targets) {
    const prefix = `NS_${name.toUpperCase()}_`;
    if (config.protocol !== "https" || config.tlsSha256.length === 0) {
      throw new Error(`Target ${name}: hosted mode requires https and ${prefix}TLS_SHA256`);
    }
    if ((config.sshUser || config.forensicsUser) && config.sshSha256.length === 0) {
      throw new Error(`Target ${name}: hosted mode requires ${prefix}SSH_SHA256 when SSH is configured`);
    }
  }
  if (targets.size === 0) throw new Error("NETSCALER_TARGETS lists no targets");

  const port = Number(process.env.PORT ?? 8080);
  createServer((req, res) => {
    handle(req, res, targets).catch((err) => {
      log({ error: err instanceof Error ? err.message : String(err), url: req.url });
      if (!res.headersSent) send(res, 500, "Internal error");
    });
  }).listen(port, () => log({ listening: port, targets: [...targets.keys()] }));
}
