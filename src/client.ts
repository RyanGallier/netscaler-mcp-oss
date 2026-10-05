/**
 * NITRO REST API client for NetScaler/ADC.
 *
 * Handles authentication (header-based), TLS for self-signed NSIPs (pinned by
 * fingerprint when configured, unverified otherwise), and retry with
 * exponential backoff on transient errors. Only GETs are retried after the
 * request may have reached the appliance, so a write is never repeated.
 */

import * as http from "node:http";
import * as https from "node:https";
import * as tls from "node:tls";
import { type Config } from "./config.js";
import { redact, redactText } from "./redact.js";

const MAX_RETRIES = 2;
const RETRY_BASE_DELAY_MS = 1000;
const RETRY_STATUS_CODES = new Set([429, 502, 503, 504]);

export interface NitroResponse {
  errorcode: number;
  message: string;
  severity: string;
  [key: string]: unknown;
}

interface RawResponse {
  status: number;
  statusText: string;
  body: string;
}

function abortError(): Error {
  const err = new Error("Request aborted");
  err.name = "AbortError";
  return err;
}

/**
 * Open a TLS socket and check the peer certificate's SHA-256 fingerprint
 * before any request bytes (including the NITRO credential headers) are sent.
 */
function pinnedSocket(
  host: string,
  port: number,
  allowed: string[],
  signal: AbortSignal
): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({ host, port, rejectUnauthorized: false });
    const onAbort = () => socket.destroy(abortError());
    signal.addEventListener("abort", onAbort, { once: true });
    socket.once("secureConnect", () => {
      signal.removeEventListener("abort", onAbort);
      const fp = socket.getPeerCertificate().fingerprint256?.replace(/:/g, "") ?? "";
      if (allowed.includes(fp)) {
        resolve(socket);
      } else {
        socket.destroy();
        reject(new Error(`TLS certificate fingerprint mismatch for ${host}: got ${fp}`));
      }
    });
    socket.once("error", (err) => {
      signal.removeEventListener("abort", onAbort);
      reject(err);
    });
  });
}

/** NITRO error text can echo request values; scrub it like a response body. */
function redactError(err: Error): Error {
  err.message = redactText(err.message);
  return err;
}

/** A NITRO resource as rows: global parameter resources (sslparameter, systemparameter, auditsyslogparams) return one object, not a list. */
export function asRows(value: unknown): Record<string, unknown>[] {
  return (Array.isArray(value) ? value : value ? [value] : []) as Record<string, unknown>[];
}

export class NitroClient {
  private baseUrl: string;
  private headers: Record<string, string>;
  private timeout: number;
  private config: Config;
  private readOnly: boolean;

  /** readOnly: refuse any write locally (ping and traceroute excepted); the appliance policy is the real limit. */
  constructor(config: Config, readOnly = false) {
    this.config = config;
    this.readOnly = readOnly;
    this.baseUrl = `${config.protocol}://${config.nsip}/nitro/v1`;
    this.headers = {
      "X-NITRO-USER": config.username,
      "X-NITRO-PASS": config.password,
      "Content-Type": "application/json",
    };
    this.timeout = config.timeout;
  }

  /** Build a client targeting a specific NSIP (for peer operations). */
  forNode(nsip: string): NitroClient {
    const peerConfig = { ...this.config, nsip };
    return new NitroClient(peerConfig, this.readOnly);
  }

  /**
   * GET a config or stat resource.
   * Pass rawQueryString for pre-formatted query params (e.g., NITRO args format).
   */
  async get(
    namespace: "config" | "stat",
    resource: string,
    params?: Record<string, string>,
    rawQueryString?: string
  ): Promise<NitroResponse> {
    let url = `${this.baseUrl}/${namespace}/${resource}`;
    if (rawQueryString) {
      url += `?${rawQueryString}`;
    } else if (params) {
      // NITRO rejects an encoded ':' in filter ("Invalid filter in query parameters"), so ':' and ',' stay literal.
      const enc = (v: string) => encodeURIComponent(v).replace(/%3A/gi, ":").replace(/%2C/gi, ",");
      url += `?${Object.entries(params).map(([k, v]) => `${enc(k)}=${enc(v)}`).join("&")}`;
    }
    return this.request("GET", url);
  }

  /** POST to create a resource or invoke an action. */
  async post(
    resource: string,
    body: Record<string, unknown>,
    action?: string
  ): Promise<NitroResponse> {
    let url = `${this.baseUrl}/config/${resource}`;
    if (action) {
      url += `?action=${action}`;
    }
    return this.request("POST", url, body);
  }

  /** PUT to update a resource or add a binding; resource may carry an encoded /name. */
  async put(
    resource: string,
    body: Record<string, unknown>
  ): Promise<NitroResponse> {
    const url = `${this.baseUrl}/config/${resource}`;
    return this.request("PUT", url, body);
  }

  /** DELETE a resource, or a global binding when name is omitted. rawQuery is pre-encoded, e.g. "args=k:v". */
  async delete(
    resource: string,
    name?: string,
    rawQuery?: string
  ): Promise<NitroResponse> {
    let url = `${this.baseUrl}/config/${resource}${name ? `/${encodeURIComponent(name)}` : ""}`;
    if (rawQuery) url += `?${rawQuery}`;
    return this.request("DELETE", url);
  }

  private async request(
    method: string,
    url: string,
    body?: Record<string, unknown>
  ): Promise<NitroResponse> {
    let lastError: Error | null = null;
    const idempotent = method === "GET";
    if (this.readOnly && !idempotent && !/\/config\/(ping6?|traceroute6?)(\?|$)/.test(url)) {
      throw new Error(`Refused: this tool holds only the read-only NITRO account and cannot send ${method}.`);
    }

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeout);

      try {
        const response = await this.send(method, url, body, controller.signal);

        // Clear timer before any retry delay to prevent leak
        clearTimeout(timer);

        if (RETRY_STATUS_CODES.has(response.status) && idempotent && attempt < MAX_RETRIES) {
          const delay = RETRY_BASE_DELAY_MS * Math.pow(2, attempt);
          await new Promise((r) => setTimeout(r, delay));
          continue;
        }

        let data: NitroResponse;
        try {
          data = (response.body ? JSON.parse(response.body) : {}) as NitroResponse;
        } catch {
          // A write that got a 2xx (or a proxy page) we cannot read may still have been applied.
          if (!idempotent) throw new Error(`Outcome unknown: unreadable reply (HTTP ${response.status}). The change may have been applied; check its state before retrying.`);
          throw new Error(`Unreadable NITRO reply (HTTP ${response.status})`);
        }

        if (response.status < 200 || response.status >= 300) {
          const msg =
            data.message ?? `NITRO error ${response.status}: ${response.statusText}`;
          throw new Error(msg);
        }

        // NITRO returns errorcode 0 on success
        if (data.errorcode && data.errorcode !== 0) {
          throw new Error(`NITRO errorcode ${data.errorcode}: ${data.message}`);
        }

        return redact(data);
      } catch (err) {
        clearTimeout(timer);
        lastError = err instanceof Error ? err : new Error(String(err));

        // A timeout may fire after the appliance acted, so only GETs retry it.
        // ECONNREFUSED means nothing was sent, so any method may retry.
        if (
          attempt < MAX_RETRIES &&
          ((idempotent && (lastError.name === "AbortError" || (err as NodeJS.ErrnoException).code === "ECONNRESET")) ||
            (err as NodeJS.ErrnoException).code === "ECONNREFUSED")
        ) {
          const delay = RETRY_BASE_DELAY_MS * Math.pow(2, attempt);
          await new Promise((r) => setTimeout(r, delay));
          continue;
        }
        // A write with no reply may have been applied: say so rather than look like a clean failure.
        if (!idempotent && (lastError.name === "AbortError" || ["ECONNRESET", "EPIPE"].includes((err as NodeJS.ErrnoException).code ?? ""))) {
          throw new Error(`Outcome unknown: no reply from the appliance (${lastError.message}). The change may have been applied; check its state before retrying.`);
        }
        throw redactError(lastError);
      }
    }

    throw lastError ?? new Error("Request failed after retries");
  }

  private async send(
    method: string,
    url: string,
    body: Record<string, unknown> | undefined,
    signal: AbortSignal
  ): Promise<RawResponse> {
    const target = new URL(url);
    const secure = target.protocol === "https:";
    const options: https.RequestOptions = { method, headers: this.headers, signal };

    if (secure && this.config.tlsSha256.length > 0) {
      const port = Number(target.port) || 443;
      const socket = await pinnedSocket(target.hostname, port, this.config.tlsSha256, signal);
      options.createConnection = () => socket;
    } else if (secure) {
      // Unpinned (local stdio use): NSIP management certs are self-signed.
      options.rejectUnauthorized = false;
    }

    return new Promise((resolve, reject) => {
      let req: http.ClientRequest;
      try {
        req = (secure ? https : http).request(target, options, (res) => {
        let data = "";
        res.setEncoding("utf8");
        res.on("data", (chunk: string) => (data += chunk));
        res.on("end", () =>
          resolve({ status: res.statusCode ?? 0, statusText: res.statusMessage ?? "", body: data })
        );
        res.on("error", reject);
        });
      } catch (err) {
        (options.createConnection as (() => tls.TLSSocket) | undefined)?.().destroy();
        return reject(err);
      }
      req.on("error", reject);
      if (body) req.write(JSON.stringify(body));
      req.end();
    });
  }
}
