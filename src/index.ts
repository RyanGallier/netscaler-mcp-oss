#!/usr/bin/env node

/**
 * NetScaler/ADC MCP Server
 *
 * Exposes Citrix NetScaler NITRO REST API operations as MCP tools
 * for operational management and troubleshooting of NetScaler HA pairs.
 *
 * Tested against firmware 13.1 builds 62.23, 64.24 and 64.28.
 *
 * Default: stdio, one appliance from NETSCALER_* env vars, or several from
 * NETSCALER_TARGETS, chosen per call. The accounts configured decide the tools:
 * an admin account adds the admin tools, a forensics account the forensic tools.
 * MCP_TRANSPORT=http: hosted mode behind App Service authentication (http.ts).
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig, loadTargets, type Config } from "./config.js";
import { buildServer } from "./server.js";
import { startHttp } from "./http.js";

/** Local mode runs unpinned if asked to; say so, since the credentials go to whoever answers. */
function warnInsecure(config: Config, prefix: string): void {
  const warn = (msg: string) => process.stderr.write(`WARNING: ${msg}\n`);
  if (config.protocol === "http") warn(`${prefix}PROTOCOL=http sends the NITRO password in clear text.`);
  else if (config.tlsSha256.length === 0) warn(`${prefix}TLS_SHA256 is not set: any TLS certificate is accepted, so a machine in the path can capture the NITRO password.`);
  if ((config.sshUser || config.forensicsUser) && config.sshSha256.length === 0) {
    warn(`${prefix}SSH_SHA256 is not set: any SSH host key is accepted, so a machine in the path can capture the SSH password.`);
  }
}

async function main() {
  if (process.env.MCP_TRANSPORT === "http") {
    startHttp();
    return;
  }
  const listed = loadTargets();
  const single = listed.size === 0;
  const targets = single ? new Map([["default", loadConfig()]]) : listed;
  const configs = [...targets.entries()];
  for (const [name, config] of configs) warnInsecure(config, single ? "NETSCALER_" : `NS_${name.toUpperCase()}_`);
  // The credentials an operator is given are the role: an admin tool is offered if any target has its account,
  // and refused for a target without it.
  const server = buildServer(targets, {
    allowAdmin: configs.some(([, c]) => c.adminUser),
    allowForensics: configs.some(([, c]) => c.forensicsUser),
  });
  await server.connect(new StdioServerTransport());
}

main().catch((err) => {
  process.stderr.write(`Fatal: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(1);
});
