/**
 * DNS and GSLB troubleshooting tools.
 */

import { type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { type NitroClient } from "../client.js";

export function registerDNSTools(server: McpServer, client: NitroClient) {
  server.tool(
    "get_dns_config",
    "Get DNS configuration: nameservers, DNS suffix list, and DNS parameters. Shows what DNS servers the NetScaler uses for resolution.",
    {},
    async () => {
      const [nameservers, suffixes, params] = await Promise.allSettled([
        client.get("config", "dnsnameserver"),
        client.get("config", "dnssuffix"),
        client.get("config", "dnsparameter"),
      ]);

      const result: Record<string, unknown> = {};
      if (nameservers.status === "fulfilled") result.nameservers = nameservers.value.dnsnameserver;
      if (suffixes.status === "fulfilled") result.suffixes = suffixes.value.dnssuffix;
      if (params.status === "fulfilled") result.parameters = params.value.dnsparameter;

      return {
        content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
      };
    }
  );

  server.tool(
    "list_gslb_sites",
    "List all GSLB sites with their MEP (Metric Exchange Protocol) status, site IP, public IP, and connectivity state. MEP DOWN between sites is the #1 cause of GSLB failures.",
    {},
    async () => {
      const resp = await client.get("config", "gslbsite");
      return {
        content: [{ type: "text" as const, text: JSON.stringify(resp.gslbsite, null, 2) }],
      };
    }
  );

  server.tool(
    "list_gslb_services",
    "List all GSLB services with their IP, port, site name, state, health monitors, and MEP state. Shows which backend services are participating in GSLB and their health.",
    {},
    async () => {
      const resp = await client.get("config", "gslbservice");
      return {
        content: [{ type: "text" as const, text: JSON.stringify(resp.gslbservice, null, 2) }],
      };
    }
  );

  server.tool(
    "get_gslb_sync_status",
    "Check GSLB configuration sync status across all sites. Shows if configs are in sync or if manual sync is needed.",
    {},
    async () => {
      const resp = await client.get("config", "gslbsyncstatus");
      return {
        content: [{ type: "text" as const, text: JSON.stringify(resp.gslbsyncstatus, null, 2) }],
      };
    }
  );

  server.tool(
    "list_dns_records",
    "List DNS records of a specific type hosted on the NetScaler (ADNS). Supports A, AAAA, CNAME, MX, SRV, and NS record types.",
    {
      type: z.enum(["a", "aaaa", "cname", "mx", "srv", "ns"]).describe("DNS record type."),
      domain: z.string().optional().describe("Filter by domain name. Omit to list all records of this type."),
    },
    async (args) => {
      const typeMap: Record<string, string> = {
        a: "dnsaddrec",
        aaaa: "dnsaaaarec",
        cname: "dnscnamerec",
        mx: "dnsmxrec",
        srv: "dnssrvrec",
        ns: "dnsnsrec",
      };

      const resource = typeMap[args.type as string];
      const domain = args.domain as string | undefined;

      // Filter the collection: aaaa and srv records have no GET-by-name in NITRO.
      const keyField: Record<string, string> = {
        dnsaddrec: "hostname", dnsaaaarec: "hostname", dnscnamerec: "aliasname",
        dnsmxrec: "domain", dnssrvrec: "domain", dnsnsrec: "domain",
      };
      const resp = await client.get("config", resource, domain ? { filter: `${keyField[resource]}:${domain}` } : undefined);

      return {
        content: [{ type: "text" as const, text: JSON.stringify(resp[resource], null, 2) }],
      };
    }
  );
}
