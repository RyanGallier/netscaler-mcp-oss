/**
 * High Availability monitoring and management tools.
 */

import { type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { type NitroClient } from "../client.js";
import { type Config } from "../config.js";

export function registerHATools(server: McpServer, client: NitroClient, config: Config) {
  server.tool(
    "get_ha_status",
    "Get HA pair status from both nodes: state (primary/secondary), firmware build on each node and whether they match, sync status, peer health, last failover reason, and propagation state. Queries both the primary NSIP and the peer NSIP if configured.",
    {},
    async () => {
      // Firmware is extra detail: a failed read leaves it blank rather than failing the HA status.
      const version = (c: NitroClient) =>
        c.get("config", "nsversion")
          .then((r) => (r.nsversion as Record<string, unknown> | undefined)?.version as string | undefined)
          .catch(() => undefined);
      const [primaryResponse, primaryVersion] = await Promise.all([client.get("config", "hanode"), version(client)]);
      const primaryNodes = primaryResponse.hanode as Record<string, unknown>[] | undefined;

      const result: Record<string, unknown> = {
        primary_nsip: config.nsip,
        primary_firmware: primaryVersion,
        primary_node: primaryNodes,
      };

      if (config.peerNsip) {
        try {
          const peerClient = client.forNode(config.peerNsip);
          const [peerResponse, peerVersion] = await Promise.all([peerClient.get("config", "hanode"), version(peerClient)]);
          result.peer_nsip = config.peerNsip;
          result.peer_firmware = peerVersion;
          result.firmware_match = primaryVersion && peerVersion ? peerVersion === primaryVersion : null;
          result.peer_node = peerResponse.hanode;
        } catch (err) {
          result.peer_nsip = config.peerNsip;
          result.peer_error = err instanceof Error ? err.message : String(err);
        }
      }

      return { content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }] };
    }
  );

  server.tool(
    "force_ha_failover",
    "Force an HA failover. The current primary becomes secondary and vice versa. The command is issued against the current primary; the peer NSIP is needed only when the configured node is the secondary. USE WITH CAUTION - this causes a brief traffic interruption.",
    {
      confirm: z.literal("yes").describe("Must pass 'yes' to confirm the failover action."),
      expected_primary: z
        .string()
        .describe("NSIP of the node you expect to be PRIMARY right now (from get_ha_status). The failover is refused if it differs, so a retried call cannot fail back."),
    },
    async (args) => {
      if (args.confirm !== "yes") {
        return {
          content: [{ type: "text" as const, text: "Failover aborted - confirmation not provided." }],
          isError: true,
        };
      }

      // Determine which node is currently primary
      const response = await client.get("config", "hanode");
      const nodes = response.hanode as Record<string, unknown>[] | undefined;
      const localNode = nodes?.[0];
      const localState = (localNode?.state as string)?.toUpperCase();

      let targetClient: NitroClient;
      let targetIp: string;

      if (localState === "PRIMARY") {
        targetClient = client;
        targetIp = config.nsip;
      } else if (localState === "SECONDARY" && config.peerNsip) {
        // Confirm the peer really is PRIMARY rather than assuming it.
        const peerClient = client.forNode(config.peerNsip);
        const peer = await peerClient.get("config", "hanode");
        const peerState = ((peer.hanode as Record<string, unknown>[] | undefined)?.[0]?.state as string)?.toUpperCase();
        if (peerState !== "PRIMARY") {
          return {
            content: [{ type: "text" as const, text: `Failover refused: local node is SECONDARY but peer ${config.peerNsip} reports ${peerState ?? "no state"}, not PRIMARY.` }],
            isError: true,
          };
        }
        targetClient = peerClient;
        targetIp = config.peerNsip;
      } else {
        return {
          content: [
            {
              type: "text" as const,
              text: `Local node (${config.nsip}) is ${localState}, not PRIMARY. Failover needs a PRIMARY local node, or a SECONDARY local node with a configured peer that reports PRIMARY.`,
            },
          ],
          isError: true,
        };
      }

      if (targetIp !== args.expected_primary) {
        return {
          content: [
            {
              type: "text" as const,
              text: `Failover refused: current primary is ${targetIp}, not ${args.expected_primary}. Check get_ha_status before retrying.`,
            },
          ],
          isError: true,
        };
      }

      await targetClient.post("hafailover", { hafailover: { force: true } }, "force");

      return {
        content: [
          {
            type: "text" as const,
            text: `HA failover initiated against ${targetIp}. Allow 30-60 seconds for the transition to complete, then verify with get_ha_status.`,
          },
        ],
      };
    }
  );

  server.tool(
    "force_ha_sync",
    "Force HA configuration sync from primary to secondary. Useful after config changes if auto-sync is delayed or disabled.",
    {},
    async () => {
      await client.post("hasync", { hasync: {} }, "force");

      return {
        content: [
          {
            type: "text" as const,
            text: "HA sync initiated. Check sync status with get_ha_status after a few seconds.",
          },
        ],
      };
    }
  );
}
