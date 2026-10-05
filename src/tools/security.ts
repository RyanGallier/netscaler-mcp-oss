/**
 * Security posture reads for incident response: who can administer the appliance,
 * who is logged in to management now, and which IPs expose the management plane.
 */

import { type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { asRows, type NitroClient } from "../client.js";

type Row = Record<string, unknown>;
const BUILTIN_POLICIES = new Set(["superuser", "read-only", "operator", "network", "sysadmin"]);
const text = (t: unknown) => ({ content: [{ type: "text" as const, text: typeof t === "string" ? t : JSON.stringify(t, null, 2) }] });

/** Superuser in all but name: the built-in, or a custom ALLOW policy whose cmdspec matches everything. */
export function allowsAll(policy: Row | undefined, name: string): boolean {
  if (name === "superuser") return true;
  return policy?.action === "ALLOW" && /^\^?\(?\.[*+]\)?\$?$/.test(String(policy.cmdspec ?? "").trim());
}

/** Reads one resource; a failure is recorded in errors so a partial audit never looks complete. */
async function rows(client: NitroClient, resource: string, errors: string[]): Promise<Row[]> {
  try {
    return asRows((await client.get("config", resource))[resource.split("/")[0]]) as Row[];
  } catch (err) {
    errors.push(`${resource}: ${err instanceof Error ? err.message : String(err)}`);
    return [];
  }
}

export function registerSecurityTools(server: McpServer, client: NitroClient) {
  server.tool(
    "audit_admin_access",
    "Audit who can administer this NetScaler: every system user and group, their command policies (direct and via group), which accounts are superuser-equivalent, custom command policies, local versus external auth, current management sessions with client IPs, and system auth parameters. Use after a suspected compromise to spot unexpected accounts, policies or sessions.",
    {},
    async () => {
      const errors: string[] = [];
      const [users, groups, policies, sessions, params] = await Promise.all([
        rows(client, "systemuser", errors), rows(client, "systemgroup", errors), rows(client, "systemcmdpolicy", errors),
        rows(client, "systemsession", errors), rows(client, "systemparameter", errors),
      ]);

      const policyByName = new Map(policies.map((p) => [String(p.policyname), p]));
      const custom = policies.filter((p) => !BUILTIN_POLICIES.has(String(p.policyname)) && !(Array.isArray(p.builtin) && p.builtin.length));

      const groupPolicies = new Map<string, string[]>();
      await Promise.all(groups.map(async (g) => {
        const name = String(g.groupname);
        const b = await rows(client, `systemgroup_systemcmdpolicy_binding/${encodeURIComponent(name)}`, errors);
        groupPolicies.set(name, b.map((r) => String(r.policyname)));
      }));

      const userReport = await Promise.all(users.map(async (u) => {
        const name = String(u.username);
        const [pol, grp] = await Promise.all([
          rows(client, `systemuser_systemcmdpolicy_binding/${encodeURIComponent(name)}`, errors),
          rows(client, `systemuser_systemgroup_binding/${encodeURIComponent(name)}`, errors),
        ]);
        const direct = pol.map((r) => String(r.policyname));
        const viaGroups = grp.map((r) => String(r.groupname));
        const inherited = viaGroups.flatMap((g) => groupPolicies.get(g) ?? []);
        const flags: string[] = [];
        if (name === "nsroot" || [...direct, ...inherited].some((p) => allowsAll(policyByName.get(p), p))) flags.push("SUPERUSER-EQUIVALENT");
        if (u.externalauth === "DISABLED") flags.push("local password only");
        if (u.logging === "DISABLED") flags.push("command logging off");
        return {
          username: name, flags, direct_policies: direct, groups: viaGroups, group_policies: inherited,
          externalauth: u.externalauth, allowedmanagementinterface: u.allowedmanagementinterface, timeout: u.timeout,
        };
      }));

      return text({
        ...(errors.length && { incomplete: true, errors }),
        note: "Local accounts only; users who log in through external auth groups do not appear. nsroot is a built-in superuser with no visible binding. SUPERUSER-EQUIVALENT is a heuristic: it ignores binding priority and DENY ordering, and does not flag the built-in sysadmin policy. Compare this list against who should have access.",
        users: userReport,
        groups: groups.map((g) => ({ groupname: g.groupname, policies: groupPolicies.get(String(g.groupname)) ?? [] })),
        custom_command_policies: custom.map((p) => ({ policyname: p.policyname, action: p.action, cmdspec: p.cmdspec })),
        management_sessions: sessions.map((s) => ({
          sid: s.sid, username: s.username, clientipaddress: s.clientipaddress, clienttype: s.clienttype,
          logintime: s.logintime, lastactivitytime: s.lastactivitytime,
        })),
        system_parameters: params[0] && {
          localauth: params[0].localauth, basicauth: params[0].basicauth, strongpassword: params[0].strongpassword,
          minpasswordlen: params[0].minpasswordlen, timeout: params[0].timeout, restrictedtimeout: params[0].restrictedtimeout,
        },
      });
    }
  );

  server.tool(
    "check_management_exposure",
    "Check which IPs on this NetScaler expose the management plane (GUI, SSH, NITRO, SNMP, telnet, FTP) and flag risky settings: management access on a SNIP/VIP without restricted access, GUI over plain HTTP, telnet or FTP enabled. Use to confirm management is not reachable from client-facing addresses.",
    {},
    async () => {
      const errors: string[] = [];
      const ips = await rows(client, "nsip", errors);
      if (errors.length) return { ...text(`Could not read nsip: ${errors.join("; ")}`), isError: true };
      const exposed = ips.filter((ip) => ip.type === "NSIP" || ip.mgmtaccess === "ENABLED");
      const findings: string[] = [];
      for (const ip of exposed) {
        const id = `${ip.ipaddress} (${ip.type})`;
        if (ip.type !== "NSIP" && ip.restrictaccess !== "ENABLED") findings.push(`${id}: management access enabled without restrictaccess, so management ports answer on this address.`);
        if (ip.gui === "ENABLED") findings.push(`${id}: GUI allows plain HTTP (set gui SECUREONLY).`);
        if (ip.telnet === "ENABLED") findings.push(`${id}: telnet enabled.`);
        if (ip.ftp === "ENABLED") findings.push(`${id}: FTP enabled.`);
      }
      return text({
        findings: findings.length ? findings : ["No risky management settings found on the configured IPs."],
        management_ips: exposed.map((ip) => ({
          ipaddress: ip.ipaddress, type: ip.type, td: ip.td, mgmtaccess: ip.mgmtaccess, restrictaccess: ip.restrictaccess,
          gui: ip.gui, ssh: ip.ssh, snmp: ip.snmp, telnet: ip.telnet, ftp: ip.ftp,
        })),
        note: "Settings only: whether these addresses are reachable from the internet depends on your firewalls.",
      });
    }
  );

  server.tool(
    "kill_admin_session",
    "End ONE management (GUI, SSH or NITRO) session by its sid, e.g. a session from an unexpected IP found with audit_admin_access. The username must match the session's user or the call is refused. Never ends all sessions. The account can log straight back in, so disable or re-password it first if it is compromised.",
    {
      sid: z.number().int().positive().max(Number.MAX_SAFE_INTEGER).describe("Session ID from audit_admin_access management_sessions."),
      username: z.string().min(1).describe("The username that session belongs to, as a check."),
    },
    async (args) => {
      const sid = args.sid as number;
      const username = args.username as string;
      const errors: string[] = [];
      const sessions = await rows(client, "systemsession", errors);
      if (errors.length) return { ...text(`Refused: could not read sessions first (${errors.join("; ")}).`), isError: true };
      const s = sessions.find((r) => Number(r.sid) === sid);
      if (!s) return { ...text(`Refused: no management session with sid ${sid}.`), isError: true };
      if (String(s.username) !== username) return { ...text(`Refused: session ${sid} belongs to '${s.username}', not '${username}'.`), isError: true };
      if (String(s.currentconn).toLowerCase() === "true") return { ...text(`Refused: session ${sid} is this server's own session.`), isError: true };

      await client.post("systemsession", { systemsession: { sid } }, "kill");
      return text({ killed: { sid, username, clientipaddress: s.clientipaddress, clienttype: s.clienttype, logintime: s.logintime } });
    }
  );
}
