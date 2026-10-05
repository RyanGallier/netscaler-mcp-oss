/**
 * Authentication troubleshooting engine.
 *
 * Covers LDAP/AD, SAML, RADIUS, OAuth/OIDC, nFactor, certificate auth
 * and authentication vserver configuration.
 */

import { type McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { type NitroClient } from "../client.js";
import { redactText } from "../redact.js";

/** get_auth_objects kinds and the NITRO resource each reads. */
const AUTH_RESOURCES = {
  ldap_action: "authenticationldapaction",
  saml_action: "authenticationsamlaction",
  radius_action: "authenticationradiusaction",
  oauth_action: "authenticationoauthaction",
  saml_idp_profile: "authenticationsamlidpprofile",
  oauth_idp_profile: "authenticationoauthidpprofile",
  policylabel: "authenticationpolicylabel",
  login_schema: "authenticationloginschema",
  auth_vserver: "authenticationvserver",
  aaa_parameter: "aaaparameter",
} as const;
const AUTH_KINDS = Object.keys(AUTH_RESOURCES) as [keyof typeof AUTH_RESOURCES, ...(keyof typeof AUTH_RESOURCES)[]];

/** Binding rows name the policy only; its rule and action live on the advanced authenticationpolicy object. */
async function policyRuleAction(client: NitroClient, name: string): Promise<{ rule?: unknown; action?: unknown }> {
  try {
    const resp = await client.get("config", `authenticationpolicy/${encodeURIComponent(name)}`);
    const pol = (resp.authenticationpolicy as Record<string, unknown>[] | undefined)?.[0];
    return { rule: pol?.rule, action: pol?.action };
  } catch {
    return {};
  }
}

export function registerAuthTools(server: McpServer, client: NitroClient) {

  // ── LDAP / Active Directory ──────────────────────────────────────

  server.tool(
    "list_ldap_policies",
    "List all LDAP authentication policies with their expressions and bound LDAP actions. Shows where each policy is bound (authentication vserver, VPN vserver, global).",
    {},
    async () => {
      const resp = await client.get("config", "authenticationldappolicy");
      const policies = resp.authenticationldappolicy as Record<string, unknown>[] | undefined;

      if (!policies || policies.length === 0) {
        return { content: [{ type: "text" as const, text: "No LDAP policies configured." }] };
      }

      // Enrich with binding info
      const enriched = await Promise.all(
        policies.map(async (p) => {
          const pName = p.name as string;
          const detail: Record<string, unknown> = { ...p };
          try {
            const bindResp = await client.get("config", `authenticationldappolicy_binding/${encodeURIComponent(pName)}`);
            detail.bindings = bindResp.authenticationldappolicy_binding;
          } catch { /* not bound */ }
          return detail;
        })
      );

      return {
        content: [{ type: "text" as const, text: JSON.stringify(enriched, null, 2) }],
      };
    }
  );

  // ── SAML ─────────────────────────────────────────────────────────

  server.tool(
    "list_saml_policies",
    "List all SAML authentication policies with expressions, bound actions, and binding locations.",
    {},
    async () => {
      const resp = await client.get("config", "authenticationsamlpolicy");
      const policies = resp.authenticationsamlpolicy as Record<string, unknown>[] | undefined;

      if (!policies || policies.length === 0) {
        return { content: [{ type: "text" as const, text: "No SAML policies configured." }] };
      }

      const enriched = await Promise.all(
        policies.map(async (p) => {
          const pName = p.name as string;
          const detail: Record<string, unknown> = { ...p };
          try {
            const bindResp = await client.get("config", `authenticationsamlpolicy_binding/${encodeURIComponent(pName)}`);
            detail.bindings = bindResp.authenticationsamlpolicy_binding;
          } catch { /* not bound */ }
          return detail;
        })
      );

      return {
        content: [{ type: "text" as const, text: JSON.stringify(enriched, null, 2) }],
      };
    }
  );

  // ── RADIUS ───────────────────────────────────────────────────────

  server.tool(
    "list_radius_policies",
    "List all RADIUS authentication policies with expressions, actions, and bindings.",
    {},
    async () => {
      const resp = await client.get("config", "authenticationradiuspolicy");
      const policies = resp.authenticationradiuspolicy as Record<string, unknown>[] | undefined;

      if (!policies || policies.length === 0) {
        return { content: [{ type: "text" as const, text: "No RADIUS policies configured." }] };
      }

      const enriched = await Promise.all(
        policies.map(async (p) => {
          const pName = p.name as string;
          const detail: Record<string, unknown> = { ...p };
          try {
            const bindResp = await client.get("config", `authenticationradiuspolicy_binding/${encodeURIComponent(pName)}`);
            detail.bindings = bindResp.authenticationradiuspolicy_binding;
          } catch { /* not bound */ }
          return detail;
        })
      );

      return {
        content: [{ type: "text" as const, text: JSON.stringify(enriched, null, 2) }],
      };
    }
  );

  // ── Auth objects ─────────────────────────────────────────────────

  server.tool(
    "get_auth_objects",
    "List authentication objects of one kind, or get one by name: LDAP/AD servers (ldap_action: server, port, base DN, bind DN, login attribute, group extraction, TLS), SAML SP settings (saml_action: IdP URLs, certificates, signature, binding), RADIUS servers, OAuth/OIDC actions, SAML or OAuth IdP profiles (NetScaler as the identity provider), nFactor policy labels, login schemas, authentication vservers (the nFactor entry points), and the global AAA parameters (max users, login attempts, lockout, default auth type). Secrets are redacted. For policies with their bindings use list_ldap_policies / list_saml_policies / list_radius_policies; for everything about one vserver use diagnose_auth.",
    {
      kind: z.enum(AUTH_KINDS).describe("ldap_action, saml_action, radius_action, oauth_action, saml_idp_profile, oauth_idp_profile, policylabel, login_schema, auth_vserver, or aaa_parameter (global, takes no name)."),
      name: z.string().min(1).optional().describe("One object's name. Omit to list all of that kind."),
    },
    async (args) => {
      const resource = AUTH_RESOURCES[args.kind];
      if (args.kind === "aaa_parameter" && args.name) {
        return { content: [{ type: "text" as const, text: "aaa_parameter is global and takes no name." }], isError: true };
      }
      const resp = await client.get("config", args.name ? `${resource}/${encodeURIComponent(args.name)}` : resource);
      return { content: [{ type: "text" as const, text: JSON.stringify(resp[resource] ?? [], null, 2) }] };
    }
  );

  // ── nFactor Authentication ───────────────────────────────────────

  server.tool(
    "trace_nfactor_flow",
    "Trace the complete nFactor authentication flow for an authentication vserver or a specific policy label. Walks the chain: auth vserver → first factor policies → nextFactor policy labels → their policies → next factors, building the full flow tree. Essential for debugging multi-factor auth issues.",
    {
      start: z.string().describe("Starting point: authentication vserver name or policy label name."),
      start_type: z.enum(["vserver", "policylabel"]).default("vserver").describe("Whether the start is an auth vserver or a policy label."),
    },
    async (args) => {
      const startName = args.start as string;
      const startType = args.start_type as string;

      interface FlowStep {
        name: string;
        type: string;
        loginSchema?: unknown;
        policies: Array<{
          name: string;
          expression: unknown;
          action: unknown;
          priority: unknown;
          nextFactor?: string;
          gotoExpression?: unknown;
          nextFactorFlow?: FlowStep;
        }>;
      }

      // Recursively walk policy labels to build the flow tree
      async function traceLabel(labelName: string, depth: number): Promise<FlowStep> {
        if (depth > 10) {
          return { name: labelName, type: "policylabel", policies: [{ name: "MAX_DEPTH", expression: null, action: null, priority: null }] };
        }

        const step: FlowStep = { name: labelName, type: "policylabel", policies: [] };

        // Get the label itself
        try {
          const labelResp = await client.get("config", `authenticationpolicylabel/${encodeURIComponent(labelName)}`);
          const label = (labelResp.authenticationpolicylabel as Record<string, unknown>[] | undefined)?.[0] ?? labelResp.authenticationpolicylabel;
          step.loginSchema = (label as Record<string, unknown>)?.loginschema;
        } catch { /* label not found */ }

        // Get policies bound to this label
        try {
          const bindResp = await client.get("config", `authenticationpolicylabel_authenticationpolicy_binding/${encodeURIComponent(labelName)}`);
          const bindings = bindResp.authenticationpolicylabel_authenticationpolicy_binding as Record<string, unknown>[] | undefined;

          if (bindings) {
            for (const b of bindings) {
              const pol = await policyRuleAction(client, b.policyname as string);
              const policyEntry: FlowStep["policies"][0] = {
                name: b.policyname as string,
                expression: pol.rule,
                action: pol.action,
                priority: b.priority,
                nextFactor: b.nextfactor as string | undefined,
                gotoExpression: b.gotopriorityexpression,
              };

              // If there's a nextFactor, recurse
              if (policyEntry.nextFactor) {
                policyEntry.nextFactorFlow = await traceLabel(policyEntry.nextFactor, depth + 1);
              }

              step.policies.push(policyEntry);
            }

            // Sort by priority
            step.policies.sort((a, b) => Number(a.priority ?? 0) - Number(b.priority ?? 0));
          }
        } catch { /* no policies bound */ }

        return step;
      }

      const result: Record<string, unknown> = {};

      if (startType === "vserver") {
        // Get auth vserver config
        try {
          const vsResp = await client.get("config", `authenticationvserver/${encodeURIComponent(startName)}`);
          result.auth_vserver = vsResp.authenticationvserver;
        } catch (err) {
          return {
            content: [{
              type: "text" as const,
              text: `Cannot find authentication vserver '${startName}': ${err instanceof Error ? err.message : String(err)}`,
            }],
            isError: true,
          };
        }

        // Get auth vserver stats
        try {
          const statsResp = await client.get("stat", `authenticationvserver/${encodeURIComponent(startName)}`);
          result.stats = statsResp.authenticationvserver;
        } catch { /* no stats */ }

        // Get policies bound to the auth vserver (these are the first-factor policies)
        try {
          const bindResp = await client.get("config", `authenticationvserver_authenticationpolicy_binding/${encodeURIComponent(startName)}`);
          const firstFactorPolicies = bindResp.authenticationvserver_authenticationpolicy_binding as Record<string, unknown>[] | undefined;

          if (firstFactorPolicies) {
            const flow: FlowStep = { name: startName, type: "vserver", policies: [] };

            for (const b of firstFactorPolicies) {
              const pol = await policyRuleAction(client, b.policy as string);
              const policyEntry: FlowStep["policies"][0] = {
                name: b.policy as string,
                expression: pol.rule,
                action: pol.action,
                priority: b.priority,
                nextFactor: b.nextfactor as string | undefined,
                gotoExpression: b.gotopriorityexpression,
              };

              if (policyEntry.nextFactor) {
                policyEntry.nextFactorFlow = await traceLabel(policyEntry.nextFactor, 0);
              }

              flow.policies.push(policyEntry);
            }

            flow.policies.sort((a, b) => Number(a.priority ?? 0) - Number(b.priority ?? 0));
            result.nfactor_flow = flow;
          }
        } catch { /* no policies bound */ }

        // Also get login schema policies bound to the vserver
        try {
          const lsResp = await client.get("config", `authenticationvserver_authenticationloginschemapolicy_binding/${encodeURIComponent(startName)}`);
          result.login_schema_policies = lsResp.authenticationvserver_authenticationloginschemapolicy_binding;
        } catch { /* none */ }

      } else {
        // Start from a policy label directly
        result.nfactor_flow = await traceLabel(startName, 0);
      }

      return {
        content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
      };
    }
  );

  // ── Authentication Virtual Servers ───────────────────────────────

  server.tool(
    "get_auth_vserver_full",
    "Get complete configuration of an authentication vserver including ALL bound policies (LDAP, SAML, RADIUS, OAuth, cert, negotiate), login schema policies, and audit policies. The single-call view of everything attached to an auth vserver.",
    {
      name: z.string().describe("The authentication vserver name."),
    },
    async (args) => {
      const name = args.name as string;

      const result: Record<string, unknown> = {};

      // Get vserver config
      try {
        const resp = await client.get("config", `authenticationvserver/${encodeURIComponent(name)}`);
        result.config = resp.authenticationvserver;
      } catch (err) {
        return {
          content: [{
            type: "text" as const,
            text: `Cannot find authentication vserver '${name}': ${err instanceof Error ? err.message : String(err)}`,
          }],
          isError: true,
        };
      }

      // Get all policy type bindings in parallel
      const bindingTypes = [
        "authenticationpolicy",
        "authenticationldappolicy",
        "authenticationsamlpolicy",
        "authenticationradiuspolicy",
        "authenticationcertpolicy",
        "authenticationnegotiatepolicy",
        "authenticationoauthidppolicy",
        "authenticationsamlidppolicy",
        "authenticationloginschemapolicy",
        "authenticationlocalpolicy",
        "authenticationtacacspolicy",
        "authenticationwebauthpolicy",
        "auditsyslogpolicy",
        "auditnslogpolicy",
      ];

      const bindings: Record<string, unknown> = {};

      const results = await Promise.allSettled(
        bindingTypes.map(async (bt) => {
          const bindingResource = `authenticationvserver_${bt}_binding`;
          const resp = await client.get("config", `${bindingResource}/${encodeURIComponent(name)}`);
          return { type: bt, data: resp[bindingResource] };
        })
      );

      for (const r of results) {
        if (r.status === "fulfilled" && r.value.data) {
          bindings[r.value.type] = r.value.data;
        }
      }

      result.bindings = bindings;

      // Get stats
      try {
        const statsResp = await client.get("stat", `authenticationvserver/${encodeURIComponent(name)}`);
        result.stats = statsResp.authenticationvserver;
      } catch { /* no stats */ }

      return {
        content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
      };
    }
  );

  // ── Certificate Authentication ───────────────────────────────────

  server.tool(
    "list_cert_auth_policies",
    "List all certificate-based authentication policies. Shows the policy expression and the cert action (which fields to extract from the client cert for authentication).",
    {},
    async () => {
      const [policies, actions] = await Promise.allSettled([
        client.get("config", "authenticationcertpolicy"),
        client.get("config", "authenticationcertaction"),
      ]);

      const result: Record<string, unknown> = {};
      if (policies.status === "fulfilled") {
        result.policies = policies.value.authenticationcertpolicy;
      }
      if (actions.status === "fulfilled") {
        result.actions = actions.value.authenticationcertaction;
      }

      return {
        content: [{ type: "text" as const, text: JSON.stringify(result, null, 2) }],
      };
    }
  );

  // ── Diagnose Auth Failure ────────────────────────────────────────

  /** Everything about auth on one vserver; a string is the not-found error. A Gateway's nFactor auth vserver is nested. */
  const diagnose = async (name: string, vtype: string, withLogs: boolean): Promise<Record<string, unknown> | string> => {
    const result: Record<string, unknown> = {};

    // 1. Get vserver config
    const vsResource = vtype === "vpn" ? "vpnvserver" : "authenticationvserver";
    try {
      const resp = await client.get("config", `${vsResource}/${encodeURIComponent(name)}`);
      result.vserver = resp[vsResource];
    } catch (err) {
      return `Cannot find ${vsResource} '${name}': ${err instanceof Error ? err.message : String(err)}`;
    }

    // 2. Collect all auth policy bindings and resolve their actions
    const authBindingTypes = vtype === "vpn"
      ? [
          { binding: "vpnvserver_authenticationpolicy_binding", actionResource: null },
          { binding: "vpnvserver_authenticationldappolicy_binding", actionResource: "authenticationldapaction" },
          { binding: "vpnvserver_authenticationsamlpolicy_binding", actionResource: "authenticationsamlaction" },
          { binding: "vpnvserver_authenticationradiuspolicy_binding", actionResource: "authenticationradiusaction" },
          { binding: "vpnvserver_aaapreauthenticationpolicy_binding", actionResource: null },
          { binding: "vpnvserver_vpnsessionpolicy_binding", actionResource: null },
        ]
      : [
          { binding: "authenticationvserver_authenticationpolicy_binding", actionResource: null },
          { binding: "authenticationvserver_authenticationldappolicy_binding", actionResource: "authenticationldapaction" },
          { binding: "authenticationvserver_authenticationsamlpolicy_binding", actionResource: "authenticationsamlaction" },
          { binding: "authenticationvserver_authenticationradiuspolicy_binding", actionResource: "authenticationradiusaction" },
          { binding: "authenticationvserver_authenticationcertpolicy_binding", actionResource: "authenticationcertaction" },
          { binding: "authenticationvserver_authenticationnegotiatepolicy_binding", actionResource: "authenticationnegotiateaction" },
          { binding: "authenticationvserver_authenticationoauthidppolicy_binding", actionResource: "authenticationoauthidpprofile" },
          { binding: "authenticationvserver_authenticationloginschemapolicy_binding", actionResource: null },
        ];

    const authConfig: Record<string, unknown> = {};
    const actionDetails: Record<string, unknown> = {};

    for (const { binding, actionResource } of authBindingTypes) {
      try {
        const resp = await client.get("config", `${binding}/${encodeURIComponent(name)}`);
        const data = resp[binding] as Record<string, unknown>[] | undefined;
        if (data && data.length > 0) {
          authConfig[binding] = data;

          // Binding rows carry only the policy name; the action name is on the policy (reqaction, or action for OAuth IdP).
          if (actionResource) {
            const policyResource = binding.replace(/^(vpnvserver|authenticationvserver)_/, "").replace(/_binding$/, "");
            for (const row of data) {
              let actionName: string | undefined;
              try {
                const polResp = await client.get("config", `${policyResource}/${encodeURIComponent(row.policy as string)}`);
                const pol = (polResp[policyResource] as Record<string, unknown>[] | undefined)?.[0];
                actionName = (pol?.reqaction ?? pol?.action) as string | undefined;
              } catch { /* policy not found */ }
              if (actionName && !actionDetails[actionName]) {
                try {
                  const actionResp = await client.get("config", `${actionResource}/${encodeURIComponent(actionName)}`);
                  actionDetails[actionName] = actionResp[actionResource];
                } catch { /* action not found by that name */ }
              }
            }
          }
        }
      } catch { /* binding type not present */ }
    }

    result.auth_policy_bindings = authConfig;
    result.action_configs = actionDetails;

    // 3. If auth vserver, trace nFactor flow
    if (vtype === "auth") {
      try {
        const bindResp = await client.get("config", `authenticationvserver_authenticationpolicy_binding/${encodeURIComponent(name)}`);
        const firstFactorPolicies = bindResp.authenticationvserver_authenticationpolicy_binding as Record<string, unknown>[] | undefined;
        if (firstFactorPolicies) {
          const nfactorSteps: Record<string, unknown>[] = [];
          for (const p of firstFactorPolicies) {
            const pol = await policyRuleAction(client, p.policy as string);
            const step: Record<string, unknown> = {
              policy: p.policy,
              priority: p.priority,
              action: pol.action,
              expression: pol.rule,
              nextFactor: p.nextfactor,
            };

            // If there's a nextFactor, get the label config
            if (p.nextfactor) {
              try {
                const labelResp = await client.get("config", `authenticationpolicylabel/${encodeURIComponent(p.nextfactor as string)}`);
                step.nextFactor_config = labelResp.authenticationpolicylabel;
              } catch { /* label not found */ }
            }

            nfactorSteps.push(step);
          }
          result.nfactor_first_factor = nfactorSteps;
        }
      } catch { /* no nfactor policies */ }
    }

    // 4. Get SSL cert bound to the vserver (needed for SAML signing)
    try {
      const sslResp = await client.get("config", `sslvserver_sslcertkey_binding/${encodeURIComponent(name)}`);
      result.ssl_certs = sslResp.sslvserver_sslcertkey_binding;
    } catch { /* no SSL certs */ }

    // 5. Try to get recent auth-related log entries
    if (withLogs) try {
      const logResp = await client.get(
        "config", "systemfile", undefined,
        "args=filename:ns.log,filelocation:/var/log"
      );
      const fileData = (logResp.systemfile as Record<string, unknown>[] | undefined)?.[0];
      if (fileData?.filecontent) {
        const logContent = redactText(Buffer.from(fileData.filecontent as string, "base64").toString("utf-8"));
        const authLines = logContent
          .split("\n")
          .filter((l) => {
            const lower = l.toLowerCase();
            return lower.includes("auth") || lower.includes("ldap") ||
                   lower.includes("saml") || lower.includes("radius") ||
                   lower.includes("login") || lower.includes("aaa");
          })
          .slice(-50); // Last 50 auth-related log entries
        if (authLines.length > 0) {
          result.recent_auth_logs = authLines;
        }
      }
    } catch { /* log not available */ }

    // 6. A Gateway with an authentication profile hands logon to an nFactor auth vserver: diagnose that too.
    const profile = (Array.isArray(result.vserver) ? result.vserver[0] : result.vserver)?.authnprofile as string | undefined;
    if (vtype === "vpn" && profile) {
      try {
        const p = await client.get("config", `authenticationauthnprofile/${encodeURIComponent(profile)}`);
        const authVs = (p.authenticationauthnprofile as Record<string, unknown>[] | undefined)?.[0]?.authnvsname as string | undefined;
        if (!authVs) result.authnprofile_error = `Profile ${profile} names no authentication vserver.`;
        else {
          const nested = await diagnose(authVs, "auth", false);
          if (typeof nested === "string") result.authnprofile_error = nested;
          else result.nfactor_auth_vserver = { authnprofile: profile, ...nested };
        }
      } catch (err) {
        result.authnprofile_error = `Profile ${profile}: ${err instanceof Error ? err.message : String(err)}`;
      }
    }
    return result;
  };

  server.tool(
    "diagnose_auth",
    "Comprehensive authentication diagnostic for a VPN or auth vserver. Collects: vserver state and config, all bound auth policies, the LDAP/SAML/RADIUS/OAuth action configs referenced by those policies, nFactor flow if present (for a Gateway with an authentication profile, the nFactor authentication vserver it hands logon to, nested under nfactor_auth_vserver), login schemas, SSL cert bindings, and recent auth-related syslog entries. This is the 'tell me everything about auth on this vserver' tool.",
    {
      vserver_name: z.string().describe("The VPN vserver or authentication vserver name."),
      vserver_type: z.enum(["vpn", "auth"]).default("vpn").describe("Whether this is a VPN (Gateway) vserver or a dedicated authentication vserver."),
    },
    async (args) => {
      const out = await diagnose(args.vserver_name as string, args.vserver_type as string, true);
      if (typeof out === "string") return { content: [{ type: "text" as const, text: out }], isError: true };
      return { content: [{ type: "text" as const, text: JSON.stringify(out, null, 2) }] };
    }
  );
}
