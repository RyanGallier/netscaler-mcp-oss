# netscaler-mcp

An MCP (Model Context Protocol) server that lets Claude and other MCP clients troubleshoot Citrix NetScaler / ADC appliances over the NITRO REST API, plus a sandboxed SSH path for the per-PPE counters and newnslog events NITRO does not expose.

- **Read-only by default.** 52 read and diagnostic tools on the read account (53 with the nsconmsg SSH account), including a generic `nitro_get` for anything the curated tools do not cover. The 17 admin tools (a generic `nitro_write` for any configuration change, plus HA failover and sync, enable/disable, drain a service group member, replace a certificate, backup, kill a Gateway or admin session, block and unblock an IP, packet capture, save config, and `get_system_file`) appear only when you configure an admin account.
- **One NetScaler account per job.** Read tools hold only a read-only NITRO account and write tools a separate admin account, so the appliance itself guarantees reads cannot write. Three optional forensic tools (gdb backtrace of a core, search a core's memory, capture the authentication daemon's debug stream) run fixed commands as their own restricted SSH account.
- **HA-aware.** Point it at both nodes: HA and crash checks query both, failover finds the current primary, and log and SSH tools take a `node` argument.
- **Two ways to run it:** locally over stdio for one operator, on Linux, Windows or macOS with Node.js 20+, or hosted over HTTP for a team on Azure App Service, with Entra ID sign-in, per-user roles and an audit log of every write.

Tested against NetScaler 13.1 builds 62.23, 64.24 and 64.28, and 14.1 build 73.41 on a standalone appliance. Other 13.1 and 14.1 builds should work. On 14.1, the HA tools (`force_ha_failover`, `force_ha_sync`, peer-node reads) have not been tested.

## Which mode?

| | Local (stdio) | Hosted (HTTP) |
|---|---|---|
| Who | One operator on their own machine | A team, through one shared endpoint |
| Runs | As a child process of your MCP client | Azure App Service behind App Service authentication (Easy Auth) |
| Credentials | Env vars in your MCP client config | Key Vault references in App Service settings |
| Who may write | Whoever is given the admin account's credentials | Users assigned the `NetScaler.Admin` Entra app role |
| Audit | The NetScaler's own audit log | Plus an attempt and result line per admin-tier call (write tools, `get_system_file`, forensic tools, `nitro_write` previews), with the user's identity |
| Appliances | One HA pair, or several with `NETSCALER_TARGETS` | Several with `NETSCALER_TARGETS` |
| Guide | [docs/local-mode.md](docs/local-mode.md) | [docs/hosted-mode.md](docs/hosted-mode.md) |

## Quick start (local)

```bash
git clone https://github.com/RyanGallier/netscaler-mcp-oss.git && cd netscaler-mcp-oss
npm ci
npm run build
```

Add it to your MCP client. For Claude Code:

```bash
claude mcp add netscaler -e NETSCALER_NSIP=10.0.0.1 -e NETSCALER_USER=mcp_read -e NETSCALER_PASS=changeme -- node /path/to/netscaler-mcp-oss/dist/index.js
```

Create the read-only NetScaler account first; the built-in `read-only` policy is not enough. The commands are in [docs/local-mode.md](docs/local-mode.md#nitro-read-account).

Or copy `.mcp.json.example` to `.mcp.json` and fill it in. Then ask things like "is the HA pair healthy", "why is lb_vs_web DOWN", "which certs expire this quarter" or "trace the nFactor flow for the Gateway login".

Read [Security](#security) and pin the appliance certificates ([how](docs/local-mode.md#2-pin-the-certificates)) before pointing it at production.

## Configuration

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `NETSCALER_NSIP` | yes, local mode with one appliance | - | NSIP of the primary node (`host`, or `host:port` for NITRO on a non-standard port; the SSH tools need a bare host and use `NETSCALER_SSH_PORT`) |
| `NETSCALER_USER` | yes, local mode with one appliance | - | Read-only NITRO account, used by every read tool |
| `NETSCALER_PASS` | yes, local mode with one appliance | - | Its password |
| `NETSCALER_ADMIN_USER` / `NETSCALER_ADMIN_PASS` | no | - | Admin NITRO account. Setting it is what turns on the write tools and `get_system_file`; leave it out of a read-only (helpdesk) config |
| `NETSCALER_PEER_NSIP` | no | - | NSIP of the HA peer. Lets the HA tools reach the peer and enables `node: peer` reads |
| `NETSCALER_PROTOCOL` | no | `https` | `https` or `http` |
| `NETSCALER_TIMEOUT` | no | `15000` | NITRO request timeout, ms |
| `NETSCALER_TLS_SHA256` | no | - | Comma-separated SHA-256 certificate fingerprints to pin, one per node. Strongly recommended |
| `NETSCALER_SSH_USER` / `NETSCALER_SSH_PASS` | no | - | SSH user for `run_nsconmsg`. Leave unset to disable that tool |
| `NETSCALER_SSH_PORT` | no | `22` | SSH port |
| `NETSCALER_SSH_TIMEOUT` | no | `30000` | SSH command timeout, ms |
| `NETSCALER_SSH_SHA256` | no | - | Comma-separated SSH host key fingerprints to pin (`SHA256:...`) |
| `NETSCALER_FORENSICS_USER` / `NETSCALER_FORENSICS_PASS` | no | - | Restricted SSH account. Setting it turns on the forensic tools |
| `NETSCALER_BLOCK_PROTECT` | no | - | Comma-separated /24s that `block_ip_acl` refuses, e.g. your own management egress. Applies to every appliance |
| `NETSCALER_TARGETS` | no | - | Several appliances: comma-separated short names. Each one reads the appliance settings above (all except `NETSCALER_BLOCK_PROTECT`) under `NS_<NAME>_` instead of `NETSCALER_`, which are then ignored. Hosted mode always uses it, even for one appliance |

Several appliances, either mode: set `NETSCALER_TARGETS=east,west` and give each one the settings above under its own prefix (`NS_EAST_NSIP`, `NS_EAST_USER`, `NS_WEST_NSIP`, ...). Every tool then takes an `appliance` argument, and each appliance uses only the accounts set for it, so a tool is refused for an appliance without its account. See [docs/local-mode.md](docs/local-mode.md#several-appliances).

## Roles: which credentials to hand out

One server. The NetScaler accounts you put in someone's config are their role: a tool whose account is missing is not offered, and the appliance refuses anything the account's command policy does not allow, whatever the server does.

| Role | Give them | Appliance users (example names) | Tools |
|---|---|---|---|
| Helpdesk / read-only | Read account | `mcp_read` (API only, policy `mcp_read_policy`) | 52 read tools |
| Read-only plus counters | Read + nsconmsg SSH accounts | `mcp_read`, `ns_nsconmsg_ro` (CLI only) | 53: adds `run_nsconmsg` |
| Operator (no config changes) | Read + admin account bound to `mcp_writes` only | `mcp_read`, `mcp_admin` | 69: adds the 17 admin tools (16 write tools plus `get_system_file`); `nitro_write` limited to the operational commands |
| Admin | All four accounts: read, admin bound to `sysadmin` + `mcp_writes`, nsconmsg SSH, forensics SSH | `mcp_read`, `mcp_admin`, `ns_nsconmsg_ro`, `mcp_forensics` (CLI only) | 73, every tool: the write tools, `run_nsconmsg`, full configuration changes through `nitro_write`, and the forensic tools `get_core_backtrace`, `search_core`, `capture_aaad_debug` |

The forensic tools read process memory and the authentication debug stream as root, which can include end users' passwords. Leave the forensics account out of an admin config (70 tools) if that admin should not see them.

The exact `add system cmdPolicy` / `add system user` / `bind` commands for each account, what each one cannot do, and the checks behind them are in [docs/local-mode.md](docs/local-mode.md#accounts). Hosted mode uses the same accounts per appliance; there the server holds them all and each person's Entra role (`NetScaler.Reader` or `NetScaler.Admin`) picks the tools.

A helpdesk config for Claude Code:

```bash
claude mcp add netscaler \
  -e NETSCALER_NSIP=10.0.0.1 -e NETSCALER_PEER_NSIP=10.0.0.2 \
  -e NETSCALER_USER=mcp_read -e NETSCALER_PASS=<read password> \
  -e NETSCALER_TLS_SHA256=AA...,BB... \
  -- node /path/to/netscaler-mcp-oss/dist/index.js
```

An admin config is the same command with the other accounts added:

```bash
  -e NETSCALER_ADMIN_USER=mcp_admin -e NETSCALER_ADMIN_PASS=<admin password> \
  -e NETSCALER_SSH_USER=ns_nsconmsg_ro -e NETSCALER_SSH_PASS=<ssh password> \
  -e NETSCALER_FORENSICS_USER=mcp_forensics -e NETSCALER_FORENSICS_PASS=<forensics password> \
  -e NETSCALER_SSH_SHA256=SHA256:...,SHA256:... \
```

## Tools

Read tools, on the read account (every role), plus `run_nsconmsg` on the nsconmsg SSH account:

| Area | Tools |
|---|---|
| System | `get_system_info`, `get_system_stats`, `get_crash_state`, `list_features`, `get_running_config`, `get_saved_config`, `get_config_diff`, `get_syslog`, `get_nslog_events` |
| HA | `get_ha_status` (includes the firmware build on each node and whether they match) |
| Virtual servers | `list_virtual_servers`, `get_virtual_server`, `get_virtual_server_stats` (LB, CS, Gateway and GSLB, including GSLB domain bindings) |
| Services | `list_services`, `get_service`, `list_service_groups`, `get_service_group_members`, `list_down_services`, `get_monitor_details` |
| SSL | `list_ssl_certificates`, `get_ssl_certificate`, `list_ssl_profiles`, `get_ssl_vserver_config`, `audit_ssl_posture` (old protocols, weak ciphers by name, expiring certs, missing intermediates across all SSL vservers) |
| Network | `list_ip_addresses`, `list_vlans`, `list_routes`, `get_interface_stats`, `test_reachability` (ping or traceroute from the appliance, optionally from a SNIP; fixed small probes) |
| DNS / GSLB | `get_dns_config`, `list_dns_records`, `list_gslb_sites`, `list_gslb_services`, `get_gslb_sync_status` |
| Authentication | `diagnose_auth` (follows a Gateway's authentication profile to its nFactor authentication vserver), `trace_nfactor_flow`, `get_auth_vserver_full`, `get_auth_objects` (LDAP, SAML, RADIUS and OAuth actions, SAML and OAuth IdP profiles, policy labels, login schemas, authentication vservers, global AAA parameters: list a kind or get one by name), `list_ldap_policies`, `list_saml_policies`, `list_radius_policies`, `list_cert_auth_policies` |
| Gateway | `get_gateway_sessions` (AAA sessions and ICA connections, by user or domain), `get_gateway_session_policies` |
| Security posture | `audit_admin_access` (users, groups, command policies, superuser-equivalent accounts, live management sessions), `check_management_exposure` (management access on SNIPs/VIPs, plain-HTTP GUI, telnet, FTP) |
| Troubleshooting | `trace_vserver_health`, `search_config`, `list_policies_with_hits`, `check_policy_coverage` (which Gateway and authentication vservers a responder or rewrite policy is NOT bound to), `check_log_actions` (log actions whose messages no syslog or nslog path will accept) |
| Counters | `run_nsconmsg` (needs the nsconmsg SSH account) |
| Anything else | `nitro_get`: read any NITRO config or stat resource by name, such as `systemuser`, `systemsession`, `nsip`, `auditsyslogaction`, `appfwprofile` or stat `aaa`. Refuses resources that return file contents or key material, run something, or are unbounded |

Write tools, on the admin account (only when it is configured locally, or for the `NetScaler.Admin` role hosted). The forensic tools are in this table too, but they use only the forensics SSH account, not the admin account (a read + forensics config offers 55 tools):

| Tool | What it does | Blast radius |
|---|---|---|
| `force_ha_failover` | Swaps primary and secondary | Brief traffic interruption on every vserver |
| `force_ha_sync` | Pushes config from primary to secondary | Whole appliance config |
| `save_config` | `save ns config` | Persists every unsaved change, including other admins' |
| `enable_disable_vserver` | Takes a vserver in or out of service | That vserver |
| `enable_disable_service` | Drains or restores a service | That service |
| `enable_disable_server` | Drains or restores a server object | Every service bound to that server |
| `drain_service_group_member` | Drains or restores one service group member (server + port) | That member, in every vserver the group is bound to |
| `create_backup` | `create system backup`, basic or full | Disk under `/var/ns_sys_backup`. Restore is not offered |
| `kill_admin_session` | Ends one management session by sid, only if the username matches | That session. The account can log straight back in |
| `update_ssl_certificate` | Replaces a cert-key pair in place, keeping bindings | Every vserver bound to that certkey |
| `kill_gateway_session` | Logs one user off Gateway: AAA sessions plus ICA, PCoIP and RDP connections | One username. No domain, so the same name in two tenants is logged off in both. They can sign straight back in |
| `block_ip_acl` / `unblock_ip_acl` | Drops one public IP or /24 with an ACL this tool owns | Every vserver and the NSIP. Refuses private ranges and `NETSCALER_BLOCK_PROTECT` |
| `start_nstrace` / `stop_nstrace` | Packet capture limited to 1-4 IPs, one size-capped file | Disk under `/var/nstrace`. Stop is box-wide |
| `get_system_file` | Reads any file the admin account can see | Can read private keys under `/nsconfig/ssl`, so it is gated like a write |
| `get_core_backtrace`, `search_core`, `capture_aaad_debug` | Fixed commands as root over the forensics SSH account: gdb `bt` on a core, grep a core for a marker, read the nsaaad debug pipe for up to 120 s | Output can include process memory and authentication traffic (redacted, but sensitive). The account's policy admits only these command shapes |
| `nitro_write` | Any configuration change NITRO supports: add, set, unset, rm, bind, unbind, actions. Previews the exact request by default; sends only with `preview: false` | Anything the NITRO user's command policy allows. Refuses reboot, shutdown, firmware install, system backups (use `create_backup`; restore is not offered), file writes, key material, cluster changes, session kills, `nsconfig` (save and clear config; use `save_config`) and the dynamic routing CLI (dedicated tools cover the safe versions). Changes are unsaved until `save_config` |

## Security

Read this before connecting it to a production appliance.

- **Give it its own NetScaler accounts,** one per job, each bound to the command policy in [docs/local-mode.md](docs/local-mode.md#accounts): a read account that cannot write or read key material, an admin account for write tools only, and CLI-only SSH accounts limited to exact command shapes. The appliance's command policy is the hard limit. This server's own gating sits above it, not instead of it.
- **Approve every write.** Read tools return text an outsider controls (Gateway usernames, request strings, User-Agents in logs), and a model that reads it can be steered. Write tools carry the MCP `destructiveHint` annotation; configure your client to ask before each one, or do write work in a session that is not reading logs.
- **Secrets are redacted** before anything reaches the model: password, key and secret fields in NITRO responses, the matching flags in running and saved config text, system user hashes, private-key blocks, SNMP community strings and credentials in URLs. Forensic output also masks form and JSON passwords, `Authorization` headers and `NSC_*` session cookies. The redaction is pattern-based, so treat core and debug output as sensitive. `get_system_file` returns binary files as unredacted base64.
- **Pin certificates.** NSIP management certificates are usually self-signed, so without `NETSCALER_TLS_SHA256` the server accepts any certificate and the NITRO credentials could go to an impostor on the path. The same applies to SSH and `NETSCALER_SSH_SHA256`. Local mode warns on stderr when it runs unpinned; hosted mode refuses to start.
- **Writes are off by default.** Readers get the full read surface; Admins get `nitro_write`, which can change any configuration the admin account's command policy allows, plus narrow tools for common operations. Nothing here runs arbitrary CLI or shell commands, writes files or reboots. The command policy you bind to the admin account is the real limit: give it only what your Admins should be able to change.
- **Tool output goes to your model provider.** Running config, session lists and logs contain hostnames, IPs and usernames. Use a provider and account your organisation has approved for that data.
- `run_nsconmsg` and the forensic tools build only fixed command shapes. The appliance's command policy for each account admits exactly those shapes and nothing else. Their output is redacted like every NITRO response.

Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Development

```bash
npm run dev     # run from TypeScript via tsx
npm run build   # tsc -> dist/
npm test        # after npm run build: hosted mode against a fake NITRO endpoint, local multi-appliance tool gating, nitro_write planning, redaction, forensic command shapes (needs openssl)
```

Check every NITRO resource and field used in `src/tools/` against the NITRO OpenAPI spec for your build. Download the spec from Citrix and extract it under `spec/` (gitignored). It is Citrix content and is not redistributed here.

## License

MIT. See [LICENSE](LICENSE). Not affiliated with or endorsed by Cloud Software Group. NetScaler and Citrix are trademarks of their respective owners.
