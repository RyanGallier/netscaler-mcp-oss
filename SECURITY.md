# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security problem. Use GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability"). Include the version or commit, the mode (local or hosted), and steps to reproduce.

You can expect an acknowledgement within a week.

## Scope

In scope: this server's code, including tool input validation, the read/write gating, hosted-mode authorization, TLS and SSH pinning, and the `run_nsconmsg` and forensic-tool sandboxes.

## Account model

Each credential is a separate NetScaler user whose command policy (see [docs/local-mode.md](docs/local-mode.md#accounts)) is the hard limit on what it can do if it leaks:

| Credential | If it leaks |
|---|---|
| NITRO read (`NETSCALER_USER`) | Read the configuration (secrets in it are encrypted or hashed on the appliance), stats, sessions and `/var/log/ns.log`; ping and traceroute with fixed options. No writes, no other files, no core dumps or TLS key files. API only, so no SSH session |
| NITRO admin (`NETSCALER_ADMIN_USER`) | Whatever its policy allows: with the documented `sysadmin` plus `mcp_writes` pair, any configuration change except system users, command policies, shell, partitions and installs, plus reading any file through NITRO, including private keys. API only |
| SSH nsconmsg (`NETSCALER_SSH_USER`) | Run `nsconmsg` in exactly the four shapes its policy allows (event, current counters, stats, oldconmsg) against `/var/nslog/newnslog` or an uncompressed `newnslog.<n>`, as root. CLI only |
| SSH forensics (`NETSCALER_FORENSICS_USER`) | Run exactly four commands as root: gdb `bt` on a core, grep a core for a marker, read the nsaaad debug pipe, list `/var/core`. Core memory and the debug stream can hold credentials and session data. CLI only. In hosted mode these tools go to the `NetScaler.Admin` role, so leave the forensics account off any appliance where Admins should not have them |

Forensic output is redacted like everything else, plus form-encoded and JSON secrets (`passwd=`, `password=`, `pwd=`, `secret=`, `"password":"..."`), `Authorization` headers and `NSC_*` session cookies, but the redaction is pattern-based: treat core and debug output as sensitive. `stop_nstrace` with TLS keys points at the `.sslkeys` file, and fetching it with `get_system_file` puts live session keys for real user traffic into the model's context and its provider. Do that only when you need to decrypt that capture.

## Prompt injection

Read tools return text that people outside your organisation control: Gateway login names, request strings and User-Agents in logs and session lists. A model that reads that text can be steered. Keep write and forensic tools behind per-call approval in your MCP client (they carry the `destructiveHint` annotation), or run write work in a session that is not reading logs. The command policies above bound the damage either way.

Out of scope: vulnerabilities in NetScaler / ADC itself (report those to Cloud Software Group), in your MCP client, or in Azure App Service authentication.
