# Local mode (stdio)

One operator, one or more HA pairs, running on your own machine as a child process of your MCP client. Nothing listens on the network. Credentials live in your client's MCP config.

## 1. NetScaler-side setup

### Accounts

The server uses a separate NetScaler account for each kind of job, so the appliance itself enforces what each class of tool can do:

| Account | Variables | Interface | Used by | Needed |
|---|---|---|---|---|
| NITRO read | `NETSCALER_USER` / `NETSCALER_PASS` | API only | Every read tool except `run_nsconmsg` | Always |
| NITRO admin | `NETSCALER_ADMIN_USER` / `NETSCALER_ADMIN_PASS` | API only | Every write tool, plus `get_system_file` | For write tools |
| SSH nsconmsg | `NETSCALER_SSH_USER` / `NETSCALER_SSH_PASS` | CLI only | `run_nsconmsg` | Optional |
| SSH forensics | `NETSCALER_FORENSICS_USER` / `NETSCALER_FORENSICS_PASS` | CLI only | `get_core_backtrace`, `search_core`, `capture_aaad_debug` | Optional |

The credentials you configure are the role. A tool whose account is not configured is not offered, and no tool falls back to another account: a helpdesk config with only the read account gets the read tools and nothing else; an admin config with all four accounts gets everything. `-allowedManagementInterface` keeps each account on one path: an API-only user cannot open an SSH session, and a CLI-only user is refused by NITRO.

### NITRO read account

The built-in `read-only` policy is not enough: it denies `show system ...`, the running and saved config and audit messages, so about ten read tools would fail. Bind this policy instead. It is the built-in read-only shape plus exactly what the read tools need: the system user, group, policy, session and parameter reads for `audit_admin_access`, reading `/var/log/ns.log`, and the exact `ping` and `traceroute` commands `test_reachability` sends:

```
add system cmdPolicy mcp_read_policy ALLOW "(^man.*)|(^show (?!system)(?!configstatus)(?!ns ns\.conf)(?!gslb runningConfig)(?!techsupport)(?!ns rpcNode).*)|(^stat.*)|(^show system (user|group|cmdPolicy|session|global|parameter)( .*)?$)|(^show system file ns\.log -fileLocation \x22?/var/log\x22?$)|(^ping -c 3(( -S [0-9a-fA-F.:]+)|( -T [0-9]{1,4})){0,2} -t 5 [A-Za-z0-9:][A-Za-z0-9.:-]*$)|(^traceroute -m [1-6] -q 1(( -s [0-9a-fA-F.:]+)|( -T [0-9]{1,4})){0,2} -w 2 [A-Za-z0-9:][A-Za-z0-9.:-]*$)"
add system user mcp_read <password> -externalAuth DISABLED -allowedManagementInterface API -timeout 900
bind system user mcp_read mcp_read_policy 100
save ns config
```

What this account cannot do, checked on 13.1-64.28: any write, reading or downloading any other file (`/nsconfig`, `/nsconfig/ssl`, trace files, TLS key files, core files, other logs), and `ping` or `traceroute` with other options, a larger count or an extra command. Core files are listed and read only by the forensic tools, over SSH.

### NITRO admin account

The admin tools need this account. Its policy is the hard limit on what Admins can change. For full configuration changes through `nitro_write`, bind the built-in `sysadmin` policy (everything except shell, file transfer, system users and command policies, partitions and installs) plus the system commands the narrow tools use, which `sysadmin` denies:

| Tool | CLI command it maps to |
|---|---|
| `force_ha_failover` | `force ha failover -force` |
| `force_ha_sync` | `force ha sync` |
| `save_config` | `save ns config` |
| `enable_disable_vserver` | `enable` / `disable` `lb` / `cs` / `vpn` / `gslb vserver` |
| `enable_disable_service` | `enable` / `disable service` |
| `enable_disable_server` | `enable` / `disable server` |
| `drain_service_group_member` | `enable` / `disable servicegroup <group> <server> <port>` |
| `create_backup` | `create system backup` |
| `kill_admin_session` | `kill system session <sid>` |
| `update_ssl_certificate` | `update ssl certKey` |
| `kill_gateway_session` | `kill aaa session`, `kill vpn icaConnection`, `kill vpn pcoipConnection`, `kill rdp connections` (policies match case-insensitively) |
| `block_ip_acl` / `unblock_ip_acl` | `add ns acl mcp_block_...`, `rm ns acl mcp_block_...`, `apply ns acls` |
| `start_nstrace` / `stop_nstrace` | `start nstrace`, `stop nstrace` (and listing `/var/nstrace`) |
| `get_system_file` | `show system file` |
| Reads the admin tools make first | `show ha node` (failover), `show ns acl` (block, unblock), `show system session` (kill admin session), `show system backup` (backup read-back), `show servicegroup` (drain read-back) |
| `nitro_write` | Whatever configuration command the request maps to (`add`, `set`, `unset`, `rm`, `bind`, `unbind`, `enable`, `link` and so on) |

```
add system cmdPolicy mcp_writes ALLOW "^((enable|disable) (lb|cs|vpn|gslb) vserver|(enable|disable) (service|server|servicegroup)|create system backup|kill system session \d+|update ssl certKey|kill (aaa session|vpn icaconnection|vpn pcoipconnection|rdp connections)|(add|rm) ns acl mcp_block_\S+|apply ns acls|(start|stop) nstrace|save ns config|force ha (failover|sync)|show (system (file|session|backup)|ha node|ns acl|servicegroup))(\s|$)"
add system user mcp_admin <password> -externalAuth DISABLED -allowedManagementInterface API -timeout 900
bind system user mcp_admin mcp_writes 90
bind system user mcp_admin sysadmin 100
save ns config
```

Every admin tool passed with this pair on 13.1-64.28. For Admins who should only operate (enable, disable, drain, kill, block, trace) and not change configuration, leave out `sysadmin`; `nitro_write` can then do only what `mcp_writes` allows. `mcp_writes` carries the `show` commands those tools read first, so it works on its own: every operate tool passed with `mcp_writes` alone on 13.1-64.28. Check the built-in policies' exact rules on your build with `show system cmdPolicy` before relying on one. Use `preview` (on by default) to see the exact NITRO request before it is sent.

The policy cannot tell a member-level `disable servicegroup` from a whole-group one, so that narrowing lives in the tool. `kill system session \d+` does admit one session ID only, which keeps `kill system session -all` out at the appliance. `create system backup` does not match restore.

If you use per-node reads against the secondary, confirm the users and policies exist there too.

### SSH user for `run_nsconmsg` (optional)

`run_nsconmsg` reads per-PPE counters and newnslog events over SSH. Give it its own user that can run nothing but `nsconmsg`:

```
add system user ns_nsconmsg_ro <password> -externalAuth DISABLED -allowedManagementInterface CLI -logging ENABLED -timeout 300
add system cmdPolicy ns_nsconmsg_ro_policy ALLOW "^shell nsconmsg (-K /var/nslog/newnslog(\.[0-9]{1,4})? (-d event( -s disptime=1)?|-d current( -g [A-Za-z0-9_.-]+)?|-d stats)|-d oldconmsg -s ConLb=2)$"
bind system user ns_nsconmsg_ro ns_nsconmsg_ro_policy 100
save ns config
```

The tool builds only these four command shapes, and the policy allows exactly these and nothing else. `<logfile>` is `/var/nslog/newnslog` or an uncompressed `/var/nslog/newnslog.<n>`; `<group>` is letters, digits, `_`, `.` and `-`.

- `nsconmsg -K <logfile> -d event [-s disptime=1]`
- `nsconmsg -K <logfile> -d current [-g <group>]`
- `nsconmsg -K <logfile> -d stats`
- `nsconmsg -d oldconmsg -s ConLb=2`

If the user already exists with an older, looser policy, `set system cmdPolicy ns_nsconmsg_ro_policy ALLOW "<the regex above>"` replaces it in place; the binding stays.

Rotated newnslog archives (`/var/nslog/newnslog.N.tar.gz`) are refused: on 13.1 `nsconmsg` decompresses and extracts an archive in place under `/var/nslog` (a 31 MB archive became 244 MB), which a read tool must not do. `-K pipe` does not read stdin on 13.1 either. For older syslog events, read `/var/log/ns.log.N.gz` with `get_system_file` (admin account); `get_syslog` returns only the most recent 256 messages.

### SSH user for the forensic tools (optional)

`get_core_backtrace` (list cores, gdb backtrace of one), `search_core` (find a marker such as an IdP issuer in a core's memory, with the readable text around it) and `capture_aaad_debug` (stream the authentication daemon's debug output for 5-120 seconds while you reproduce a logon) need root on the appliance. They run as their own CLI-only account whose policy allows exactly the commands they send, and nothing else:

```
add system cmdPolicy mcp_forensics_policy ALLOW "^shell (gdb -nx -batch -ex bt /netscaler/([a-z][a-z0-9_]{1,31}) /var/core/([0-9]{1,4}/)?\2-[0-9]{1,7}|grep -a -o -b -E -m [0-9]{1,2} \[\[:print:\]\]\{0,128\}[A-Za-z0-9_.:/=@][A-Za-z0-9_.:/=@-]{2,63}\[\[:print:\]\]\{0,128\} /var/core/([0-9]{1,4}/)?[a-z][a-z0-9_]{1,31}-[0-9]{1,7}|cat /tmp/aaad\.debug|ls -lR /var/core)$"
add system user mcp_forensics <password> -externalAuth DISABLED -allowedManagementInterface CLI -logging ENABLED -timeout 300
bind system user mcp_forensics mcp_forensics_policy 100
save ns config
```

Be clear about what this account is: the commands it may run execute as root, and its output can include process memory and authentication traffic. The policy pins each command to one shape (gdb only with `bt`, on a binary under `/netscaler/` matching the core's own daemon; grep only on `/var/core`; cat only on `/tmp/aaad.debug`; `ls` only on `/var/core`), and the appliance refuses everything else, including `;`, `|`, `&&`, `$()` and extra arguments. Output is redacted before it reaches the model, but treat it as sensitive.

Then set `NETSCALER_FORENSICS_USER` and `NETSCALER_FORENSICS_PASS`; that is what turns the tools on. Hosted mode also requires the target's `NS_<NAME>_SSH_SHA256` pins for them. Notes from 13.1:

- Cores land in `/var/core/<daemon>-<pid>` or `/var/core/<n>/<daemon>-<pid>`. gdb reads only uncompressed cores.
- A capture or search cut off by its time limit closes the SSH session, which ends `cat` and `grep` on the appliance. gdb ignores the hang-up when it is blocked, so a gdb run that hangs keeps running as root until it finishes; on a real core it completes in seconds.
- The appliance CLI drops output lines that hold unprintable bytes, which is why `search_core` returns printable context only.

To trace with TLS keys, use the admin tools: `start_nstrace` with `capture_ssl_keys`, then `stop_nstrace`, which lists the trace directories and their `.sslkeys` files. Fetch the keys file with `get_system_file`, copy the trace off the appliance with scp or the GUI, and delete both when done: the keys decrypt every captured session.

## 2. Pin the certificates

On Windows, run the `openssl` and `ssh-keyscan` commands below in Git Bash (installed with Git for Windows) or WSL.

Get each node's NSIP certificate fingerprint:

```bash
openssl s_client -connect 10.0.0.1:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

Put both nodes' values in `NETSCALER_TLS_SHA256`, comma-separated. Colons are optional. Without a pin, the server accepts any certificate on the path. It says so on stderr at startup.

For SSH, get each node's host key fingerprint and put the `SHA256:...` values in `NETSCALER_SSH_SHA256`:

```bash
ssh-keyscan 10.0.0.1 2>/dev/null | ssh-keygen -lf -
```

Verify both against the console or a known-good session, not just the network you are on. That's the point of pinning.

When a node's certificate changes, its calls fail with `TLS certificate fingerprint mismatch ... got <new value>`. Confirm the change was yours, then update the pin.

## 3. Build

Node.js 20 or newer.

```bash
npm ci
npm run build
```

## 4. Add it to your MCP client

The multi-line examples use bash line continuation (`\`). In PowerShell, end each line with a backtick or put the command on one line.

### Claude Code

```bash
claude mcp add netscaler \
  -e NETSCALER_NSIP=10.0.0.1 -e NETSCALER_PEER_NSIP=10.0.0.2 \
  -e NETSCALER_USER=mcp_read -e NETSCALER_PASS=changeme \
  -e NETSCALER_TLS_SHA256=AA...,BB... \
  -- node /path/to/netscaler-mcp-oss/dist/index.js
```

Or copy `.mcp.json.example` to `.mcp.json` in the folder you run Claude Code from. `.mcp.json` is gitignored. Never commit it.

### Several appliances

One server can cover several HA pairs. List short names (lowercase letters and digits) in `NETSCALER_TARGETS` and give each one the usual settings under `NS_<NAME>_` instead of `NETSCALER_`:

```bash
claude mcp add netscaler \
  -e NETSCALER_TARGETS=east,west \
  -e NS_EAST_NSIP=10.0.0.1 -e NS_EAST_PEER_NSIP=10.0.0.2 -e NS_EAST_USER=mcp_read -e NS_EAST_PASS=changeme -e NS_EAST_TLS_SHA256=AA...,BB... \
  -e NS_WEST_NSIP=10.1.0.1 -e NS_WEST_USER=mcp_read -e NS_WEST_PASS=changeme -e NS_WEST_TLS_SHA256=CC... \
  -- node /path/to/netscaler-mcp-oss/dist/index.js
```

With `NETSCALER_TARGETS` set, the plain `NETSCALER_*` appliance settings are ignored; `NETSCALER_BLOCK_PROTECT` stays global and protects your /24s on every appliance. With more than one target, every tool gains a required `appliance` argument listing the names and NSIPs, and the model asks which one when the request does not say. Accounts are per appliance: add `NS_EAST_ADMIN_USER` and only EAST gets write access; the write tools appear, and a write aimed at WEST is refused before anything is sent.

### Claude Desktop and other clients

Any client that launches stdio servers takes the same shape. In Claude Desktop, add it to `claude_desktop_config.json` under `mcpServers`, using the block from `.mcp.json.example`. On Windows, use a full path to `dist/index.js`, with forward slashes or escaped backslashes.

## 5. Turning on write tools

Set `NETSCALER_ADMIN_USER` and `NETSCALER_ADMIN_PASS` and restart the client. Leave them out of any config you hand to someone who should only read. The 17 admin tools (16 write tools plus `get_system_file`) then appear alongside the read tools. Before you do:

- Create the admin account above.
- Make your client ask before every write tool call. The write tools carry the MCP `destructiveHint` annotation for clients that honour it; in Claude Code, do not add them to an allow list. This matters because the read tools return text an outsider controls (Gateway usernames, request strings, User-Agents in logs), and a model reading that text in the same session could be steered into a write. Approve each write, or do write work in a session that is not reading logs.
- Set `NETSCALER_BLOCK_PROTECT` to the /24 you manage the appliance from, so `block_ip_acl` cannot lock you out.
- Remember the client asks you to approve tool calls, but an approval is only as good as the reading behind it. `force_ha_failover` refuses if the expected current primary is wrong, `nitro_write` only previews unless `preview: false`, and `kill_admin_session` checks the username. The other write tools act on the first call.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `Missing required environment variables` | `NETSCALER_NSIP`, `NETSCALER_USER` or `NETSCALER_PASS` (or a target's `NS_<NAME>_` equivalent) not set in the client config |
| `TLS certificate fingerprint mismatch` | The pin does not match the node's certificate. See step 2 |
| A NITRO authorization error on one tool | The account's command policy denies it. The error names the exact CLI command, which is the string to allow |
| No write tools listed | `NETSCALER_ADMIN_USER` / `NETSCALER_ADMIN_PASS` (or the target's `NS_<NAME>_` equivalent) not set |
| A `node: peer` call says no peer NSIP is configured | Set `NETSCALER_PEER_NSIP` (or the target's `NS_<NAME>_PEER_NSIP`) |
| `run_nsconmsg` not listed | `NETSCALER_SSH_USER` / `NETSCALER_SSH_PASS` (or the target's `NS_<NAME>_` equivalent) not set |
| No forensic tools listed | `NETSCALER_FORENSICS_USER` / `NETSCALER_FORENSICS_PASS` (or the target's `NS_<NAME>_` equivalent) not set |
