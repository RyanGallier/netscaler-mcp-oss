# Hosted mode (HTTP)

One shared endpoint for a team. Each person signs in with Entra ID, gets the tools their role allows, and every admin-tier call (writes, file reads, forensic tools) is logged with their identity. It runs on Azure App Service, with App Service authentication (Easy Auth) doing all token validation in front of the code.

## How it works

```
MCP client
  -> Entra access token
App Service Easy Auth
  -> X-MS-CLIENT-PRINCIPAL header
netscaler-mcp
  -> NITRO and SSH, pinned
NetScalers
```

1. The client discovers the auth server from Easy Auth's protected-resource metadata, signs the user in, and sends a bearer token.
2. Easy Auth validates the token: issuer, audience, and that the calling client app is on `allowedApplications`. Invalid tokens get a 401 and never reach the code.
3. The server reads the caller's claims from the `X-MS-CLIENT-PRINCIPAL` header Easy Auth injects. It requires the `NetScaler.Access` scope plus either the `NetScaler.Reader` or `NetScaler.Admin` app role, or returns 403.
4. A fresh MCP server is built for that one request with only the tools the role allows. Readers never see the write tools at all.
5. Each admin-tier call (write tools, `get_system_file`, forensic tools, including `nitro_write` previews) logs an `attempt` line before it runs and a `result` line after, as JSON on stdout: user, object ID, client app, tool, arguments, outcome and duration. App Service log streaming and diagnostic settings carry these to Log Analytics.

Transport details: stateless Streamable HTTP, `POST /mcp` only, JSON responses, no JSON-RPC batches, 256 KB request cap. It listens on `PORT`, which App Service sets (default 8080).

**The server trusts `X-MS-CLIENT-PRINCIPAL`, so it must only ever run behind Easy Auth.** It refuses to start unless `WEBSITE_AUTH_ENABLED` is `true`, which App Service sets when authentication is on. Never set that variable by hand anywhere else. Anyone who can reach the port directly could forge the header and get admin.

## Several appliances, one endpoint

This is the same `NETSCALER_TARGETS` scheme local mode uses; hosted mode adds the pinning requirement below. `NETSCALER_TARGETS` lists short names, lowercase letters and digits only. Each target reads the usual settings under its own prefix:

```
NETSCALER_TARGETS=prod,dr
NS_PROD_NSIP=203.0.113.10
NS_PROD_PEER_NSIP=203.0.113.11
NS_PROD_USER=mcp_read
NS_PROD_PASS=@Microsoft.KeyVault(VaultName=kv-example;SecretName=ns-prod-pass)
NS_PROD_TLS_SHA256=AA...,BB...
NS_PROD_SSH_USER=ns_nsconmsg_ro
NS_PROD_SSH_PASS=@Microsoft.KeyVault(VaultName=kv-example;SecretName=ns-prod-ssh-pass)
NS_PROD_SSH_SHA256=SHA256:...,SHA256:...
NS_PROD_ADMIN_USER=mcp_admin
NS_PROD_ADMIN_PASS=@Microsoft.KeyVault(VaultName=kv-example;SecretName=ns-prod-admin-pass)
NS_PROD_FORENSICS_USER=mcp_forensics
NS_PROD_FORENSICS_PASS=@Microsoft.KeyVault(VaultName=kv-example;SecretName=ns-prod-forensics-pass)
NS_DR_NSIP=...
```

Each account is optional except the read account, and a tool is offered only for targets that have the account it needs. `NetScaler.Admin` callers get every tool: the write tools on targets with an admin account and the forensic tools on targets with a forensics account. The forensic tools read core memory and the authentication debug stream, which can hold end users' passwords, so configure a forensics account only on appliances where every Admin should have them. A call naming a target without the account it needs is refused before anything is sent. The read and admin accounts are separate NetScaler users, so a Reader's requests can never carry write rights.

With more than one target, every tool gains a required `appliance` argument listing the names and NSIPs, and the model asks the user when the request does not say which. With one target, the tools look exactly as they do in local mode.

At startup each target must use `https` with a TLS pin, plus an SSH pin when an SSH or forensics user is set, or the server refuses to start.

## Setup

You need: an Azure subscription, rights to create Entra app registrations, PowerShell 7 and the Azure CLI. The NetScaler-side accounts and command policies are the same as [local mode](local-mode.md#accounts). The hosted server enforces roles, but the command policy is still the hard limit. Cap it at what your Admins' tools need.

### 1. Register the Entra apps

```powershell
az login
./infra/register-app.ps1 -WhatIf
./infra/register-app.ps1
```

This creates:

- **netscaler-mcp**, the API: v2 tokens, scope `NetScaler.Access`, user app roles `NetScaler.Reader` and `NetScaler.Admin`, assignment required. It assigns you `NetScaler.Admin`.
- **netscaler-mcp-claude-code**, a public client for Claude Code with redirect `http://localhost:8080/callback`.

Azure CLI is pre-authorized for testing. Add other front ends, such as a chat app or a gateway calling on behalf of the user, with `-ExtraClientAppIds`. Note the `ApiClientId` and `ClaudeClientId` it prints.

Assign people to the roles in Entra under Enterprise applications > netscaler-mcp > Users and groups. Unassigned users cannot get a token at all.

### 2. Create the App Service

- Linux App Service plan, Node 20 LTS or newer runtime. B1 is enough.
- Startup command `node dist/index.js`, HTTPS only, minimum TLS 1.2, FTP and SCM basic auth disabled, Always On.
- A system-assigned managed identity with **Key Vault Secrets User** on the vault holding the NetScaler passwords.

### 3. App settings

```
MCP_TRANSPORT=http
SCM_DO_BUILD_DURING_DEPLOYMENT=false
WEBSITE_AUTH_PRM_DEFAULT_WITH_SCOPES=api://<ApiClientId>/NetScaler.Access
NETSCALER_TARGETS=...
NS_<NAME>_...                 (as above; passwords as Key Vault references)
NETSCALER_BLOCK_PROTECT=<your egress /24>
```

`WEBSITE_AUTH_PRM_DEFAULT_WITH_SCOPES` makes Easy Auth publish protected-resource metadata at `/.well-known/oauth-protected-resource` and name it in the 401 challenge. That is how MCP clients discover where to sign in. It is a preview Easy Auth feature.

### 4. Authentication (Easy Auth v2)

Configure `authsettingsV2` like this. In Bicep it is a `Microsoft.Web/sites/config` resource named `authsettingsV2`:

```json
{
  "platform": { "enabled": true },
  "globalValidation": { "requireAuthentication": true, "unauthenticatedClientAction": "Return401" },
  "httpSettings": { "requireHttps": true },
  "identityProviders": {
    "azureActiveDirectory": {
      "enabled": true,
      "registration": {
        "openIdIssuer": "https://login.microsoftonline.com/<tenant-id>/v2.0",
        "clientId": "<ApiClientId>"
      },
      "validation": {
        "allowedAudiences": ["<ApiClientId>", "api://<ApiClientId>"],
        "defaultAuthorizationPolicy": {
          "allowedApplications": ["<ClaudeClientId>", "04b07795-8ddb-461a-bbee-02f9e1bf7b46"]
        }
      }
    }
  }
}
```

`allowedApplications` is enforced: Easy Auth rejects a token whose calling app is not listed. The second ID is Azure CLI, for testing. Drop it in production if you like. Add any `-ExtraClientAppIds` here too. No client secret is needed, because the app only validates bearer tokens.

### 5. Network path to the appliances

Allowlist one stable source IP on the NetScaler management side. App Service's default outbound IPs are shared across a scale unit, so allowlisting them would let other tenants' apps reach your NSIPs. Instead:

- Enable VNet integration with route-all, and put a NAT gateway with a static public IP on the integration subnet. Or route through your own firewall if the NSIPs are private.
- Allow that IP to the NSIPs on 443 (NITRO) and 22 (SSH, only if `run_nsconmsg` or the forensic tools are used).
- Put its /24 in `NETSCALER_BLOCK_PROTECT`.

### 6. Deploy

```bash
npm ci && npm run build
npm prune --omit=dev
zip -r app.zip dist node_modules package.json
az webapp deploy -g <rg> -n <app> --src-path app.zip --type zip
```

### 7. Custom domain and identifier URIs

Claude clients send the server URL as the OAuth resource, and Entra rejects it unless that URL is an identifier URI on the API app. Entra accepts `https://` identifier URIs only on a domain verified in your tenant, and `azurewebsites.net` is not one. So in practice you need a custom domain on the App Service:

```powershell
./infra/register-app.ps1 -ServerUrls https://netscaler-mcp.example.com/mcp
```

Some client UIs also restrict which domains they accept. Check yours before choosing the hostname.

## Connecting clients

### Claude Code

```bash
claude mcp add --transport http netscaler https://netscaler-mcp.example.com/mcp --client-id <ClaudeClientId> --callback-port 8080
```

Then run `/mcp` in Claude Code and sign in.

### Other clients

Any MCP client that supports OAuth with a pre-registered client works. Register a client app for it, pre-authorize it with `-ExtraClientAppIds`, and add it to `allowedApplications`.

## Verify

- An anonymous `POST /mcp` returns 401 with a `WWW-Authenticate` header naming the metadata URL.
- With every account configured, a Reader lists 53 tools and an Admin 73. With several targets each tool carries the `appliance` argument.
- A Reader calling a write tool by name gets an error, and nothing reaches the appliance.
- `get_system_info` succeeds against every target, and `run_nsconmsg` too if SSH is configured.
- An Admin write produces `attempt` and `result` lines in the log stream.

## Operating it

- **Rotating a NetScaler password:** update the Key Vault secret, then restart the app so it re-resolves the reference.
- **Certificate renewed on a node:** calls fail with `TLS certificate fingerprint mismatch ... got <new value>`. Confirm, update `NS_<NAME>_TLS_SHA256`, restart.
- **Removing someone's access:** remove their role assignment. Tokens already issued stay valid until they expire, by default a random 60-90 minutes.
- **Turning writes off for everyone:** remove all `NetScaler.Admin` assignments, or tighten the NetScaler command policy, which takes effect immediately.
