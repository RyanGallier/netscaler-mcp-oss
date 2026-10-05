<#
.SYNOPSIS
    Creates the Entra app registrations for the hosted netscaler-mcp server.

.DESCRIPTION
    Run once, as a user allowed to create app registrations, after `az login`.
      - netscaler-mcp: the API. v2 tokens, scope NetScaler.Access, user-only app roles
        NetScaler.Reader and NetScaler.Admin, assignment required.
      - netscaler-mcp-claude-code: public client Claude Code signs in with
        (redirect http://localhost:8080/callback).
    Pre-authorizes the Claude Code client, Azure CLI (for testing) and any -ExtraClientAppIds for the
    scope, and assigns the signed-in user to NetScaler.Admin.
    Add the server URLs as identifier URIs afterwards with -ServerUrls.

.PARAMETER ServerUrls
    Server URLs to add as identifier URIs (e.g. https://host/mcp). Claude clients send
    the server URL as the OAuth resource, and Entra rejects it unless it is an identifier URI.

.PARAMETER ExtraClientAppIds
    Further client app IDs to pre-authorize for the scope, e.g. a chat front end or gateway that calls
    on behalf of the user. Each must also be listed in Easy Auth allowedApplications.

.EXAMPLE
    ./register-app.ps1 -WhatIf
    ./register-app.ps1
    ./register-app.ps1 -ServerUrls https://netscaler-mcp.example.com/mcp
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [string[]]$ServerUrls = @(),
    [string[]]$ExtraClientAppIds = @()
)

$ErrorActionPreference = 'Stop'
$graph = 'https://graph.microsoft.com/v1.0'
$azureCliAppId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'

function Invoke-Graph([string]$Method, [string]$Path, $Body) {
    $arguments = @('rest', '--method', $Method, '--url', "$graph$Path")
    if ($Body) {
        $file = New-TemporaryFile
        $Body | ConvertTo-Json -Depth 10 | Set-Content -Path $file -Encoding utf8
        $arguments += @('--headers', 'Content-Type=application/json', '--body', "@$file")
    }
    $out = az @arguments
    if ($LASTEXITCODE -ne 0) { throw "Graph $Method $Path failed" }
    if ($out) { $out | ConvertFrom-Json }
}

function Get-App([string]$Name) {
    (Invoke-Graph GET "/applications?`$filter=displayName eq '$Name'").value | Select-Object -First 1
}

$api = Get-App 'netscaler-mcp'
if (-not $api) {
    if (-not $PSCmdlet.ShouldProcess('netscaler-mcp', 'Create API app registration')) { return }
    $scopeId = [guid]::NewGuid().ToString()
    $api = Invoke-Graph POST '/applications' @{
        displayName    = 'netscaler-mcp'
        signInAudience = 'AzureADMyOrg'
        api            = @{
            requestedAccessTokenVersion = 2
            oauth2PermissionScopes      = @(@{
                    id                      = $scopeId
                    value                   = 'NetScaler.Access'
                    type                    = 'User'
                    isEnabled               = $true
                    adminConsentDisplayName = 'Use the NetScaler MCP server'
                    adminConsentDescription = 'Call NetScaler MCP tools as the signed-in user, within their assigned role.'
                    userConsentDisplayName  = 'Use the NetScaler MCP server'
                    userConsentDescription  = 'Call NetScaler MCP tools as you, within your assigned role.'
                })
        }
        appRoles       = @(
            @{ id = [guid]::NewGuid().ToString(); value = 'NetScaler.Reader'; displayName = 'NetScaler Reader'
                description = 'Read and diagnostic tools.'; allowedMemberTypes = @('User'); isEnabled = $true },
            @{ id = [guid]::NewGuid().ToString(); value = 'NetScaler.Admin'; displayName = 'NetScaler Admin'
                description = 'All tools, including failover, sync, enable/disable, save config, file reads and the forensic tools.'; allowedMemberTypes = @('User'); isEnabled = $true }
        )
    }
    Invoke-Graph PATCH "/applications/$($api.id)" @{ identifierUris = @("api://$($api.appId)") } | Out-Null
    Write-Output "Created API app $($api.appId)"
}
$api = Invoke-Graph GET "/applications/$($api.id)"
$scopeId = ($api.api.oauth2PermissionScopes | Where-Object value -EQ 'NetScaler.Access').id

$client = Get-App 'netscaler-mcp-claude-code'
if (-not $client -and $PSCmdlet.ShouldProcess('netscaler-mcp-claude-code', 'Create public client registration')) {
    $client = Invoke-Graph POST '/applications' @{
        displayName            = 'netscaler-mcp-claude-code'
        signInAudience         = 'AzureADMyOrg'
        isFallbackPublicClient = $true
        publicClient           = @{ redirectUris = @('http://localhost:8080/callback') }
        requiredResourceAccess = @(@{
                resourceAppId  = $api.appId
                resourceAccess = @(@{ id = $scopeId; type = 'Scope' })
            })
    }
    Write-Output "Created Claude Code client $($client.appId)"
}

$preAuthorized = @(@($client.appId, $azureCliAppId) + $ExtraClientAppIds | Select-Object -Unique) | ForEach-Object {
    @{ appId = $_; delegatedPermissionIds = @($scopeId) }
}
$uris = @(@("api://$($api.appId)") + $ServerUrls | Select-Object -Unique)
if ($PSCmdlet.ShouldProcess('netscaler-mcp', "Set pre-authorized clients and identifier URIs: $($uris -join ', ')")) {
    Invoke-Graph PATCH "/applications/$($api.id)" @{
        identifierUris = $uris
        api            = @{ preAuthorizedApplications = @($preAuthorized) }
    } | Out-Null
}

foreach ($appId in @($api.appId, $client.appId)) {
    $sp = (Invoke-Graph GET "/servicePrincipals?`$filter=appId eq '$appId'").value | Select-Object -First 1
    if (-not $sp -and $PSCmdlet.ShouldProcess($appId, 'Create service principal')) {
        $sp = Invoke-Graph POST '/servicePrincipals' @{ appId = $appId }
    }
    if ($appId -eq $api.appId) { $apiSp = $sp }
}

if ($PSCmdlet.ShouldProcess('netscaler-mcp', 'Require assignment and assign signed-in user to NetScaler.Admin')) {
    Invoke-Graph PATCH "/servicePrincipals/$($apiSp.id)" @{ appRoleAssignmentRequired = $true } | Out-Null
    $me = Invoke-Graph GET '/me'
    $adminRoleId = ($api.appRoles | Where-Object value -EQ 'NetScaler.Admin').id
    $existing = (Invoke-Graph GET "/servicePrincipals/$($apiSp.id)/appRoleAssignedTo").value |
        Where-Object { $_.principalId -eq $me.id -and $_.appRoleId -eq $adminRoleId }
    if (-not $existing) {
        Invoke-Graph POST "/servicePrincipals/$($apiSp.id)/appRoleAssignedTo" @{
            principalId = $me.id; resourceId = $apiSp.id; appRoleId = $adminRoleId
        } | Out-Null
    }
}

[pscustomobject]@{
    ApiClientId    = $api.appId
    ClaudeClientId = $client.appId
    Scope          = "api://$($api.appId)/NetScaler.Access"
    IdentifierUris = $uris -join ', '
}
