<#
.SYNOPSIS
    Creates (or updates) the Entra ID app registration PAW Proxy Pilot signs in with.

.DESCRIPTION
    - App registration "PAW Proxy Pilot", single tenant, Web redirect URI
      https://<HostName>:<Port>/auth/callback
    - App role PAWProxyPilot.Admin (users and groups)
    - Enterprise app with "Assignment required" switched on
    - Admin consent for the sign-in scopes (openid, profile, offline_access),
      so users never see a consent prompt
    - Assigns the PAWProxyPilot.Admin role to the users/groups you name
    - Creates a client secret and prints a PAW Proxy Pilot setup code: one line holding
      the tenant ID, client ID, secret and expiry, which you paste into the
      PAW Proxy Pilot installer on the Ubuntu server. It's copied to your clipboard too.

    Run it on your own Windows or Mac machine. Safe to re-run: an existing
    "PAW Proxy Pilot" app is updated rather than duplicated, and each run adds a new
    secret (that's how you rotate it).

    Needs PowerShell 7 (Windows PowerShell 5.1 also works) and the Microsoft
    Graph modules, which are installed for you if missing. Sign in as a Global
    Administrator, or Cloud Application Administrator plus Privileged Role
    Administrator.

.EXAMPLE
    # Windows or Mac, in the folder you extracted PAW Proxy Pilot to
    pwsh ./deploy/New-PAWProxyPilotApp.ps1 -HostName pawproxy.example.com -AssignTo you@example.com

.EXAMPLE
    # Show the separate values as well as the setup code
    pwsh ./deploy/New-PAWProxyPilotApp.ps1 -AssignTo you@example.com -ShowValues

.NOTES
    The setup code contains the client secret: treat it like a password.
    install.sh can also run this script on the server itself (-UseDeviceCode
    -OutputJson); that's the fallback, not the usual route.
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]   $HostName     = 'pawproxy.example.com',
    [ValidateRange(1024, 65535)]
    [int]      $Port         = 8443,
    [string[]] $AssignTo     = @(),
    [string]   $DisplayName  = 'PAW Proxy Pilot',
    [ValidateRange(1, 24)]
    [int]      $SecretMonths = 12,
    [string]   $TenantId,
    [switch]   $UseDeviceCode,
    # Used by install.sh: write the results (including the secret) to this
    # file as JSON instead of printing the secret on screen.
    [string]   $OutputJson,
    # Also print the separate values (tenant ID, client ID, secret)
    [switch]   $ShowValues
)

$ErrorActionPreference = 'Stop'
$ProgressPreference    = 'SilentlyContinue'
$RoleValue   = 'PAWProxyPilot.Admin'
$GraphAppId  = '00000003-0000-0000-c000-000000000000'
$SignInScopes = @('openid', 'profile', 'offline_access')
$RedirectUri = "https://$($HostName):$Port/auth/callback"

function Write-Step($Text) { Write-Host "`n==> $Text" -ForegroundColor DarkYellow }

# --- Modules -----------------------------------------------------------------
# All Graph sub-modules must be the same version as Microsoft.Graph.Authentication,
# otherwise PowerShell fails with "Assembly with same name is already loaded".
$auth = Get-Module -Name Microsoft.Graph.Authentication
if (-not $auth) {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Step 'Installing Microsoft.Graph.Authentication'
        Install-Module Microsoft.Graph.Authentication -Scope CurrentUser -Force -AllowClobber
    }
    $auth = Get-Module -ListAvailable -Name Microsoft.Graph.Authentication |
        Sort-Object Version -Descending | Select-Object -First 1
    Import-Module Microsoft.Graph.Authentication -RequiredVersion $auth.Version -ErrorAction Stop
}
$graphVersion = $auth.Version
Write-Host "Using Microsoft Graph PowerShell $graphVersion"

foreach ($m in 'Microsoft.Graph.Applications', 'Microsoft.Graph.Users', 'Microsoft.Graph.Groups',
               'Microsoft.Graph.Identity.SignIns') {
    $loaded = Get-Module -Name $m
    if ($loaded -and $loaded.Version -ne $graphVersion) {
        throw "$m $($loaded.Version) is already loaded but Graph Authentication is $graphVersion. Open a new PowerShell window and run the script again."
    }
    if ($loaded) { continue }
    if (-not (Get-Module -ListAvailable -Name $m | Where-Object Version -eq $graphVersion)) {
        Write-Step "Installing $m $graphVersion to match"
        Install-Module $m -RequiredVersion $graphVersion -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $m -RequiredVersion $graphVersion -ErrorAction Stop
}

# --- Sign in -------------------------------------------------------------------
Write-Step 'Signing in to Microsoft Graph'
$connect = @{
    Scopes    = 'Application.ReadWrite.All', 'AppRoleAssignment.ReadWrite.All',
                'DelegatedPermissionGrant.ReadWrite.All', 'User.Read.All', 'Group.Read.All'
    NoWelcome = $true
}
if ($TenantId)      { $connect.TenantId = $TenantId }
if ($UseDeviceCode) { $connect.UseDeviceCode = $true }
Connect-MgGraph @connect
$ctx = Get-MgContext
Write-Host "Signed in as $($ctx.Account) to tenant $($ctx.TenantId)"

# --- App registration --------------------------------------------------------
$app = Get-MgApplication -Filter "displayName eq '$DisplayName'" -All | Select-Object -First 1
$roles = @()
if ($app) {
    Write-Step "Updating existing app registration '$DisplayName' ($($app.AppId))"
    $roles = @($app.AppRoles)
} else {
    Write-Step "Creating app registration '$DisplayName'"
}

$role = $roles | Where-Object Value -eq $RoleValue | Select-Object -First 1
if (-not $role) {
    $role = @{
        Id                 = [guid]::NewGuid().ToString()
        AllowedMemberTypes = @('User')
        DisplayName        = 'PAW Proxy Pilot Admin'
        Description        = 'Can sign in to PAW Proxy Pilot and change the PAW proxy allow list.'
        Value              = $RoleValue
        IsEnabled          = $true
    }
    $roles += $role
}

$graphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'"
$scopeAccess = foreach ($s in $SignInScopes) {
    $scope = $graphSp.Oauth2PermissionScopes | Where-Object Value -eq $s
    @{ Id = $scope.Id; Type = 'Scope' }
}

$redirects = @($RedirectUri)
if ($app -and $app.Web.RedirectUris) {
    $redirects = @($app.Web.RedirectUris + $RedirectUri | Select-Object -Unique)
}

$body = @{
    DisplayName            = $DisplayName
    SignInAudience         = 'AzureADMyOrg'
    Web                    = @{
        RedirectUris          = $redirects
        LogoutUrl             = "https://$($HostName):$Port/login"
        ImplicitGrantSettings = @{ EnableIdTokenIssuance = $false; EnableAccessTokenIssuance = $false }
    }
    AppRoles               = $roles
    RequiredResourceAccess = @(@{ ResourceAppId = $GraphAppId; ResourceAccess = @($scopeAccess) })
    Notes                  = "PAW Proxy Pilot (Squid allow-list admin) on $HostName. Created by New-PAWProxyPilotApp.ps1."
}

if ($app) {
    Update-MgApplication -ApplicationId $app.Id -BodyParameter $body
    $app = Get-MgApplication -ApplicationId $app.Id
} else {
    $app = New-MgApplication -BodyParameter $body
}
$roleId = ($app.AppRoles | Where-Object Value -eq $RoleValue).Id

# --- Enterprise app (service principal) --------------------------------------------
$sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'"
if (-not $sp) {
    Write-Step 'Creating the enterprise application'
    # Graph can take a few seconds to see a brand-new app.
    for ($i = 0; -not $sp -and $i -lt 6; $i++) {
        try {
            $sp = New-MgServicePrincipal -AppId $app.AppId -AppRoleAssignmentRequired:$true `
                -Tags @('WindowsAzureActiveDirectoryIntegratedApp')
        } catch { Start-Sleep -Seconds 5 }
    }
    if (-not $sp) { throw 'Could not create the enterprise application. Re-run the script.' }
} else {
    Update-MgServicePrincipal -ServicePrincipalId $sp.Id -AppRoleAssignmentRequired:$true
}
Write-Host 'Assignment required: Yes'

# --- Admin consent for sign-in scopes ------------------------------------------
Write-Step 'Granting admin consent for sign-in (openid, profile, offline_access)'
$grant = Get-MgOauth2PermissionGrant -Filter "clientId eq '$($sp.Id)' and resourceId eq '$($graphSp.Id)' and consentType eq 'AllPrincipals'" |
    Select-Object -First 1
$scopeString = $SignInScopes -join ' '
if ($grant) {
    Update-MgOauth2PermissionGrant -OAuth2PermissionGrantId $grant.Id -Scope $scopeString
} else {
    New-MgOauth2PermissionGrant -ClientId $sp.Id -ResourceId $graphSp.Id -ConsentType 'AllPrincipals' `
        -Scope $scopeString | Out-Null
}

# --- Role assignments ----------------------------------------------------------
if (-not $AssignTo) { $AssignTo = @($ctx.Account) }
$existing = Get-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -All
foreach ($who in $AssignTo) {
    $principal = $null
    try { $principal = Get-MgUser -UserId $who -ErrorAction Stop } catch {
        $principal = Get-MgGroup -Filter "displayName eq '$who'" | Select-Object -First 1
    }
    if (-not $principal) { Write-Warning "Couldn't find a user or group called '$who'; skipped."; continue }
    if ($existing | Where-Object { $_.PrincipalId -eq $principal.Id -and $_.AppRoleId -eq $roleId }) {
        Write-Host "$who already has $RoleValue"
        continue
    }
    New-MgServicePrincipalAppRoleAssignedTo -ServicePrincipalId $sp.Id -PrincipalId $principal.Id `
        -ResourceId $sp.Id -AppRoleId $roleId | Out-Null
    Write-Host "Assigned $RoleValue to $who"
}

# --- Client secret -------------------------------------------------------------
Write-Step "Creating a client secret (valid $SecretMonths months)"
$secret = Add-MgApplicationPassword -ApplicationId $app.Id -PasswordCredential @{
    DisplayName = "pawpilot-server $(Get-Date -Format yyyy-MM-dd)"
    EndDateTime = (Get-Date).AddMonths($SecretMonths)
}

# --- Output -----------------------------------------------------------------------
$expires = $secret.EndDateTime.ToString('yyyy-MM-dd')
$result = [ordered]@{
    tenantId      = $ctx.TenantId
    clientId      = $app.AppId
    clientSecret  = $secret.SecretText
    role          = $RoleValue
    secretExpires = $expires
    redirectUri   = $RedirectUri
}
$json = $result | ConvertTo-Json -Compress

if ($OutputJson) {
    Set-Content -Path $OutputJson -Value $json -NoNewline -Encoding utf8
    Write-Host "`nDone. App '$DisplayName' ($($app.AppId)) is ready; the installer will save its details." -ForegroundColor Green
} else {
    # One line for the installer: PAWPILOT1. + base64url(JSON)
    $b64  = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($json)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
    $code = "PAWPILOT1.$b64"

    Write-Host "`nDone. App '$DisplayName' is ready." -ForegroundColor Green
    Write-Host "  Tenant ID:      $($ctx.TenantId)"
    Write-Host "  Client ID:      $($app.AppId)"
    Write-Host "  Redirect URI:   $RedirectUri"
    Write-Host "  Secret expires: $expires"
    if ($ShowValues) { Write-Host "  Client secret:  $($secret.SecretText)" }

    Write-Host "`nPAW Proxy Pilot setup code (paste this into the installer on the Ubuntu server):`n" -ForegroundColor Yellow
    Write-Host $code
    $copied = $false
    try { Set-Clipboard -Value $code -ErrorAction Stop; $copied = $true } catch {
        if (Get-Command pbcopy -ErrorAction SilentlyContinue) { $code | pbcopy; $copied = $true }
    }
    if ($copied) { Write-Host "`n(Copied to your clipboard.)" -ForegroundColor DarkGray }
    Write-Host "`nIt contains the client secret, so treat it like a password. It can't be shown again."
    Write-Host 'On the server:  sudo ./install.sh   (new install)'
    Write-Host '           or:  sudo ./install.sh --entra   (replacing the secret on an existing install)'
}
Write-Host "Client secret expires $expires; PAW Proxy Pilot warns you 30 days before. To rotate it, run this script again."
Write-Host 'Recommended: a Conditional Access policy for the PAW Proxy Pilot app requiring phishing-resistant MFA.'

Disconnect-MgGraph | Out-Null
