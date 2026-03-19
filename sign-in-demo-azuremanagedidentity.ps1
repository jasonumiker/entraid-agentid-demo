$blueprintAppId = "ae6aff65-c6bf-4935-8dfb-f91d19ca0837"
$tenantId = "99238842-6a3b-4feb-8866-9ec5bc878bb4"
$agentIdentityAppId = "cfef2994-48a3-4c27-bf6b-c1e2996d730c"
$agentUserId = "d9d235cf-8b52-4561-b863-e4ed34b2c7cd"
$agentUserPrincipalName = "MyAgentUser@M365x41156588.onmicrosoft.com"
$vmManagedIdentityId = "087b6eb6-06f3-4e42-9a0b-22a938b92e4d"
$managedIdentityClientId = $env:MANAGED_IDENTITY_CLIENT_ID

#Functions
function Get-DecodedJwtToken {
    <#
    .SYNOPSIS
    Decodes a JWT token and returns the payload as formatted JSON.
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$Token
    )
    
    try {
        $tokenParts = $Token.Split('.')
        if ($tokenParts.Count -lt 2) {
            throw "Invalid JWT token format"
        }
        
        $payload = $tokenParts[1]
        while ($payload.Length % 4 -ne 0) {
            $payload += '='
        }
        
        $decodedBytes = [System.Convert]::FromBase64String($payload.Replace('-', '+').Replace('_', '/'))
        $decodedJson = [System.Text.Encoding]::UTF8.GetString($decodedBytes)
        
        return ($decodedJson | ConvertFrom-Json | ConvertTo-Json -Depth 10)
    }
    catch {
        Write-Error "Failed to decode JWT token: $_"
        return $null
    }
}

function Get-ManagedIdentityAssertionToken {
    <#
    .SYNOPSIS
    Gets a managed identity token for api://AzureADTokenExchange.
    Tries IMDS first (Azure-hosted runtime), then Azure CLI as a fallback.
    #>
    param(
        [Parameter(Mandatory = $false)]
        [string]$ManagedIdentityClientId
    )

    $resource = "api://AzureADTokenExchange"

    # 1. Try IMDS (Azure VMs, VMSS)
    try {
        $imdsUri = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=$([System.Uri]::EscapeDataString($resource))"
        if ($ManagedIdentityClientId) {
            $imdsUri += "&client_id=$([System.Uri]::EscapeDataString($ManagedIdentityClientId))"
        }

        $imdsResponse = Invoke-RestMethod -Method GET `
            -Uri $imdsUri `
            -Headers @{ Metadata = "true" } `
            -TimeoutSec 3 `
            -ErrorAction Stop

        if ($imdsResponse.access_token) {
            Write-Host "Acquired managed identity assertion from IMDS."
            return $imdsResponse.access_token
        }
    }
    catch {
        Write-Host "IMDS not available." -ForegroundColor Yellow
    }

    # 2. Try IDENTITY_ENDPOINT (App Service, Container Instances, newer Cloud Shell)
    if ($env:IDENTITY_ENDPOINT -and $env:IDENTITY_HEADER) {
        try {
            $identityUri = "$($env:IDENTITY_ENDPOINT)?resource=$([System.Uri]::EscapeDataString($resource))&api-version=2019-08-01"
            if ($ManagedIdentityClientId) {
                $identityUri += "&client_id=$([System.Uri]::EscapeDataString($ManagedIdentityClientId))"
            }

            $identityResponse = Invoke-RestMethod -Method GET `
                -Uri $identityUri `
                -Headers @{ "X-IDENTITY-HEADER" = $env:IDENTITY_HEADER } `
                -ErrorAction Stop

            if ($identityResponse.access_token) {
                Write-Host "Acquired managed identity assertion from IDENTITY_ENDPOINT."
                return $identityResponse.access_token
            }
        }
        catch {
            Write-Host "IDENTITY_ENDPOINT token acquisition failed: $_" -ForegroundColor Yellow
        }
    }

    # 3. Try MSI_ENDPOINT (older App Service - NOT Cloud Shell, which doesn't support api://AzureADTokenExchange)
    if ($env:MSI_ENDPOINT -and -not $env:ACC_CLOUD) {
        try {
            $msiBody = @{ resource = $resource }
            if ($ManagedIdentityClientId) {
                $msiBody["client_id"] = $ManagedIdentityClientId
            }

            $msiHeaders = @{ "Metadata" = "true" }
            if ($env:MSI_SECRET) {
                $msiHeaders["secret"] = $env:MSI_SECRET
            }

            $msiResponse = Invoke-RestMethod -Method POST `
                -Uri $env:MSI_ENDPOINT `
                -Headers $msiHeaders `
                -Body $msiBody `
                -ErrorAction Stop

            if ($msiResponse.access_token) {
                Write-Host "Acquired managed identity assertion from MSI_ENDPOINT."
                return $msiResponse.access_token
            }
        }
        catch {
            Write-Host "MSI_ENDPOINT token acquisition failed: $_" -ForegroundColor Yellow
        }
    }
    elseif ($env:MSI_ENDPOINT -and $env:ACC_CLOUD) {
        Write-Host "Cloud Shell detected. Its managed identity does not support the api://AzureADTokenExchange audience." -ForegroundColor Yellow
        Write-Host "Falling back to Azure CLI (using your logged-in user session)..." -ForegroundColor Yellow
    }

    # 4. Fall back to Azure CLI (uses the logged-in user's session, not managed identity)
    try {
        $cliToken = az account get-access-token --resource $resource --query accessToken -o tsv 2>&1
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($cliToken)) {
            throw "Azure CLI did not return a token for $resource."
        }

        Write-Host "Acquired assertion token from Azure CLI (user session)."
        return $cliToken.Trim()
    }
    catch {
        throw "Unable to get assertion token for $resource. Tried IMDS, IDENTITY_ENDPOINT, MSI_ENDPOINT, and Azure CLI. Cloud Shell's managed identity does NOT support the api://AzureADTokenExchange audience - use a VM, Container Instance, or App Service for true managed identity flows, or ensure you are logged in via 'az login'."
    }
}

# Log into the Blueprint with our managed identity
$managedIdentityAssertion = Get-ManagedIdentityAssertionToken -ManagedIdentityClientId $managedIdentityClientId
$managedIdentityAssertionPayload = Get-DecodedJwtToken -Token $managedIdentityAssertion
Write-Host "Managed Identity Token ($vmManagedIdentityId) we're using to authenticate to the Blueprint via Federation:"
Write-Host "$($managedIdentityAssertionPayload)"
Write-Host "------------------------------"

$blueprintTokenBody = @{
    client_id = $blueprintAppId
    scope = "api://AzureADTokenExchange/.default"
    fmi_path = $agentIdentityAppId
    client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    grant_type = "client_credentials"
    client_assertion = $managedIdentityAssertion
}

$blueprintResponse = Invoke-RestMethod -Method POST `
    -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body $blueprintTokenBody `
    -ErrorAction Stop

$blueprintToken = $blueprintResponse.access_token
$blueprintTokenPayload = Get-DecodedJwtToken -Token $blueprintToken
Write-Host "Blueprint's ($blueprintAppId) Access Token:"
Write-Host "$($blueprintTokenPayload)"
Write-Host "------------------------------"

# Exchange Blueprint token for the Agent ID token
$agentIdTokenBodyGraph = @{
    client_id             = $agentIdentityAppId
    scope                 = "https://graph.microsoft.com/.default"
    grant_type            = "client_credentials"
    client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    client_assertion      = $blueprintToken
}

$agentIdTokenResponseGraph = Invoke-RestMethod -Method POST `
    -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body $agentIdTokenBodyGraph `
    -ErrorAction Stop

$agentIdTokenGraph = $agentIdTokenResponseGraph.access_token
$agentIdTokenPayloadGraph = Get-DecodedJwtToken -Token $agentIdTokenGraph
Write-Host "Exchanged for the Agent ID's ($agentIdentityAppId) Access Token:"
Write-Host "$($agentIdTokenPayloadGraph)"
Write-Host "------------------------------"

# Use the Agent ID token to call Microsoft Graph
# We'll ask it to list Users in the tenant, which requires the "User.Read.All" permission
$agentIdMsGraphTestResponse = Invoke-RestMethod -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/users?`$top=5" `
    -Headers @{
    "Authorization" = "Bearer $agentIdTokenGraph"
    "Content-Type"  = "application/json"
}

Write-Host "Tenant Users (retrieved from MS Graph with our Agent ID token):"
# Display users in a formatted table
$userTable = $agentIdMsGraphTestResponse.value | Select-Object @{
    Name       = 'Display Name'
    Expression = { $_.displayName }
}, @{
    Name       = 'User Principal Name'
    Expression = { $_.userPrincipalName }
}, @{
    Name       = 'ID'
    Expression = { $_.id }
} | Format-Table -AutoSize | Out-String

Write-Host $userTable
Write-Host "------------------------------"

# Get another token for the Agent ID but this time scoped to api://AzureADTokenExchange/.default not the MS Graph
$agentIdTokenBody = @{
    client_id             = $agentIdentityAppId
    scope                 = "api://AzureADTokenExchange/.default"
    grant_type            = "client_credentials"
    client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    client_assertion      = $blueprintToken
}

$agentIdTokenResponse = Invoke-RestMethod -Method POST `
    -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body $agentIdTokenBody `
    -ErrorAction Stop

$agentIdToken = $agentIdTokenResponse.access_token
$agentIdTokenPayload = Get-DecodedJwtToken -Token $agentIdToken
Write-Host "New Agent ID token scoped to AzureADTokenExchange (needed for exchange) instead of MS Graph"
Write-Host "$($agentIdTokenPayload)"
Write-Host "------------------------------"


# Exchange that for the Agent User token
$agentUserTokenBody = @{
    client_id             = $agentIdentityAppId
    scope                 = "https://graph.microsoft.com/.default"
    grant_type            = "user_fic"
    client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    client_assertion      = $blueprintToken
    username              = $agentUserPrincipalName
    user_federated_identity_credential = $agentIdToken
}

$agentUserTokenResponse = Invoke-RestMethod -Method POST `
    -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body $agentUserTokenBody `
    -ErrorAction Stop

$agentUserToken = $agentUserTokenResponse.access_token
$agentUserTokenPayload = Get-DecodedJwtToken -Token $agentUserToken
Write-Host "Exchanging that new Agent ID ($agentIdentityAppId) token for the Agent User's ($agentUserPrincipalName) Access Token"
Write-Host "$($agentUserTokenPayload)"
Write-Host "------------------------------"

# Use the Agent User's token to call Microsoft Graph
# We'll ask it to list Users in the tenant, which requires the "User.Read.All" permission
$agentUserMsGraphTestResponse = Invoke-RestMethod -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/users?`$top=5" `
    -Headers @{
    "Authorization" = "Bearer $agentUserToken"
    "Content-Type"  = "application/json"
}

Write-Host "Tenant Users (retrieved from MS Graph with our Agent User's token):"
# Display users in a formatted table
$userTable = $agentUserMsGraphTestResponse.value | Select-Object @{
    Name       = 'Display Name'
    Expression = { $_.displayName }
}, @{
    Name       = 'User Principal Name'
    Expression = { $_.userPrincipalName }
}, @{
    Name       = 'ID'
    Expression = { $_.id }
} | Format-Table -AutoSize | Out-String

Write-Host $userTable
Write-Host "------------------------------"

#Exchange for my User's Entra ID token using OBO flow
#az logout
#az login --tenant $tenantId --scope "api://$blueprintAppId/access_as_user"
<# $userToken = az account get-access-token --resource "api://$blueprintAppId" --query accessToken -o tsv
$userTokenBody = @{
    client_id              = $agentIdentityAppId
    scope                  = "https://graph.microsoft.com/.default"
    client_assertion_type  = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    client_assertion       = $blueprintToken  # T1
    grant_type             = "urn:ietf:params:oauth:grant-type:jwt-bearer"
    assertion              = $userToken       # Tc
    requested_token_use    = "on_behalf_of"
}

$userTokenResponse = Invoke-RestMethod -Method POST `
    -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
    -ContentType "application/x-www-form-urlencoded" `
    -Body $userTokenBody

$userToken = $userTokenResponse.access_token
$userTokenPayload = Get-DecodedJwtToken -Token $userToken
Write-Host "Now we have exchanged our Agent ID ($agentIdentityAppId) token for my Entra User's (admin@M365x41156588.onmicrosoft.com) token OBO"
Write-Host "$($userTokenPayload)"
Write-Host "------------------------------" #>

# Use my User's OBO token to call the Microsoft Graph API
# We'll ask it to list Users in the tenant, which requires the "User.Read.All" permission
<# $userMsGraphTestResponse = Invoke-RestMethod -Method GET `
    -Uri "https://graph.microsoft.com/v1.0/users?`$top=5" `
    -Headers @{
    "Authorization" = "Bearer $userToken"
    "Content-Type"  = "application/json"
}

Write-Host "Tenant Users (retrieved from MS Graph with our User's OBO token):"
# Display users in a formatted table
$userTable = $userMsGraphTestResponse.value | Select-Object @{
    Name       = 'Display Name'
    Expression = { $_.displayName }
}, @{
    Name       = 'User Principal Name'
    Expression = { $_.userPrincipalName }
}, @{
    Name       = 'ID'
    Expression = { $_.id }
} | Format-Table -AutoSize | Out-String

Write-Host $userTable
Write-Host "------------------------------" #>