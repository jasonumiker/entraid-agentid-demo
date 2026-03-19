# Entra ID Configuration
$blueprintAppId = "1ff6464b-416a-4c25-8f15-42c9c6964391"
$tenantId = "99238842-6a3b-4feb-8866-9ec5bc878bb4"
$agentIdentityAppId = "b7b1f2f6-060f-4152-b81c-a8b6b8a309db"
$agentUserId = "937fd89c-e466-415a-b3ba-8fd6ae437658"
$agentUserPrincipalName = "MyAgentUser@M365x41156588.onmicrosoft.com"

# AWS Configuration
# Set AWS_ROLE_ARN to assume a specific role before getting the web identity token.
# If not set, uses whatever AWS credentials are already configured (env vars, instance profile, etc.).
$awsRoleArn = $env:AWS_ROLE_ARN

# Prerequisites:
# 1. AWS CLI v2 installed and configured with valid credentials
# 2. The IAM role must have permission to call sts:GetWebIdentityToken
# 3. A Federated Identity Credential on the Entra ID Blueprint configured to trust AWS STS:
#    - Issuer:   https://sts.amazonaws.com
#    - Subject:  The IAM role's ARN (e.g. arn:aws:iam::123456789012:role/MyRole)
#    - Audience: api://AzureADTokenExchange

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

# Step 1: Get AWS IAM Role credentials
if ($awsRoleArn) {
    Write-Host "Assuming AWS IAM Role: $awsRoleArn" -ForegroundColor Cyan
    $assumeRoleJson = aws sts assume-role --role-arn $awsRoleArn --role-session-name "EntraAgentID" --output json 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to assume AWS IAM Role: $assumeRoleJson"
    }
    $assumeRoleOutput = $assumeRoleJson | ConvertFrom-Json
    $env:AWS_ACCESS_KEY_ID = $assumeRoleOutput.Credentials.AccessKeyId
    $env:AWS_SECRET_ACCESS_KEY = $assumeRoleOutput.Credentials.SecretAccessKey
    $env:AWS_SESSION_TOKEN = $assumeRoleOutput.Credentials.SessionToken
    Write-Host "Successfully assumed role." -ForegroundColor Green
}

# Display current AWS identity
$callerIdentityJson = aws sts get-caller-identity --output json 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Failed to get AWS caller identity. Ensure AWS CLI is configured with valid credentials."
}
$callerIdentity = $callerIdentityJson | ConvertFrom-Json
Write-Host "AWS Caller Identity:"
Write-Host "  Account: $($callerIdentity.Account)"
Write-Host "  UserId:  $($callerIdentity.UserId)"
Write-Host "  Arn:     $($callerIdentity.Arn)"
Write-Host "------------------------------"

# Step 2: Get an OIDC token from AWS STS via Outbound Identity Federation
# This calls aws sts get-web-identity-token which returns a signed JWT representing
# the current AWS identity, suitable for federation to external OIDC-compatible services.
Write-Host "Requesting OIDC token from AWS STS (Outbound Identity Federation)..." -ForegroundColor Cyan
$awsTokenJson = aws sts get-web-identity-token `
    --audience "api://AzureADTokenExchange" `
    --signing-algorithm RS256 `
    --output json 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "Failed to get web identity token from AWS STS: $awsTokenJson"
}
$awsTokenOutput = $awsTokenJson | ConvertFrom-Json
$awsOidcToken = $awsTokenOutput.WebIdentityToken

$awsOidcTokenPayload = Get-DecodedJwtToken -Token $awsOidcToken
Write-Host "AWS OIDC Token (Outbound Identity Federation) we're using to authenticate to the Blueprint via Federation:"
Write-Host "$($awsOidcTokenPayload)"
Write-Host "------------------------------"

# Step 3: Log into the Entra ID Blueprint using the AWS OIDC token as the federated assertion
$blueprintTokenBody = @{
    client_id = $blueprintAppId
    scope = "api://AzureADTokenExchange/.default"
    fmi_path = $agentIdentityAppId
    client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    grant_type = "client_credentials"
    client_assertion = $awsOidcToken
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
az logout
az login --tenant $tenantId --scope "api://$blueprintAppId/access_as_user" --use-device-code
$userToken = az account get-access-token --resource "api://$blueprintAppId" --query accessToken -o tsv
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
Write-Host "------------------------------"

# Use my User's OBO token to call the Microsoft Graph API
# We'll ask it to list Users in the tenant, which requires the "User.Read.All" permission
$userMsGraphTestResponse = Invoke-RestMethod -Method GET `
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
Write-Host "------------------------------"