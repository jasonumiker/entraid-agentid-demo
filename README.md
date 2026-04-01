# Entra ID Agent ID Demo

TODO: I know I need to do more work here in documenting the prerequistes for these scripts such as Powershell, the cloud CLIs they call, etc.

## Setting up Entra ID Agent ID for the Demos

### Setting up for sign-in-demo-secret.ps1
Run the following commands:
1. `pwsh`
1. `az login --tenant <your tenant ID>`
1. `Connect-MgGraph -TenantId <your tenant ID>`
1. `. ./EntraAgentID-Functions.ps1`
1. `Start-EntraAgentIDWorkflow -BlueprintName 'My Blueprint' -AgentName 'My Agent'`
1. Copy the secret out of the output and paste it into the secret variable at the top of sign-in-demo-secret.ps1
1. Copy the following doing a find/replace into the variables on the top of all the sign-in scripts:
    1. Tenant ID to tenantId
    1. Blueprint App ID to blueprintAppId
    1. Agent App ID to agentIdentityAppId
1. `New-AgentUser -AgentIdentityId '<your Agent App ID>' -DisplayName 'My Agent User'`
1. Copy AgentUserId doing a find/replace into the agentUserId variable at the top of all the sign-in scripts
1. `Add-AgentUserDelegatedPermission -AgentIdentityAppId '<your Agent App ID>' -AgentUserObjectId '<your Agent User ID>'`
1. `Add-BlueprintExposedScope -BlueprintAppId '<your Blueprint ID'`
1. `Grant-AgentIdentityDelegatedConsent -AgentIdentityAppId '<your Agent App ID>'`

### Continuing setup for sign-in-demo-azuremanagedidentity.ps1
Everything from sign-in-demo-secret.ps1 (if you haven't done it already) plus:
1. `Add-BlueprintFederatedCredential -BlueprintAppId '<your Blueprint ID>' -Name 'entra-demo' -Issuer 'https://login.microsoftonline.com/<your Tenant ID>/v2.0' -Subject '<your Azure Managed ID>'`


### Continuing setup for sign-in-demo-aws-iam.ps1
Everything from sign-in-demo-secret.ps1 (if you haven't done it already) plus:
1. Run sign-in-demo-aws-iam.ps1 on an AWS EC2 Instance or Lambda Function etc. and you'll see the decoded JWT token to use to fill in the values in the next command
1. `Add-BlueprintFederatedCredential -BlueprintAppId '<your Blueprint ID>' -Name 'entra-demo-aws' -Issuer '<iss from above>' -Subject '<sub from above>'`

### Continuing setup for sign-in-demo-gcp-iam.ps1
Everything from sign-in-demo-secret.ps1 (if you haven't done it already) plus:
1. Run sign-in-demo-gcp-iam.ps1 on a GCP VM etc. and you'll see the decoded JWT token to use to fill in the values in the next command
1. `Add-BlueprintFederatedCredential -BlueprintAppId '<your Blueprint ID>' -Name 'entra-demo-gcp' -Issuer 'https://accounts.google.com' -Subject '<sub from above>'`

## Running the demos

After you've filled in the required variables at the top of the scripts you can:
1. You can run sign-in-demo-secret.ps1 from anywhere - because you are authenticating with a secret copied into a variable at the top of the file
1. You can run sign-in-demo-azuremanagedidentity.ps1 from a VM or function etc. in Azure
1. You can run sign-in-demo-aws-iam.ps1 from a EC2 Instance or Lambda function etc. in AWS
1. You can run sign-in-demo-gcp-iam.ps1 from a VM etc. in GCP

## Sample outputs

If you don't want to build the environments and run the scripts yourself you can see sample outputs of the various commands in the output-*.txt files in the repo.
