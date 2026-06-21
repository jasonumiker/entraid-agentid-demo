r"""
Entra ID Agent ID demo running inside an AWS Bedrock AgentCore Runtime agent.

This is the AgentCore equivalent of sign-in-demo-aws-iam.ps1. Instead of a
PowerShell script that runs on an EC2 instance, this is an agent hosted in the
Amazon Bedrock AgentCore Runtime. The agent:

  1. Reads its own AWS workload identity (the AgentCore Runtime execution role)
     via STS GetCallerIdentity.
  2. Mints an OIDC token from AWS STS using Outbound Identity Federation
     (STS GetWebIdentityToken) with the audience api://AzureADTokenExchange.
  3. Federates that AWS OIDC token into the Entra ID Blueprint to obtain the
     Blueprint access token.
  4. Exchanges the Blueprint token for the Agent ID (application) token and calls
     Microsoft Graph as the Agent ID.
  5. Exchanges again for the Agent User token (user_fic flow) and calls Microsoft
     Graph as the Agent User.

Every step decodes and emits the JWT it received. In AgentCore Runtime anything
written to stdout/stderr (here via the standard logging module) is captured to
Amazon CloudWatch Logs under
/aws/bedrock-agentcore/runtimes/{agent-id}-DEFAULT, so the same narrative that
the PowerShell script printed to the console shows up in the agent's logs.

Federated Identity Credential prerequisite (on the Entra ID Blueprint):
  - Issuer:   the STS issuer from the minted OIDC token (https://<id>.tokens.sts.global.api.aws)
  - Subject:  the AgentCore Runtime execution role ARN
  - Audience: api://AzureADTokenExchange

Run locally:
    uv venv
    .\.venv\Scripts\Activate.ps1
    uv pip install -e .
    python main.py
    curl.exe -X POST "http://localhost:8080/invocations" -H "Content-Type: application/json" -d "{}"

Deploy to AgentCore Runtime:
    # 1) Install CDK dependencies:
    #    cd agentcore\cdk
    #    npm install
    # 2) Deploy - agentcore deploy
    # 3) Verify and test:
    #    agentcore status
    #    agentcore invoke "run"
"""

import base64
import binascii
import json
import logging
import os
import subprocess
import sys

import boto3
import requests
from botocore.exceptions import ClientError, BotoCoreError, NoCredentialsError

from bedrock_agentcore import BedrockAgentCoreApp

# ---------------------------------------------------------------------------
# Logging: write to stdout so the AgentCore Runtime forwards it to CloudWatch.
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("entra-agentid-demo")

SEPARATOR = "------------------------------"

# ---------------------------------------------------------------------------
# Entra ID configuration (override with environment variables for your tenant).
# Defaults mirror sign-in-demo-aws-iam.ps1.
# ---------------------------------------------------------------------------
BLUEPRINT_APP_ID = os.environ.get(
    "ENTRA_BLUEPRINT_APP_ID", "d7ad46be-1aaf-45d4-9a60-419625acdf09"
)
TENANT_ID = os.environ.get(
    "ENTRA_TENANT_ID", "99238842-6a3b-4feb-8866-9ec5bc878bb4"
)
AGENT_IDENTITY_APP_ID = os.environ.get(
    "ENTRA_AGENT_IDENTITY_APP_ID", "2fd494f6-ac21-46eb-a888-f9d5b251c0f8"
)
AGENT_USER_PRINCIPAL_NAME = os.environ.get(
    "ENTRA_AGENT_USER_UPN", "MyAgentUser@M365x41156588.onmicrosoft.com"
)

# Audience expected by Entra ID for the federated assertion.
TOKEN_EXCHANGE_AUDIENCE = "api://AzureADTokenExchange"

TOKEN_ENDPOINT = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
GRAPH_USERS_URL = "https://graph.microsoft.com/v1.0/users?$top=5"

app = BedrockAgentCoreApp()


def decode_jwt_payload(token):
    """Decode a JWT and return its payload as pretty-printed JSON (claims only)."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            raise ValueError("Invalid JWT token format")

        payload_segment = parts[1]
        # Restore base64url padding.
        payload_segment += "=" * (-len(payload_segment) % 4)
        decoded_bytes = base64.urlsafe_b64decode(payload_segment)
        claims = json.loads(decoded_bytes.decode("utf-8"))
        return json.dumps(claims, indent=2)
    except (ValueError, binascii.Error, json.JSONDecodeError) as exc:
        logger.error("Failed to decode JWT token: %s", exc)
        return None


def log_block(title, body):
    """Emit a titled block followed by a separator, matching the PS Write-Host style."""
    logger.info(title)
    if body is not None:
        # Log multi-line bodies as a single record so they stay together in CloudWatch.
        logger.info("%s", body)
    logger.info(SEPARATOR)


def log_users_table(users):
    """Render the Graph users response as a compact table for the logs."""
    rows = [("Display Name", "User Principal Name", "ID")]
    for user in users:
        rows.append(
            (
                user.get("displayName", "") or "",
                user.get("userPrincipalName", "") or "",
                user.get("id", "") or "",
            )
        )
    widths = [max(len(row[i]) for row in rows) for i in range(3)]
    lines = []
    for idx, row in enumerate(rows):
        lines.append("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))
        if idx == 0:
            lines.append("  ".join("-" * widths[i] for i in range(3)))
    return "\n".join(lines)


def get_aws_oidc_token():
    """
    Mint an OIDC token representing this agent's AWS workload identity using
    STS Outbound Identity Federation (the equivalent of
    `aws sts get-web-identity-token` in the PowerShell script).

    Prefers the boto3 STS API and falls back to the AWS CLI if the installed
    boto3 version predates the GetWebIdentityToken operation.
    """
    sts = boto3.client("sts")
    if hasattr(sts, "get_web_identity_token"):
        response = sts.get_web_identity_token(
            Audience=[TOKEN_EXCHANGE_AUDIENCE],
            SigningAlgorithm="RS256",
        )
        return response["WebIdentityToken"]

    logger.info(
        "boto3 STS client lacks get_web_identity_token; falling back to the AWS CLI."
    )
    result = subprocess.run(
        [
            "aws",
            "sts",
            "get-web-identity-token",
            "--audience",
            TOKEN_EXCHANGE_AUDIENCE,
            "--signing-algorithm",
            "RS256",
            "--output",
            "json",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)["WebIdentityToken"]


def post_token(body):
    """POST a form-encoded body to the Entra ID token endpoint and return the access token."""
    response = requests.post(
        TOKEN_ENDPOINT,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["access_token"]


def call_graph_users(access_token):
    """Call Microsoft Graph /users with the supplied bearer token."""
    response = requests.get(
        GRAPH_USERS_URL,
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
        timeout=30,
    )
    response.raise_for_status()
    return response.json().get("value", [])


def run_demo():
    """Execute the full Entra ID Agent ID federation walkthrough and log each step."""

    # Step 1: Show the agent's current AWS identity (the AgentCore execution role).
    caller = boto3.client("sts").get_caller_identity()
    log_block(
        "AWS Caller Identity (this AgentCore Runtime's execution role):",
        f"  Account: {caller['Account']}\n"
        f"  UserId:  {caller['UserId']}\n"
        f"  Arn:     {caller['Arn']}",
    )

    # Step 2: Mint an AWS OIDC token via Outbound Identity Federation.
    logger.info("Requesting OIDC token from AWS STS (Outbound Identity Federation)...")
    aws_oidc_token = get_aws_oidc_token()
    log_block(
        "AWS OIDC Token (Outbound Identity Federation) we're using to "
        "authenticate to the Blueprint via Federation:",
        decode_jwt_payload(aws_oidc_token),
    )

    # Step 3: Federate the AWS OIDC token into the Entra ID Blueprint.
    blueprint_token = post_token(
        {
            "client_id": BLUEPRINT_APP_ID,
            "scope": f"{TOKEN_EXCHANGE_AUDIENCE}/.default",
            "fmi_path": AGENT_IDENTITY_APP_ID,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "grant_type": "client_credentials",
            "client_assertion": aws_oidc_token,
        }
    )
    log_block(
        f"Blueprint's ({BLUEPRINT_APP_ID}) Access Token:",
        decode_jwt_payload(blueprint_token),
    )

    # Step 4: Exchange the Blueprint token for the Agent ID (app) token for Graph.
    agent_id_token_graph = post_token(
        {
            "client_id": AGENT_IDENTITY_APP_ID,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": blueprint_token,
        }
    )
    log_block(
        f"Exchanged for the Agent ID's ({AGENT_IDENTITY_APP_ID}) Access Token:",
        decode_jwt_payload(agent_id_token_graph),
    )

    # Call Microsoft Graph as the Agent ID.
    agent_id_users = call_graph_users(agent_id_token_graph)
    log_block(
        "Tenant Users (retrieved from MS Graph with our Agent ID token):",
        log_users_table(agent_id_users),
    )

    # Step 5: Get an Agent ID token scoped to AzureADTokenExchange (for the next exchange).
    agent_id_token_exchange = post_token(
        {
            "client_id": AGENT_IDENTITY_APP_ID,
            "scope": f"{TOKEN_EXCHANGE_AUDIENCE}/.default",
            "grant_type": "client_credentials",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": blueprint_token,
        }
    )
    log_block(
        "New Agent ID token scoped to AzureADTokenExchange (needed for exchange) "
        "instead of MS Graph",
        decode_jwt_payload(agent_id_token_exchange),
    )

    # Step 6: Exchange for the Agent User token (user_fic flow).
    agent_user_token = post_token(
        {
            "client_id": AGENT_IDENTITY_APP_ID,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "user_fic",
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": blueprint_token,
            "username": AGENT_USER_PRINCIPAL_NAME,
            "user_federated_identity_credential": agent_id_token_exchange,
        }
    )
    log_block(
        f"Exchanging that new Agent ID ({AGENT_IDENTITY_APP_ID}) token for the "
        f"Agent User's ({AGENT_USER_PRINCIPAL_NAME}) Access Token",
        decode_jwt_payload(agent_user_token),
    )

    # Call Microsoft Graph as the Agent User.
    agent_user_users = call_graph_users(agent_user_token)
    log_block(
        "Tenant Users (retrieved from MS Graph with our Agent User's token):",
        log_users_table(agent_user_users),
    )

    return {
        "status": "completed",
        "agent_id_users_returned": len(agent_id_users),
        "agent_user_users_returned": len(agent_user_users),
    }


@app.entrypoint
def invoke(payload):
    """
    AgentCore Runtime entrypoint.

    The payload is accepted for API compatibility but is not required; the agent
    always runs the Entra ID Agent ID federation walkthrough and writes the
    narrative to the logs (CloudWatch).
    """
    logger.info("Starting Entra ID Agent ID federation walkthrough in AgentCore.")
    logger.info(SEPARATOR)
    try:
        result = run_demo()
        logger.info("Entra ID Agent ID walkthrough completed successfully.")
        return {"result": result}
    except NoCredentialsError:
        logger.exception("AWS credentials were not found for local execution.")
        return {
            "error": (
                "AWS error: Unable to locate credentials. Configure local AWS credentials "
                "(for example, aws configure or AWS_PROFILE) or run this inside an AWS "
                "runtime with an attached IAM role."
            )
        }
    except (ClientError, BotoCoreError) as exc:
        logger.exception("AWS error during the Entra ID Agent ID walkthrough.")
        return {"error": f"AWS error: {exc}"}
    except requests.HTTPError as exc:
        # Surface the Entra ID error body to help diagnose token-exchange failures.
        detail = exc.response.text if exc.response is not None else str(exc)
        logger.error("Entra ID token/Graph request failed: %s", detail)
        return {"error": f"HTTP error: {detail}"}
    except requests.RequestException as exc:
        logger.exception("Network error during the Entra ID Agent ID walkthrough.")
        return {"error": f"Request error: {exc}"}


if __name__ == "__main__":
    app.run()
