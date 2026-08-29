"""Self-service provider connection contracts."""

from denali.connections.aws import (
    AWS_COVERAGE_AUTOMATIC,
    AWS_COVERAGE_SELECTED,
    AWS_SCOPE_AGENTCORE,
    AWS_SCOPE_BEDROCK_ACTIVITY,
    AWS_SCOPE_BEDROCK_AGENTS,
    AWS_SCOPE_BEDROCK_LOGGING,
    AWS_SCOPES,
    AwsConnectionValidator,
    aws_connection_coverage_plan,
    aws_coverage_plan,
    render_cloudformation,
)
from denali.connections.aws_onboarding import (
    AWS_ONBOARDING_TEMPLATE_VERSION,
    AwsCloudFormationLauncher,
)
from denali.connections.azure import (
    AZURE_CLOUD_PUBLIC,
    AZURE_SCOPE_AI_ACTIVITY,
    AZURE_SCOPE_AI_PLATFORM,
    AZURE_SCOPE_AI_SERVICES,
    AZURE_SCOPES,
    AzureConnectionValidator,
    azure_coverage_plan,
)
from denali.connections.azure_onboarding import (
    AZURE_ONBOARDING_SCRIPT_VERSION,
    AzureSetupScriptLauncher,
    render_setup_script,
)

__all__ = [
    "AWS_COVERAGE_AUTOMATIC",
    "AWS_COVERAGE_SELECTED",
    "AWS_SCOPE_AGENTCORE",
    "AWS_SCOPE_BEDROCK_ACTIVITY",
    "AWS_SCOPE_BEDROCK_AGENTS",
    "AWS_SCOPE_BEDROCK_LOGGING",
    "AWS_SCOPES",
    "AWS_ONBOARDING_TEMPLATE_VERSION",
    "AwsCloudFormationLauncher",
    "AwsConnectionValidator",
    "AZURE_CLOUD_PUBLIC",
    "AZURE_ONBOARDING_SCRIPT_VERSION",
    "AZURE_SCOPE_AI_ACTIVITY",
    "AZURE_SCOPE_AI_PLATFORM",
    "AZURE_SCOPE_AI_SERVICES",
    "AZURE_SCOPES",
    "AzureConnectionValidator",
    "AzureSetupScriptLauncher",
    "aws_connection_coverage_plan",
    "aws_coverage_plan",
    "azure_coverage_plan",
    "render_cloudformation",
    "render_setup_script",
]
