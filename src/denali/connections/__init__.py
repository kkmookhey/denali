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
    "aws_connection_coverage_plan",
    "aws_coverage_plan",
    "render_cloudformation",
]
