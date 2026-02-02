"""AWS provider configuration for cross-account access."""

import pulumi
import pulumi_aws as aws

from infra.config import PulumiCustomerConfig


def create_customer_aws_provider(config: PulumiCustomerConfig) -> aws.Provider:
    """Create AWS provider that assumes role in customer's AWS account."""
    # Merge default tags with custom tags
    default_tags = {
        "ManagedBy": "Pulumi",
        "Environment": config.environment,
        "Customer": config.customer_id,
        "Stack": pulumi.get_stack(),
    }
    # Custom tags override defaults
    all_tags = {**default_tags, **config.tags}

    return aws.Provider(
        "customer-aws",
        region=config.aws_region,
        assume_roles=[
            aws.ProviderAssumeRoleArgs(
                role_arn=config.customer_role_arn,
                external_id=config.external_id,
                session_name=f"pulumi-{pulumi.get_stack()}",
                duration="1h",
            )
        ],
        default_tags=aws.ProviderDefaultTagsArgs(
            tags=all_tags,
        ),
    )
