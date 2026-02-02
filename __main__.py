"""Main Pulumi program for BYOC EKS infrastructure."""

import pulumi

from infra.components.eks import EksCluster
from infra.components.iam import EksIamRoles
from infra.components.networking import Networking
from infra.config import load_customer_config
from infra.providers import create_customer_aws_provider

# Load customer configuration
config = load_customer_config()

# Create AWS provider for customer account
aws_provider = create_customer_aws_provider(config)

# Create networking infrastructure
networking = Networking(
    name=config.customer_name,
    vpc_config=config.vpc_config,
    availability_zones=config.availability_zones,
    provider=aws_provider,
    tags=config.tags,
)

# Create IAM roles for EKS
iam = EksIamRoles(
    name=config.customer_id,
    eks_mode=config.eks_config.mode.value,
    provider=aws_provider,
    opts=pulumi.ResourceOptions(depends_on=[networking]),
)

# Create EKS cluster
eks = EksCluster(
    name=config.customer_id,
    vpc_id=networking.vpc_id,
    vpc_cidr=config.vpc_config.cidr_block,
    private_subnet_ids=networking.private_subnet_ids,
    public_subnet_ids=networking.public_subnet_ids,
    cluster_role_arn=iam.cluster_role_arn,
    node_role_arn=iam.node_role_arn,
    eks_config=config.eks_config,
    node_group_config=config.node_group_config,
    provider=aws_provider,
    tags=config.tags,
    opts=pulumi.ResourceOptions(depends_on=[iam]),
)

# Export VPC outputs
pulumi.export("vpc_id", networking.vpc_id)
pulumi.export("private_subnet_ids", networking.private_subnet_ids)
pulumi.export("public_subnet_ids", networking.public_subnet_ids)
pulumi.export("pod_subnet_ids", networking.pod_subnet_ids)

# Export IAM outputs
pulumi.export("eks_cluster_role_arn", iam.cluster_role_arn)
pulumi.export("eks_node_role_arn", iam.node_role_arn)
pulumi.export("eks_node_instance_profile_arn", iam.node_instance_profile_arn)

# Export EKS outputs
pulumi.export("eks_cluster_name", eks.cluster_name)
pulumi.export("eks_cluster_endpoint", eks.cluster_endpoint)
pulumi.export("eks_cluster_arn", eks.cluster_arn)
pulumi.export("eks_mode", config.eks_config.mode.value)
pulumi.export("eks_oidc_provider_arn", eks.oidc_provider_arn)

# Export configuration summary
pulumi.export("config_summary", {
    "customer_name": config.customer_name,
    "environment": config.environment,
    "aws_region": config.aws_region,
    "eks_version": config.eks_config.version,
    "eks_mode": config.eks_config.mode.value,
    "endpoint_access": config.eks_config.access.endpoint_access.value,
    "nat_gateway_strategy": config.vpc_config.nat_gateway_strategy.value,
    "service_cidr": config.eks_config.service_ipv4_cidr,
})
