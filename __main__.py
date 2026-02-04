import pulumi

from infra.components.eks import EksCluster
from infra.components.iam import EksIamRoles
from infra.components.networking import Networking
from infra.config import load_customer_config
from infra.providers import create_customer_aws_provider

config = load_customer_config()

aws_provider = create_customer_aws_provider(config)

networking = Networking(
    name=config.customer_id,
    vpc_config=config.vpc_config,
    availability_zones=config.availability_zones,
    provider=aws_provider,
    tags=config.tags,
)

iam = EksIamRoles(
    name=config.customer_id,
    eks_mode=config.eks_config.mode.value,
    provider=aws_provider,
    opts=pulumi.ResourceOptions(depends_on=[networking]),
)

eks = EksCluster(
    name=config.customer_id,
    vpc_id=networking.vpc_id,
    vpc_cidr=config.vpc_config.cidr_block,
    private_subnet_ids=networking.private_subnet_ids,
    public_subnet_ids=networking.public_subnet_ids,
    cluster_role_arn=iam.cluster_role_arn,
    node_role_arn=iam.node_role_arn,
    eks_config=config.eks_config,
    provider=aws_provider,
    tags=config.tags,
    opts=pulumi.ResourceOptions(depends_on=[iam]),
)

pulumi.export("vpc_id", networking.vpc_id)
pulumi.export("private_subnet_ids", networking.private_subnet_ids)
pulumi.export("public_subnet_ids", networking.public_subnet_ids)
pulumi.export("pod_subnet_ids", networking.pod_subnet_ids)


pulumi.export("eks_cluster_role_arn", iam.cluster_role_arn)
pulumi.export("eks_node_role_arn", iam.node_role_arn)
pulumi.export("eks_node_instance_profile_arn", iam.node_instance_profile_arn)


pulumi.export("eks_cluster_name", eks.cluster_name)
pulumi.export("eks_cluster_endpoint", eks.cluster_endpoint)
pulumi.export("eks_cluster_arn", eks.cluster_arn)
pulumi.export("eks_mode", config.eks_config.mode.value)
pulumi.export("eks_oidc_provider_arn", eks.oidc_provider_arn)


pulumi.export(
    "config_summary",
    {
        "customer_id": config.customer_id,
        "environment": config.environment,
        "aws_region": config.aws_region,
        "eks_version": config.eks_config.version,
        "eks_mode": config.eks_config.mode.value,
        "endpoint_private_access": config.eks_config.access.endpoint_private_access,
        "endpoint_public_access": config.eks_config.access.endpoint_public_access,
        "nat_gateway_strategy": config.vpc_config.nat_gateway_strategy.value,
        "service_cidr": config.eks_config.service_ipv4_cidr,
    },
)
