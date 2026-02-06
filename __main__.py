import pulumi
import pulumi_aws as aws

from infra.components.eks import EksCluster
from infra.components.iam import EksIamRoles
from infra.components.networking import Networking
from infra.config import load_customer_config
from infra.providers import create_customer_aws_provider
from infra.components.access_node import AccessNode

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

access_node = None
if (
    config.eks_config.access.ssm_access_node
    and config.eks_config.access.ssm_access_node.enabled
):
    def get_first_subnet(ids: list[str]) -> str:
        if not ids:
            raise ValueError("No private subnets available for access node")
        return ids[0]

    access_node = AccessNode(
        name=config.customer_id,
        vpc_id=networking.vpc_id,
        subnet_id=networking.private_subnet_ids.apply(get_first_subnet),
        cluster_security_group_id=eks.cluster_security_group_id,
        cluster_name=eks.cluster_name,
        instance_type=config.eks_config.access.ssm_access_node.instance_type,
        provider=aws_provider,
        tags=config.tags,
        opts=pulumi.ResourceOptions(depends_on=[eks]),
    )

if access_node:
    # Grant the access node's IAM role Kubernetes cluster-admin permissions
    # This allows users SSM'd into the access node to run kubectl commands
    aws.eks.AccessEntry(
        f"{config.customer_id}-access-node-eks-access",
        cluster_name=eks.cluster_name,
        principal_arn=access_node.role.arn,
        type="STANDARD",
        opts=pulumi.ResourceOptions(
            provider=aws_provider,
            depends_on=[eks, access_node],
        ),
    )

    aws.eks.AccessPolicyAssociation(
        f"{config.customer_id}-access-node-eks-policy",
        cluster_name=eks.cluster_name,
        principal_arn=access_node.role.arn,
        policy_arn="arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
        access_scope=aws.eks.AccessPolicyAssociationAccessScopeArgs(
            type="cluster",
        ),
        opts=pulumi.ResourceOptions(
            provider=aws_provider,
            depends_on=[eks, access_node],
        ),
    )

    pulumi.export("access_node_instance_id", access_node.instance_id)
    pulumi.export("access_node_private_ip", access_node.private_ip)
    pulumi.export("access_node_role_arn", access_node.role.arn)

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
