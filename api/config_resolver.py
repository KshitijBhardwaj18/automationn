import ipaddress
from datetime import datetime, timezone
from typing import Optional

from api.models import (
    AddonConfigInput,
    AmiType,
    AwsConfigInput,
    AwsConfigResolved,
    CapacityType,
    CustomerConfigInput,
    CustomerConfigResolved,
    EksAccessInput,
    EksAccessResolved,
    EksAddonsInput,
    EksAddonsResolved,
    EksConfigInput,
    EksConfigResolved,
    EksMode,
    NatGatewayStrategy,
    NodeGroupInput,
    NodeGroupResolved,
    NodeGroupScalingInput,
    SsmAccessNodeConfig,
    SubnetInput,
    SubnetResolved,
    VpcConfigInput,
    VpcConfigResolved,
    VpcEndpointsInput,
    VpcEndpointsResolved,
)

def get_default_availability_zones(region: str, count: int = 3) -> list[str]:
    """Get default availability zones for a region."""
    suffixes = ["a", "b", "c", "d", "e", "f"][:count]
    return [f"{region}{suffix}" for suffix in suffixes]


def resolve_aws_config(input_config: AwsConfigInput) -> AwsConfigResolved:
    """Resolve AWS configuration with computed availability zones."""
    return AwsConfigResolved(
        role_arn=input_config.role_arn,
        external_id=input_config.external_id,
        region=input_config.region,
        availability_zones=get_default_availability_zones(input_config.region, 3),
    )

def calculate_subnet_cidrs(
    vpc_cidr: str,
    availability_zones: list[str],
    cidr_mask: int,
    offset_blocks: int = 0,
) -> list[tuple[str, str]]:
    """Calculate subnet CIDRs automatically from VPC CIDR.

    Returns list of (cidr_block, availability_zone) tuples.
 """
    vpc_network = ipaddress.ip_network(vpc_cidr, strict=False)
    subnets = []

    for i, az in enumerate(availability_zones):
        block_index = offset_blocks + i
   
        subnet_size = 2 ** (32 - cidr_mask)
        subnet_offset = block_index * subnet_size
        subnet_addr = ipaddress.ip_address(int(vpc_network.network_address) + subnet_offset)
        subnet_cidr = f"{subnet_addr}/{cidr_mask}"
        subnets.append((subnet_cidr, az))

    return subnets


def resolve_subnets(
    custom_subnets: Optional[list[SubnetInput]],
    vpc_cidr: str,
    availability_zones: list[str],
    subnet_type: str,
    cidr_mask: int,
    offset_blocks: int,
    customer_id: str,
    base_tags: dict[str, str],
) -> list[SubnetResolved]:
    """Resolve subnet configuration - use custom if provided, otherwise auto-calculate. """
    if custom_subnets:
        return [
            SubnetResolved(
                cidr_block=s.cidr_block,
                availability_zone=s.availability_zone,
                name=s.name or f"{customer_id}-{subnet_type}-{s.availability_zone[-1]}",
                tags={**base_tags, **s.tags},
            )
            for s in custom_subnets
        ]

    calculated = calculate_subnet_cidrs(vpc_cidr, availability_zones, cidr_mask, offset_blocks)

    k8s_tags: dict[str, str] = {}
    if subnet_type == "public":
        k8s_tags["kubernetes.io/role/elb"] = "1"
    elif subnet_type in ("private", "pod"):
        k8s_tags["kubernetes.io/role/internal-elb"] = "1"

    return [
        SubnetResolved(
            cidr_block=cidr,
            availability_zone=az,
            name=f"{customer_id}-{subnet_type}-{az[-1]}",
            tags={
                "SubnetType": subnet_type,
                **k8s_tags,
                **base_tags,
            },
        )
        for cidr, az in calculated
    ]


def resolve_vpc_endpoints(
    input_endpoints: Optional[VpcEndpointsInput],
    eks_mode: EksMode,
    nat_strategy: NatGatewayStrategy,
    ssm_access_node_enabled: bool = False,
) -> VpcEndpointsResolved:
    """Resolve VPC endpoints configuration.
    
    If SSM access node is enabled and no custom endpoints config provided,
    automatically enables required SSM endpoints.
    """
    if input_endpoints:
        # If SSM access node is enabled, ensure SSM endpoints are enabled
        ssm_enabled = input_endpoints.ssm or ssm_access_node_enabled
        ssmmessages_enabled = input_endpoints.ssmmessages or ssm_access_node_enabled
        ec2messages_enabled = input_endpoints.ec2messages or ssm_access_node_enabled

        return VpcEndpointsResolved(
            s3=input_endpoints.s3,
            dynamodb=input_endpoints.dynamodb,
            ecr_api=input_endpoints.ecr_api,
            ecr_dkr=input_endpoints.ecr_dkr,
            sts=input_endpoints.sts,
            logs=input_endpoints.logs,
            ec2=input_endpoints.ec2,
            ssm=ssm_enabled,
            ssmmessages=ssmmessages_enabled,
            ec2messages=ec2messages_enabled,
            elasticloadbalancing=input_endpoints.elasticloadbalancing,
            autoscaling=input_endpoints.autoscaling,
        )

    return VpcEndpointsResolved(
        s3=True,
        dynamodb=False,
        ecr_api=False,
        ecr_dkr=False,
        sts=False,
        logs=False,
        ec2=False,
        ssm=ssm_access_node_enabled,
        ssmmessages=ssm_access_node_enabled,
        ec2messages=ssm_access_node_enabled,
        elasticloadbalancing=False,
        autoscaling=False,
    )


def resolve_vpc_config(
    input_config: Optional[VpcConfigInput],
    availability_zones: list[str],
    customer_id: str,
    eks_mode: EksMode,
    global_tags: dict[str, str],
    ssm_access_node_enabled: bool = False,
) -> VpcConfigResolved:
    """Resolve VPC configuration with all defaults filled.
    
    If ssm_access_node_enabled is True, automatically enables required
    VPC endpoints for SSM (ssm, ssmmessages, ec2messages).
    """
    vpc_input = input_config or VpcConfigInput()

    vpc_cidr = vpc_input.cidr_block
    nat_strategy = vpc_input.nat_gateway_strategy

    # Calculate subnet offsets to avoid overlap
    # Public: /24 = 256 IPs, need 3 blocks = 768 IPs
    # Private: /20 = 4096 IPs, need 3 blocks = 12288 IPs
    # With /16 VPC (65536 IPs), this fits comfortably

    # Public subnets: start at offset 0, /24 each
    public_subnets = resolve_subnets(
        custom_subnets=vpc_input.public_subnets,
        vpc_cidr=vpc_cidr,
        availability_zones=availability_zones,
        subnet_type="public",
        cidr_mask=24,
        offset_blocks=0,
        customer_id=customer_id,
        base_tags=global_tags,
    )

    if vpc_input.private_subnets:
        private_subnets = [
            SubnetResolved(
                cidr_block=s.cidr_block,
                availability_zone=s.availability_zone,
                name=s.name or f"{customer_id}-private-{s.availability_zone[-1]}",
                tags={
                    "SubnetType": "private",
                    "kubernetes.io/role/internal-elb": "1",
                    **global_tags,
                    **s.tags,
                },
            )
            for s in vpc_input.private_subnets
        ]
    else:
        vpc_network = ipaddress.ip_network(vpc_cidr, strict=False)
        private_base = int(vpc_network.network_address) + (16 * 256)

        private_subnets = []
        for i, az in enumerate(availability_zones):
            subnet_size = 2 ** (32 - 20)
            subnet_addr = ipaddress.ip_address(private_base + (i * subnet_size))
            subnet_cidr = f"{subnet_addr}/20"

            private_subnets.append(
                SubnetResolved(
                    cidr_block=subnet_cidr,
                    availability_zone=az,
                    name=f"{customer_id}-private-{az[-1]}",
                    tags={
                        "SubnetType": "private",
                        "kubernetes.io/role/internal-elb": "1",
                        **global_tags,
                    },
                )
            )

    # Pod subnets: only if secondary CIDR is provided
    pod_subnets: list[SubnetResolved] = []
    if vpc_input.pod_subnets:
        pod_subnets = [
            SubnetResolved(
                cidr_block=s.cidr_block,
                availability_zone=s.availability_zone,
                name=s.name or f"{customer_id}-pod-{s.availability_zone[-1]}",
                tags={
                    "SubnetType": "pod",
                    "kubernetes.io/role/internal-elb": "1",
                    **global_tags,
                    **s.tags,
                },
            )
            for s in vpc_input.pod_subnets
        ]
    elif vpc_input.secondary_cidr_blocks:
        # Auto-calculate pod subnets from first secondary CIDR
        secondary_cidr = vpc_input.secondary_cidr_blocks[0]
        pod_calculated = calculate_subnet_cidrs(
            secondary_cidr, availability_zones, cidr_mask=18, offset_blocks=0
        )
        pod_subnets = [
            SubnetResolved(
                cidr_block=cidr,
                availability_zone=az,
                name=f"{customer_id}-pod-{az[-1]}",
                tags={
                    "SubnetType": "pod",
                    "kubernetes.io/role/internal-elb": "1",
                    **global_tags,
                },
            )
            for cidr, az in pod_calculated
        ]

    vpc_endpoints = resolve_vpc_endpoints(
        vpc_input.vpc_endpoints,
        eks_mode,
        nat_strategy,
        ssm_access_node_enabled=ssm_access_node_enabled,
    )

    return VpcConfigResolved(
        cidr_block=vpc_cidr,
        secondary_cidr_blocks=vpc_input.secondary_cidr_blocks,
        nat_gateway_strategy=nat_strategy,
        public_subnets=public_subnets,
        private_subnets=private_subnets,
        pod_subnets=pod_subnets,
        vpc_endpoints=vpc_endpoints,
        enable_dns_hostnames=vpc_input.enable_dns_hostnames,
        enable_dns_support=vpc_input.enable_dns_support,
        tags={**global_tags, **vpc_input.tags},
    )



def resolve_eks_access(input_access: Optional[EksAccessInput]) -> EksAccessResolved:
    """Resolve EKS access configuration.
    Default: private endpoint only (most secure).
    """
    if input_access:
        return EksAccessResolved(
            endpoint_private_access=input_access.endpoint_private_access,
            endpoint_public_access=input_access.endpoint_public_access,
            public_access_cidrs=input_access.public_access_cidrs,
            authentication_mode=input_access.authentication_mode,
            bootstrap_cluster_creator_admin_permissions=input_access.bootstrap_cluster_creator_admin_permissions,
            access_entries=input_access.access_entries,
            ssm_access_node=input_access.ssm_access_node,
        )

    return EksAccessResolved(
        endpoint_private_access=True,
        endpoint_public_access=False,
        public_access_cidrs=[],
        authentication_mode="API_AND_CONFIG_MAP",
        bootstrap_cluster_creator_admin_permissions=True,
        access_entries=[],
        ssm_access_node=None,
    )



def get_default_addon_config(enabled: bool = True) -> AddonConfigInput:
    """Get default addon configuration."""
    return AddonConfigInput(
        enabled=enabled,
        version=None,  # Latest
        service_account_role_arn=None,
        configuration={},
        resolve_conflicts_on_create="OVERWRITE",
        resolve_conflicts_on_update="PRESERVE",
    )


def resolve_eks_addons(
    input_addons: Optional[EksAddonsInput],
    eks_mode: EksMode,
) -> EksAddonsResolved:
    """Resolve EKS addons configuration.
    For managed mode: core addons (vpc-cni, coredns, kube-proxy) are required.
    For auto mode: AWS manages addons automatically.
    """
    if input_addons:
        vpc_cni = input_addons.vpc_cni or get_default_addon_config(True)
        coredns = input_addons.coredns or get_default_addon_config(True)
        kube_proxy = input_addons.kube_proxy or get_default_addon_config(True)
        ebs_csi = input_addons.ebs_csi_driver or get_default_addon_config(True)
        efs_csi = input_addons.efs_csi_driver or get_default_addon_config(False)
        pod_identity = input_addons.pod_identity_agent or get_default_addon_config(True)
        snapshot = input_addons.snapshot_controller or get_default_addon_config(False)
    else:
        vpc_cni = get_default_addon_config(True)
        coredns = get_default_addon_config(True)
        kube_proxy = get_default_addon_config(True)
        ebs_csi = get_default_addon_config(True)
        efs_csi = get_default_addon_config(False)
        pod_identity = get_default_addon_config(True)
        snapshot = get_default_addon_config(False)

    if eks_mode == EksMode.AUTO:
        vpc_cni.enabled = False  
        coredns.enabled = False  
        kube_proxy.enabled = False

    return EksAddonsResolved(
        vpc_cni=vpc_cni,
        coredns=coredns,
        kube_proxy=kube_proxy,
        ebs_csi_driver=ebs_csi,
        efs_csi_driver=efs_csi,
        pod_identity_agent=pod_identity,
        snapshot_controller=snapshot,
    )

def resolve_node_group(
    input_ng: NodeGroupInput,
    customer_id: str,
    global_tags: dict[str, str],
) -> NodeGroupResolved:
    """Resolve a single node group configuration."""
    scaling = input_ng.scaling or NodeGroupScalingInput()

    return NodeGroupResolved(
        name=input_ng.name,
        instance_types=input_ng.instance_types,
        capacity_type=input_ng.capacity_type,
        ami_type=input_ng.ami_type,
        disk_size=input_ng.disk_size,
        desired_size=scaling.desired_size,
        min_size=scaling.min_size,
        max_size=scaling.max_size,
        labels=input_ng.labels,
        taints=input_ng.taints,
        tags={**global_tags, **input_ng.tags},
    )


def resolve_node_groups(
    input_groups: Optional[list[NodeGroupInput]],
    eks_mode: EksMode,
    customer_id: str,
    global_tags: dict[str, str],
) -> list[NodeGroupResolved]:
    """Resolve node groups configuration."""
    if eks_mode == EksMode.AUTO:
        return []

    if input_groups:
        return [resolve_node_group(ng, customer_id, global_tags) for ng in input_groups]

    return [
        NodeGroupResolved(
            name="general",
            instance_types=["t3.medium"],
            capacity_type=CapacityType.ON_DEMAND,
            ami_type=AmiType.AL2023_X86_64_STANDARD,
            disk_size=50,
            desired_size=2,
            min_size=1,
            max_size=5,
            labels={"workload": "general"},
            taints=[],
            tags=global_tags,
        )
    ]


def resolve_eks_config(
    input_config: Optional[EksConfigInput],
    customer_id: str,
    global_tags: dict[str, str],
) -> EksConfigResolved:
    """Resolve EKS configuration with all defaults filled."""
    eks_input = input_config or EksConfigInput()

    mode = eks_input.mode
    access = resolve_eks_access(eks_input.access)
    addons = resolve_eks_addons(eks_input.addons, mode)
    node_groups = resolve_node_groups(eks_input.node_groups, mode, customer_id, global_tags)

    return EksConfigResolved(
        version=eks_input.version,
        mode=mode,
        service_ipv4_cidr=eks_input.service_ipv4_cidr,
        access=access,
        logging_enabled=eks_input.logging_enabled,
        logging_types=eks_input.logging_types if eks_input.logging_enabled else [],
        encryption_enabled=eks_input.encryption_enabled,
        encryption_kms_key_arn=eks_input.encryption_kms_key_arn,
        zonal_shift_enabled=eks_input.zonal_shift_enabled,
        deletion_protection=eks_input.deletion_protection,
        addons=addons,
        node_groups=node_groups,
        tags={**global_tags, **eks_input.tags},
    )

def resolve_customer_config(input_config: CustomerConfigInput) -> CustomerConfigResolved:
    """Transform partial input config into fully-resolved config."""

    global_tags = {
        "Environment": input_config.environment,
        "Customer": input_config.customer_id,
        "ManagedBy": "pulumi",
        **input_config.tags,
    }
    aws_config = resolve_aws_config(input_config.aws_config)

    eks_mode = input_config.eks_config.mode if input_config.eks_config else EksMode.AUTO

    # Check if SSM access node is enabled
    ssm_access_node_enabled = (
        input_config.eks_config
        and input_config.eks_config.access
        and input_config.eks_config.access.ssm_access_node
        and input_config.eks_config.access.ssm_access_node.enabled
    ) or False

    vpc_config = resolve_vpc_config(
        input_config.vpc_config,
        aws_config.availability_zones,
        input_config.customer_id,
        eks_mode,
        global_tags,
        ssm_access_node_enabled=ssm_access_node_enabled,
    )

    eks_config = resolve_eks_config(
        input_config.eks_config,
        input_config.customer_id,
        global_tags,
    )

    now = datetime.now(timezone.utc)

    return CustomerConfigResolved(
        customer_id=input_config.customer_id,
        environment=input_config.environment,
        aws_config=aws_config,
        vpc_config=vpc_config,
        eks_config=eks_config,
        tags=global_tags,
        created_at=now,
        updated_at=now,
    )


def update_resolved_config(
    existing: CustomerConfigResolved,
    updates: CustomerConfigInput,
) -> CustomerConfigResolved:
    """Apply updates to an existing resolved config.
    Re-resolves the entire config to ensure consistency.
    """
    
    resolved = resolve_customer_config(updates)

    resolved.created_at = existing.created_at
    resolved.updated_at = datetime.now(timezone.utc)

    return resolved
