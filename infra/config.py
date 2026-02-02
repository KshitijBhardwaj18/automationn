"""Customer configuration schema and loader."""

import ipaddress
from dataclasses import dataclass, field

import pulumi

from api.models import (
    AccessEntryConfig,
    EksAccessConfig,
    EksConfig,
    EndpointAccess,
    EksMode,
    NatGatewayStrategy,
    NodeGroupConfig,
    PodSubnetConfig,
    SubnetConfig,
    SubnetGroupConfig,
    VpcConfig,
    VpcEndpointsConfig,
)


@dataclass
class CustomerConfig:
    """Customer configuration loaded from Pulumi config."""

    customer_id: str
    environment: str

    customer_role_arn: str
    external_id: pulumi.Output[str]
    aws_region: str

    availability_zones: list[str]

    # VPC Configuration
    vpc_config: VpcConfig

    # EKS Configuration
    eks_config: EksConfig

    # Node Group Configuration (for managed mode)
    node_group_config: NodeGroupConfig | None

    # Custom tags
    tags: dict[str, str] = field(default_factory=dict)


def _parse_list(value: str | None, default: list[str] | None = None) -> list[str] | None:
    """Parse a comma-separated string into a list."""
    if value is None:
        return default
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_bool(value: str | None, default: bool = False) -> bool:
    """Parse a string boolean value."""
    if value is None:
        return default
    return value.lower() in ("true", "1", "yes")


def _parse_custom_subnets(config: pulumi.Config, prefix: str) -> list[SubnetConfig] | None:
    """Parse custom subnet configuration from Pulumi config."""
    subnets_json = config.get(f"{prefix}CustomSubnets")
    if not subnets_json:
        return None

    import json

    try:
        subnets_data = json.loads(subnets_json)
        return [SubnetConfig(**s) for s in subnets_data]
    except (json.JSONDecodeError, TypeError):
        return None


def load_customer_config() -> CustomerConfig:
    """Load customer configuration from Pulumi config."""
    config = pulumi.Config()

    # Basic settings
    customer_id = config.require("customerId")
    environment = config.get("environment") or "prod"
    customer_role_arn = config.require("customerRoleArn")
    external_id = config.require_secret("externalId")
    aws_region = config.get("awsRegion") or "us-east-1"

    # Availability zones
    az_config = config.get("availabilityZones")
    if az_config:
        availability_zones = [az.strip() for az in az_config.split(",")]
    else:
        availability_zones = [f"{aws_region}a", f"{aws_region}b", f"{aws_region}c"]

    # VPC Configuration
    vpc_cidr = config.get("vpcCidr") or "10.0.0.0/16"
    secondary_cidrs_str = config.get("secondaryCidrBlocks")
    secondary_cidr_blocks = _parse_list(secondary_cidrs_str, []) or []

    nat_strategy_str = config.get("natGatewayStrategy") or "one_per_az"
    nat_gateway_strategy = NatGatewayStrategy(nat_strategy_str)

    # Public subnet configuration
    public_cidr_mask = int(config.get("publicSubnetCidrMask") or "24")
    public_custom_subnets = _parse_custom_subnets(config, "public")
    public_subnets = SubnetGroupConfig(
        cidr_mask=public_cidr_mask if not public_custom_subnets else None,
        custom_subnets=public_custom_subnets,
    ) if public_custom_subnets else SubnetGroupConfig(cidr_mask=public_cidr_mask)

    # Private subnet configuration
    private_cidr_mask = int(config.get("privateSubnetCidrMask") or "20")
    private_custom_subnets = _parse_custom_subnets(config, "private")
    private_subnets = SubnetGroupConfig(
        cidr_mask=private_cidr_mask if not private_custom_subnets else None,
        custom_subnets=private_custom_subnets,
    ) if private_custom_subnets else SubnetGroupConfig(cidr_mask=private_cidr_mask)

    # Pod subnet configuration
    pod_subnets_enabled = _parse_bool(config.get("podSubnetsEnabled"), False)
    pod_cidr_mask = int(config.get("podSubnetCidrMask") or "18")
    pod_custom_subnets = _parse_custom_subnets(config, "pod")
    pod_subnets = PodSubnetConfig(
        enabled=pod_subnets_enabled,
        cidr_mask=pod_cidr_mask if not pod_custom_subnets else None,
        custom_subnets=pod_custom_subnets,
    ) if pod_subnets_enabled else None

    # VPC Endpoints configuration
    vpc_endpoints = VpcEndpointsConfig(
        s3_gateway=_parse_bool(config.get("vpcEndpointS3"), True),
        ecr_api=_parse_bool(config.get("vpcEndpointEcrApi"), False),
        ecr_dkr=_parse_bool(config.get("vpcEndpointEcrDkr"), False),
        sts=_parse_bool(config.get("vpcEndpointSts"), False),
        logs=_parse_bool(config.get("vpcEndpointLogs"), False),
        ec2=_parse_bool(config.get("vpcEndpointEc2"), False),
        ssm=_parse_bool(config.get("vpcEndpointSsm"), False),
        ssmmessages=_parse_bool(config.get("vpcEndpointSsmMessages"), False),
        ec2messages=_parse_bool(config.get("vpcEndpointEc2Messages"), False),
    )

    vpc_config = VpcConfig(
        cidr_block=vpc_cidr,
        secondary_cidr_blocks=secondary_cidr_blocks,
        nat_gateway_strategy=nat_gateway_strategy,
        public_subnets=public_subnets,
        private_subnets=private_subnets,
        pod_subnets=pod_subnets,
        vpc_endpoints=vpc_endpoints,
        enable_dns_hostnames=_parse_bool(config.get("enableDnsHostnames"), True),
        enable_dns_support=_parse_bool(config.get("enableDnsSupport"), True),
    )

    # EKS Configuration
    eks_version = config.get("eksVersion") or "1.31"
    eks_mode_str = config.get("eksMode") or "managed"
    eks_mode = EksMode(eks_mode_str)

    service_ipv4_cidr = config.get("serviceIpv4Cidr") or "172.20.0.0/16"

    # Endpoint access configuration
    endpoint_access_str = config.get("endpointAccess") or "private"
    endpoint_access = EndpointAccess(endpoint_access_str)
    public_access_cidrs = _parse_list(config.get("publicAccessCidrs"), []) or []

    grant_admin = _parse_bool(config.get("grantAdminToCreator"), True)
    auth_mode = config.get("authenticationMode") or "API_AND_CONFIG_MAP"

    # Access entries
    access_entries: list[AccessEntryConfig] = []
    access_entries_json = config.get("accessEntries")
    if access_entries_json:
        import json

        try:
            entries_data = json.loads(access_entries_json)
            access_entries = [AccessEntryConfig(**e) for e in entries_data]
        except (json.JSONDecodeError, TypeError):
            pass

    eks_access = EksAccessConfig(
        endpoint_access=endpoint_access,
        public_access_cidrs=public_access_cidrs,
        grant_admin_to_creator=grant_admin,
        authentication_mode=auth_mode,
        access_entries=access_entries,
    )

    # Logging and encryption
    logging_enabled = _parse_bool(config.get("loggingEnabled"), False)
    logging_types = _parse_list(
        config.get("loggingTypes"),
        ["api", "audit", "authenticator", "controllerManager", "scheduler"],
    ) or []

    encryption_enabled = _parse_bool(config.get("encryptionEnabled"), False)
    encryption_kms_key_arn = config.get("encryptionKmsKeyArn")

    deletion_protection = _parse_bool(config.get("deletionProtection"), False)
    zonal_shift_enabled = _parse_bool(config.get("zonalShiftEnabled"), False)

    eks_config = EksConfig(
        version=eks_version,
        mode=eks_mode,
        service_ipv4_cidr=service_ipv4_cidr,
        access=eks_access,
        logging_enabled=logging_enabled,
        logging_types=logging_types,
        encryption_enabled=encryption_enabled,
        encryption_kms_key_arn=encryption_kms_key_arn,
        deletion_protection=deletion_protection,
        zonal_shift_enabled=zonal_shift_enabled,
    )

    # Node group configuration (for managed mode)
    node_group_config = None
    if eks_mode == EksMode.MANAGED:
        instance_types_str = config.get("nodeInstanceTypes") or "t3.medium"
        instance_types = [t.strip() for t in instance_types_str.split(",")]

        node_group_config = NodeGroupConfig(
            name=config.get("nodeGroupName") or "general",
            instance_types=instance_types,
            desired_size=int(config.get("nodeDesiredSize") or "2"),
            min_size=int(config.get("nodeMinSize") or "1"),
            max_size=int(config.get("nodeMaxSize") or "5"),
            disk_size=int(config.get("nodeDiskSize") or "50"),
            capacity_type=config.get("nodeCapacityType") or "ON_DEMAND",
            ami_type=config.get("nodeAmiType") or "AL2_x86_64",
        )

    # Custom tags
    tags: dict[str, str] = {}
    tags_json = config.get("tags")
    if tags_json:
        import json

        try:
            tags = json.loads(tags_json)
        except json.JSONDecodeError:
            pass

    return CustomerConfig(
        customer_id=customer_id,
        environment=environment,
        customer_role_arn=customer_role_arn,
        external_id=external_id,
        aws_region=aws_region,
        availability_zones=availability_zones,
        vpc_config=vpc_config,
        eks_config=eks_config,
        node_group_config=node_group_config,
        tags=tags,
    )