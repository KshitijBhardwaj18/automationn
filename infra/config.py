import json
from dataclasses import dataclass, field
from typing import Optional

import pulumi

from api.models import (
    AddonConfigInput,
    AddonsConfigResolved,
    AmiType,
    ArgoCDConfigResolved,
    ArgoCDRepoConfig,
    CapacityType,
    EksAccessResolved,
    EksAddonsResolved,
    EksConfigResolved,
    EksMode,
    NatGatewayStrategy,
    NodeGroupResolved,
    SsmAccessNodeConfig,
    SubnetResolved,
    VpcConfigResolved,
    VpcEndpointsResolved,
)


@dataclass
class PulumiCustomerConfig:
    """Customer configuration loaded from Pulumi config for use in infrastructure code."""

    customer_id: str
    environment: str

    # AWS settings
    customer_role_arn: str
    external_id: pulumi.Output[str]
    aws_region: str
    availability_zones: list[str]

    # VPC Configuration (resolved)
    vpc_config: VpcConfigResolved

    # EKS Configuration (resolved)
    eks_config: EksConfigResolved

    # Cluster Addons (ArgoCD, etc.)
    addons: AddonsConfigResolved

    # Global tags
    tags: dict[str, str] = field(default_factory=dict)


def _parse_list(value: Optional[str], default: Optional[list[str]] = None) -> list[str]:
    """Parse a comma-separated string into a list."""
    if value is None:
        return default or []
    return [item.strip() for item in value.split(",") if item.strip()]


def _parse_bool(value: Optional[str], default: bool = False) -> bool:
    """Parse a string boolean value."""
    if value is None:
        return default
    return value.lower() in ("true", "1", "yes")


def _parse_json_dict(value: Optional[str], default: dict[str, str] | None = None) -> dict[str, str]:
    """Parse a JSON string as a dict."""
    if value is None:
        return default or {}
    try:
        result = json.loads(value)
        if isinstance(result, dict):
            return result
        return default or {}
    except json.JSONDecodeError:
        return default or {}


def _parse_json_list(
    value: Optional[str], default: list[dict[str, str]] | None = None
) -> list[dict[str, str]]:
    """Parse a JSON string as a list."""
    if value is None:
        return default or []
    try:
        result = json.loads(value)
        if isinstance(result, list):
            return result
        return default or []
    except json.JSONDecodeError:
        return default or []


def _load_subnets(config: pulumi.Config, prefix: str) -> list[SubnetResolved]:
    """Load subnet configuration from Pulumi config."""
    subnets_json = config.get(f"{prefix}Subnets")
    if not subnets_json:
        return []

    try:
        subnets_data = json.loads(subnets_json)
        return [
            SubnetResolved(
                cidr_block=s["cidr_block"],
                availability_zone=s["availability_zone"],
                name=s["name"],
                tags=s.get("tags", {}),
            )
            for s in subnets_data
        ]
    except (json.JSONDecodeError, KeyError, TypeError):
        return []


def _load_vpc_endpoints(config: pulumi.Config) -> VpcEndpointsResolved:
    """Load VPC endpoints configuration."""
    return VpcEndpointsResolved(
        s3=_parse_bool(config.get("vpcEndpointS3"), True),
        dynamodb=_parse_bool(config.get("vpcEndpointDynamodb"), False),
        ecr_api=_parse_bool(config.get("vpcEndpointEcrApi"), False),
        ecr_dkr=_parse_bool(config.get("vpcEndpointEcrDkr"), False),
        sts=_parse_bool(config.get("vpcEndpointSts"), False),
        logs=_parse_bool(config.get("vpcEndpointLogs"), False),
        ec2=_parse_bool(config.get("vpcEndpointEc2"), False),
        ssm=_parse_bool(config.get("vpcEndpointSsm"), False),
        ssmmessages=_parse_bool(config.get("vpcEndpointSsmMessages"), False),
        ec2messages=_parse_bool(config.get("vpcEndpointEc2Messages"), False),
        elasticloadbalancing=_parse_bool(config.get("vpcEndpointElb"), False),
        autoscaling=_parse_bool(config.get("vpcEndpointAutoscaling"), False),
    )


def _load_vpc_config(config: pulumi.Config) -> VpcConfigResolved:
    """Load VPC configuration from Pulumi config."""
    vpc_cidr = config.get("vpcCidr") or "10.0.0.0/16"
    secondary_cidrs = _parse_list(config.get("secondaryCidrBlocks"), [])
    nat_strategy_str = config.get("natGatewayStrategy") or "single"
    nat_strategy = NatGatewayStrategy(nat_strategy_str)

    public_subnets = _load_subnets(config, "public")
    private_subnets = _load_subnets(config, "private")
    pod_subnets = _load_subnets(config, "pod")

    vpc_endpoints = _load_vpc_endpoints(config)

    return VpcConfigResolved(
        cidr_block=vpc_cidr,
        secondary_cidr_blocks=secondary_cidrs,
        nat_gateway_strategy=nat_strategy,
        public_subnets=public_subnets,
        private_subnets=private_subnets,
        pod_subnets=pod_subnets,
        vpc_endpoints=vpc_endpoints,
        enable_dns_hostnames=_parse_bool(config.get("enableDnsHostnames"), True),
        enable_dns_support=_parse_bool(config.get("enableDnsSupport"), True),
        tags=_parse_json_dict(config.get("vpcTags"), {}),
    )


def _load_ssm_access_node(config: pulumi.Config) -> Optional[SsmAccessNodeConfig]:
    """Load SSM access node configuration."""
    enabled = _parse_bool(config.get("ssmAccessNodeEnabled"), False)
    if not enabled:
        return None

    return SsmAccessNodeConfig(
        enabled=True,
        instance_type=config.get("ssmAccessNodeInstanceType") or "t3.micro",
    )


def _load_eks_access(config: pulumi.Config) -> EksAccessResolved:
    """Load EKS access configuration."""
    ssm_access_node = _load_ssm_access_node(config)

    return EksAccessResolved(
        endpoint_private_access=_parse_bool(config.get("endpointPrivateAccess"), True),
        endpoint_public_access=_parse_bool(config.get("endpointPublicAccess"), False),
        public_access_cidrs=_parse_list(config.get("publicAccessCidrs"), []),
        authentication_mode=config.get("authenticationMode") or "API_AND_CONFIG_MAP",
        bootstrap_cluster_creator_admin_permissions=_parse_bool(
            config.get("bootstrapClusterCreatorAdmin"), True
        ),
        access_entries=[],  # Access entries handled separately if needed
        ssm_access_node=ssm_access_node,
    )


def _get_default_addon_config(enabled: bool = True) -> AddonConfigInput:
    """Get default addon configuration."""
    return AddonConfigInput(
        enabled=enabled,
        version=None,
        service_account_role_arn=None,
        configuration={},
        resolve_conflicts_on_create="OVERWRITE",
        resolve_conflicts_on_update="PRESERVE",
    )


def _load_eks_addons(config: pulumi.Config, eks_mode: EksMode) -> EksAddonsResolved:
    """Load EKS addons configuration."""
    # For auto mode, core addons are managed by AWS
    if eks_mode == EksMode.AUTO:
        return EksAddonsResolved(
            vpc_cni=_get_default_addon_config(False),
            coredns=_get_default_addon_config(False),
            kube_proxy=_get_default_addon_config(False),
            ebs_csi_driver=_get_default_addon_config(True),
            efs_csi_driver=_get_default_addon_config(False),
            pod_identity_agent=_get_default_addon_config(True),
            snapshot_controller=_get_default_addon_config(False),
        )

    # For managed mode, enable core addons
    return EksAddonsResolved(
        vpc_cni=_get_default_addon_config(_parse_bool(config.get("addonVpcCni"), True)),
        coredns=_get_default_addon_config(_parse_bool(config.get("addonCoredns"), True)),
        kube_proxy=_get_default_addon_config(_parse_bool(config.get("addonKubeProxy"), True)),
        ebs_csi_driver=_get_default_addon_config(_parse_bool(config.get("addonEbsCsi"), True)),
        efs_csi_driver=_get_default_addon_config(_parse_bool(config.get("addonEfsCsi"), False)),
        pod_identity_agent=_get_default_addon_config(
            _parse_bool(config.get("addonPodIdentity"), True)
        ),
        snapshot_controller=_get_default_addon_config(
            _parse_bool(config.get("addonSnapshot"), False)
        ),
    )


def _load_node_groups(config: pulumi.Config, eks_mode: EksMode) -> list[NodeGroupResolved]:
    """Load node group configuration."""
    if eks_mode == EksMode.AUTO:
        return []  # Auto mode doesn't use node groups

    node_groups_json = config.get("nodeGroups")
    if node_groups_json:
        try:
            groups_data = json.loads(node_groups_json)
            return [
                NodeGroupResolved(
                    name=ng["name"],
                    instance_types=ng.get("instance_types", ["t3.medium"]),
                    capacity_type=CapacityType(ng.get("capacity_type", "ON_DEMAND")),
                    ami_type=AmiType(ng.get("ami_type", "AL2023_x86_64_STANDARD")),
                    disk_size=ng.get("disk_size", 50),
                    desired_size=ng.get("desired_size", 2),
                    min_size=ng.get("min_size", 1),
                    max_size=ng.get("max_size", 5),
                    labels=ng.get("labels", {}),
                    taints=ng.get("taints", []),
                    tags=ng.get("tags", {}),
                )
                for ng in groups_data
            ]
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

    # Default node group for managed mode
    instance_types = _parse_list(config.get("nodeInstanceTypes"), ["t3.medium"])
    return [
        NodeGroupResolved(
            name=config.get("nodeGroupName") or "general",
            instance_types=instance_types,
            capacity_type=CapacityType(config.get("nodeCapacityType") or "ON_DEMAND"),
            ami_type=AmiType(config.get("nodeAmiType") or "AL2023_x86_64_STANDARD"),
            disk_size=int(config.get("nodeDiskSize") or "50"),
            desired_size=int(config.get("nodeDesiredSize") or "2"),
            min_size=int(config.get("nodeMinSize") or "1"),
            max_size=int(config.get("nodeMaxSize") or "5"),
            labels=_parse_json_dict(config.get("nodeLabels"), {}),
            taints=_parse_json_list(config.get("nodeTaints"), []),
            tags={},
        )
    ]


def _load_eks_config(config: pulumi.Config) -> EksConfigResolved:
    """Load EKS configuration from Pulumi config."""
    eks_version = config.get("eksVersion") or "1.31"
    eks_mode_str = config.get("eksMode") or "auto"
    eks_mode = EksMode(eks_mode_str)

    service_cidr = config.get("serviceIpv4Cidr") or "172.20.0.0/16"

    access = _load_eks_access(config)
    addons = _load_eks_addons(config, eks_mode)
    node_groups = _load_node_groups(config, eks_mode)

    logging_enabled = _parse_bool(config.get("loggingEnabled"), False)
    logging_types = (
        _parse_list(config.get("loggingTypes"), ["api", "audit", "authenticator"])
        if logging_enabled
        else []
    )

    return EksConfigResolved(
        version=eks_version,
        mode=eks_mode,
        service_ipv4_cidr=service_cidr,
        access=access,
        logging_enabled=logging_enabled,
        logging_types=logging_types,
        encryption_enabled=_parse_bool(config.get("encryptionEnabled"), True),
        encryption_kms_key_arn=config.get("encryptionKmsKeyArn"),
        zonal_shift_enabled=_parse_bool(config.get("zonalShiftEnabled"), False),
        deletion_protection=_parse_bool(config.get("deletionProtection"), False),
        addons=addons,
        node_groups=node_groups,
        tags=_parse_json_dict(config.get("eksTags"), {}),
    )


def _load_addons_config(config: pulumi.Config) -> AddonsConfigResolved:
    """Load cluster addons configuration from Pulumi config."""
    argocd_enabled = _parse_bool(config.get("argoCDEnabled"), False)

    # Load ArgoCD repository config if provided
    argocd_repo: Optional[ArgoCDRepoConfig] = None
    repo_url = config.get("argoCDRepoUrl")
    if repo_url:
        # Note: password is stored as regular config, not secret, for simplicity
        # The actual secret handling happens in Pulumi deployments
        argocd_repo = ArgoCDRepoConfig(
            url=repo_url,
            username=config.get("argoCDRepoUsername") or "git",
            password=config.get("argoCDRepoPassword") or "",
        )

    argocd = ArgoCDConfigResolved(
        enabled=argocd_enabled,
        server_replicas=int(config.get("argoCDServerReplicas") or "2"),
        repo_server_replicas=int(config.get("argoCDRepoServerReplicas") or "2"),
        ha_enabled=_parse_bool(config.get("argoCDHAEnabled"), False),
        repository=argocd_repo,
        root_app_path=config.get("argoCDRootAppPath") or "apps/",
    )

    return AddonsConfigResolved(argocd=argocd)


def load_customer_config() -> PulumiCustomerConfig:
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

    # Load VPC, EKS, and Addons configs
    vpc_config = _load_vpc_config(config)
    eks_config = _load_eks_config(config)
    addons_config = _load_addons_config(config)

    # Global tags
    tags: dict[str, str] = {
        "Environment": environment,
        "Customer": customer_id,
        "ManagedBy": "pulumi",
    }
    custom_tags = _parse_json_dict(config.get("tags"), {})
    if custom_tags:
        tags.update(custom_tags)

    return PulumiCustomerConfig(
        customer_id=customer_id,
        environment=environment,
        customer_role_arn=customer_role_arn,
        external_id=external_id,
        aws_region=aws_region,
        availability_zones=availability_zones,
        vpc_config=vpc_config,
        eks_config=eks_config,
        addons=addons_config,
        tags=tags,
    )
