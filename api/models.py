"""Pydantic models for API requests and responses."""

import ipaddress
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator, model_validator


class DeploymentStatus(str, Enum):
    """Status of a customer deployment."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DESTROYING = "destroying"
    DESTROYED = "destroyed"


class EksMode(str, Enum):
    """EKS compute mode."""

    AUTO = "auto"
    MANAGED = "managed"


class NatGatewayStrategy(str, Enum):
    """NAT Gateway deployment strategy."""

    NONE = "none"  # No NAT gateway (public subnets only)
    SINGLE = "single"  # Single NAT gateway for all AZs (~$32/mo)
    ONE_PER_AZ = "one_per_az"  # One NAT gateway per AZ (~$96/mo for 3 AZs)


class EndpointAccess(str, Enum):
    """EKS cluster endpoint access configuration."""

    PRIVATE = "private"  # API server only accessible from within VPC
    PUBLIC = "public"  # API server accessible from internet
    PUBLIC_AND_PRIVATE = "public_and_private"  # Both public and private access


# -----------------------------------------------------------------------------
# Subnet Configuration Models
# -----------------------------------------------------------------------------


class SubnetConfig(BaseModel):
    """Configuration for a single subnet."""

    cidr_block: str = Field(
        ...,
        description="CIDR block for the subnet (e.g., '10.0.0.0/24')",
    )
    availability_zone: str = Field(
        ...,
        description="Availability zone for the subnet (e.g., 'us-east-1a')",
    )
    name: Optional[str] = Field(
        default=None,
        description="Optional name for the subnet",
    )

    @field_validator("cidr_block")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        """Validate CIDR format."""
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR block: {e}") from e
        return v


class SubnetGroupConfig(BaseModel):
    """Configuration for a group of subnets (public, private, or pod)."""

    cidr_mask: Optional[int] = Field(
        default=None,
        ge=16,
        le=28,
        description="CIDR mask for auto-calculated subnets",
    )
    custom_subnets: Optional[list[SubnetConfig]] = Field(
        default=None,
        description="Custom subnet configurations (overrides cidr_mask)",
    )

    @model_validator(mode="after")
    def validate_subnet_config(self) -> "SubnetGroupConfig":
        """Ensure either cidr_mask or custom_subnets is provided."""
        if self.cidr_mask is None and self.custom_subnets is None:
            raise ValueError("Either cidr_mask or custom_subnets must be provided")
        return self


class PodSubnetConfig(BaseModel):
    """Configuration for pod subnets (custom networking)."""

    enabled: bool = Field(
        default=False,
        description="Enable pod subnets for custom networking",
    )
    cidr_mask: Optional[int] = Field(
        default=18,
        ge=16,
        le=28,
        description="CIDR mask for auto-calculated pod subnets",
    )
    custom_subnets: Optional[list[SubnetConfig]] = Field(
        default=None,
        description="Custom pod subnet configurations",
    )


# -----------------------------------------------------------------------------
# VPC Configuration Models
# -----------------------------------------------------------------------------


class VpcEndpointsConfig(BaseModel):
    """Configuration for VPC endpoints."""

    s3_gateway: bool = Field(
        default=True,
        description="Enable S3 gateway endpoint",
    )
    ecr_api: bool = Field(
        default=False,
        description="Enable ECR API interface endpoint",
    )
    ecr_dkr: bool = Field(
        default=False,
        description="Enable ECR DKR interface endpoint",
    )
    sts: bool = Field(
        default=False,
        description="Enable STS interface endpoint",
    )
    logs: bool = Field(
        default=False,
        description="Enable CloudWatch Logs interface endpoint",
    )
    ec2: bool = Field(
        default=False,
        description="Enable EC2 interface endpoint",
    )
    ssm: bool = Field(
        default=False,
        description="Enable SSM interface endpoint",
    )
    ssmmessages: bool = Field(
        default=False,
        description="Enable SSM Messages interface endpoint",
    )
    ec2messages: bool = Field(
        default=False,
        description="Enable EC2 Messages interface endpoint",
    )


class VpcConfig(BaseModel):
    """VPC configuration options."""

    cidr_block: str = Field(
        default="10.0.0.0/16",
        description="Primary VPC CIDR block",
    )
    secondary_cidr_blocks: list[str] = Field(
        default_factory=list,
        description="Secondary CIDR blocks for the VPC (e.g., for pod subnets)",
    )
    nat_gateway_strategy: NatGatewayStrategy = Field(
        default=NatGatewayStrategy.ONE_PER_AZ,
        description="NAT gateway deployment strategy",
    )
    public_subnets: Optional[SubnetGroupConfig] = Field(
        default=None,
        description="Public subnet configuration",
    )
    private_subnets: Optional[SubnetGroupConfig] = Field(
        default=None,
        description="Private subnet configuration",
    )
    pod_subnets: Optional[PodSubnetConfig] = Field(
        default=None,
        description="Pod subnet configuration for custom networking",
    )
    vpc_endpoints: VpcEndpointsConfig = Field(
        default_factory=VpcEndpointsConfig,
        description="VPC endpoints configuration",
    )
    enable_dns_hostnames: bool = Field(
        default=True,
        description="Enable DNS hostnames in VPC (required for EKS)",
    )
    enable_dns_support: bool = Field(
        default=True,
        description="Enable DNS support in VPC (required for EKS)",
    )

    @field_validator("cidr_block")
    @classmethod
    def validate_vpc_cidr(cls, v: str) -> str:
        """Validate VPC CIDR format."""
        try:
            network = ipaddress.ip_network(v, strict=False)
            if network.prefixlen < 16 or network.prefixlen > 24:
                raise ValueError("VPC CIDR prefix must be between /16 and /24")
        except ValueError as e:
            raise ValueError(f"Invalid VPC CIDR: {e}") from e
        return v

    @field_validator("secondary_cidr_blocks")
    @classmethod
    def validate_secondary_cidrs(cls, v: list[str]) -> list[str]:
        """Validate secondary CIDR blocks."""
        for cidr in v:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as e:
                raise ValueError(f"Invalid secondary CIDR block '{cidr}': {e}") from e
        return v


# -----------------------------------------------------------------------------
# EKS Access Configuration Models
# -----------------------------------------------------------------------------


class AccessEntryConfig(BaseModel):
    """Configuration for an EKS access entry."""

    principal_arn: str = Field(
        ...,
        description="IAM principal ARN to grant access",
        pattern=r"^arn:aws:iam::\d{12}:(role|user)/.+$",
    )
    policy: str = Field(
        default="AmazonEKSClusterAdminPolicy",
        description="EKS access policy name",
    )
    access_scope: str = Field(
        default="cluster",
        description="Access scope: 'cluster' or 'namespace'",
        pattern=r"^(cluster|namespace)$",
    )
    namespaces: list[str] = Field(
        default_factory=list,
        description="Namespaces for namespace-scoped access",
    )


class EksAccessConfig(BaseModel):
    """EKS cluster access configuration."""

    endpoint_access: EndpointAccess = Field(
        default=EndpointAccess.PRIVATE,
        description="Cluster endpoint access type",
    )
    public_access_cidrs: list[str] = Field(
        default_factory=list,
        description="CIDRs allowed for public endpoint access",
    )
    grant_admin_to_creator: bool = Field(
        default=True,
        description="Grant cluster admin to the role that creates the cluster",
    )
    authentication_mode: str = Field(
        default="API_AND_CONFIG_MAP",
        description="Authentication mode: API, CONFIG_MAP, or API_AND_CONFIG_MAP",
        pattern=r"^(API|CONFIG_MAP|API_AND_CONFIG_MAP)$",
    )
    access_entries: list[AccessEntryConfig] = Field(
        default_factory=list,
        description="Additional access entries for IAM principals",
    )

    @field_validator("public_access_cidrs")
    @classmethod
    def validate_public_cidrs(cls, v: list[str]) -> list[str]:
        """Validate public access CIDRs."""
        for cidr in v:
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as e:
                raise ValueError(f"Invalid public access CIDR '{cidr}': {e}") from e
        return v


# -----------------------------------------------------------------------------
# EKS Configuration Models
# -----------------------------------------------------------------------------


class EksConfig(BaseModel):
    """EKS cluster configuration options."""

    version: str = Field(
        default="1.31",
        description="Kubernetes version",
    )
    mode: EksMode = Field(
        default=EksMode.MANAGED,
        description="EKS compute mode: 'auto' or 'managed'",
    )
    service_ipv4_cidr: str = Field(
        default="172.20.0.0/16",
        description="Kubernetes service CIDR (must not overlap with VPC CIDR)",
    )
    access: EksAccessConfig = Field(
        default_factory=EksAccessConfig,
        description="Cluster access configuration",
    )
    logging_enabled: bool = Field(
        default=False,
        description="Enable control plane logging",
    )
    logging_types: list[str] = Field(
        default=["api", "audit", "authenticator", "controllerManager", "scheduler"],
        description="Control plane log types to enable",
    )
    encryption_enabled: bool = Field(
        default=False,
        description="Enable secrets encryption",
    )
    encryption_kms_key_arn: Optional[str] = Field(
        default=None,
        description="KMS key ARN for secrets encryption",
    )
    deletion_protection: bool = Field(
        default=False,
        description="Enable deletion protection",
    )
    zonal_shift_enabled: bool = Field(
        default=False,
        description="Enable ARC zonal shift",
    )

    @field_validator("service_ipv4_cidr")
    @classmethod
    def validate_service_cidr(cls, v: str) -> str:
        """Validate service CIDR format."""
        try:
            network = ipaddress.ip_network(v, strict=False)
            if network.prefixlen < 12 or network.prefixlen > 24:
                raise ValueError("Service CIDR prefix must be between /12 and /24")
        except ValueError as e:
            raise ValueError(f"Invalid service CIDR: {e}") from e
        return v


# -----------------------------------------------------------------------------
# Node Group Configuration Models
# -----------------------------------------------------------------------------


class NodeGroupConfig(BaseModel):
    """Configuration for managed node group (only used when eks_mode=managed)."""

    name: str = Field(
        default="general",
        description="Node group name",
    )
    instance_types: list[str] = Field(
        default=["t3.medium"],
        description="EC2 instance types for worker nodes",
    )
    desired_size: int = Field(
        default=2,
        description="Desired number of nodes",
        ge=0,
        le=100,
    )
    min_size: int = Field(
        default=1,
        description="Minimum number of nodes",
        ge=0,
        le=100,
    )
    max_size: int = Field(
        default=5,
        description="Maximum number of nodes",
        ge=1,
        le=100,
    )
    disk_size: int = Field(
        default=50,
        description="Disk size in GB for each node",
        ge=20,
        le=1000,
    )
    capacity_type: str = Field(
        default="ON_DEMAND",
        description="Capacity type: ON_DEMAND or SPOT",
        pattern=r"^(ON_DEMAND|SPOT)$",
    )
    ami_type: str = Field(
        default="AL2_x86_64",
        description="AMI type for nodes",
    )
    labels: dict[str, str] = Field(
        default_factory=dict,
        description="Kubernetes labels for nodes",
    )
    taints: list[dict[str, str]] = Field(
        default_factory=list,
        description="Kubernetes taints for nodes",
    )


# -----------------------------------------------------------------------------
# Main Customer Configuration Models
# -----------------------------------------------------------------------------


class CustomerConfigCreate(BaseModel):
    """Request model for creating a customer configuration."""

    customer_id: str = Field(
        ...,
        description="Unique customer identifier",
        pattern=r"^[a-z0-9-]+$",
        min_length=3,
        max_length=50,
    )
    role_arn: str = Field(
        ...,
        description="Customer's IAM role ARN for cross-account access",
        pattern=r"^arn:aws:iam::\d{12}:role/.+$",
    )
    external_id: str = Field(
        ...,
        description="External ID for secure role assumption",
        min_length=10,
    )
    aws_region: str = Field(
        default="us-east-1",
        description="AWS region for deployment",
    )
    availability_zones: Optional[list[str]] = Field(
        default=None,
        description="Availability zones (defaults to 3 AZs in the region)",
    )

    # VPC Configuration
    vpc_config: VpcConfig = Field(
        default_factory=VpcConfig,
        description="VPC configuration",
    )

    # EKS Configuration
    eks_config: EksConfig = Field(
        default_factory=EksConfig,
        description="EKS cluster configuration",
    )

    # Node Group Configuration (for managed mode)
    node_group_config: Optional[NodeGroupConfig] = Field(
        default=None,
        description="Node group configuration (only used when eks_mode=managed)",
    )

    # Tags
    tags: dict[str, str] = Field(
        default_factory=dict,
        description="Custom tags to apply to all resources",
    )

    @field_validator("aws_region")
    @classmethod
    def validate_aws_region(cls, v: str) -> str:
        """Validate AWS region format."""
        valid_regions = [
            "us-east-1",
            "us-east-2",
            "us-west-1",
            "us-west-2",
            "eu-west-1",
            "eu-west-2",
            "eu-west-3",
            "eu-central-1",
            "eu-north-1",
            "ap-south-1",
            "ap-southeast-1",
            "ap-southeast-2",
            "ap-northeast-1",
            "ap-northeast-2",
            "ap-northeast-3",
            "sa-east-1",
            "ca-central-1",
        ]
        if v not in valid_regions:
            raise ValueError(f"Invalid AWS region. Must be one of: {valid_regions}")
        return v

    @model_validator(mode="after")
    def validate_cidr_no_overlap(self) -> "CustomerConfigCreate":
        """Validate that service CIDR doesn't overlap with VPC CIDR."""
        vpc_network = ipaddress.ip_network(self.vpc_config.cidr_block, strict=False)
        service_network = ipaddress.ip_network(
            self.eks_config.service_ipv4_cidr, strict=False
        )

        if vpc_network.overlaps(service_network):
            raise ValueError(
                f"Service CIDR {self.eks_config.service_ipv4_cidr} overlaps with "
                f"VPC CIDR {self.vpc_config.cidr_block}. Use a different service CIDR."
            )

        # Validate secondary CIDRs don't overlap with primary
        for secondary in self.vpc_config.secondary_cidr_blocks:
            secondary_network = ipaddress.ip_network(secondary, strict=False)
            if vpc_network.overlaps(secondary_network):
                raise ValueError(
                    f"Secondary CIDR {secondary} overlaps with primary VPC CIDR "
                    f"{self.vpc_config.cidr_block}"
                )

        return self

    @model_validator(mode="after")
    def validate_pod_subnets_require_secondary_cidr(self) -> "CustomerConfigCreate":
        """Validate that pod subnets have a secondary CIDR if enabled."""
        if (
            self.vpc_config.pod_subnets
            and self.vpc_config.pod_subnets.enabled
            and not self.vpc_config.secondary_cidr_blocks
            and not self.vpc_config.pod_subnets.custom_subnets
        ):
            raise ValueError(
                "Pod subnets require either secondary_cidr_blocks or custom_subnets "
                "to be configured"
            )
        return self

    @model_validator(mode="after")
    def validate_custom_subnets_match_azs(self) -> "CustomerConfigCreate":
        """Validate custom subnets match availability zones."""
        if not self.availability_zones:
            return self

        azs = set(self.availability_zones)

        # Check public subnets
        if (
            self.vpc_config.public_subnets
            and self.vpc_config.public_subnets.custom_subnets
        ):
            subnet_azs = {s.availability_zone for s in self.vpc_config.public_subnets.custom_subnets}
            if not subnet_azs.issubset(azs):
                invalid = subnet_azs - azs
                raise ValueError(
                    f"Public subnet AZs {invalid} not in availability_zones {azs}"
                )

        # Check private subnets
        if (
            self.vpc_config.private_subnets
            and self.vpc_config.private_subnets.custom_subnets
        ):
            subnet_azs = {s.availability_zone for s in self.vpc_config.private_subnets.custom_subnets}
            if not subnet_azs.issubset(azs):
                invalid = subnet_azs - azs
                raise ValueError(
                    f"Private subnet AZs {invalid} not in availability_zones {azs}"
                )

        # Check pod subnets
        if (
            self.vpc_config.pod_subnets
            and self.vpc_config.pod_subnets.enabled
            and self.vpc_config.pod_subnets.custom_subnets
        ):
            subnet_azs = {s.availability_zone for s in self.vpc_config.pod_subnets.custom_subnets}
            if not subnet_azs.issubset(azs):
                invalid = subnet_azs - azs
                raise ValueError(
                    f"Pod subnet AZs {invalid} not in availability_zones {azs}"
                )

        return self


class CustomerConfigUpdate(BaseModel):
    """Request model for updating a customer configuration."""

    role_arn: Optional[str] = Field(
        default=None,
        description="Customer's IAM role ARN for cross-account access",
        pattern=r"^arn:aws:iam::\d{12}:role/.+$",
    )
    external_id: Optional[str] = Field(
        default=None,
        description="External ID for secure role assumption",
        min_length=10,
    )
    aws_region: Optional[str] = Field(
        default=None,
        description="AWS region for deployment",
    )
    availability_zones: Optional[list[str]] = Field(
        default=None,
        description="Availability zones",
    )
    vpc_config: Optional[VpcConfig] = Field(
        default=None,
        description="VPC configuration",
    )
    eks_config: Optional[EksConfig] = Field(
        default=None,
        description="EKS cluster configuration",
    )
    node_group_config: Optional[NodeGroupConfig] = Field(
        default=None,
        description="Node group configuration",
    )
    tags: Optional[dict[str, str]] = Field(
        default=None,
        description="Custom tags",
    )

    @field_validator("aws_region")
    @classmethod
    def validate_aws_region(cls, v: Optional[str]) -> Optional[str]:
        """Validate AWS region format if provided."""
        if v is None:
            return v
        valid_regions = [
            "us-east-1",
            "us-east-2",
            "us-west-1",
            "us-west-2",
            "eu-west-1",
            "eu-west-2",
            "eu-west-3",
            "eu-central-1",
            "eu-north-1",
            "ap-south-1",
            "ap-southeast-1",
            "ap-southeast-2",
            "ap-northeast-1",
            "ap-northeast-2",
            "ap-northeast-3",
            "sa-east-1",
            "ca-central-1",
        ]
        if v not in valid_regions:
            raise ValueError(f"Invalid AWS region. Must be one of: {valid_regions}")
        return v


class CustomerConfig(BaseModel):
    """Full customer configuration model (stored in file)."""

    customer_id: str = Field(
        ...,
        description="Unique customer identifier",
    )
    role_arn: str = Field(
        ...,
        description="Customer's IAM role ARN for cross-account access",
    )
    external_id: str = Field(
        ...,
        description="External ID for secure role assumption",
    )
    aws_region: str = Field(
        default="us-east-1",
        description="AWS region for deployment",
    )
    availability_zones: Optional[list[str]] = Field(
        default=None,
        description="Availability zones",
    )
    vpc_config: VpcConfig = Field(
        default_factory=VpcConfig,
        description="VPC configuration",
    )
    eks_config: EksConfig = Field(
        default_factory=EksConfig,
        description="EKS cluster configuration",
    )
    node_group_config: Optional[NodeGroupConfig] = Field(
        default=None,
        description="Node group configuration",
    )
    tags: dict[str, str] = Field(
        default_factory=dict,
        description="Custom tags",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Configuration creation timestamp",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Configuration last update timestamp",
    )

    @classmethod
    def from_create_request(cls, request: CustomerConfigCreate) -> "CustomerConfig":
        """Create a CustomerConfig from a create request."""
        now = datetime.now(timezone.utc)
        return cls(
            customer_id=request.customer_id,
            role_arn=request.role_arn,
            external_id=request.external_id,
            aws_region=request.aws_region,
            availability_zones=request.availability_zones,
            vpc_config=request.vpc_config,
            eks_config=request.eks_config,
            node_group_config=request.node_group_config,
            tags=request.tags,
            created_at=now,
            updated_at=now,
        )

    def apply_update(self, update: CustomerConfigUpdate) -> "CustomerConfig":
        """Apply an update to this configuration."""
        update_data = update.model_dump(exclude_unset=True)
        current_data = self.model_dump()
        current_data.update(update_data)
        current_data["updated_at"] = datetime.now(timezone.utc)
        return CustomerConfig.model_validate(current_data)


class CustomerConfigResponse(BaseModel):
    """Response model for customer configuration (hides sensitive fields)."""

    customer_id: str
    role_arn: str
    aws_region: str
    availability_zones: Optional[list[str]]
    vpc_config: VpcConfig
    eks_config: EksConfig
    node_group_config: Optional[NodeGroupConfig]
    tags: dict[str, str]
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_config(cls, config: CustomerConfig) -> "CustomerConfigResponse":
        """Create a response from a full config (excludes external_id)."""
        return cls(
            customer_id=config.customer_id,
            role_arn=config.role_arn,
            aws_region=config.aws_region,
            availability_zones=config.availability_zones,
            vpc_config=config.vpc_config,
            eks_config=config.eks_config,
            node_group_config=config.node_group_config,
            tags=config.tags,
            created_at=config.created_at,
            updated_at=config.updated_at,
        )


class CustomerConfigListResponse(BaseModel):
    """Response model for listing customer configurations."""

    configs: list[CustomerConfigResponse]
    total: int


# -----------------------------------------------------------------------------
# Deployment Request/Response Models
# -----------------------------------------------------------------------------


class CustomerOnboardRequest(BaseModel):
    """Request to onboard a new customer."""

    customer_id: str = Field(
        ...,
        description="Unique customer identifier (used in stack name)",
        pattern=r"^[a-z0-9-]+$",
        min_length=3,
        max_length=50,
    )
    environment: str = Field(
        default="prod",
        description="Environment name (dev/staging/prod)",
        pattern=r"^[a-z0-9-]+$",
    )

    role_arn: str = Field(
        ...,
        description="Customer's IAM role ARN for cross-account access",
        pattern=r"^arn:aws:iam::\d{12}:role/.+$",
    )
    external_id: str = Field(
        ...,
        description="External ID for secure role assumption",
        min_length=10,
    )

    aws_region: str = Field(
        default="us-east-1",
        description="AWS region for deployment",
    )

    vpc_config: VpcConfig = Field(
        default_factory=VpcConfig,
        description="VPC configuration",
    )

    availability_zones: Optional[list[str]] = Field(
        default=None,
        description="Availability zones (defaults to 3 AZs in the region)",
    )

    eks_config: EksConfig = Field(
        default_factory=EksConfig,
        description="EKS cluster configuration",
    )

    node_group_config: Optional[NodeGroupConfig] = Field(
        default=None,
        description="Node group configuration (only used when eks_mode=managed)",
    )

    tags: dict[str, str] = Field(
        default_factory=dict,
        description="Custom tags",
    )


class CustomerDeployment(BaseModel):
    """Customer deployment record."""

    id: int
    customer_id: str
    environment: str
    stack_name: str
    aws_region: str
    role_arn: str
    status: DeploymentStatus
    pulumi_deployment_id: Optional[str] = None
    outputs: Optional[dict] = None
    error_message: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class DeploymentResponse(BaseModel):
    """Response for deployment operations."""

    customer_id: str
    environment: str
    stack_name: str
    status: DeploymentStatus
    message: str
    deployment_id: Optional[str] = None


class DeployRequest(BaseModel):
    """Request model for triggering a deployment."""

    environment: str = Field(
        default="prod",
        description="Environment name (dev/staging/prod)",
        pattern=r"^[a-z0-9-]+$",
    )


class DestroyRequest(BaseModel):
    """Request model for destroying infrastructure."""

    confirm: bool = Field(
        ...,
        description="Must be true to confirm destruction",
    )

    @field_validator("confirm")
    @classmethod
    def validate_confirm(cls, v: bool) -> bool:
        """Ensure confirm is explicitly set to true."""
        if not v:
            raise ValueError("confirm must be true to destroy infrastructure")
        return v