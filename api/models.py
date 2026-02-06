import ipaddress
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator


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

    NONE = "none"  
    SINGLE = "single"  
    ONE_PER_AZ = "one_per_az"  


class EndpointAccess(str, Enum):
    """EKS cluster endpoint access configuration."""

    PRIVATE = "private"  
    PUBLIC = "public"  
    PUBLIC_AND_PRIVATE = "public_and_private"  


class CapacityType(str, Enum):
    """EC2 capacity type for node groups."""

    ON_DEMAND = "ON_DEMAND"
    SPOT = "SPOT"


class AmiType(str, Enum):
    """AMI type for EKS nodes."""

    AL2_X86_64 = "AL2_x86_64"
    AL2_X86_64_GPU = "AL2_x86_64_GPU"
    AL2_ARM_64 = "AL2_ARM_64"
    AL2023_X86_64_STANDARD = "AL2023_x86_64_STANDARD"
    AL2023_ARM_64_STANDARD = "AL2023_ARM_64_STANDARD"
    BOTTLEROCKET_X86_64 = "BOTTLEROCKET_x86_64"
    BOTTLEROCKET_ARM_64 = "BOTTLEROCKET_ARM_64"


class AwsConfigInput(BaseModel):
    """AWS account configuration - required fields for cross-account access."""

    role_arn: str = Field(
        ...,
        description="IAM role ARN for cross-account access",
        pattern=r"^arn:aws:iam::\d{12}:role/.+$",
    )
    external_id: str = Field(
        ...,
        description="External ID for secure role assumption",
        min_length=10,
    )
    region: str = Field(
        default="us-east-1",
        description="AWS region for deployment",
    )


class AwsConfigResolved(BaseModel):
    """Fully resolved AWS configuration."""

    role_arn: str
    external_id: str
    region: str
    availability_zones: list[str]  # Always 3 AZs, computed from region



class SubnetInput(BaseModel):
    """Input for a single subnet - user can specify custom subnets."""

    cidr_block: str = Field(..., description="CIDR block for the subnet")
    availability_zone: str = Field(..., description="Availability zone")
    name: Optional[str] = Field(default=None, description="Optional subnet name")
    tags: dict[str, str] = Field(default_factory=dict, description="Additional tags")

    @field_validator("cidr_block")
    @classmethod
    def validate_cidr(cls, v: str) -> str:
        try:
            ipaddress.ip_network(v, strict=False)
        except ValueError as e:
            raise ValueError(f"Invalid CIDR block: {e}") from e
        return v


class SubnetResolved(BaseModel):
    """Fully resolved subnet configuration."""

    cidr_block: str
    availability_zone: str
    name: str  
    tags: dict[str, str]


class VpcEndpointsInput(BaseModel):
    """VPC endpoints configuration - all optional with sensible defaults."""

    # Gateway endpoints (free)
    s3: bool = Field(default=True, description="Enable S3 gateway endpoint")
    dynamodb: bool = Field(default=False, description="Enable DynamoDB gateway endpoint")

    # Interface endpoints (cost ~$7.50/mo each + data transfer)
    ecr_api: bool = Field(default=False, description="Enable ECR API endpoint")
    ecr_dkr: bool = Field(default=False, description="Enable ECR DKR endpoint")
    sts: bool = Field(default=False, description="Enable STS endpoint")
    logs: bool = Field(default=False, description="Enable CloudWatch Logs endpoint")
    ec2: bool = Field(default=False, description="Enable EC2 endpoint")
    ssm: bool = Field(default=False, description="Enable SSM endpoint")
    ssmmessages: bool = Field(default=False, description="Enable SSM Messages endpoint")
    ec2messages: bool = Field(default=False, description="Enable EC2 Messages endpoint")
    elasticloadbalancing: bool = Field(default=False, description="Enable ELB endpoint")
    autoscaling: bool = Field(default=False, description="Enable Auto Scaling endpoint")


class VpcEndpointsResolved(BaseModel):
    """Fully resolved VPC endpoints configuration."""

    s3: bool
    dynamodb: bool
    ecr_api: bool
    ecr_dkr: bool
    sts: bool
    logs: bool
    ec2: bool
    ssm: bool
    ssmmessages: bool
    ec2messages: bool
    elasticloadbalancing: bool
    autoscaling: bool


class VpcConfigInput(BaseModel):
    """VPC configuration input - minimal required, rest uses defaults."""

    cidr_block: str = Field(
        default="10.0.0.0/16",
        description="Primary VPC CIDR block",
    )
    secondary_cidr_blocks: list[str] = Field(
        default_factory=list,
        description="Secondary CIDR blocks (e.g., for pod subnets)",
    )
    nat_gateway_strategy: NatGatewayStrategy = Field(
        default=NatGatewayStrategy.SINGLE,
        description="NAT gateway strategy - single is cost-effective default",
    )

    # Optional custom subnets - if not provided, auto-calculated
    public_subnets: Optional[list[SubnetInput]] = Field(
        default=None,
        description="Custom public subnet configs (auto-calculated if not provided)",
    )
    private_subnets: Optional[list[SubnetInput]] = Field(
        default=None,
        description="Custom private subnet configs (auto-calculated if not provided)",
    )
    pod_subnets: Optional[list[SubnetInput]] = Field(
        default=None,
        description="Custom pod subnet configs (requires secondary CIDR)",
    )

    # VPC endpoints
    vpc_endpoints: Optional[VpcEndpointsInput] = Field(
        default=None,
        description="VPC endpoints configuration",
    )

    # DNS settings - AWS defaults
    enable_dns_hostnames: bool = Field(default=True)
    enable_dns_support: bool = Field(default=True)

    tags: dict[str, str] = Field(default_factory=dict)

    @field_validator("cidr_block")
    @classmethod
    def validate_vpc_cidr(cls, v: str) -> str:
        try:
            network = ipaddress.ip_network(v, strict=False)
            if network.prefixlen < 16 or network.prefixlen > 24:
                raise ValueError("VPC CIDR prefix must be between /16 and /24")
        except ValueError as e:
            raise ValueError(f"Invalid VPC CIDR: {e}") from e
        return v


class VpcConfigResolved(BaseModel):
    """Fully resolved VPC configuration - all fields populated."""

    cidr_block: str
    secondary_cidr_blocks: list[str]
    nat_gateway_strategy: NatGatewayStrategy

    public_subnets: list[SubnetResolved]
    private_subnets: list[SubnetResolved]
    pod_subnets: list[SubnetResolved]  # Empty list if not enabled

    vpc_endpoints: VpcEndpointsResolved

    enable_dns_hostnames: bool
    enable_dns_support: bool

    tags: dict[str, str]



class AccessEntryInput(BaseModel):
    """EKS access entry for IAM principal."""

    principal_arn: str = Field(
        ...,
        description="IAM principal ARN",
        pattern=r"^arn:aws:iam::\d{12}:(role|user)/.+$",
    )
    type: str = Field(default="STANDARD", description="Access entry type")
    policy_associations: list[dict] = Field(
        default_factory=list,
        description="Policy associations for this principal",
    )

class SsmAccessNodeConfig(BaseModel):
    """SSM access node configuration for private cluster access."""

    enabled: bool = Field(
        default=False,
        description="Enable SSM access node for private cluster access",
    )
    instance_type: str = Field(
        default="t3.micro",
        description="EC2 instance type for access node",
    )


class SsmNodeStatus(BaseModel):
    """SSM access node status."""

    enabled: bool
    instance_id: Optional[str] = None
    instance_state: Optional[str] = None
    availability_zone: Optional[str] = None
    private_ip: Optional[str] = None


class SsmSessionInfo(BaseModel):
    """SSM session connection information."""

    instance_id: str
    region: str
    
    start_session_command: str = Field(
        description="Command to start SSM session to access node"
    )
    configure_kubectl_command: str = Field(
        description="Command to run inside session to configure kubectl"
    )
    
    instructions: list[str] = Field(default_factory=list)


class SsmStatusResponse(BaseModel):
    """Response for SSM status endpoint."""

    customer_id: str
    environment: str
    cluster_name: str
    access_node: SsmNodeStatus
    vpc_endpoints: dict[str, bool] = Field(
        description="Required VPC endpoints status"
    )
    ready: bool = Field(
        description="Whether SSM access is fully configured and ready"
    )
    issues: list[str] = Field(
        default_factory=list,
        description="Any issues preventing SSM access"
    )


class SsmSessionResponse(BaseModel):
    """Response for SSM session endpoint."""

    customer_id: str
    environment: str
    session: SsmSessionInfo


class EksAccessInput(BaseModel):
    """EKS access configuration input."""

    endpoint_private_access: bool = Field(
        default=True,
        description="Enable private endpoint access",
    )
    endpoint_public_access: bool = Field(
        default=False,
        description="Enable public endpoint access",
    )
    public_access_cidrs: list[str] = Field(
        default_factory=list,
        description="CIDRs allowed for public access",
    )
    authentication_mode: str = Field(
        default="API_AND_CONFIG_MAP",
        description="Authentication mode",
    )
    bootstrap_cluster_creator_admin_permissions: bool = Field(
        default=True,
        description="Grant admin to cluster creator",
    )
    access_entries: list[AccessEntryInput] = Field(
        default_factory=list,
        description="Additional access entries",
    )
    # NEW: SSM access node configuration
    ssm_access_node: Optional[SsmAccessNodeConfig] = Field(
        default=None,
        description="SSM access node for private cluster access",
    )



class EksAccessResolved(BaseModel):
    """Fully resolved EKS access configuration."""

    endpoint_private_access: bool
    endpoint_public_access: bool
    public_access_cidrs: list[str]
    authentication_mode: str
    bootstrap_cluster_creator_admin_permissions: bool
    access_entries: list[AccessEntryInput]
    ssm_access_node: Optional[SsmAccessNodeConfig] = None  # NEW


class AddonConfigInput(BaseModel):
    """Configuration for a single EKS addon."""

    enabled: bool = Field(default=True)
    version: Optional[str] = Field(
        default=None,
        description="Addon version (None = latest)",
    )
    service_account_role_arn: Optional[str] = Field(default=None)
    configuration: dict = Field(default_factory=dict)
    resolve_conflicts_on_create: str = Field(default="OVERWRITE")
    resolve_conflicts_on_update: str = Field(default="PRESERVE")


class EksAddonsInput(BaseModel):
    """EKS addons configuration - platform defaults applied."""

    # Core addons (always enabled for managed mode)
    vpc_cni: Optional[AddonConfigInput] = None
    coredns: Optional[AddonConfigInput] = None
    kube_proxy: Optional[AddonConfigInput] = None

    # Storage addons
    ebs_csi_driver: Optional[AddonConfigInput] = None
    efs_csi_driver: Optional[AddonConfigInput] = None

    # Other addons
    pod_identity_agent: Optional[AddonConfigInput] = None
    snapshot_controller: Optional[AddonConfigInput] = None


class EksAddonsResolved(BaseModel):
    """Fully resolved EKS addons configuration."""

    vpc_cni: AddonConfigInput
    coredns: AddonConfigInput
    kube_proxy: AddonConfigInput
    ebs_csi_driver: AddonConfigInput
    efs_csi_driver: AddonConfigInput
    pod_identity_agent: AddonConfigInput
    snapshot_controller: AddonConfigInput



class NodeGroupScalingInput(BaseModel):
    """Node group scaling configuration."""

    desired_size: int = Field(default=2, ge=0, le=100)
    min_size: int = Field(default=1, ge=0, le=100)
    max_size: int = Field(default=5, ge=1, le=100)


class NodeGroupInput(BaseModel):
    """Node group configuration input."""

    name: str = Field(default="general")
    instance_types: list[str] = Field(default_factory=lambda: ["t3.medium"])
    capacity_type: CapacityType = Field(default=CapacityType.ON_DEMAND)
    ami_type: AmiType = Field(default=AmiType.AL2023_X86_64_STANDARD)
    disk_size: int = Field(default=50, ge=20, le=1000)
    scaling: Optional[NodeGroupScalingInput] = None
    labels: dict[str, str] = Field(default_factory=dict)
    taints: list[dict[str, str]] = Field(default_factory=list)
    tags: dict[str, str] = Field(default_factory=dict)


class NodeGroupResolved(BaseModel):
    """Fully resolved node group configuration."""

    name: str
    instance_types: list[str]
    capacity_type: CapacityType
    ami_type: AmiType
    disk_size: int
    desired_size: int
    min_size: int
    max_size: int
    labels: dict[str, str]
    taints: list[dict[str, str]]
    tags: dict[str, str]



class EksConfigInput(BaseModel):
    """EKS cluster configuration input."""

    version: str = Field(default="1.31", description="Kubernetes version")
    mode: EksMode = Field(
        default=EksMode.AUTO,
        description="EKS mode: auto (AWS manages everything) or managed (node groups)",
    )
    service_ipv4_cidr: str = Field(
        default="172.20.0.0/16",
        description="Kubernetes service CIDR",
    )

    # Access configuration
    access: Optional[EksAccessInput] = None

    # Logging - disabled by default (cost consideration)
    logging_enabled: bool = Field(default=False)
    logging_types: list[str] = Field(
        default_factory=lambda: ["api", "audit", "authenticator"],
    )

    # Encryption - enabled by default (AWS managed key)
    encryption_enabled: bool = Field(default=True)
    encryption_kms_key_arn: Optional[str] = Field(
        default=None,
        description="KMS key ARN (None = AWS creates one)",
    )

    # Other settings
    zonal_shift_enabled: bool = Field(default=False)
    deletion_protection: bool = Field(default=False)

    # Addons
    addons: Optional[EksAddonsInput] = None

    # Node groups (only for managed mode)
    node_groups: Optional[list[NodeGroupInput]] = None

    tags: dict[str, str] = Field(default_factory=dict)

    @field_validator("service_ipv4_cidr")
    @classmethod
    def validate_service_cidr(cls, v: str) -> str:
        try:
            network = ipaddress.ip_network(v, strict=False)
            if network.prefixlen < 12 or network.prefixlen > 24:
                raise ValueError("Service CIDR prefix must be between /12 and /24")
        except ValueError as e:
            raise ValueError(f"Invalid service CIDR: {e}") from e
        return v


class EksConfigResolved(BaseModel):
    """Fully resolved EKS configuration."""

    version: str
    mode: EksMode
    service_ipv4_cidr: str

    access: EksAccessResolved

    logging_enabled: bool
    logging_types: list[str]

    encryption_enabled: bool
    encryption_kms_key_arn: Optional[str]

    zonal_shift_enabled: bool
    deletion_protection: bool

    addons: EksAddonsResolved

    # Node groups - empty for auto mode, populated for managed mode
    node_groups: list[NodeGroupResolved]

    tags: dict[str, str]


class CustomerConfigInput(BaseModel):
    """Input model for creating/updating customer configuration.

    This is what the API accepts - partial config with sensible defaults.
    """

    customer_id: str = Field(
        ...,
        description="Unique customer identifier",
        pattern=r"^[a-z0-9-]+$",
        min_length=3,
        max_length=50,
    )
    environment: str = Field(
        default="prod",
        description="Environment name",
        pattern=r"^[a-z0-9-]+$",
    )

    # AWS configuration - required
    aws_config: AwsConfigInput

    # VPC configuration - optional, uses defaults
    vpc_config: Optional[VpcConfigInput] = None

    # EKS configuration - optional, uses defaults
    eks_config: Optional[EksConfigInput] = None

    # Global tags applied to all resources
    tags: dict[str, str] = Field(default_factory=dict)


class CustomerConfigResolved(BaseModel):
    """Fully resolved customer configuration.

    This is what gets stored - complete config with all defaults filled.
    Every field is explicitly set, no optionals.
    """

    customer_id: str
    environment: str

    aws_config: AwsConfigResolved
    vpc_config: VpcConfigResolved
    eks_config: EksConfigResolved

    tags: dict[str, str]

    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CustomerConfigResponse(BaseModel):
    """Response model for customer configuration (hides sensitive fields)."""

    customer_id: str
    environment: str
    aws_region: str
    vpc_config: VpcConfigResolved
    eks_config: EksConfigResolved
    tags: dict[str, str]
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_resolved(cls, config: CustomerConfigResolved) -> "CustomerConfigResponse":
        """Create response from resolved config (excludes sensitive AWS fields)."""
        return cls(
            customer_id=config.customer_id,
            environment=config.environment,
            aws_region=config.aws_config.region,
            vpc_config=config.vpc_config,
            eks_config=config.eks_config,
            tags=config.tags,
            created_at=config.created_at,
            updated_at=config.updated_at,
        )


class CustomerConfigListResponse(BaseModel):
    """Response model for listing customer configurations."""

    configs: list[CustomerConfigResponse]
    total: int



class DeployRequest(BaseModel):
    """Request model for triggering a deployment."""

    environment: str = Field(
        default="prod",
        description="Environment name",
        pattern=r"^[a-z0-9-]+$",
    )


class DestroyRequest(BaseModel):
    """Request model for destroying infrastructure."""

    confirm: bool = Field(..., description="Must be true to confirm destruction")

    @field_validator("confirm")
    @classmethod
    def validate_confirm(cls, v: bool) -> bool:
        if not v:
            raise ValueError("confirm must be true to destroy infrastructure")
        return v


class DeploymentResponse(BaseModel):
    """Response for deployment operations."""

    customer_id: str
    environment: str
    stack_name: str
    status: DeploymentStatus
    message: str
    deployment_id: Optional[str] = None


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



class ValidationErrorDetail(BaseModel):
    """Single validation error detail."""

    field: str
    message: str
    value: Optional[str] = None


class ValidationErrorResponse(BaseModel):
    """Structured validation error response."""

    error: str = "validation_error"
    message: str
    details: list[ValidationErrorDetail]

