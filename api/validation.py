"""Configuration validation - comprehensive checks before persisting configs.

This module performs strict validation to reject invalid configurations early.
Validation happens AFTER resolution, on the fully-resolved config.

Validation Categories:
1. CIDR Validation - format, ranges, overlaps
2. Subnet Validation - within VPC range, no overlaps
3. Relationship Validation - NAT/IGW requirements, subnet dependencies
4. Semantic Validation - contradictory settings, invalid combinations
"""

import ipaddress
from typing import Optional

from api.models import (
    CustomerConfigInput,
    CustomerConfigResolved,
    EksMode,
    NatGatewayStrategy,
    SubnetResolved,
    ValidationErrorDetail,
    ValidationErrorResponse,
    VpcConfigResolved,
)


class ConfigValidationError(Exception):
    """Exception raised when config validation fails."""

    def __init__(self, errors: list[ValidationErrorDetail]):
        self.errors = errors
        messages = [f"{e.field}: {e.message}" for e in errors]
        super().__init__(f"Configuration validation failed: {'; '.join(messages)}")

    def to_response(self) -> ValidationErrorResponse:
        """Convert to API response format."""
        return ValidationErrorResponse(
            error="validation_error",
            message=f"Configuration validation failed with {len(self.errors)} error(s)",
            details=self.errors,
        )


# =============================================================================
# CIDR Validation Helpers
# =============================================================================


def is_valid_cidr(cidr: str) -> tuple[bool, Optional[str]]:
    """Check if a CIDR string is valid.

    Returns (is_valid, error_message).
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True, None
    except ValueError as e:
        return False, str(e)


def cidrs_overlap(cidr1: str, cidr2: str) -> bool:
    """Check if two CIDR blocks overlap."""
    try:
        net1 = ipaddress.ip_network(cidr1, strict=False)
        net2 = ipaddress.ip_network(cidr2, strict=False)
        return net1.overlaps(net2)
    except ValueError:
        return False  # Invalid CIDRs handled elsewhere


def is_subnet_of(subnet_cidr: str, vpc_cidr: str) -> bool:
    """Check if subnet CIDR is within VPC CIDR range."""
    try:
        subnet = ipaddress.ip_network(subnet_cidr, strict=False)
        vpc = ipaddress.ip_network(vpc_cidr, strict=False)
        return subnet.subnet_of(vpc)
    except ValueError:
        return False


# =============================================================================
# Input Validation (Pre-Resolution)
# =============================================================================


def validate_input_config(config: CustomerConfigInput) -> list[ValidationErrorDetail]:
    """Validate input configuration before resolution.

    These are basic format checks that should fail fast.
    """
    errors: list[ValidationErrorDetail] = []

    # Validate customer_id format
    if not config.customer_id:
        errors.append(
            ValidationErrorDetail(
                field="customer_id",
                message="Customer ID is required",
            )
        )

    # Validate AWS config
    if not config.aws_config.role_arn:
        errors.append(
            ValidationErrorDetail(
                field="aws_config.role_arn",
                message="AWS role ARN is required",
            )
        )

    if not config.aws_config.external_id:
        errors.append(
            ValidationErrorDetail(
                field="aws_config.external_id",
                message="External ID is required",
            )
        )

    # Validate VPC CIDR if provided
    if config.vpc_config and config.vpc_config.cidr_block:
        valid, err = is_valid_cidr(config.vpc_config.cidr_block)
        if not valid:
            errors.append(
                ValidationErrorDetail(
                    field="vpc_config.cidr_block",
                    message=f"Invalid VPC CIDR: {err}",
                    value=config.vpc_config.cidr_block,
                )
            )

    # Validate secondary CIDRs if provided
    if config.vpc_config and config.vpc_config.secondary_cidr_blocks:
        for i, cidr in enumerate(config.vpc_config.secondary_cidr_blocks):
            valid, err = is_valid_cidr(cidr)
            if not valid:
                errors.append(
                    ValidationErrorDetail(
                        field=f"vpc_config.secondary_cidr_blocks[{i}]",
                        message=f"Invalid secondary CIDR: {err}",
                        value=cidr,
                    )
                )

    # Validate custom subnet CIDRs if provided
    if config.vpc_config:
        for subnet_type in ["public_subnets", "private_subnets", "pod_subnets"]:
            subnets = getattr(config.vpc_config, subnet_type, None)
            if subnets:
                for i, subnet in enumerate(subnets):
                    valid, err = is_valid_cidr(subnet.cidr_block)
                    if not valid:
                        errors.append(
                            ValidationErrorDetail(
                                field=f"vpc_config.{subnet_type}[{i}].cidr_block",
                                message=f"Invalid subnet CIDR: {err}",
                                value=subnet.cidr_block,
                            )
                        )

    # Validate EKS service CIDR if provided
    if config.eks_config and config.eks_config.service_ipv4_cidr:
        valid, err = is_valid_cidr(config.eks_config.service_ipv4_cidr)
        if not valid:
            errors.append(
                ValidationErrorDetail(
                    field="eks_config.service_ipv4_cidr",
                    message=f"Invalid service CIDR: {err}",
                    value=config.eks_config.service_ipv4_cidr,
                )
            )

    return errors


# =============================================================================
# Resolved Config Validation
# =============================================================================


def validate_vpc_cidrs(vpc_config: VpcConfigResolved) -> list[ValidationErrorDetail]:
    """Validate VPC CIDR configurations."""
    errors: list[ValidationErrorDetail] = []

    vpc_cidr = vpc_config.cidr_block

    # Check VPC CIDR size (must be /16 to /24)
    try:
        vpc_net = ipaddress.ip_network(vpc_cidr, strict=False)
        if vpc_net.prefixlen < 16 or vpc_net.prefixlen > 24:
            errors.append(
                ValidationErrorDetail(
                    field="vpc_config.cidr_block",
                    message="VPC CIDR must be between /16 and /24",
                    value=vpc_cidr,
                )
            )
    except ValueError:
        pass  # Already validated in input validation

    # Check secondary CIDRs don't overlap with primary
    for i, secondary in enumerate(vpc_config.secondary_cidr_blocks):
        if cidrs_overlap(vpc_cidr, secondary):
            errors.append(
                ValidationErrorDetail(
                    field=f"vpc_config.secondary_cidr_blocks[{i}]",
                    message=f"Secondary CIDR {secondary} overlaps with primary VPC CIDR {vpc_cidr}",
                    value=secondary,
                )
            )

    # Check secondary CIDRs don't overlap with each other
    for i, cidr1 in enumerate(vpc_config.secondary_cidr_blocks):
        for j, cidr2 in enumerate(vpc_config.secondary_cidr_blocks):
            if i < j and cidrs_overlap(cidr1, cidr2):
                errors.append(
                    ValidationErrorDetail(
                        field="vpc_config.secondary_cidr_blocks",
                        message=f"Secondary CIDRs overlap: {cidr1} and {cidr2}",
                    )
                )

    return errors


def validate_subnets(vpc_config: VpcConfigResolved) -> list[ValidationErrorDetail]:
    """Validate subnet configurations."""
    errors: list[ValidationErrorDetail] = []

    vpc_cidr = vpc_config.cidr_block
    all_vpc_cidrs = [vpc_cidr] + vpc_config.secondary_cidr_blocks

    # Collect all subnets for overlap checking
    all_subnets: list[tuple[str, SubnetResolved]] = []

    for i, subnet in enumerate(vpc_config.public_subnets):
        all_subnets.append((f"vpc_config.public_subnets[{i}]", subnet))

    for i, subnet in enumerate(vpc_config.private_subnets):
        all_subnets.append((f"vpc_config.private_subnets[{i}]", subnet))

    for i, subnet in enumerate(vpc_config.pod_subnets):
        all_subnets.append((f"vpc_config.pod_subnets[{i}]", subnet))

    # Validate each subnet is within a VPC CIDR
    for field, subnet in all_subnets:
        in_vpc = False
        for vpc_net in all_vpc_cidrs:
            if is_subnet_of(subnet.cidr_block, vpc_net):
                in_vpc = True
                break

        if not in_vpc:
            errors.append(
                ValidationErrorDetail(
                    field=field,
                    message=f"Subnet CIDR {subnet.cidr_block} is not within VPC CIDR range ({vpc_cidr}) or secondary CIDRs",
                    value=subnet.cidr_block,
                )
            )

    # Check for subnet overlaps
    for i, (field1, subnet1) in enumerate(all_subnets):
        for j, (field2, subnet2) in enumerate(all_subnets):
            if i < j and cidrs_overlap(subnet1.cidr_block, subnet2.cidr_block):
                errors.append(
                    ValidationErrorDetail(
                        field=field1,
                        message=f"Subnet {subnet1.cidr_block} ({subnet1.name}) overlaps with {subnet2.cidr_block} ({subnet2.name})",
                        value=subnet1.cidr_block,
                    )
                )

    # Validate subnet AZ distribution
    public_azs = {s.availability_zone for s in vpc_config.public_subnets}
    private_azs = {s.availability_zone for s in vpc_config.private_subnets}

    # Private subnets should cover same AZs as public (for NAT routing)
    if vpc_config.nat_gateway_strategy != NatGatewayStrategy.NONE:
        missing_azs = private_azs - public_azs
        if missing_azs:
            errors.append(
                ValidationErrorDetail(
                    field="vpc_config.private_subnets",
                    message=f"Private subnets exist in AZs {missing_azs} without corresponding public subnets (required for NAT gateway routing)",
                )
            )

    return errors


def validate_nat_gateway_requirements(
    vpc_config: VpcConfigResolved,
) -> list[ValidationErrorDetail]:
    """Validate NAT gateway configuration requirements."""
    errors: list[ValidationErrorDetail] = []

    strategy = vpc_config.nat_gateway_strategy

    # If NAT is enabled, we need public subnets
    if strategy != NatGatewayStrategy.NONE:
        if not vpc_config.public_subnets:
            errors.append(
                ValidationErrorDetail(
                    field="vpc_config.nat_gateway_strategy",
                    message=f"NAT gateway strategy '{strategy.value}' requires public subnets, but none are configured",
                )
            )

    # If we have private subnets but no NAT, warn about internet access
    if strategy == NatGatewayStrategy.NONE and vpc_config.private_subnets:
        # This is a warning, not an error - private subnets can work without NAT
        # if VPC endpoints are configured. We'll just note it.
        pass

    # ONE_PER_AZ requires at least one public subnet per AZ with private subnets
    if strategy == NatGatewayStrategy.ONE_PER_AZ:
        public_azs = {s.availability_zone for s in vpc_config.public_subnets}
        private_azs = {s.availability_zone for s in vpc_config.private_subnets}

        missing = private_azs - public_azs
        if missing:
            errors.append(
                ValidationErrorDetail(
                    field="vpc_config.nat_gateway_strategy",
                    message=f"ONE_PER_AZ NAT strategy requires public subnets in all AZs with private subnets. Missing public subnets in: {missing}",
                )
            )

    return errors


def validate_eks_config(
    config: CustomerConfigResolved,
) -> list[ValidationErrorDetail]:
    """Validate EKS configuration."""
    errors: list[ValidationErrorDetail] = []

    eks = config.eks_config
    vpc = config.vpc_config

    # Service CIDR must not overlap with VPC CIDR
    if cidrs_overlap(eks.service_ipv4_cidr, vpc.cidr_block):
        errors.append(
            ValidationErrorDetail(
                field="eks_config.service_ipv4_cidr",
                message=f"EKS service CIDR {eks.service_ipv4_cidr} overlaps with VPC CIDR {vpc.cidr_block}",
                value=eks.service_ipv4_cidr,
            )
        )

    # Service CIDR must not overlap with secondary CIDRs
    for secondary in vpc.secondary_cidr_blocks:
        if cidrs_overlap(eks.service_ipv4_cidr, secondary):
            errors.append(
                ValidationErrorDetail(
                    field="eks_config.service_ipv4_cidr",
                    message=f"EKS service CIDR {eks.service_ipv4_cidr} overlaps with secondary VPC CIDR {secondary}",
                    value=eks.service_ipv4_cidr,
                )
            )

    # Managed mode requires node groups
    if eks.mode == EksMode.MANAGED and not eks.node_groups:
        errors.append(
            ValidationErrorDetail(
                field="eks_config.node_groups",
                message="EKS managed mode requires at least one node group",
            )
        )

    # Auto mode should not have node groups
    if eks.mode == EksMode.AUTO and eks.node_groups:
        errors.append(
            ValidationErrorDetail(
                field="eks_config.node_groups",
                message="EKS auto mode manages compute automatically; node groups should not be specified",
            )
        )

    # Validate node group scaling
    for i, ng in enumerate(eks.node_groups):
        if ng.min_size > ng.max_size:
            errors.append(
                ValidationErrorDetail(
                    field=f"eks_config.node_groups[{i}].min_size",
                    message=f"Node group '{ng.name}' min_size ({ng.min_size}) cannot exceed max_size ({ng.max_size})",
                )
            )
        if ng.desired_size < ng.min_size or ng.desired_size > ng.max_size:
            errors.append(
                ValidationErrorDetail(
                    field=f"eks_config.node_groups[{i}].desired_size",
                    message=f"Node group '{ng.name}' desired_size ({ng.desired_size}) must be between min_size ({ng.min_size}) and max_size ({ng.max_size})",
                )
            )

    # Private endpoint access requires private subnets
    if eks.access.endpoint_private_access and not vpc.private_subnets:
        errors.append(
            ValidationErrorDetail(
                field="eks_config.access.endpoint_private_access",
                message="Private endpoint access requires private subnets",
            )
        )

    # Public-only access with no public CIDRs is insecure
    if (
        eks.access.endpoint_public_access
        and not eks.access.endpoint_private_access
        and not eks.access.public_access_cidrs
    ):
        errors.append(
            ValidationErrorDetail(
                field="eks_config.access.public_access_cidrs",
                message="Public-only endpoint access without CIDR restrictions is insecure. Specify public_access_cidrs or enable private access.",
            )
        )

    return errors


def validate_semantic_consistency(
    config: CustomerConfigResolved,
) -> list[ValidationErrorDetail]:
    """Validate semantic consistency across the configuration."""
    errors: list[ValidationErrorDetail] = []

    vpc = config.vpc_config
    eks = config.eks_config

    # Pod subnets require secondary CIDR (unless custom subnets provided)
    if vpc.pod_subnets and not vpc.secondary_cidr_blocks:
        # Check if pod subnets are within primary VPC CIDR
        for i, pod_subnet in enumerate(vpc.pod_subnets):
            if not is_subnet_of(pod_subnet.cidr_block, vpc.cidr_block):
                errors.append(
                    ValidationErrorDetail(
                        field=f"vpc_config.pod_subnets[{i}]",
                        message=f"Pod subnet {pod_subnet.cidr_block} is outside VPC CIDR and no secondary CIDR is configured",
                    )
                )

    # Private-only EKS with no NAT requires VPC endpoints for functionality
    if (
        eks.access.endpoint_private_access
        and not eks.access.endpoint_public_access
        and vpc.nat_gateway_strategy == NatGatewayStrategy.NONE
    ):
        # Check if essential endpoints are enabled
        endpoints = vpc.vpc_endpoints
        missing_endpoints = []

        if not endpoints.ecr_api:
            missing_endpoints.append("ecr_api")
        if not endpoints.ecr_dkr:
            missing_endpoints.append("ecr_dkr")
        if not endpoints.sts:
            missing_endpoints.append("sts")

        if missing_endpoints:
            errors.append(
                ValidationErrorDetail(
                    field="vpc_config.vpc_endpoints",
                    message=f"Private-only EKS cluster without NAT gateway requires VPC endpoints for: {', '.join(missing_endpoints)}. Enable these endpoints or add NAT gateway.",
                )
            )

    # Validate AZ consistency
    aws_azs = set(config.aws_config.availability_zones)
    public_azs = {s.availability_zone for s in vpc.public_subnets}
    private_azs = {s.availability_zone for s in vpc.private_subnets}

    invalid_public = public_azs - aws_azs
    if invalid_public:
        errors.append(
            ValidationErrorDetail(
                field="vpc_config.public_subnets",
                message=f"Public subnets reference invalid availability zones: {invalid_public}. Valid AZs: {aws_azs}",
            )
        )

    invalid_private = private_azs - aws_azs
    if invalid_private:
        errors.append(
            ValidationErrorDetail(
                field="vpc_config.private_subnets",
                message=f"Private subnets reference invalid availability zones: {invalid_private}. Valid AZs: {aws_azs}",
            )
        )

    return errors


# =============================================================================
# Main Validation Entry Point
# =============================================================================


def validate_resolved_config(config: CustomerConfigResolved) -> list[ValidationErrorDetail]:
    """Perform comprehensive validation on a resolved configuration.

    This is the main validation entry point called after resolution.
    Returns a list of validation errors (empty if valid).
    """
    errors: list[ValidationErrorDetail] = []

    # VPC CIDR validation
    errors.extend(validate_vpc_cidrs(config.vpc_config))

    # Subnet validation
    errors.extend(validate_subnets(config.vpc_config))

    # NAT gateway requirements
    errors.extend(validate_nat_gateway_requirements(config.vpc_config))

    # EKS configuration
    errors.extend(validate_eks_config(config))

    # Semantic consistency
    errors.extend(validate_semantic_consistency(config))

    return errors


def validate_config(
    input_config: CustomerConfigInput,
    resolved_config: CustomerConfigResolved,
) -> None:
    """Validate both input and resolved configuration.

    Raises ConfigValidationError if validation fails.
    """
    errors: list[ValidationErrorDetail] = []

    # Input validation (basic format checks)
    errors.extend(validate_input_config(input_config))

    # If input validation fails, don't proceed to resolved validation
    if errors:
        raise ConfigValidationError(errors)

    # Resolved config validation (comprehensive checks)
    errors.extend(validate_resolved_config(resolved_config))

    if errors:
        raise ConfigValidationError(errors)
