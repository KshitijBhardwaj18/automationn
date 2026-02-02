"""VPC and networking infrastructure for BYOC platform."""

import ipaddress

import pulumi
import pulumi_aws as aws
import pulumi_awsx as awsx

from api.models import (
    NatGatewayStrategy,
    PodSubnetConfig,
    SubnetConfig,
    SubnetGroupConfig,
    VpcConfig,
    VpcEndpointsConfig,
)


def _get_nat_strategy(strategy: NatGatewayStrategy) -> awsx.ec2.NatGatewayStrategy:
    """Convert NatGatewayStrategy enum to awsx enum."""
    mapping = {
        NatGatewayStrategy.NONE: awsx.ec2.NatGatewayStrategy.NONE,
        NatGatewayStrategy.SINGLE: awsx.ec2.NatGatewayStrategy.SINGLE,
        NatGatewayStrategy.ONE_PER_AZ: awsx.ec2.NatGatewayStrategy.ONE_PER_AZ,
    }
    return mapping[strategy]


def _calculate_subnet_cidrs(
    vpc_cidr: str,
    availability_zones: list[str],
    cidr_mask: int,
    offset_blocks: int = 0,
) -> list[SubnetConfig]:
    """Calculate subnet CIDRs automatically from VPC CIDR."""
    vpc_network = ipaddress.ip_network(vpc_cidr, strict=False)
    subnets = []

    for i, az in enumerate(availability_zones):
        block_index = offset_blocks + i
        subnet_offset = block_index * (2 ** (32 - cidr_mask))
        subnet_addr = ipaddress.ip_address(int(vpc_network.network_address) + subnet_offset)
        subnet_cidr = f"{subnet_addr}/{cidr_mask}"
        subnets.append(
            SubnetConfig(
                cidr_block=subnet_cidr,
                availability_zone=az,
            )
        )

    return subnets


class Networking(pulumi.ComponentResource):
    """VPC and networking infrastructure for a customer."""

    def __init__(
        self,
        name: str,
        vpc_config: VpcConfig,
        availability_zones: list[str],
        provider: aws.Provider,
        tags: dict[str, str] | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ):
        super().__init__("byoc:infrastructure:Networking", name, None, opts)

        child_opts = pulumi.ResourceOptions(parent=self, provider=provider)
        self._tags = tags or {}
        self._name = name
        self._availability_zones = availability_zones
        self._provider = provider
        self._vpc_cidr = vpc_config.cidr_block

        # Determine subnet configurations
        public_subnets = self._resolve_subnet_config(
            vpc_config.cidr_block,
            vpc_config.public_subnets,
            default_mask=24,
            offset_blocks=0,
        )

        public_block_count = len(availability_zones)
        private_subnets = self._resolve_subnet_config(
            vpc_config.cidr_block,
            vpc_config.private_subnets,
            default_mask=20,
            offset_blocks=public_block_count,
        )

        # Build subnet specs for awsx VPC
        subnet_specs = [
            awsx.ec2.SubnetSpecArgs(
                type=awsx.ec2.SubnetType.PUBLIC,
                cidr_mask=self._get_cidr_mask(public_subnets[0].cidr_block) if public_subnets else 24,
                tags={
                    "kubernetes.io/role/elb": "1",
                    "karpenter.sh/discovery": name,
                    **self._tags,
                },
            ),
            awsx.ec2.SubnetSpecArgs(
                type=awsx.ec2.SubnetType.PRIVATE,
                cidr_mask=self._get_cidr_mask(private_subnets[0].cidr_block) if private_subnets else 20,
                tags={
                    "kubernetes.io/role/internal-elb": "1",
                    "karpenter.sh/discovery": name,
                    **self._tags,
                },
            ),
        ]

        # Create VPC using awsx
        self.vpc = awsx.ec2.Vpc(
            f"{name}-vpc",
            cidr_block=vpc_config.cidr_block,
            availability_zone_names=availability_zones,
            nat_gateways=awsx.ec2.NatGatewayConfigurationArgs(
                strategy=_get_nat_strategy(vpc_config.nat_gateway_strategy),
            ),
            subnet_specs=subnet_specs,
            enable_dns_hostnames=vpc_config.enable_dns_hostnames,
            enable_dns_support=vpc_config.enable_dns_support,
            tags={
                "Name": f"{name}-vpc",
                **self._tags,
            },
            opts=child_opts,
        )

        self.vpc_id = self.vpc.vpc_id
        self.private_subnet_ids = self.vpc.private_subnet_ids
        self.public_subnet_ids = self.vpc.public_subnet_ids

        # Get route table IDs from AWSX VPC for later use
        self._private_route_table_ids = self.vpc.route_tables.apply(
            lambda rts: [rt.id for rt in rts if rt.tags.get("Name", "").find("private") != -1] if rts else []
        )

        # Add secondary CIDR blocks if specified
        self.secondary_cidr_associations = []
        for i, secondary_cidr in enumerate(vpc_config.secondary_cidr_blocks):
            association = aws.ec2.VpcIpv4CidrBlockAssociation(
                f"{name}-secondary-cidr-{i}",
                vpc_id=self.vpc_id,
                cidr_block=secondary_cidr,
                opts=child_opts,
            )
            self.secondary_cidr_associations.append(association)

        # Create pod subnets if enabled
        self.pod_subnet_ids: list[pulumi.Output[str]] = []
        if vpc_config.pod_subnets and vpc_config.pod_subnets.enabled:
            self.pod_subnet_ids = self._create_pod_subnets(
                vpc_config.pod_subnets,
                vpc_config.secondary_cidr_blocks,
                vpc_config.nat_gateway_strategy,
                child_opts,
            )

        # Create VPC endpoints
        self._create_vpc_endpoints(vpc_config.vpc_endpoints, child_opts)

        self.register_outputs(
            {
                "vpc_id": self.vpc_id,
                "private_subnet_ids": self.private_subnet_ids,
                "public_subnet_ids": self.public_subnet_ids,
                "pod_subnet_ids": self.pod_subnet_ids,
            }
        )

    def _resolve_subnet_config(
        self,
        vpc_cidr: str,
        subnet_group: SubnetGroupConfig | None,
        default_mask: int,
        offset_blocks: int,
    ) -> list[SubnetConfig]:
        """Resolve subnet configuration to actual subnet configs."""
        if subnet_group and subnet_group.custom_subnets:
            return subnet_group.custom_subnets

        cidr_mask = subnet_group.cidr_mask if subnet_group else default_mask
        return _calculate_subnet_cidrs(
            vpc_cidr,
            self._availability_zones,
            cidr_mask or default_mask,
            offset_blocks,
        )

    def _get_cidr_mask(self, cidr: str) -> int:
        """Extract CIDR mask from CIDR string."""
        return int(cidr.split("/")[1])

    def _create_pod_subnets(
        self,
        pod_config: PodSubnetConfig,
        secondary_cidrs: list[str],
        nat_strategy: NatGatewayStrategy,
        opts: pulumi.ResourceOptions,
    ) -> list[pulumi.Output[str]]:
        """Create pod subnets for custom networking with proper routing."""
        pod_subnet_ids = []

        if pod_config.custom_subnets:
            pod_subnets = pod_config.custom_subnets
        elif secondary_cidrs:
            pod_subnets = _calculate_subnet_cidrs(
                secondary_cidrs[0],
                self._availability_zones,
                pod_config.cidr_mask or 18,
                offset_blocks=0,
            )
        else:
            return []

        # Create route table for pod subnets
        pod_route_table = aws.ec2.RouteTable(
            f"{self._name}-pod-rt",
            vpc_id=self.vpc_id,
            tags={
                "Name": f"{self._name}-pod-rt",
                **self._tags,
            },
            opts=pulumi.ResourceOptions(
                parent=self,
                provider=self._provider,
            ),
        )

        # Add route to NAT gateway if NAT is enabled
        if nat_strategy != NatGatewayStrategy.NONE:
            # Get NAT gateway ID from AWSX VPC
            nat_gateway_id = self.vpc.nat_gateways.apply(
                lambda nats: nats[0].id if nats and len(nats) > 0 else None
            )

            # Create route to NAT gateway
            aws.ec2.Route(
                f"{self._name}-pod-nat-route",
                route_table_id=pod_route_table.id,
                destination_cidr_block="0.0.0.0/0",
                nat_gateway_id=nat_gateway_id,
                opts=pulumi.ResourceOptions(
                    parent=self,
                    provider=self._provider,
                    depends_on=[pod_route_table],
                ),
            )

        # Create pod subnets
        for i, subnet_config in enumerate(pod_subnets):
            az = subnet_config.availability_zone
            subnet_name = subnet_config.name or f"{self._name}-pod-{az[-1]}"

            depends_on = self.secondary_cidr_associations if self.secondary_cidr_associations else []

            subnet = aws.ec2.Subnet(
                f"{self._name}-pod-subnet-{i}",
                vpc_id=self.vpc_id,
                cidr_block=subnet_config.cidr_block,
                availability_zone=az,
                map_public_ip_on_launch=False,
                tags={
                    "Name": subnet_name,
                    "SubnetType": "pod",
                    "kubernetes.io/role/internal-elb": "1",
                    "karpenter.sh/discovery": self._name,
                    **self._tags,
                },
                opts=pulumi.ResourceOptions(
                    parent=self,
                    provider=self._provider,
                    depends_on=depends_on,
                ),
            )
            pod_subnet_ids.append(subnet.id)

            # Associate subnet with pod route table
            aws.ec2.RouteTableAssociation(
                f"{self._name}-pod-subnet-{i}-rta",
                subnet_id=subnet.id,
                route_table_id=pod_route_table.id,
                opts=pulumi.ResourceOptions(
                    parent=self,
                    provider=self._provider,
                    depends_on=[subnet, pod_route_table],
                ),
            )

        return pod_subnet_ids

    def _create_vpc_endpoints(
        self,
        endpoints_config: VpcEndpointsConfig,
        opts: pulumi.ResourceOptions,
    ) -> None:
        """Create VPC endpoints based on configuration."""
        # Create security group for interface endpoints
        if any([
            endpoints_config.ecr_api,
            endpoints_config.ecr_dkr,
            endpoints_config.sts,
            endpoints_config.logs,
            endpoints_config.ec2,
            endpoints_config.ssm,
            endpoints_config.ssmmessages,
            endpoints_config.ec2messages,
        ]):
            self.endpoint_sg = aws.ec2.SecurityGroup(
                f"{self._name}-vpc-endpoints-sg",
                vpc_id=self.vpc_id,
                description="Security group for VPC endpoints",
                ingress=[
                    aws.ec2.SecurityGroupIngressArgs(
                        protocol="tcp",
                        from_port=443,
                        to_port=443,
                        cidr_blocks=[self._vpc_cidr],
                        description="HTTPS from VPC",
                    ),
                ],
                egress=[
                    aws.ec2.SecurityGroupEgressArgs(
                        protocol="-1",
                        from_port=0,
                        to_port=0,
                        cidr_blocks=["0.0.0.0/0"],
                    ),
                ],
                tags={
                    "Name": f"{self._name}-vpc-endpoints-sg",
                    **self._tags,
                },
                opts=opts,
            )

        # S3 Gateway Endpoint - with route table association
        if endpoints_config.s3_gateway:
            # Get all route table IDs
            route_table_ids = self.vpc.route_tables.apply(
                lambda rts: [rt.id for rt in rts] if rts else []
            )

            aws.ec2.VpcEndpoint(
                f"{self._name}-s3-endpoint",
                vpc_id=self.vpc_id,
                service_name=f"com.amazonaws.{self._get_region()}.s3",
                vpc_endpoint_type="Gateway",
                route_table_ids=route_table_ids,
                tags={
                    "Name": f"{self._name}-s3-endpoint",
                    **self._tags,
                },
                opts=opts,
            )

        # Interface endpoints
        interface_endpoints = {
            "ecr.api": endpoints_config.ecr_api,
            "ecr.dkr": endpoints_config.ecr_dkr,
            "sts": endpoints_config.sts,
            "logs": endpoints_config.logs,
            "ec2": endpoints_config.ec2,
            "ssm": endpoints_config.ssm,
            "ssmmessages": endpoints_config.ssmmessages,
            "ec2messages": endpoints_config.ec2messages,
        }

        for service_suffix, enabled in interface_endpoints.items():
            if enabled:
                service_name = f"com.amazonaws.{self._get_region()}.{service_suffix}"
                endpoint_name = service_suffix.replace(".", "-")

                aws.ec2.VpcEndpoint(
                    f"{self._name}-{endpoint_name}-endpoint",
                    vpc_id=self.vpc_id,
                    service_name=service_name,
                    vpc_endpoint_type="Interface",
                    subnet_ids=self.private_subnet_ids,
                    security_group_ids=[self.endpoint_sg.id],
                    private_dns_enabled=True,
                    tags={
                        "Name": f"{self._name}-{endpoint_name}-endpoint",
                        **self._tags,
                    },
                    opts=opts,
                )

    def _get_region(self) -> str:
        """Get the AWS region from availability zones."""
        if self._availability_zones:
            return self._availability_zones[0][:-1]
        return "us-east-1"