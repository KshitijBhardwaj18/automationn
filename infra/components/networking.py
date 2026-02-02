"""VPC and networking infrastructure for BYOC platform.

This module creates VPC infrastructure with subnets configured from the resolved
customer configuration. Subnets are created manually (not auto-calculated) to ensure
exact CIDRs, names, and tags from the config are used.
"""

import pulumi
import pulumi_aws as aws

from api.models import (
    NatGatewayStrategy,
    SubnetResolved,
    VpcConfigResolved,
    VpcEndpointsResolved,
)


class Networking(pulumi.ComponentResource):
    """VPC and networking infrastructure for a customer.

    Creates:
    - VPC with specified CIDR
    - Internet Gateway
    - Public subnets (from resolved config)
    - Private subnets (from resolved config)
    - Pod subnets (if configured, from resolved config)
    - NAT Gateway(s) based on strategy
    - Route tables with appropriate routes
    - VPC Endpoints (gateway and interface types)
    """

    def __init__(
        self,
        name: str,
        vpc_config: VpcConfigResolved,
        availability_zones: list[str],
        provider: aws.Provider,
        tags: dict[str, str] | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ):
        super().__init__("byoc:infrastructure:Networking", name, None, opts)

        self._tags = tags or {}
        self._name = name
        self._availability_zones = availability_zones
        self._provider = provider
        self._vpc_cidr = vpc_config.cidr_block
        # Store subnet configs for AZ lookup (resource properties are Outputs)
        self._public_subnet_configs = vpc_config.public_subnets
        self._private_subnet_configs = vpc_config.private_subnets

        child_opts = pulumi.ResourceOptions(parent=self, provider=provider)

        # 1. Create VPC
        self.vpc = aws.ec2.Vpc(
            f"{name}-vpc",
            cidr_block=vpc_config.cidr_block,
            enable_dns_hostnames=vpc_config.enable_dns_hostnames,
            enable_dns_support=vpc_config.enable_dns_support,
            tags={
                "Name": f"{name}-vpc",
                **self._tags,
                **vpc_config.tags,
            },
            opts=child_opts,
        )
        self.vpc_id = self.vpc.id

        # 2. Add secondary CIDR blocks if specified
        self.secondary_cidr_associations: list[aws.ec2.VpcIpv4CidrBlockAssociation] = []
        for i, secondary_cidr in enumerate(vpc_config.secondary_cidr_blocks):
            association = aws.ec2.VpcIpv4CidrBlockAssociation(
                f"{name}-secondary-cidr-{i}",
                vpc_id=self.vpc_id,
                cidr_block=secondary_cidr,
                opts=child_opts,
            )
            self.secondary_cidr_associations.append(association)

        # 3. Create Internet Gateway
        self.igw = aws.ec2.InternetGateway(
            f"{name}-igw",
            vpc_id=self.vpc_id,
            tags={
                "Name": f"{name}-igw",
                **self._tags,
            },
            opts=child_opts,
        )

        # 4. Create public subnets using resolved config
        self.public_subnets: list[aws.ec2.Subnet] = []
        for i, subnet_config in enumerate(vpc_config.public_subnets):
            subnet = aws.ec2.Subnet(
                f"{name}-public-subnet-{i}",
                vpc_id=self.vpc_id,
                cidr_block=subnet_config.cidr_block,
                availability_zone=subnet_config.availability_zone,
                map_public_ip_on_launch=True,
                tags={
                    "Name": subnet_config.name,
                    "SubnetType": "public",
                    "kubernetes.io/role/elb": "1",
                    "karpenter.sh/discovery": name,
                    **self._tags,
                    **subnet_config.tags,
                },
                opts=child_opts,
            )
            self.public_subnets.append(subnet)

        self.public_subnet_ids = pulumi.Output.all(
            *[s.id for s in self.public_subnets]
        ).apply(lambda ids: list(ids))

        # 5. Create public route table with IGW route
        self.public_route_table = aws.ec2.RouteTable(
            f"{name}-public-rt",
            vpc_id=self.vpc_id,
            tags={
                "Name": f"{name}-public-rt",
                **self._tags,
            },
            opts=child_opts,
        )

        # Add route to Internet Gateway
        aws.ec2.Route(
            f"{name}-public-igw-route",
            route_table_id=self.public_route_table.id,
            destination_cidr_block="0.0.0.0/0",
            gateway_id=self.igw.id,
            opts=pulumi.ResourceOptions(
                parent=self,
                provider=provider,
                depends_on=[self.public_route_table, self.igw],
            ),
        )

        # Associate public subnets with public route table
        for i, subnet in enumerate(self.public_subnets):
            aws.ec2.RouteTableAssociation(
                f"{name}-public-rta-{i}",
                subnet_id=subnet.id,
                route_table_id=self.public_route_table.id,
                opts=pulumi.ResourceOptions(
                    parent=self,
                    provider=provider,
                    depends_on=[subnet, self.public_route_table],
                ),
            )

        # 6. Create NAT Gateway(s) based on strategy
        self.nat_gateways: list[aws.ec2.NatGateway] = []
        self.nat_eips: list[aws.ec2.Eip] = []
        self._create_nat_gateways(vpc_config.nat_gateway_strategy, child_opts)

        # 7. Create private subnets using resolved config
        self.private_subnets: list[aws.ec2.Subnet] = []
        for i, subnet_config in enumerate(vpc_config.private_subnets):
            subnet = aws.ec2.Subnet(
                f"{name}-private-subnet-{i}",
                vpc_id=self.vpc_id,
                cidr_block=subnet_config.cidr_block,
                availability_zone=subnet_config.availability_zone,
                map_public_ip_on_launch=False,
                tags={
                    "Name": subnet_config.name,
                    "SubnetType": "private",
                    "kubernetes.io/role/internal-elb": "1",
                    "karpenter.sh/discovery": name,
                    **self._tags,
                    **subnet_config.tags,
                },
                opts=child_opts,
            )
            self.private_subnets.append(subnet)

        self.private_subnet_ids = pulumi.Output.all(
            *[s.id for s in self.private_subnets]
        ).apply(lambda ids: list(ids))

        # 8. Create private route table(s) with NAT route
        self._create_private_routing(vpc_config.nat_gateway_strategy, child_opts)

        # 9. Create pod subnets if configured
        self.pod_subnets: list[aws.ec2.Subnet] = []
        self.pod_subnet_ids: pulumi.Output[list[str]] = pulumi.Output.from_input([])
        if vpc_config.pod_subnets:
            self._create_pod_subnets(
                vpc_config.pod_subnets,
                vpc_config.nat_gateway_strategy,
                child_opts,
            )

        # 10. Create VPC endpoints
        self._create_vpc_endpoints(vpc_config.vpc_endpoints, child_opts)

        # Collect all route tables for gateway endpoints
        self._all_route_tables: list[aws.ec2.RouteTable] = [self.public_route_table]
        self._all_route_tables.extend(self.private_route_tables)
        if hasattr(self, "pod_route_table"):
            self._all_route_tables.append(self.pod_route_table)

        self.register_outputs(
            {
                "vpc_id": self.vpc_id,
                "public_subnet_ids": self.public_subnet_ids,
                "private_subnet_ids": self.private_subnet_ids,
                "pod_subnet_ids": self.pod_subnet_ids,
            }
        )

    def _create_nat_gateways(
        self,
        strategy: NatGatewayStrategy,
        opts: pulumi.ResourceOptions,
    ) -> None:
        """Create NAT gateways based on strategy."""
        if strategy == NatGatewayStrategy.NONE:
            return

        if strategy == NatGatewayStrategy.SINGLE:
            # Single NAT in first public subnet
            eip = aws.ec2.Eip(
                f"{self._name}-nat-eip",
                domain="vpc",
                tags={
                    "Name": f"{self._name}-nat-eip",
                    **self._tags,
                },
                opts=opts,
            )
            self.nat_eips.append(eip)

            nat = aws.ec2.NatGateway(
                f"{self._name}-nat",
                subnet_id=self.public_subnets[0].id,
                allocation_id=eip.id,
                tags={
                    "Name": f"{self._name}-nat",
                    **self._tags,
                },
                opts=pulumi.ResourceOptions(
                    parent=self,
                    provider=self._provider,
                    depends_on=[self.igw, eip, self.public_subnets[0]],
                ),
            )
            self.nat_gateways.append(nat)

        elif strategy == NatGatewayStrategy.ONE_PER_AZ:
            # One NAT per AZ for high availability
            for i, subnet in enumerate(self.public_subnets):
                eip = aws.ec2.Eip(
                    f"{self._name}-nat-eip-{i}",
                    domain="vpc",
                    tags={
                        "Name": f"{self._name}-nat-eip-{i}",
                        **self._tags,
                    },
                    opts=opts,
                )
                self.nat_eips.append(eip)

                nat = aws.ec2.NatGateway(
                    f"{self._name}-nat-{i}",
                    subnet_id=subnet.id,
                    allocation_id=eip.id,
                    tags={
                        "Name": f"{self._name}-nat-{i}",
                        **self._tags,
                    },
                    opts=pulumi.ResourceOptions(
                        parent=self,
                        provider=self._provider,
                        depends_on=[self.igw, eip, subnet],
                    ),
                )
                self.nat_gateways.append(nat)

    def _create_private_routing(
        self,
        strategy: NatGatewayStrategy,
        opts: pulumi.ResourceOptions,
    ) -> None:
        """Create private route tables with NAT routes."""
        self.private_route_tables: list[aws.ec2.RouteTable] = []

        if strategy == NatGatewayStrategy.NONE:
            # Single route table without NAT route
            rt = aws.ec2.RouteTable(
                f"{self._name}-private-rt",
                vpc_id=self.vpc_id,
                tags={
                    "Name": f"{self._name}-private-rt",
                    **self._tags,
                },
                opts=opts,
            )
            self.private_route_tables.append(rt)

            # Associate all private subnets with this route table
            for i, subnet in enumerate(self.private_subnets):
                aws.ec2.RouteTableAssociation(
                    f"{self._name}-private-rta-{i}",
                    subnet_id=subnet.id,
                    route_table_id=rt.id,
                    opts=pulumi.ResourceOptions(
                        parent=self,
                        provider=self._provider,
                        depends_on=[subnet, rt],
                    ),
                )

        elif strategy == NatGatewayStrategy.SINGLE:
            # Single route table with NAT route
            rt = aws.ec2.RouteTable(
                f"{self._name}-private-rt",
                vpc_id=self.vpc_id,
                tags={
                    "Name": f"{self._name}-private-rt",
                    **self._tags,
                },
                opts=opts,
            )
            self.private_route_tables.append(rt)

            # Add NAT route
            aws.ec2.Route(
                f"{self._name}-private-nat-route",
                route_table_id=rt.id,
                destination_cidr_block="0.0.0.0/0",
                nat_gateway_id=self.nat_gateways[0].id,
                opts=pulumi.ResourceOptions(
                    parent=self,
                    provider=self._provider,
                    depends_on=[rt, self.nat_gateways[0]],
                ),
            )

            # Associate all private subnets with this route table
            for i, subnet in enumerate(self.private_subnets):
                aws.ec2.RouteTableAssociation(
                    f"{self._name}-private-rta-{i}",
                    subnet_id=subnet.id,
                    route_table_id=rt.id,
                    opts=pulumi.ResourceOptions(
                        parent=self,
                        provider=self._provider,
                        depends_on=[subnet, rt],
                    ),
                )

        elif strategy == NatGatewayStrategy.ONE_PER_AZ:
            # One route table per AZ, each with its own NAT
            # Build a map of AZ -> (NAT gateway, route table)
            # Use vpc_config to get AZ strings (resource properties are Outputs)
            az_to_nat: dict[str, aws.ec2.NatGateway] = {}
            az_to_rt: dict[str, aws.ec2.RouteTable] = {}

            # NAT gateways are created in order of public subnets
            for i, (subnet_config, nat) in enumerate(
                zip(self._public_subnet_configs, self.nat_gateways)
            ):
                az = subnet_config.availability_zone
                az_to_nat[az] = nat

                rt = aws.ec2.RouteTable(
                    f"{self._name}-private-rt-{i}",
                    vpc_id=self.vpc_id,
                    tags={
                        "Name": f"{self._name}-private-rt-{az[-1]}",
                        **self._tags,
                    },
                    opts=opts,
                )
                self.private_route_tables.append(rt)
                az_to_rt[az] = rt

                # Add NAT route for this AZ
                aws.ec2.Route(
                    f"{self._name}-private-nat-route-{i}",
                    route_table_id=rt.id,
                    destination_cidr_block="0.0.0.0/0",
                    nat_gateway_id=nat.id,
                    opts=pulumi.ResourceOptions(
                        parent=self,
                        provider=self._provider,
                        depends_on=[rt, nat],
                    ),
                )

            # Associate each private subnet with its AZ's route table
            for i, (subnet_config, subnet) in enumerate(
                zip(self._private_subnet_configs, self.private_subnets)
            ):
                subnet_az = subnet_config.availability_zone
                rt = az_to_rt.get(subnet_az)
                if rt:
                    aws.ec2.RouteTableAssociation(
                        f"{self._name}-private-rta-{i}",
                        subnet_id=subnet.id,
                        route_table_id=rt.id,
                        opts=pulumi.ResourceOptions(
                            parent=self,
                            provider=self._provider,
                            depends_on=[subnet, rt],
                        ),
                    )

    def _create_pod_subnets(
        self,
        pod_subnets: list[SubnetResolved],
        nat_strategy: NatGatewayStrategy,
        opts: pulumi.ResourceOptions,
    ) -> None:
        """Create pod subnets for custom networking with proper routing."""
        # Create route table for pod subnets
        self.pod_route_table = aws.ec2.RouteTable(
            f"{self._name}-pod-rt",
            vpc_id=self.vpc_id,
            tags={
                "Name": f"{self._name}-pod-rt",
                **self._tags,
            },
            opts=opts,
        )

        # Add route to NAT gateway if NAT is enabled (use first NAT for simplicity)
        if nat_strategy != NatGatewayStrategy.NONE and self.nat_gateways:
            aws.ec2.Route(
                f"{self._name}-pod-nat-route",
                route_table_id=self.pod_route_table.id,
                destination_cidr_block="0.0.0.0/0",
                nat_gateway_id=self.nat_gateways[0].id,
                opts=pulumi.ResourceOptions(
                    parent=self,
                    provider=self._provider,
                    depends_on=[self.pod_route_table, self.nat_gateways[0]],
                ),
            )

        # Create pod subnets using resolved config
        depends_on = self.secondary_cidr_associations if self.secondary_cidr_associations else []

        for i, subnet_config in enumerate(pod_subnets):
            subnet = aws.ec2.Subnet(
                f"{self._name}-pod-subnet-{i}",
                vpc_id=self.vpc_id,
                cidr_block=subnet_config.cidr_block,
                availability_zone=subnet_config.availability_zone,
                map_public_ip_on_launch=False,
                tags={
                    "Name": subnet_config.name,
                    "SubnetType": "pod",
                    "kubernetes.io/role/internal-elb": "1",
                    "karpenter.sh/discovery": self._name,
                    **self._tags,
                    **subnet_config.tags,
                },
                opts=pulumi.ResourceOptions(
                    parent=self,
                    provider=self._provider,
                    depends_on=depends_on,
                ),
            )
            self.pod_subnets.append(subnet)

            # Associate subnet with pod route table
            aws.ec2.RouteTableAssociation(
                f"{self._name}-pod-rta-{i}",
                subnet_id=subnet.id,
                route_table_id=self.pod_route_table.id,
                opts=pulumi.ResourceOptions(
                    parent=self,
                    provider=self._provider,
                    depends_on=[subnet, self.pod_route_table],
                ),
            )

        self.pod_subnet_ids = pulumi.Output.all(
            *[s.id for s in self.pod_subnets]
        ).apply(lambda ids: list(ids))

    def _create_vpc_endpoints(
        self,
        endpoints_config: VpcEndpointsResolved,
        opts: pulumi.ResourceOptions,
    ) -> None:
        """Create VPC endpoints based on configuration."""
        # Determine if we need a security group for interface endpoints
        has_interface_endpoints = any(
            [
                endpoints_config.ecr_api,
                endpoints_config.ecr_dkr,
                endpoints_config.sts,
                endpoints_config.logs,
                endpoints_config.ec2,
                endpoints_config.ssm,
                endpoints_config.ssmmessages,
                endpoints_config.ec2messages,
                endpoints_config.elasticloadbalancing,
                endpoints_config.autoscaling,
            ]
        )

        if has_interface_endpoints:
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

        # Collect all route table IDs for gateway endpoints
        all_route_table_ids = pulumi.Output.all(
            self.public_route_table.id,
            *[rt.id for rt in self.private_route_tables],
            *([self.pod_route_table.id] if hasattr(self, "pod_route_table") else []),
        ).apply(lambda ids: list(ids))

        # S3 Gateway Endpoint
        if endpoints_config.s3:
            aws.ec2.VpcEndpoint(
                f"{self._name}-s3-endpoint",
                vpc_id=self.vpc_id,
                service_name=f"com.amazonaws.{self._get_region()}.s3",
                vpc_endpoint_type="Gateway",
                route_table_ids=all_route_table_ids,
                tags={
                    "Name": f"{self._name}-s3-endpoint",
                    **self._tags,
                },
                opts=opts,
            )

        # DynamoDB Gateway Endpoint
        if endpoints_config.dynamodb:
            aws.ec2.VpcEndpoint(
                f"{self._name}-dynamodb-endpoint",
                vpc_id=self.vpc_id,
                service_name=f"com.amazonaws.{self._get_region()}.dynamodb",
                vpc_endpoint_type="Gateway",
                route_table_ids=all_route_table_ids,
                tags={
                    "Name": f"{self._name}-dynamodb-endpoint",
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
            "elasticloadbalancing": endpoints_config.elasticloadbalancing,
            "autoscaling": endpoints_config.autoscaling,
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
            # Extract region by removing the AZ suffix (e.g., "us-east-1a" -> "us-east-1")
            return self._availability_zones[0][:-1]
        return "us-east-1"
