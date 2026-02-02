"""EKS cluster infrastructure component."""

from typing import Sequence

import pulumi
import pulumi_aws as aws
import pulumi_tls as tls

from api.models import (
    EksAccessResolved,
    EksConfigResolved,
    EksMode,
    NodeGroupResolved,
)


class EksCluster(pulumi.ComponentResource):
    """EKS cluster with configurable endpoint access and networking."""

    def __init__(
        self,
        name: str,
        vpc_id: pulumi.Output[str],
        vpc_cidr: str,
        private_subnet_ids: pulumi.Output[Sequence[str]],
        public_subnet_ids: pulumi.Output[Sequence[str]],
        cluster_role_arn: pulumi.Output[str],
        node_role_arn: pulumi.Output[str],
        eks_config: EksConfigResolved,
        provider: aws.Provider,
        tags: dict[str, str] | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ):
        super().__init__("byoc:infrastructure:EksCluster", name, None, opts)

        child_opts = pulumi.ResourceOptions(parent=self, provider=provider)
        self._tags = tags or {}
        self._name = name
        self._provider = provider
        self._vpc_cidr = vpc_cidr

        # Create cluster security group with proper rules
        self.cluster_sg = self._create_cluster_security_group(vpc_id, child_opts)

        # Determine which subnets to use based on endpoint access
        access = eks_config.access
        if access.endpoint_private_access and not access.endpoint_public_access:
            # Private only - use private subnets
            subnet_ids = private_subnet_ids
        else:
            # Public or both - use all subnets
            subnet_ids = pulumi.Output.all(private_subnet_ids, public_subnet_ids).apply(
                lambda args: list(args[0]) + list(args[1])
            )

        # Build VPC config
        vpc_config_args = self._build_vpc_config(
            subnet_ids=subnet_ids,
            security_group_ids=[self.cluster_sg.id],
            access_config=access,
        )

        # Build cluster arguments
        cluster_args: dict = {
            "role_arn": cluster_role_arn,
            "version": eks_config.version,
            "vpc_config": vpc_config_args,
            "tags": {
                "Name": f"{name}-eks-cluster",
                **self._tags,
            },
        }

        # Add access config
        cluster_args["access_config"] = aws.eks.ClusterAccessConfigArgs(
            authentication_mode=access.authentication_mode,
            bootstrap_cluster_creator_admin_permissions=access.bootstrap_cluster_creator_admin_permissions,
        )

        # Add kubernetes network config (service CIDR)
        k8s_network_config_args: dict = {
            "service_ipv4_cidr": eks_config.service_ipv4_cidr,
        }

        # Add logging if enabled
        if eks_config.logging_enabled and eks_config.logging_types:
            cluster_args["enabled_cluster_log_types"] = eks_config.logging_types

        # Add encryption if enabled
        if eks_config.encryption_enabled:
            kms_key_arn = eks_config.encryption_kms_key_arn
            if kms_key_arn:
                cluster_args["encryption_config"] = aws.eks.ClusterEncryptionConfigArgs(
                    provider=aws.eks.ClusterEncryptionConfigProviderArgs(
                        key_arn=kms_key_arn,
                    ),
                    resources=["secrets"],
                )
            else:
                # Create KMS key if not provided
                self.kms_key = aws.kms.Key(
                    f"{name}-eks-secrets-key",
                    description=f"KMS key for EKS secrets encryption - {name}",
                    enable_key_rotation=True,
                    tags={
                        "Name": f"{name}-eks-secrets-key",
                        **self._tags,
                    },
                    opts=child_opts,
                )
                cluster_args["encryption_config"] = aws.eks.ClusterEncryptionConfigArgs(
                    provider=aws.eks.ClusterEncryptionConfigProviderArgs(
                        key_arn=self.kms_key.arn,
                    ),
                    resources=["secrets"],
                )

        # Add zonal shift if enabled
        if eks_config.zonal_shift_enabled:
            cluster_args["zonal_shift_config"] = aws.eks.ClusterZonalShiftConfigArgs(
                enabled=True,
            )

        # Configure based on mode
        if eks_config.mode == EksMode.AUTO:
            cluster_args["bootstrap_self_managed_addons"] = False
            cluster_args["compute_config"] = aws.eks.ClusterComputeConfigArgs(
                enabled=True,
                node_pools=["general-purpose"],
                node_role_arn=node_role_arn,
            )
            cluster_args["storage_config"] = aws.eks.ClusterStorageConfigArgs(
                block_storage=aws.eks.ClusterStorageConfigBlockStorageArgs(
                    enabled=True,
                ),
            )
            k8s_network_config_args["elastic_load_balancing"] = (
                aws.eks.ClusterKubernetesNetworkConfigElasticLoadBalancingArgs(
                    enabled=True,
                )
            )

        cluster_args["kubernetes_network_config"] = aws.eks.ClusterKubernetesNetworkConfigArgs(
            **k8s_network_config_args
        )

        # Create the cluster
        self.cluster = aws.eks.Cluster(
            f"{name}-eks-cluster",
            **cluster_args,
            opts=child_opts,
        )

        # Create OIDC provider for IRSA
        self.oidc_provider = self._create_oidc_provider(child_opts)

        # Create addons and node groups for managed mode
        if eks_config.mode == EksMode.MANAGED:
            self._create_addons(eks_config, child_opts)

            for ng_config in eks_config.node_groups:
                self._create_node_group(
                    node_role_arn=node_role_arn,
                    private_subnet_ids=private_subnet_ids,
                    node_group_config=ng_config,
                    child_opts=child_opts,
                )

        # Export cluster properties
        self.cluster_name = self.cluster.name
        self.cluster_endpoint = self.cluster.endpoint
        self.cluster_ca_data = self.cluster.certificate_authority.data
        self.cluster_arn = self.cluster.arn
        self.cluster_security_group_id = self.cluster_sg.id
        self.oidc_provider_arn = self.oidc_provider.arn
        self.oidc_provider_url = self.oidc_provider.url

        self.register_outputs(
            {
                "cluster_name": self.cluster_name,
                "cluster_endpoint": self.cluster_endpoint,
                "cluster_arn": self.cluster_arn,
                "eks_mode": eks_config.mode.value,
                "oidc_provider_arn": self.oidc_provider_arn,
            }
        )

    def _create_cluster_security_group(
        self,
        vpc_id: pulumi.Output[str],
        opts: pulumi.ResourceOptions,
    ) -> aws.ec2.SecurityGroup:
        """Create security group for EKS cluster with proper rules."""
        sg = aws.ec2.SecurityGroup(
            f"{self._name}-eks-cluster-sg",
            vpc_id=vpc_id,
            description="Security group for EKS cluster control plane",
            tags={
                "Name": f"{self._name}-eks-cluster-sg",
                **self._tags,
            },
            opts=opts,
        )

        # Allow all traffic from self (cluster-to-cluster communication)
        aws.ec2.SecurityGroupRule(
            f"{self._name}-eks-sg-self-ingress",
            type="ingress",
            security_group_id=sg.id,
            source_security_group_id=sg.id,
            protocol="-1",
            from_port=0,
            to_port=0,
            description="Allow all traffic from self",
            opts=opts,
        )

        # Allow HTTPS from VPC CIDR (for kubectl, API access)
        aws.ec2.SecurityGroupRule(
            f"{self._name}-eks-sg-https-ingress",
            type="ingress",
            security_group_id=sg.id,
            cidr_blocks=[self._vpc_cidr],
            protocol="tcp",
            from_port=443,
            to_port=443,
            description="Allow HTTPS from VPC",
            opts=opts,
        )

        # Allow all outbound traffic
        aws.ec2.SecurityGroupRule(
            f"{self._name}-eks-sg-egress",
            type="egress",
            security_group_id=sg.id,
            cidr_blocks=["0.0.0.0/0"],
            protocol="-1",
            from_port=0,
            to_port=0,
            description="Allow all outbound traffic",
            opts=opts,
        )

        return sg

    def _create_oidc_provider(
        self,
        opts: pulumi.ResourceOptions,
    ) -> aws.iam.OpenIdConnectProvider:
        """Create OIDC provider for IAM Roles for Service Accounts (IRSA)."""
        oidc_issuer = self.cluster.identities[0].oidcs[0].issuer

        # Use pulumi_tls to get the certificate (not aws.tls which doesn't exist)
        tls_cert = oidc_issuer.apply(lambda url: tls.get_certificate(url=url))
        thumbprint = tls_cert.apply(lambda cert: cert.certificates[0].sha1_fingerprint)

        return aws.iam.OpenIdConnectProvider(
            f"{self._name}-oidc-provider",
            url=oidc_issuer,
            client_id_lists=["sts.amazonaws.com"],
            thumbprint_lists=[thumbprint],
            tags={
                "Name": f"{self._name}-oidc-provider",
                **self._tags,
            },
            opts=pulumi.ResourceOptions(
                parent=self,
                provider=self._provider,
                depends_on=[self.cluster],
            ),
        )

    def _create_addons(
        self,
        eks_config: EksConfigResolved,
        opts: pulumi.ResourceOptions,
    ) -> None:
        """Create EKS addons for managed mode."""
        addons = eks_config.addons

        # VPC CNI addon
        if addons.vpc_cni.enabled:
            self.vpc_cni_addon = aws.eks.Addon(
                f"{self._name}-vpc-cni",
                cluster_name=self.cluster.name,
                addon_name="vpc-cni",
                resolve_conflicts_on_create=addons.vpc_cni.resolve_conflicts_on_create,
                resolve_conflicts_on_update=addons.vpc_cni.resolve_conflicts_on_update,
                tags={"Name": f"{self._name}-vpc-cni", **self._tags},
                opts=pulumi.ResourceOptions(
                    parent=self,
                    provider=self._provider,
                    depends_on=[self.cluster],
                ),
            )

        # kube-proxy addon
        if addons.kube_proxy.enabled:
            self.kube_proxy_addon = aws.eks.Addon(
                f"{self._name}-kube-proxy",
                cluster_name=self.cluster.name,
                addon_name="kube-proxy",
                resolve_conflicts_on_create=addons.kube_proxy.resolve_conflicts_on_create,
                resolve_conflicts_on_update=addons.kube_proxy.resolve_conflicts_on_update,
                tags={"Name": f"{self._name}-kube-proxy", **self._tags},
                opts=pulumi.ResourceOptions(
                    parent=self,
                    provider=self._provider,
                    depends_on=[self.cluster],
                ),
            )

        # CoreDNS addon
        if addons.coredns.enabled:
            depends = [self.cluster]
            if addons.vpc_cni.enabled:
                depends.append(self.vpc_cni_addon)

            self.coredns_addon = aws.eks.Addon(
                f"{self._name}-coredns",
                cluster_name=self.cluster.name,
                addon_name="coredns",
                resolve_conflicts_on_create=addons.coredns.resolve_conflicts_on_create,
                resolve_conflicts_on_update=addons.coredns.resolve_conflicts_on_update,
                tags={"Name": f"{self._name}-coredns", **self._tags},
                opts=pulumi.ResourceOptions(
                    parent=self,
                    provider=self._provider,
                    depends_on=depends,
                ),
            )

        # EBS CSI Driver addon
        if addons.ebs_csi_driver.enabled:
            self.ebs_csi_addon = aws.eks.Addon(
                f"{self._name}-ebs-csi",
                cluster_name=self.cluster.name,
                addon_name="aws-ebs-csi-driver",
                resolve_conflicts_on_create=addons.ebs_csi_driver.resolve_conflicts_on_create,
                resolve_conflicts_on_update=addons.ebs_csi_driver.resolve_conflicts_on_update,
                tags={"Name": f"{self._name}-ebs-csi", **self._tags},
                opts=pulumi.ResourceOptions(
                    parent=self,
                    provider=self._provider,
                    depends_on=[self.cluster],
                ),
            )

        # Pod Identity Agent addon
        if addons.pod_identity_agent.enabled:
            self.pod_identity_addon = aws.eks.Addon(
                f"{self._name}-pod-identity",
                cluster_name=self.cluster.name,
                addon_name="eks-pod-identity-agent",
                resolve_conflicts_on_create=addons.pod_identity_agent.resolve_conflicts_on_create,
                resolve_conflicts_on_update=addons.pod_identity_agent.resolve_conflicts_on_update,
                tags={"Name": f"{self._name}-pod-identity", **self._tags},
                opts=pulumi.ResourceOptions(
                    parent=self,
                    provider=self._provider,
                    depends_on=[self.cluster],
                ),
            )

    def _create_node_group(
        self,
        node_role_arn: pulumi.Output[str],
        private_subnet_ids: pulumi.Output[Sequence[str]],
        node_group_config: NodeGroupResolved,
        child_opts: pulumi.ResourceOptions,
    ) -> aws.eks.NodeGroup:
        """Create managed node group with launch template."""
        ng_name = node_group_config.name

        # Create launch template for better control
        launch_template = aws.ec2.LaunchTemplate(
            f"{self._name}-{ng_name}-launch-template",
            name_prefix=f"{self._name}-{ng_name}-",
            metadata_options=aws.ec2.LaunchTemplateMetadataOptionsArgs(
                http_endpoint="enabled",
                http_tokens="required",  # Require IMDSv2
                http_put_response_hop_limit=2,
            ),
            block_device_mappings=[
                aws.ec2.LaunchTemplateBlockDeviceMappingArgs(
                    device_name="/dev/xvda",
                    ebs=aws.ec2.LaunchTemplateBlockDeviceMappingEbsArgs(
                        volume_size=node_group_config.disk_size,
                        volume_type="gp3",
                        encrypted=True,
                        delete_on_termination=True,
                    ),
                ),
            ],
            tag_specifications=[
                aws.ec2.LaunchTemplateTagSpecificationArgs(
                    resource_type="instance",
                    tags={"Name": f"{self._name}-{ng_name}-node", **self._tags},
                ),
                aws.ec2.LaunchTemplateTagSpecificationArgs(
                    resource_type="volume",
                    tags={"Name": f"{self._name}-{ng_name}-volume", **self._tags},
                ),
            ],
            tags={"Name": f"{self._name}-{ng_name}-launch-template", **self._tags},
            opts=pulumi.ResourceOptions(parent=self, provider=self._provider),
        )

        # Convert taints to proper format
        node_taints = None
        if node_group_config.taints:
            node_taints = [
                aws.eks.NodeGroupTaintArgs(
                    key=t["key"],
                    value=t.get("value", ""),
                    effect=t["effect"],
                )
                for t in node_group_config.taints
            ]

        # Determine dependencies
        depends = [self.cluster]
        if hasattr(self, "vpc_cni_addon"):
            depends.append(self.vpc_cni_addon)

        return aws.eks.NodeGroup(
            f"{self._name}-{ng_name}-node-group",
            cluster_name=self.cluster.name,
            node_group_name=ng_name,
            node_role_arn=node_role_arn,
            subnet_ids=private_subnet_ids,
            launch_template=aws.eks.NodeGroupLaunchTemplateArgs(
                id=launch_template.id,
                version=launch_template.latest_version,
            ),
            instance_types=node_group_config.instance_types,
            capacity_type=node_group_config.capacity_type.value,
            ami_type=node_group_config.ami_type.value,
            scaling_config=aws.eks.NodeGroupScalingConfigArgs(
                desired_size=node_group_config.desired_size,
                min_size=node_group_config.min_size,
                max_size=node_group_config.max_size,
            ),
            update_config=aws.eks.NodeGroupUpdateConfigArgs(
                max_unavailable_percentage=25,
            ),
            labels=node_group_config.labels if node_group_config.labels else None,
            taints=node_taints,
            tags={"Name": f"{self._name}-{ng_name}", **self._tags},
            opts=pulumi.ResourceOptions(
                parent=self,
                provider=self._provider,
                depends_on=depends,
            ),
        )

    def _build_vpc_config(
        self,
        subnet_ids: pulumi.Output[Sequence[str]],
        security_group_ids: list[pulumi.Output[str]],
        access_config: EksAccessResolved,
    ) -> aws.eks.ClusterVpcConfigArgs:
        """Build VPC configuration for the cluster."""
        vpc_config_args: dict = {
            "subnet_ids": subnet_ids,
            "security_group_ids": security_group_ids,
            "endpoint_private_access": access_config.endpoint_private_access,
            "endpoint_public_access": access_config.endpoint_public_access,
        }

        if access_config.endpoint_public_access and access_config.public_access_cidrs:
            vpc_config_args["public_access_cidrs"] = access_config.public_access_cidrs

        return aws.eks.ClusterVpcConfigArgs(**vpc_config_args)
