"""Pulumi Deployments API client for triggering deployments."""

import json
from typing import Any

import httpx

from api.models import CustomerOnboardRequest, EksMode

PULUMI_API_BASE = "https://api.pulumi.com"


class PulumiDeploymentsClient:
    """Client for interacting with Pulumi Deployments API."""

    def __init__(
        self,
        organization: str,
        access_token: str,
        aws_access_key_id: str,
        aws_secret_access_key: str,
        github_token: str | None = None,
    ):
        """Initialize the Pulumi Deployments client."""
        self.organization = organization
        self.access_token = access_token
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key = aws_secret_access_key
        self.github_token = github_token

        self.headers = {
            "Authorization": f"token {self.access_token}",
            "Content-Type": "application/json",
        }

    async def create_stack(
        self,
        project_name: str,
        stack_name: str,
    ) -> dict[str, Any]:
        """Create a new Pulumi stack."""
        url = f"{PULUMI_API_BASE}/api/stacks/{self.organization}/{project_name}"

        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                headers=self.headers,
                json={"stackName": stack_name},
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    async def configure_deployment_settings(
        self,
        project_name: str,
        stack_name: str,
        request: CustomerOnboardRequest,
        repo_url: str,
        repo_branch: str = "main",
        repo_dir: str = ".",
    ) -> dict[str, Any]:
        """Configure deployment settings for a stack."""
        url = (
            f"{PULUMI_API_BASE}/api/stacks/{self.organization}/"
            f"{project_name}/{stack_name}/deployments/settings"
        )

        stack_id = f"{self.organization}/{project_name}/{stack_name}"

        pre_run_commands = self._build_pre_run_commands(stack_id, request)

        source_context: dict[str, Any] = {
            "git": {
                "repoUrl": repo_url,
                "branch": f"refs/heads/{repo_branch}",
                "repoDir": repo_dir,
            }
        }

        if self.github_token:
            source_context["git"]["gitAuth"] = {"accessToken": {"secret": self.github_token}}

        deployment_settings = {
            "sourceContext": source_context,
            "operationContext": {
                "preRunCommands": pre_run_commands,
                "environmentVariables": {
                    "AWS_ACCESS_KEY_ID": self.aws_access_key_id,
                    "AWS_SECRET_ACCESS_KEY": {"secret": self.aws_secret_access_key},
                    "AWS_REGION": request.aws_region,
                },
            },
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                headers=self.headers,
                json=deployment_settings,
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    def _build_pre_run_commands(
        self,
        stack_id: str,
        request: CustomerOnboardRequest,
    ) -> list[str]:
        """Build pre-run commands to set all Pulumi config values."""
        commands = [
            "pip install -r requirements.txt",
        ]

        def config_set(key: str, value: str, secret: bool = False) -> str:
            secret_flag = "--secret " if secret else ""
            # Escape single quotes in value
            escaped_value = value.replace("'", "'\\''")
            return f"pulumi config set --stack {stack_id} {secret_flag}{key} '{escaped_value}'"

        # Basic settings
        commands.append(config_set("customerId", request.customer_id))
        commands.append(config_set("environment", request.environment))
        commands.append(config_set("customerRoleArn", request.role_arn))
        commands.append(config_set("externalId", request.external_id, secret=True))
        commands.append(config_set("awsRegion", request.aws_region))

        # Availability zones
        if request.availability_zones:
            az_str = ",".join(request.availability_zones)
            commands.append(config_set("availabilityZones", az_str))

        # VPC Configuration
        vpc = request.vpc_config
        commands.append(config_set("vpcCidr", vpc.cidr_block))
        commands.append(config_set("natGatewayStrategy", vpc.nat_gateway_strategy.value))

        if vpc.secondary_cidr_blocks:
            commands.append(config_set("secondaryCidrBlocks", ",".join(vpc.secondary_cidr_blocks)))

        # Public subnet configuration
        if vpc.public_subnets:
            if vpc.public_subnets.cidr_mask:
                commands.append(config_set("publicSubnetCidrMask", str(vpc.public_subnets.cidr_mask)))
            if vpc.public_subnets.custom_subnets:
                subnets_json = json.dumps([s.model_dump() for s in vpc.public_subnets.custom_subnets])
                commands.append(config_set("publicCustomSubnets", subnets_json))

        # Private subnet configuration
        if vpc.private_subnets:
            if vpc.private_subnets.cidr_mask:
                commands.append(config_set("privateSubnetCidrMask", str(vpc.private_subnets.cidr_mask)))
            if vpc.private_subnets.custom_subnets:
                subnets_json = json.dumps([s.model_dump() for s in vpc.private_subnets.custom_subnets])
                commands.append(config_set("privateCustomSubnets", subnets_json))

        # Pod subnet configuration
        if vpc.pod_subnets and vpc.pod_subnets.enabled:
            commands.append(config_set("podSubnetsEnabled", "true"))
            if vpc.pod_subnets.cidr_mask:
                commands.append(config_set("podSubnetCidrMask", str(vpc.pod_subnets.cidr_mask)))
            if vpc.pod_subnets.custom_subnets:
                subnets_json = json.dumps([s.model_dump() for s in vpc.pod_subnets.custom_subnets])
                commands.append(config_set("podCustomSubnets", subnets_json))

        # VPC Endpoints
        endpoints = vpc.vpc_endpoints
        commands.append(config_set("vpcEndpointS3", str(endpoints.s3_gateway).lower()))
        commands.append(config_set("vpcEndpointEcrApi", str(endpoints.ecr_api).lower()))
        commands.append(config_set("vpcEndpointEcrDkr", str(endpoints.ecr_dkr).lower()))
        commands.append(config_set("vpcEndpointSts", str(endpoints.sts).lower()))
        commands.append(config_set("vpcEndpointLogs", str(endpoints.logs).lower()))
        commands.append(config_set("vpcEndpointEc2", str(endpoints.ec2).lower()))
        commands.append(config_set("vpcEndpointSsm", str(endpoints.ssm).lower()))
        commands.append(config_set("vpcEndpointSsmMessages", str(endpoints.ssmmessages).lower()))
        commands.append(config_set("vpcEndpointEc2Messages", str(endpoints.ec2messages).lower()))

        # DNS settings
        commands.append(config_set("enableDnsHostnames", str(vpc.enable_dns_hostnames).lower()))
        commands.append(config_set("enableDnsSupport", str(vpc.enable_dns_support).lower()))

        # EKS Configuration
        eks = request.eks_config
        commands.append(config_set("eksVersion", eks.version))
        commands.append(config_set("eksMode", eks.mode.value))
        commands.append(config_set("serviceIpv4Cidr", eks.service_ipv4_cidr))

        # EKS Access Configuration
        access = eks.access
        commands.append(config_set("endpointAccess", access.endpoint_access.value))
        commands.append(config_set("grantAdminToCreator", str(access.grant_admin_to_creator).lower()))
        commands.append(config_set("authenticationMode", access.authentication_mode))

        if access.public_access_cidrs:
            commands.append(config_set("publicAccessCidrs", ",".join(access.public_access_cidrs)))

        if access.access_entries:
            entries_json = json.dumps([e.model_dump() for e in access.access_entries])
            commands.append(config_set("accessEntries", entries_json))

        # EKS Logging
        commands.append(config_set("loggingEnabled", str(eks.logging_enabled).lower()))
        if eks.logging_enabled and eks.logging_types:
            commands.append(config_set("loggingTypes", ",".join(eks.logging_types)))

        # EKS Encryption
        commands.append(config_set("encryptionEnabled", str(eks.encryption_enabled).lower()))
        if eks.encryption_enabled and eks.encryption_kms_key_arn:
            commands.append(config_set("encryptionKmsKeyArn", eks.encryption_kms_key_arn))

        # EKS Other settings
        commands.append(config_set("deletionProtection", str(eks.deletion_protection).lower()))
        commands.append(config_set("zonalShiftEnabled", str(eks.zonal_shift_enabled).lower()))

        # Node Group Configuration (for managed mode)
        if eks.mode == EksMode.MANAGED and request.node_group_config:
            ng = request.node_group_config
            commands.append(config_set("nodeGroupName", ng.name))
            commands.append(config_set("nodeInstanceTypes", ",".join(ng.instance_types)))
            commands.append(config_set("nodeDesiredSize", str(ng.desired_size)))
            commands.append(config_set("nodeMinSize", str(ng.min_size)))
            commands.append(config_set("nodeMaxSize", str(ng.max_size)))
            commands.append(config_set("nodeDiskSize", str(ng.disk_size)))
            commands.append(config_set("nodeCapacityType", ng.capacity_type))
            commands.append(config_set("nodeAmiType", ng.ami_type))

            if ng.labels:
                commands.append(config_set("nodeLabels", json.dumps(ng.labels)))

        # Custom Tags
        if request.tags:
            commands.append(config_set("tags", json.dumps(request.tags)))

        return commands

    async def trigger_deployment(
        self,
        project_name: str,
        stack_name: str,
        operation: str = "update",
        inherit_settings: bool = True,
    ) -> dict[str, Any]:
        """Trigger a Pulumi deployment."""
        url = f"{PULUMI_API_BASE}/api/stacks/{self.organization}/{project_name}/{stack_name}/deployments"

        payload = {
            "operation": operation,
            "inheritSettings": inherit_settings,
        }

        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                headers=self.headers,
                json=payload,
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    async def get_deployment_status(
        self,
        project_name: str,
        stack_name: str,
        deployment_id: str,
    ) -> dict[str, Any]:
        """Get the status of a deployment."""
        url = f"{PULUMI_API_BASE}/api/stacks/{self.organization}/{project_name}/{stack_name}/deployments/{deployment_id}"

        async with httpx.AsyncClient() as client:
            response = await client.get(
                url,
                headers=self.headers,
                timeout=30.0,
            )
            response.raise_for_status()
            return response.json()

    async def get_stack_outputs(
        self,
        project_name: str,
        stack_name: str,
    ) -> dict[str, Any]:
        """Get stack outputs."""
        url = f"{PULUMI_API_BASE}/api/stacks/{self.organization}/{project_name}/{stack_name}/export"

        async with httpx.AsyncClient() as client:
            response = await client.get(
                url,
                headers=self.headers,
                timeout=30.0,
            )
            response.raise_for_status()
            data = response.json()

            deployment = data.get("deployment", {})
            resources = deployment.get("resources", [])

            for resource in resources:
                if resource.get("type") == "pulumi:pulumi:Stack":
                    return resource.get("outputs", {})

            return {}

    async def delete_stack(
        self,
        project_name: str,
        stack_name: str,
        force: bool = False,
    ) -> None:
        """Delete a Pulumi stack."""
        url = f"{PULUMI_API_BASE}/api/stacks/{self.organization}/{project_name}/{stack_name}"
        if force:
            url += "?force=true"

        async with httpx.AsyncClient() as client:
            response = await client.delete(
                url,
                headers=self.headers,
                timeout=30.0,
            )
            response.raise_for_status()