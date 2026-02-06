import json
import os

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from api.config_storage import config_storage
from api.database import db
from api.models import (
    SsmNodeStatus,
    SsmSessionInfo,
)


class SsmAccessService:
    """Service for managing SSM access to private EKS clusters."""

    def __init__(self, customer_id: str, environment: str):
        self.customer_id = customer_id
        self.environment = environment
        self._config = None
        self._deployment = None
        self._clients: dict = {}

    @property
    def config(self):
        if not self._config:
            self._config = config_storage.get(self.customer_id)
            if not self._config:
                raise ValueError(f"Customer {self.customer_id} not found")
        return self._config

    @property
    def deployment(self):
        if not self._deployment:
            self._deployment = db.get_deployment(self.customer_id, self.environment)
            if not self._deployment:
                raise ValueError(f"Deployment {self.customer_id}-{self.environment} not found")
        return self._deployment

    @property
    def outputs(self) -> dict:
        if not self.deployment.outputs:
            return {}
        return json.loads(self.deployment.outputs)

    def _get_client(self, service: str):
        """Get boto3 client with assumed role credentials."""
        if service in self._clients:
            return self._clients[service]

        # Verify AWS credentials are available
        if not os.environ.get("AWS_ACCESS_KEY_ID") or not os.environ.get("AWS_SECRET_ACCESS_KEY"):
            raise ValueError(
                "AWS credentials not configured. "
                "Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables."
            )

        try:
            sts = boto3.client("sts", region_name=self.config.aws_config.region)
            assumed = sts.assume_role(
                RoleArn=self.config.aws_config.role_arn,
                ExternalId=self.config.aws_config.external_id,
                RoleSessionName=f"byoc-ssm-{self.customer_id}",
                DurationSeconds=900,
            )
        except NoCredentialsError as e:
            raise ValueError(
                f"Failed to locate AWS credentials: {e}. "
                "Ensure AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are set."
            ) from e
        except ClientError as e:
            raise ValueError(f"Failed to assume role {self.config.aws_config.role_arn}: {e}") from e

        creds = assumed["Credentials"]

        client = boto3.client(
            service,
            region_name=self.config.aws_config.region,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
        self._clients[service] = client
        return client

    async def get_access_node_status(self) -> SsmNodeStatus:
        """Get the status of the SSM access node."""
        instance_id = self.outputs.get("access_node_instance_id")

        if not instance_id:
            return SsmNodeStatus(enabled=False)

        try:
            ec2 = self._get_client("ec2")
            response = ec2.describe_instances(InstanceIds=[instance_id])

            if not response["Reservations"]:
                return SsmNodeStatus(enabled=True, instance_id=instance_id)

            instance = response["Reservations"][0]["Instances"][0]

            return SsmNodeStatus(
                enabled=True,
                instance_id=instance_id,
                instance_state=instance["State"]["Name"],
                availability_zone=instance.get("Placement", {}).get("AvailabilityZone"),
                private_ip=instance.get("PrivateIpAddress"),
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
                return SsmNodeStatus(enabled=True, instance_id=instance_id)
            raise

    async def check_vpc_endpoints(self) -> dict[str, bool]:
        """Check if required VPC endpoints for SSM are configured."""
        vpc_id = self.outputs.get("vpc_id")
        if not vpc_id:
            return {"ssm": False, "ssmmessages": False, "ec2messages": False}

        ec2 = self._get_client("ec2")
        region = self.config.aws_config.region

        required_services = {
            f"com.amazonaws.{region}.ssm": "ssm",
            f"com.amazonaws.{region}.ssmmessages": "ssmmessages",
            f"com.amazonaws.{region}.ec2messages": "ec2messages",
        }

        try:
            response = ec2.describe_vpc_endpoints(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])

            found_services = {ep["ServiceName"] for ep in response.get("VpcEndpoints", [])}

            return {
                short_name: full_service in found_services
                for full_service, short_name in required_services.items()
            }
        except ClientError:
            return {"ssm": False, "ssmmessages": False, "ec2messages": False}

    async def get_session_info(self) -> SsmSessionInfo:
        """Get SSM session connection information."""
        instance_id = self.outputs.get("access_node_instance_id")
        cluster_name = self.outputs.get("eks_cluster_name")
        region = self.config.aws_config.region

        if not instance_id:
            raise ValueError("SSM access node is not enabled for this deployment")

        node_status = await self.get_access_node_status()
        if node_status.instance_state != "running":
            raise ValueError(
                f"Access node is not running. Current state: {node_status.instance_state}"
            )

        start_session_command = f"aws ssm start-session --target {instance_id} --region {region}"

        configure_kubectl_command = (
            f"aws eks update-kubeconfig --name {cluster_name} --region {region}"
        )

        install_kubectl_commands = [
            "cd /tmp",
            'curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"',
            "chmod +x kubectl",
            "sudo mv kubectl /usr/local/bin/",
            "kubectl version --client",
        ]

        instructions = [
            "1. Install AWS CLI and Session Manager plugin locally:",
            "   https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html",
            "",
            "2. Configure AWS credentials with access to the customer account",
            "",
            "3. Start SSM session:",
            f"   {start_session_command}",
            "",
            "4. Inside the session, install kubectl (if not already installed):",
            "   " + " && ".join(install_kubectl_commands),
            "",
            "5. Configure kubectl:",
            f"   {configure_kubectl_command}",
            "",
            "6. Verify access:",
            "   kubectl get nodes",
        ]

        return SsmSessionInfo(
            instance_id=instance_id,
            region=region,
            start_session_command=start_session_command,
            configure_kubectl_command=configure_kubectl_command,
            instructions=instructions,
        )

    async def start_access_node(self) -> dict:
        """Start a stopped access node."""
        instance_id = self.outputs.get("access_node_instance_id")
        if not instance_id:
            raise ValueError("SSM access node is not enabled")

        ec2 = self._get_client("ec2")
        ec2.start_instances(InstanceIds=[instance_id])

        return {"status": "starting", "instance_id": instance_id}

    async def stop_access_node(self) -> dict:
        """Stop the access node"""
        instance_id = self.outputs.get("access_node_instance_id")
        if not instance_id:
            raise ValueError("SSM access node is not enabled")

        ec2 = self._get_client("ec2")
        ec2.stop_instances(InstanceIds=[instance_id])

        return {"status": "stopping", "instance_id": instance_id}
