import asyncio
import base64
import json
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from api.config_storage import config_storage
from api.database import db
from api.models import (
    AddonInstallResult,
    AddonInstallStatus,
    ArgoCDAddonResolved,
)
from api.settings import settings


class AddonInstallerService:
    """Install cluster addons by executing scripts on the SSM access node."""

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
                raise ValueError(
                    f"Deployment {self.customer_id}-{self.environment} not found"
                )
        return self._deployment

    @property
    def outputs(self) -> dict:
        if not self.deployment.outputs:
            return {}
        try:
            return json.loads(self.deployment.outputs)
        except (json.JSONDecodeError, TypeError):
            return {}

    def _get_client(self, service: str):
        """Get boto3 client with assumed role credentials (uses default credential chain)."""
        if service in self._clients:
            return self._clients[service]

        try:
            sts = boto3.client("sts", region_name=self.config.aws_config.region)
            assumed = sts.assume_role(
                RoleArn=self.config.aws_config.role_arn,
                ExternalId=self.config.aws_config.external_id,
                RoleSessionName=f"byoc-addon-{self.customer_id}",
                DurationSeconds=900,
            )
        except NoCredentialsError as e:
            raise ValueError(
                f"Failed to locate AWS credentials: {e}. "
                "Use env vars, IAM role (EC2/IRSA), or other default provider chain."
            ) from e
        except ClientError as e:
            raise ValueError(
                f"Failed to assume role {self.config.aws_config.role_arn}: {e}"
            ) from e

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

    @staticmethod
    def _argocd_repo_password_param_name(customer_id: str, environment: str) -> str:
        """SSM Parameter Store path for ArgoCD repo password (fetched on node, not sent in script)."""
        return f"/byoc/{customer_id}/{environment}/argocd/repo-password"

    def _state_path(self) -> Path:
        return Path(settings.config_storage_path) / f"{self.customer_id}.addons.json"

    def _save_addon_state(
        self, addon_name: str, command_id: str, instance_id: str
    ) -> None:
        """Persist the last SSM command ID for an addon install."""
        path = self._state_path()
        state: dict = {}
        if path.exists():
            state = json.loads(path.read_text())
        state[addon_name] = {
            "last_command_id": command_id,
            "instance_id": instance_id,
            "triggered_at": datetime.now(timezone.utc).isoformat(),
        }
        path.write_text(json.dumps(state, indent=2))

    def _load_addon_state(self, addon_name: str) -> dict | None:
        """Load the last known SSM command state for an addon."""
        path = self._state_path()
        if not path.exists():
            return None
        state = json.loads(path.read_text())
        return state.get(addon_name)


    def _build_argocd_install_script(
        self,
        cluster_name: str,
        region: str,
        argocd_config: ArgoCDAddonResolved,
        ssm_repo_password_param: str | None = None,
    ) -> str:
        """Build the shell script to install ArgoCD via Helm on the access node.

        Repo password is never inlined: when ssm_repo_password_param is set, the script
        fetches it from SSM Parameter Store at runtime on the node.
        """
        controller_replicas = 2 if argocd_config.ha_enabled else 1

        lines = [
            "#!/bin/bash",
            "set -euo pipefail",
            "",
            'export PATH="/usr/local/bin:$PATH"',
            "# SSM Run Command may not set HOME; use default so KUBECONFIG is predictable",
            'export HOME="${HOME:-/root}"',
            "mkdir -p \"$HOME/.kube\"",
            'export KUBECONFIG="$HOME/.kube/config"',
            "",
            f'CLUSTER_NAME="{cluster_name}"',
            f'REGION="{region}"',
            "",
            "# Configure kubectl",
            'echo "==> Configuring kubectl for $CLUSTER_NAME in $REGION..."',
            'aws eks update-kubeconfig --name "$CLUSTER_NAME" --region "$REGION"',
            'echo "==> Verifying cluster access..."',
            "kubectl get nodes",
            "",
            "# Add ArgoCD Helm repo",
            'echo "==> Adding ArgoCD Helm repository..."',
            "helm repo add argo https://argoproj.github.io/argo-helm",
            "helm repo update",
            "",
            "# Install / upgrade ArgoCD",
            f'echo "==> Installing ArgoCD (chart version {argocd_config.chart_version})..."',
            "helm upgrade --install argocd argo/argo-cd \\",
            "  --namespace argocd --create-namespace \\",
            f"  --version {argocd_config.chart_version} \\",
            f"  --set server.replicas={argocd_config.server_replicas} \\",
            f"  --set repoServer.replicas={argocd_config.repo_server_replicas} \\",
            f"  --set 'redis-ha.enabled={'true' if argocd_config.ha_enabled else 'false'}' \\",
            f"  --set controller.replicas={controller_replicas} \\",
            "  --wait --timeout 5m",
            "",
        ]

        if argocd_config.repository:
            repo = argocd_config.repository
            type_b64 = base64.b64encode(b"git").decode()
            url_b64 = base64.b64encode(repo.url.encode()).decode()
            user_b64 = base64.b64encode(repo.username.encode()).decode()

            lines.append("# Create repository credentials secret")
            lines.append('echo "==> Creating ArgoCD repository credentials..."')
            if ssm_repo_password_param:
                lines.extend(
                    [
                        "# Fetch password from SSM at runtime (never inlined in the script)",
                        f'REPO_PASSWORD=$(aws ssm get-parameter --name "{ssm_repo_password_param}" --with-decryption --region "$REGION" --query Parameter.Value --output text)',
                        'PASS_B64=$(echo -n "$REPO_PASSWORD" | base64 -w0)',
                        'unset REPO_PASSWORD',
                        f'TYPE_B64="{type_b64}"',
                        f'URL_B64="{url_b64}"',
                        f'USER_B64="{user_b64}"',
                        "kubectl apply -f - <<REPO_CREDS_EOF",
                        "apiVersion: v1",
                        "kind: Secret",
                        "metadata:",
                        "  name: repo-creds",
                        "  namespace: argocd",
                        "  labels:",
                        "    argocd.argoproj.io/secret-type: repo-creds",
                        "data:",
                        "  type: $TYPE_B64",
                        "  url: $URL_B64",
                        "  username: $USER_B64",
                        "  password: $PASS_B64",
                        "REPO_CREDS_EOF",
                        "",
                    ]
                )
            else:
                lines.extend(
                    [
                        "kubectl apply -f - <<'REPO_CREDS_EOF'",
                        "apiVersion: v1",
                        "kind: Secret",
                        "metadata:",
                        "  name: repo-creds",
                        "  namespace: argocd",
                        "  labels:",
                        "    argocd.argoproj.io/secret-type: repo-creds",
                        "data:",
                        f"  type: {type_b64}",
                        f"  url: {url_b64}",
                        f"  username: {user_b64}",
                        "REPO_CREDS_EOF",
                        "",
                    ]
                )

            # Create root application if path is configured
            if argocd_config.root_app_path:
                lines.extend(
                    [
                        "# Create root ArgoCD Application",
                        'echo "==> Creating root ArgoCD Application..."',
                        "kubectl apply -f - <<'ROOT_APP_EOF'",
                        "apiVersion: argoproj.io/v1alpha1",
                        "kind: Application",
                        "metadata:",
                        f"  name: {self.customer_id}-root-app",
                        "  namespace: argocd",
                        "spec:",
                        "  project: default",
                        "  source:",
                        f"    repoURL: {repo.url}",
                        "    targetRevision: HEAD",
                        f"    path: {argocd_config.root_app_path}",
                        "    directory:",
                        "      recurse: true",
                        "  destination:",
                        "    server: https://kubernetes.default.svc",
                        "    namespace: argocd",
                        "  syncPolicy:",
                        "    automated:",
                        "      prune: true",
                        "      selfHeal: true",
                        "ROOT_APP_EOF",
                        "",
                    ]
                )

        lines.extend(
            [
                "# Verify installation",
                'echo "==> Verifying ArgoCD installation..."',
                "kubectl get pods -n argocd",
                "kubectl get svc -n argocd",
                "",
                'echo "==> ArgoCD installation complete!"',
            ]
        )

        return "\n".join(lines)


    def _install_argocd_sync(
        self, argocd_config: ArgoCDAddonResolved
    ) -> AddonInstallResult:
        """Install ArgoCD via SSM Run Command (blocking)."""
        instance_id = self.outputs.get("access_node_instance_id")
        cluster_name = self.outputs.get("eks_cluster_name")
        region = self.config.aws_config.region

        if not instance_id:
            raise ValueError("SSM access node is not available in deployment outputs")
        if not cluster_name:
            raise ValueError("EKS cluster name not found in deployment outputs")

        ssm = self._get_client("ssm")
        ssm_repo_password_param: str | None = None
        if argocd_config.repository and (argocd_config.repository.password or "").strip():
            param_name = self._argocd_repo_password_param_name(
                self.customer_id, self.environment
            )
            # Assumed role (config.aws_config.role_arn) must have ssm:PutParameter on /byoc/*.
            try:
                ssm.put_parameter(
                    Name=param_name,
                    Value=argocd_config.repository.password,
                    Type="SecureString",
                    Overwrite=True,
                )
            except ClientError as e:
                if e.response.get("Error", {}).get("Code") == "AccessDeniedException":
                    raise ValueError(
                        "Cannot store ArgoCD repo password in SSM. "
                        "The assumed role must have ssm:PutParameter for /byoc/*."
                    ) from e
                raise
            ssm_repo_password_param = param_name

        script = self._build_argocd_install_script(
            cluster_name, region, argocd_config, ssm_repo_password_param
        )

        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={"commands": script.split("\n")},
            TimeoutSeconds=600,
            Comment=f"Install ArgoCD for {self.customer_id}-{self.environment}",
        )

        command_id = response["Command"]["CommandId"]

        self._save_addon_state("argocd", command_id, instance_id)

        return AddonInstallResult(
            addon_name="argocd",
            status=AddonInstallStatus.IN_PROGRESS,
            ssm_command_id=command_id,
            instance_id=instance_id,
            started_at=datetime.now(timezone.utc),
        )

    def _get_install_status_sync(
        self,
        command_id: str,
        instance_id: str,
    ) -> AddonInstallResult:
        """Check the status of an ArgoCD install SSM command (blocking)."""
        ssm = self._get_client("ssm")

        try:
            response = ssm.get_command_invocation(
                CommandId=command_id,
                InstanceId=instance_id,
            )
        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "InvocationDoesNotExist":
                return AddonInstallResult(
                    addon_name="argocd",
                    status=AddonInstallStatus.PENDING,
                    ssm_command_id=command_id,
                    instance_id=instance_id,
                )
            raise

        ssm_status = response.get("Status", "")
        output = response.get("StandardOutputContent", "")
        error = response.get("StandardErrorContent", "")

        if ssm_status in ("Pending", "InProgress", "Delayed"):
            install_status = AddonInstallStatus.IN_PROGRESS
        elif ssm_status == "Success":
            install_status = AddonInstallStatus.SUCCEEDED
        else:
            install_status = AddonInstallStatus.FAILED

        return AddonInstallResult(
            addon_name="argocd",
            status=install_status,
            ssm_command_id=command_id,
            instance_id=instance_id,
            output=output or None,
            error=error or None,
        )

    # -- Async wrappers --

    async def install_argocd(
        self, argocd_config: ArgoCDAddonResolved
    ) -> AddonInstallResult:
        """Install ArgoCD via SSM Run Command."""
        return await asyncio.to_thread(self._install_argocd_sync, argocd_config)

    async def get_install_status(
        self,
        command_id: str | None = None,
        instance_id: str | None = None,
    ) -> AddonInstallResult:
        """Check ArgoCD install status.

        If command_id/instance_id are not provided, looks up the last known
        install from the persisted addon state.
        """
        if not command_id or not instance_id:
            state = self._load_addon_state("argocd")
            if not state:
                raise ValueError(
                    "No ArgoCD installation found. "
                    "Trigger one via POST .../addons/argocd/install"
                )
            command_id = str(state["last_command_id"])
            instance_id = str(state["instance_id"])

        return await asyncio.to_thread(
            self._get_install_status_sync, command_id, instance_id
        )
