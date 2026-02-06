"""Cluster addons installed via Helm charts (ArgoCD, etc.)."""

import pulumi
import pulumi_kubernetes as k8s
from pulumi_kubernetes.helm.v3 import Chart, ChartOpts, FetchOpts

from api.models import AddonsConfigResolved, ArgoCDConfigResolved


class ClusterAddons(pulumi.ComponentResource):
    """Installs cluster addons via Helm charts."""

    def __init__(
        self,
        name: str,
        addons_config: AddonsConfigResolved,
        k8s_provider: k8s.Provider,
        opts: pulumi.ResourceOptions | None = None,
    ):
        super().__init__("byoc:kubernetes:ClusterAddons", name, None, opts)

        self._name = name
        self._k8s_provider = k8s_provider

        child_opts = pulumi.ResourceOptions(parent=self, provider=k8s_provider)

        # Track installed components
        self.argocd_chart: Chart | None = None
        self.argocd_repo_secret: k8s.core.v1.Secret | None = None
        self.argocd_root_app: k8s.apiextensions.CustomResource | None = None

        # Install ArgoCD if enabled
        if addons_config.argocd.enabled:
            self.argocd_chart = self._install_argocd(addons_config.argocd, child_opts)

            # Create repository secret if credentials provided
            if addons_config.argocd.repository:
                self.argocd_repo_secret = self._create_repo_secret(addons_config.argocd, child_opts)

            # Create root application if path provided
            if addons_config.argocd.repository and addons_config.argocd.root_app_path:
                self.argocd_root_app = self._create_root_app(addons_config.argocd, child_opts)

        self.register_outputs(
            {
                "argocd_enabled": addons_config.argocd.enabled,
            }
        )

    def _install_argocd(
        self,
        config: ArgoCDConfigResolved,
        opts: pulumi.ResourceOptions,
    ) -> Chart:
        """Install ArgoCD via Helm chart."""

        values: dict = {
            "server": {
                "replicas": config.server_replicas,
            },
            "repoServer": {
                "replicas": config.repo_server_replicas,
            },
            "controller": {
                "replicas": 1,
            },
        }

        # Enable HA mode if requested
        if config.ha_enabled:
            values["redis-ha"] = {"enabled": True}
            values["controller"]["replicas"] = 2
            values["server"]["replicas"] = max(config.server_replicas, 3)
            values["repoServer"]["replicas"] = max(config.repo_server_replicas, 3)

        return Chart(
            f"{self._name}-argocd",
            ChartOpts(
                chart="argo-cd",
                version="5.51.0",
                namespace="argocd",
                fetch_opts=FetchOpts(
                    repo="https://argoproj.github.io/argo-helm",
                ),
                values=values,
                skip_await=False,
            ),
            opts=opts,
        )

    def _create_repo_secret(
        self,
        config: ArgoCDConfigResolved,
        opts: pulumi.ResourceOptions,
    ) -> k8s.core.v1.Secret:
        """Create repository credentials secret for ArgoCD."""

        if not config.repository:
            raise ValueError("Repository config required to create secret")

        return k8s.core.v1.Secret(
            f"{self._name}-argocd-repo-creds",
            metadata=k8s.meta.v1.ObjectMetaArgs(
                name="repo-creds",
                namespace="argocd",
                labels={
                    "argocd.argoproj.io/secret-type": "repository",
                },
            ),
            string_data={
                "type": "git",
                "url": config.repository.url,
                "username": config.repository.username,
                "password": config.repository.password,
            },
            opts=pulumi.ResourceOptions(
                parent=self,
                provider=self._k8s_provider,
                depends_on=[self.argocd_chart] if self.argocd_chart else [],
            ),
        )

    def _create_root_app(
        self,
        config: ArgoCDConfigResolved,
        opts: pulumi.ResourceOptions,
    ) -> k8s.apiextensions.CustomResource:
        """Create root Application CR for App of Apps pattern."""

        if not config.repository:
            raise ValueError("Repository config required to create root app")

        depends: list = []
        if self.argocd_chart:
            depends.append(self.argocd_chart)
        if self.argocd_repo_secret:
            depends.append(self.argocd_repo_secret)

        return k8s.apiextensions.CustomResource(
            f"{self._name}-argocd-root-app",
            api_version="argoproj.io/v1alpha1",
            kind="Application",
            metadata=k8s.meta.v1.ObjectMetaArgs(
                name="root-app",
                namespace="argocd",
            ),
            spec={
                "project": "default",
                "source": {
                    "repoURL": config.repository.url,
                    "targetRevision": "HEAD",
                    "path": config.root_app_path,
                },
                "destination": {
                    "server": "https://kubernetes.default.svc",
                    "namespace": "argocd",
                },
                "syncPolicy": {
                    "automated": {
                        "prune": True,
                        "selfHeal": True,
                    },
                    "syncOptions": ["CreateNamespace=true"],
                },
            },
            opts=pulumi.ResourceOptions(
                parent=self,
                provider=self._k8s_provider,
                depends_on=depends,
            ),
        )
