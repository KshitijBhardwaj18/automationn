import json

import pulumi
import pulumi_aws as aws

class AccessNode(pulumi.ComponentResource):
    """SSM-enabled EC2 instance for private EKS cluster access."""

    def __init__(
        self,
        name: str,
        vpc_id: pulumi.Output[str],
        subnet_id: pulumi.Output[str],
        cluster_security_group_id: pulumi.Output[str],
        cluster_name: pulumi.Output[str],
        region: str,
        instance_type: str = "t3.micro",
        provider: aws.Provider | None = None,
        tags: dict[str, str] | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ):
        super().__init__("byoc:infrastructure:AccessNode", name, None, opts)

        self._tags = tags or {}
        self._name = name
        self._provider = provider
        self._region = region

        child_opts = pulumi.ResourceOptions(parent=self, provider=provider)

        self.role = aws.iam.Role(
            f"{name}-access-node-role",
            assume_role_policy="""{
                "Version": "2012-10-17",
                "Statement": [{
                    "Action": "sts:AssumeRole",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Effect": "Allow"
                }]
            }""",
            tags={"Name": f"{name}-access-node-role", **self._tags},
            opts=child_opts,
        )

        aws.iam.RolePolicyAttachment(
            f"{name}-access-node-ssm-policy",
            role=self.role.name,
            policy_arn="arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
            opts=child_opts,
        )

        # EKS access policy - allows describing cluster and getting tokens
        eks_access_policy = aws.iam.RolePolicy(
            f"{name}-access-node-eks-policy",
            role=self.role.name,
            policy=cluster_name.apply(
                lambda cn: f"""{{
                    "Version": "2012-10-17",
                    "Statement": [
                        {{
                            "Effect": "Allow",
                            "Action": [
                                "eks:DescribeCluster",
                                "eks:ListClusters"
                            ],
                            "Resource": "*"
                        }}
                    ]
                }}"""
            ),
            opts=child_opts,
        )

        # SSM Parameter Store read for addon secrets (e.g. ArgoCD repo password fetched at runtime)
        # Scoped to current account and region for least-privilege
        caller = aws.get_caller_identity(
            opts=pulumi.InvokeOptions(provider=provider) if provider else None
        )
        aws.iam.RolePolicy(
            f"{name}-access-node-ssm-params-policy",
            role=self.role.name,
            policy=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["ssm:GetParameter"],
                    "Resource": f"arn:aws:ssm:{region}:{caller.account_id}:parameter/byoc/*",
                }],
            }),
            opts=child_opts,
        )

        self.instance_profile = aws.iam.InstanceProfile(
            f"{name}-access-node-profile",
            role=self.role.name,
            opts=child_opts,
        )

        
        self.security_group = aws.ec2.SecurityGroup(
            f"{name}-access-node-sg",
            vpc_id=vpc_id,
            description="SSM access node - egress only, no inbound",
     
            egress=[
                aws.ec2.SecurityGroupEgressArgs(
                    protocol="-1",
                    from_port=0,
                    to_port=0,
                    cidr_blocks=["0.0.0.0/0"],
                    description="Allow all outbound (required for SSM and kubectl)",
                )
            ],
            tags={"Name": f"{name}-access-node-sg", **self._tags},
            opts=child_opts,
        )

        aws.ec2.SecurityGroupRule(
            f"{name}-access-node-to-eks",
            type="ingress",
            from_port=443,
            to_port=443,
            protocol="tcp",
            security_group_id=cluster_security_group_id,
            source_security_group_id=self.security_group.id,
            description="Allow access node to reach EKS API",
            opts=child_opts,
        )

        ami = aws.ec2.get_ami(
            most_recent=True,
            owners=["amazon"],
            filters=[
                {"name": "name", "values": ["al2023-ami-*-x86_64"]},
                {"name": "virtualization-type", "values": ["hvm"]},
                {"name": "architecture", "values": ["x86_64"]},
            ],
            opts=pulumi.InvokeOptions(provider=provider),
        )

        # Pinned tool versions for reproducibility and security
        kubectl_version = "v1.31.4"
        helm_version = "v3.16.4"

        def build_user_data(cluster_name_str: str) -> str:
            return f"""#!/bin/bash
set -ex

# Log output for debugging
exec > >(tee /var/log/user-data.log) 2>&1

# Detect package manager (AL2023 uses dnf; yum may be present as compat)
PKG_MGR="yum"
if command -v dnf >/dev/null 2>&1; then
  PKG_MGR="dnf"
fi

# Install jq (useful for scripting)
$PKG_MGR install -y jq

# Install & start SSM Agent (required for Session Manager)
if ! rpm -q amazon-ssm-agent >/dev/null 2>&1; then
  $PKG_MGR install -y amazon-ssm-agent
fi
systemctl enable --now amazon-ssm-agent
systemctl status amazon-ssm-agent --no-pager || true

# Install kubectl (pinned version with checksum verification)
echo "Installing kubectl {kubectl_version}..."
cd /tmp
curl -LO "https://dl.k8s.io/release/{kubectl_version}/bin/linux/amd64/kubectl"
curl -LO "https://dl.k8s.io/release/{kubectl_version}/bin/linux/amd64/kubectl.sha256"
echo "$(cat kubectl.sha256)  kubectl" | sha256sum --check
chmod +x kubectl
mv kubectl /usr/local/bin/
rm -f kubectl.sha256
kubectl version --client

# Install helm (pinned version with checksum verification)
echo "Installing helm {helm_version}..."
cd /tmp
curl -LO "https://get.helm.sh/helm-{helm_version}-linux-amd64.tar.gz"
curl -LO "https://get.helm.sh/helm-{helm_version}-linux-amd64.tar.gz.sha256sum"
sha256sum -c "helm-{helm_version}-linux-amd64.tar.gz.sha256sum"
tar -zxvf "helm-{helm_version}-linux-amd64.tar.gz"
mv linux-amd64/helm /usr/local/bin/helm
rm -rf linux-amd64 "helm-{helm_version}-linux-amd64.tar.gz" "helm-{helm_version}-linux-amd64.tar.gz.sha256sum"
helm version

# Ensure /usr/local/bin is in PATH for all users (including ssm-user)
echo 'export PATH="/usr/local/bin:$PATH"' > /etc/profile.d/local-bin.sh
chmod +x /etc/profile.d/local-bin.sh

# Configure kubectl and share kubeconfig so all users (e.g. ssm-user) have context on login
export HOME="${{HOME:-/root}}"
mkdir -p "$HOME/.kube"
aws eks update-kubeconfig --name {cluster_name_str!r} --region {self._region!r}
mkdir -p /etc/kube
cp "$HOME/.kube/config" /etc/kube/config
chmod 644 /etc/kube/config
echo 'export KUBECONFIG=/etc/kube/config' > /etc/profile.d/kubeconfig.sh
chmod +x /etc/profile.d/kubeconfig.sh

# Verify cluster access
kubectl get nodes || true

# Create a welcome message
cat > /etc/motd << 'MOTDEOF'
====================================================
  SSM Access Node for EKS Cluster
====================================================

kubectl is configured for all users (KUBECONFIG=/etc/kube/config).
Verify: kubectl get nodes

====================================================
MOTDEOF

echo "Access node setup complete"
"""

        user_data = cluster_name.apply(build_user_data)

        self.instance = aws.ec2.Instance(
            f"{name}-access-node",
            ami=ami.id,
            instance_type=instance_type,
            subnet_id=subnet_id,
            vpc_security_group_ids=[self.security_group.id],
            iam_instance_profile=self.instance_profile.name,
            associate_public_ip_address=False,  # NO PUBLIC IP
            user_data=user_data,
            tags={"Name": f"{name}-access-node", **self._tags},
            opts=child_opts,
        )

        self.instance_id = self.instance.id
        self.private_ip = self.instance.private_ip
        self.availability_zone = self.instance.availability_zone

        self.register_outputs({
            "instance_id": self.instance_id,
            "private_ip": self.private_ip,
            "security_group_id": self.security_group.id,
        })