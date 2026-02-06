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
        instance_type: str = "t3.micro",
        provider: aws.Provider | None = None,
        tags: dict[str, str] | None = None,
        opts: pulumi.ResourceOptions | None = None,
    ):
        super().__init__("byoc:infrastructure:AccessNode", name, None, opts)

        self._tags = tags or {}
        self._name = name
        self._provider = provider

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
        aws.iam.RolePolicy(
            f"{name}-access-node-eks-policy",
            role=self.role.name,
            policy=cluster_name.apply(
                lambda cn: (
                    """{
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Action": [
                                "eks:DescribeCluster",
                                "eks:ListClusters"
                            ],
                            "Resource": "*"
                        }
                    ]
                }"""
                )
            ),
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
        )

        user_data = r"""#!/bin/bash
set -ex

# Log output for debugging
exec > >(tee /var/log/user-data.log) 2>&1

# Install jq (useful for scripting)
yum install -y jq

# Install kubectl
echo "Installing kubectl..."
KUBECTL_VERSION=$(curl -L -s https://dl.k8s.io/release/stable.txt)
curl -LO "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/amd64/kubectl"
chmod +x kubectl
mv kubectl /usr/local/bin/
kubectl version --client

# Install helm
echo "Installing helm..."
curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash

# Ensure /usr/local/bin is in PATH for all users (including ssm-user)
echo 'export PATH="/usr/local/bin:$PATH"' > /etc/profile.d/local-bin.sh
chmod +x /etc/profile.d/local-bin.sh

# Create a welcome message
cat > /etc/motd << 'EOF'
====================================================
  SSM Access Node for EKS Cluster
====================================================

To configure kubectl, run:
  aws eks update-kubeconfig --name <cluster-name> --region <region>

Then verify access:
  kubectl get nodes

====================================================
EOF

echo "Access node setup complete"
"""

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

        self.register_outputs(
            {
                "instance_id": self.instance_id,
                "private_ip": self.private_ip,
                "security_group_id": self.security_group.id,
            }
        )
