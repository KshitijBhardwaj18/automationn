import json

import pulumi
import pulumi_aws as aws


class EksIamRoles(pulumi.ComponentResource):
    """IAM roles required for EKS cluster and worker nodes."""

    def __init__(
        self,
        name: str,
        eks_mode: str,
        provider: aws.Provider,
        opts: pulumi.ResourceOptions | None = None,
    ):
        super().__init__("byoc:infrastructure:EksIamRoles", name, None, opts)

        child_opts = pulumi.ResourceOptions(parent=self, provider=provider)

        eks_assume_role_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "eks.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        })

        self.cluster_role = aws.iam.Role(
            f"{name}-eks-cluster-role",
            assume_role_policy=eks_assume_role_policy,
            opts=child_opts,
        )

        aws.iam.RolePolicyAttachment(
            f"{name}-eks-cluster-policy",
            role=self.cluster_role.name,
            policy_arn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
            opts=child_opts,
        )

        aws.iam.RolePolicyAttachment(
            f"{name}-eks-vpc-resource-controller",
            role=self.cluster_role.name,
            policy_arn="arn:aws:iam::aws:policy/AmazonEKSVPCResourceController",
            opts=child_opts,
        )

        if eks_mode == "auto":
            aws.iam.RolePolicyAttachment(
            f"{name}-eks-cluster-compute-policy",
            role=self.cluster_role.name,
            policy_arn="arn:aws:iam::aws:policy/AmazonEKSComputePolicy",
            opts=child_opts,
           )
            aws.iam.RolePolicyAttachment(
            f"{name}-eks-cluster-storage-policy",
            role=self.cluster_role.name,
            policy_arn="arn:aws:iam::aws:policy/AmazonEKSBlockStoragePolicy",
            opts=child_opts,
            )
            aws.iam.RolePolicyAttachment(
            f"{name}-eks-cluster-lb-policy",
            role=self.cluster_role.name,
            policy_arn="arn:aws:iam::aws:policy/AmazonEKSLoadBalancingPolicy",
            opts=child_opts,
            )
            aws.iam.RolePolicyAttachment(
            f"{name}-eks-cluster-networking-policy",
            role=self.cluster_role.name,
            policy_arn="arn:aws:iam::aws:policy/AmazonEKSNetworkingPolicy",
            opts=child_opts,
            )

        ec2_assume_role_policy = json.dumps({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole"
            }]
        })

        self.node_role = aws.iam.Role(
            f"{name}-eks-node-role",
            assume_role_policy=ec2_assume_role_policy,
            opts=child_opts,
        )

        node_policies = [
            "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
            "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
            "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
            "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
        ]

        for i, policy_arn in enumerate(node_policies):
            aws.iam.RolePolicyAttachment(
                f"{name}-eks-node-policy-{i}",
                role=self.node_role.name,
                policy_arn=policy_arn,
                opts=child_opts,
            )

        self.node_instance_profile = aws.iam.InstanceProfile(
            f"{name}-eks-node-instance-profile",
            role=self.node_role.name,
            opts=child_opts,
        )

        self.cluster_role_arn = self.cluster_role.arn
        self.node_role_arn = self.node_role.arn
        self.node_instance_profile_arn = self.node_instance_profile.arn

        self.register_outputs({
            "cluster_role_arn": self.cluster_role_arn,
            "node_role_arn": self.node_role_arn,
            "node_instance_profile_arn": self.node_instance_profile_arn,
        })