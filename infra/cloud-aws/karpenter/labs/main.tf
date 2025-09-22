terraform {
  required_version = ">= 1.4.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.20"
    }
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.9"
    }
    kubectl = {
      source  = "alekc/kubectl"
      version = ">= 2.0.2"
    }
  }
}

locals {
  discovery_value = "eks-cluster-prod"
}

###############################
# Providers
###############################

provider "aws" {
  region = "ap-northeast-2"
  profile = "default"
}

data "aws_eks_cluster" "this" {
  name = "eks-cluster-prod"
}

# Resolve private subnets in the cluster VPC
data "aws_subnets" "cluster_private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_eks_cluster.this.vpc_config[0].vpc_id]
  }
  filter {
    name   = "tag:kubernetes.io/role/internal-elb"
    values = ["1"]
  }
}

data "aws_eks_cluster_auth" "this" {
  name = "eks-cluster-prod"
}

# OIDC provider for IRSA (needed for Karpenter v0.x)
resource "aws_iam_openid_connect_provider" "eks" {
  url             = data.aws_eks_cluster.this.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da0ecd3f3d8"]
}

provider "kubernetes" {
  host                   = data.aws_eks_cluster.this.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.this.token
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.this.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
    token                  = data.aws_eks_cluster_auth.this.token
  }
}

provider "kubectl" {
  apply_retry_count      = 5
  host                   = data.aws_eks_cluster.this.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
  load_config_file       = false

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = [
      "eks",
      "get-token",
      "--cluster-name",
      "eks-cluster-prod",
      "--region",
      "ap-northeast-2"
    ]
  }
}

###############################
# IAM for Karpenter (Controller + Node)
###############################

resource "aws_iam_role" "karpenter_controller" {
  name = "eks-cluster-prod-karpenter"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Federated = aws_iam_openid_connect_provider.eks.arn
        },
        Action = "sts:AssumeRoleWithWebIdentity",
        Condition = {
          StringEquals = {
            "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub" = "system:serviceaccount:karpenter:karpenter",
            "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud" = "sts.amazonaws.com"
          }
        }
      }
    ]
  })

  tags = {
    Name                      = "eks-cluster-prod-karpenter"
    "karpenter.sh/discovery" = local.discovery_value
  }
}

###############################
# (Reference) Karpenter module version pin (no-op)
# This keeps the upstream module + version visible without creating resources.
###############################
module "karpenter_ref" {
  source  = "terraform-aws-modules/eks/aws//modules/karpenter"
  version = "19.20.0"
  count   = 0

  cluster_name                    = "eks-cluster-prod"
  irsa_oidc_provider_arn          = aws_iam_openid_connect_provider.eks.arn
  irsa_namespace_service_accounts = ["karpenter:karpenter"]

  # We already create IAM role/instance profile explicitly above
  create_iam_role = false
  iam_role_arn    = aws_iam_role.karpenter_controller.arn

  irsa_use_name_prefix = false

  tags = {
    "karpenter.sh/discovery" = local.discovery_value
  }
}

# Controller permissions (condensed, covers Describe/RunInstances/Fleet/LaunchTemplates/Tags/SSM/Pricing, etc.)
resource "aws_iam_policy" "karpenter_controller_policy" {
  name        = "KarpenterControllerPolicy-eks-cluster-prod"
  description = "Permissions for Karpenter controller"
  policy      = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect   = "Allow",
        Action   = [
          "ec2:RunInstances",
          "ec2:CreateFleet",
          "ec2:TerminateInstances",
          "ec2:CreateLaunchTemplate",
          "ec2:CreateLaunchTemplateVersion",
          "ec2:DeleteLaunchTemplateVersions",
          "ec2:Describe*",
          "ec2:GetSecurityGroupsForVpc",
          "ec2:CreateTags",
          "eks:DescribeCluster",
          "pricing:GetProducts",
          "ssm:GetParameter",
          "ssm:GetParameters",
          "sqs:CreateQueue",
          "sqs:GetQueue*",
          "sqs:SetQueueAttributes",
          "sqs:SendMessage",
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:DeleteQueue",
          "sqs:TagQueue"
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "karpenter_controller_attach" {
  role       = aws_iam_role.karpenter_controller.name
  policy_arn = aws_iam_policy.karpenter_controller_policy.arn
}

# Node role + instance profile
resource "aws_iam_role" "karpenter_node" {
  name = "KarpenterNodeRole-eks-cluster-prod"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "node_worker" {
  role       = aws_iam_role.karpenter_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "node_cni" {
  role       = aws_iam_role.karpenter_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "node_ecr" {
  role       = aws_iam_role.karpenter_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "node_ssm" {
  role       = aws_iam_role.karpenter_node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "karpenter_node" {
  name = "KarpenterNodeInstanceProfile-eks-cluster-prod"
  role = aws_iam_role.karpenter_node.name

  tags = {
    Name                          = "KarpenterNodeInstanceProfile-eks-cluster-prod"
    "karpenter.sh/discovery"     = local.discovery_value
  }
}

# Allow controller to PassRole to node role
resource "aws_iam_role_policy" "controller_pass_node_role" {
  name = "AllowPassNodeRole-eks-cluster-prod"
  role = aws_iam_role.karpenter_controller.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect   = "Allow",
      Action   = ["iam:PassRole"],
      Resource = aws_iam_role.karpenter_node.arn
    }]
  })
}

# Using IRSA via ServiceAccount annotation; Pod Identity association not used in v0.x

###############################
# Install Karpenter (v0.31.3, OCI chart)
###############################

resource "aws_sqs_queue" "karpenter_interruptions" {
  name = "karpenter-eks-cluster-prod"
}

resource "helm_release" "karpenter" {
  name                = "karpenter"
  namespace           = "karpenter"
  repository          = "oci://public.ecr.aws/karpenter"
  chart               = "karpenter"
  version             = "v0.31.3"

  create_namespace = true

  set {
    name  = "settings.aws.clusterName"
    value = "eks-cluster-prod"
  }

  set {
    name  = "settings.aws.clusterEndpoint"
    value = data.aws_eks_cluster.this.endpoint
  }

  set {
    name  = "serviceAccount.annotations.eks\\.amazonaws\\.com/role-arn"
    value = aws_iam_role.karpenter_controller.arn
  }

  set {
    name  = "settings.aws.defaultInstanceProfile"
    value = aws_iam_instance_profile.karpenter_node.name
  }

  set {
    name  = "settings.aws.interruptionQueueName"
    value = aws_sqs_queue.karpenter_interruptions.name
  }
}

###############################
# Karpenter discovery tags (subnets)
###############################

resource "aws_ec2_tag" "karpenter_discovery_subnets" {
  for_each    = toset(data.aws_subnets.cluster_private.ids)
  resource_id = each.value
  key         = "karpenter.sh/discovery"
  value       = local.discovery_value
}

resource "aws_ec2_tag" "karpenter_discovery_cluster_sg" {
  resource_id = data.aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
  key         = "karpenter.sh/discovery"
  value       = local.discovery_value
}

###############################
# Karpenter v0 resources (AWSNodeTemplate + Provisioner)
###############################

resource "kubectl_manifest" "karpenter_node_template" {
  yaml_body = <<-YAML
    apiVersion: karpenter.k8s.aws/v1alpha1
    kind: AWSNodeTemplate
    metadata:
      name: default
    spec:
      subnetSelector:
        karpenter.sh/discovery: eks-cluster-prod
      securityGroupSelector:
        karpenter.sh/discovery: eks-cluster-prod
      tags:
        karpenter.sh/discovery: eks-cluster-prod
  YAML

  depends_on = [
    helm_release.karpenter,
    aws_ec2_tag.karpenter_discovery_subnets,
    aws_ec2_tag.karpenter_discovery_cluster_sg
  ]
}

resource "kubectl_manifest" "karpenter_provisioner" {
  yaml_body = <<-YAML
    apiVersion: karpenter.sh/v1alpha5
    kind: Provisioner
    metadata:
      name: default
    spec:
      requirements:
        - key: karpenter.sh/capacity-type
          operator: In
          values: ["on-demand"]
        - key: "node.kubernetes.io/instance-type"
          operator: In
          values: ["c5.large","c5a.large","c5ad.large","c5d.large","c6i.large","t2.medium","t3.medium","t3a.medium"]
      limits:
        resources:
          cpu: 1000
      providerRef:
        name: default
      ttlSecondsAfterEmpty: 30
  YAML

  depends_on = [
    helm_release.karpenter,
    kubectl_manifest.karpenter_node_template
  ]
}

###############################
# 라벨 role과 테인트 cicd에서 argocd로 변경
###############################

/*
############################################
# Provider
############################################
terraform {
  required_version = ">= 1.12.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.12"
    }
    kubectl = {
      source  = "gavinbunney/kubectl"
      version = "~> 1.14"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.28"
    }
  }
}

provider "aws" {
  region = "ap-northeast-2"
}

############################################
# 네트워크: VPC/서브넷/SG "조회"
############################################
# VPC Name 태그
data "aws_vpc" "vpc" {
  filter {
    name   = "tag:Name"
    values = ["eks-memory-vpc"]
  }
}

# �� 각 서브넷 Name 태그 (같은 VPC에 있어야 함)
data "aws_subnet" "pub_2a" {
  filter {
    name   = "tag:Name"
    values = ["eks-mmemory-subnet-public1-ap-northeast-2a"]
  }
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.vpc.id]
  }
}
data "aws_subnet" "pub_2c" {
  filter {
    name   = "tag:Name"
    values = ["eks-mmemory-subnet-public2-ap-northeast-2c"]
  }
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.vpc.id]
  }
}
data "aws_subnet" "pvt_2a" {
  filter {
    name   = "tag:Name"
    values = ["eks-mmemory-subnet-private1-ap-northeast-2a"]
  }
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.vpc.id]
  }
}
data "aws_subnet" "pvt_2c" {
  filter {
    name   = "tag:Name"
    values = ["eks-mmemory-subnet-private2-ap-northeast-2c"]
  }
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.vpc.id]
  }
}

# ===[ADD] Subnet/Cluster tags for ALB & Karpenter ===
locals {
  cluster_tag_key = "kubernetes.io/cluster/eks-cluster-prod"
}

# Public subnets
resource "aws_ec2_tag" "tag_pub_2a_cluster" {
  resource_id = data.aws_subnet.pub_2a.id
  key         = local.cluster_tag_key
  value       = "shared"
}
resource "aws_ec2_tag" "tag_pub_2a_role" {
  resource_id = data.aws_subnet.pub_2a.id
  key         = "kubernetes.io/role/elb"
  value       = "1"
}
resource "aws_ec2_tag" "tag_pub_2c_cluster" {
  resource_id = data.aws_subnet.pub_2c.id
  key         = local.cluster_tag_key
  value       = "shared"
}
resource "aws_ec2_tag" "tag_pub_2c_role" {
  resource_id = data.aws_subnet.pub_2c.id
  key         = "kubernetes.io/role/elb"
  value       = "1"
}

# Private subnets
resource "aws_ec2_tag" "tag_pvt_2a_cluster" {
  resource_id = data.aws_subnet.pvt_2a.id
  key         = local.cluster_tag_key
  value       = "shared"
}
resource "aws_ec2_tag" "tag_pvt_2a_role" {
  resource_id = data.aws_subnet.pvt_2a.id
  key         = "kubernetes.io/role/internal-elb"
  value       = "1"
}
resource "aws_ec2_tag" "tag_pvt_2a_karpenter" {
  resource_id = data.aws_subnet.pvt_2a.id
  key         = "karpenter.sh/discovery"
  value       = "eks-cluster-prod"
}
resource "aws_ec2_tag" "tag_pvt_2c_cluster" {
  resource_id = data.aws_subnet.pvt_2c.id
  key         = local.cluster_tag_key
  value       = "shared"
}
resource "aws_ec2_tag" "tag_pvt_2c_role" {
  resource_id = data.aws_subnet.pvt_2c.id
  key         = "kubernetes.io/role/internal-elb"
  value       = "1"
}
resource "aws_ec2_tag" "tag_pvt_2c_karpenter" {
  resource_id = data.aws_subnet.pvt_2c.id
  key         = "karpenter.sh/discovery"
  value       = "eks-cluster-prod"
}
# ===[END ADD]===

############################################
# NAT for private egress
############################################
data "aws_route_table" "rt_pvt_2a" {
  subnet_id = data.aws_subnet.pvt_2a.id
}
data "aws_route_table" "rt_pvt_2c" {
  subnet_id = data.aws_subnet.pvt_2c.id
}

resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "eks-nat-eip-prod" }
}
resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = data.aws_subnet.pub_2a.id
  tags          = { Name = "eks-nat-prod" }
}

resource "aws_route" "pvt_2a_default" {
  route_table_id         = data.aws_route_table.rt_pvt_2a.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat.id
}
resource "aws_route" "pvt_2c_default" {
  route_table_id         = data.aws_route_table.rt_pvt_2c.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat.id
}

data "aws_security_group" "web" {
  name   = "eks-prod-sg"
  vpc_id = data.aws_vpc.vpc.id
}

############################################
# IAM: 클러스터 롤
############################################
resource "aws_iam_role" "eks_cluster" {
  name               = "eks-cluster-iam-role"
  assume_role_policy = <<POLICY
  {
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": { "Service": "eks.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }]
  }
  POLICY
}
resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}
resource "aws_iam_role_policy_attachment" "eks_vpc_rc" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
}

############################################
# EKS Cluster
############################################
resource "aws_eks_cluster" "cluster" {
  name     = "eks-cluster-prod"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = "1.33"

  enabled_cluster_log_types = ["api", "audit", "authenticator"]

  vpc_config {
    subnet_ids              = [data.aws_subnet.pvt_2a.id, data.aws_subnet.pvt_2c.id]
    endpoint_private_access = true
    endpoint_public_access  = false
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_iam_role_policy_attachment.eks_vpc_rc
  ]
}

# EKS data sources
data "aws_eks_cluster" "this" {
  name       = aws_eks_cluster.cluster.name
  depends_on = [aws_eks_cluster.cluster]
}
data "aws_eks_cluster_auth" "this" {
  name       = aws_eks_cluster.cluster.name
  depends_on = [aws_eks_cluster.cluster]
}

# Provider configurations
provider "kubernetes" {
  host                   = data.aws_eks_cluster.this.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
  
  # 배스천에서 실행할 때 AWS CLI 사용
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = [
      "eks",
      "get-token",
      "--cluster-name",
      aws_eks_cluster.cluster.name,
      "--region",
      "ap-northeast-2"
    ]
  }
}

provider "helm" {
  kubernetes {
    host                   = data.aws_eks_cluster.this.endpoint
    cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
    
    # 배스천에서 실행할 때 AWS CLI 사용
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "aws"
      args = [
        "eks",
        "get-token",
        "--cluster-name",
        aws_eks_cluster.cluster.name,
        "--region",
        "ap-northeast-2"
      ]
    }
  }
}

provider "kubectl" {
  host                   = data.aws_eks_cluster.this.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.this.certificate_authority[0].data)
  load_config_file       = false
  
  # 배스천에서 실행할 때 AWS CLI 사용
  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    args = [
      "eks",
      "get-token",
      "--cluster-name",
      aws_eks_cluster.cluster.name,
      "--region",
      "ap-northeast-2"
    ]
  }
}

# OIDC Provider
resource "aws_iam_openid_connect_provider" "eks" {
  url             = aws_eks_cluster.cluster.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da0ecd3f3d8"]
  depends_on      = [aws_eks_cluster.cluster]
}

# ALB Controller IRSA
resource "aws_iam_policy" "alb_controller" {
  name   = "AWSLoadBalancerControllerIAMPolicy"
  policy = file("${path.module}/files/alb-controller-iam-policy.json")
}
data "aws_iam_policy_document" "alb_irsa_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:kube-system:aws-load-balancer-controller"]
    }
  }
}
resource "aws_iam_role" "alb_irsa" {
  name               = "AmazonEKSLoadBalancerControllerRole"
  assume_role_policy = data.aws_iam_policy_document.alb_irsa_trust.json
}
resource "aws_iam_role_policy_attachment" "alb_attach" {
  role       = aws_iam_role.alb_irsa.name
  policy_arn = aws_iam_policy.alb_controller.arn
}

############################################
# EKS API 보안그룹 설정
############################################
data "aws_security_group" "bastion" {
  id = "sg-0a9213ae0931a3d04"
}

resource "aws_security_group_rule" "eks_api_from_bastion" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  description              = "Allow Bastion to access EKS private API (443)"
  security_group_id        = aws_eks_cluster.cluster.vpc_config[0].cluster_security_group_id
  source_security_group_id = data.aws_security_group.bastion.id
}

# 클러스터 보안그룹에 Karpenter discovery 태그 추가
resource "aws_ec2_tag" "cluster_sg_karpenter" {
  resource_id = aws_eks_cluster.cluster.vpc_config[0].cluster_security_group_id
  key         = "karpenter.sh/discovery"
  value       = "eks-cluster-prod"
}

############################################
# IAM: 노드 롤
############################################
resource "aws_iam_role" "node" {
  name               = "eks-node-iam-role"
  assume_role_policy = <<POLICY
  {
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": { "Service": "ec2.amazonaws.com" },
      "Action": "sts:AssumeRole"
    }]
  }
  POLICY
}

resource "aws_iam_role_policy_attachment" "node_worker" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}
resource "aws_iam_role_policy_attachment" "node_cni" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}
resource "aws_iam_role_policy_attachment" "node_ecr" {
  role       = aws_iam_role.node.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# ===========================================
# Karpenter IAM (iam.tf 권한 통합)
# ===========================================

# Karpenter Controller IRSA Role
data "aws_iam_policy_document" "karpenter_controller_assume_role_policy" {
  statement {
    effect = "Allow"
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.eks.arn]
    }
    actions = ["sts:AssumeRoleWithWebIdentity"]
    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:sub"
      values   = ["system:serviceaccount:karpenter:karpenter"]
    }
    condition {
      test     = "StringEquals"
      variable = "${replace(aws_iam_openid_connect_provider.eks.url, "https://", "")}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "karpenter_controller" {
  name               = "KarpenterController-${aws_eks_cluster.cluster.name}"
  assume_role_policy = data.aws_iam_policy_document.karpenter_controller_assume_role_policy.json

  tags = {
    Name                     = "KarpenterController-${aws_eks_cluster.cluster.name}"
    "karpenter.sh/discovery" = aws_eks_cluster.cluster.name
  }
}

# Attach required AWS managed policies to Karpenter Controller role
resource "aws_iam_role_policy_attachment" "karpenter_controller_worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.karpenter_controller.name
}

resource "aws_iam_role_policy_attachment" "karpenter_controller_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.karpenter_controller.name
}

resource "aws_iam_role_policy_attachment" "karpenter_controller_ecr_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.karpenter_controller.name
}

resource "aws_iam_role_policy_attachment" "karpenter_controller_ssm_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.karpenter_controller.name
}

# Karpenter Controller custom policy for node management
resource "aws_iam_policy" "karpenter_controller" {
  name        = "KarpenterController-${aws_eks_cluster.cluster.name}"
  description = "Karpenter Controller policy for managing EC2 instances"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          # 기존 EC2 및 EKS 권한
          "ec2:DescribeImages",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceTypes",
          "ec2:DescribeInstanceTypeOfferings",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeSpotPriceHistory",
          "ec2:CreateLaunchTemplate",
          "ec2:CreateFleet",
          "ec2:CreateTags",
          "ec2:DeleteLaunchTemplate",
          "ec2:RunInstances",

          # SSM 및 Pricing 권한
          "ssm:GetParameter",
          "pricing:GetProducts",

          # EKS 권한
          "eks:DescribeCluster",

          # 누락된 핵심 IAM 권한들 (이 부분이 중요)
          "iam:GetInstanceProfile",
          "iam:CreateInstanceProfile",
          "iam:DeleteInstanceProfile",
          "iam:AddRoleToInstanceProfile",
          "iam:RemoveRoleFromInstanceProfile",
          "iam:TagInstanceProfile",
          "iam:ListInstanceProfiles",
          "iam:ListInstanceProfilesForRole"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "iam:PassRole"
        ]
        Resource = [
          "arn:aws:iam::*:role/KarpenterNodeInstanceProfile-*",
          "arn:aws:iam::*:role/KarpenterNode*"
        ]
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "ec2.amazonaws.com"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:TerminateInstances",
          "ec2:DeleteTags"
        ]
        Resource = "*"
        Condition = {
          StringLike = {
            "ec2:ResourceTag/karpenter.sh/nodepool" = "*"
          }
        }
      }
    ]
  })

  tags = {
    Name                     = "KarpenterController-${aws_eks_cluster.cluster.name}"
    "karpenter.sh/discovery" = aws_eks_cluster.cluster.name
  }
}

resource "aws_iam_role_policy_attachment" "karpenter_controller_policy" {
  policy_arn = aws_iam_policy.karpenter_controller.arn
  role       = aws_iam_role.karpenter_controller.name
}

# Additional Karpenter Controller permissions for AMI/SSM/EC2 operations
resource "aws_iam_policy" "karpenter_controller_extra" {
  name        = "${aws_eks_cluster.cluster.name}-KarpenterControllerExtra"
  description = "Additional permissions for Karpenter Controller"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:RunInstances",
          "ec2:CreateFleet",
          "ec2:CreateTags",
          "ec2:TerminateInstances",
          "ec2:Describe*",
          "ssm:GetParameter",
          "pricing:GetProducts"
        ]
        Resource = "*"
      },
      {
        Effect   = "Allow"
        Action   = ["iam:PassRole"]
        Resource = aws_iam_role.karpenter_node.arn
      }
    ]
  })

  tags = {
    Name                     = "${aws_eks_cluster.cluster.name}-KarpenterControllerExtra"
    "karpenter.sh/discovery" = aws_eks_cluster.cluster.name
  }
}

resource "aws_iam_role_policy_attachment" "karpenter_controller_extra" {
  policy_arn = aws_iam_policy.karpenter_controller_extra.arn
  role       = aws_iam_role.karpenter_controller.name
}

# IAM Role for Karpenter-managed nodes
resource "aws_iam_role" "karpenter_node" {
  name = "KarpenterNode-${aws_eks_cluster.cluster.name}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name                     = "KarpenterNode-${aws_eks_cluster.cluster.name}"
    "karpenter.sh/discovery" = aws_eks_cluster.cluster.name
  }
}

# Attach required AWS managed policies to Karpenter Node role
resource "aws_iam_role_policy_attachment" "karpenter_node_worker_node_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
  role       = aws_iam_role.karpenter_node.name
}

resource "aws_iam_role_policy_attachment" "karpenter_node_cni_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
  role       = aws_iam_role.karpenter_node.name
}

resource "aws_iam_role_policy_attachment" "karpenter_node_ecr_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
  role       = aws_iam_role.karpenter_node.name
}

resource "aws_iam_role_policy_attachment" "karpenter_node_ssm_policy" {
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  role       = aws_iam_role.karpenter_node.name
}

# Instance Profile for Karpenter-managed nodes
resource "aws_iam_instance_profile" "karpenter_node" {
  name = "KarpenterNodeInstanceProfile-${aws_eks_cluster.cluster.name}"
  role = aws_iam_role.karpenter_node.name

  tags = {
    Name                     = "KarpenterNodeInstanceProfile-${aws_eks_cluster.cluster.name}"
    "karpenter.sh/discovery" = aws_eks_cluster.cluster.name
  }
}

# ===========================================
# Karpenter Helm Installation
# ===========================================
resource "helm_release" "karpenter" {
  name             = "karpenter"
  repository       = "oci://public.ecr.aws/karpenter"
  chart            = "karpenter"
  version          = "1.7.1" # 1.0.6 → 1.7.1로 변경
  namespace        = "karpenter"
  create_namespace = true

  values = [
    yamlencode({
      settings = {
        clusterName = aws_eks_cluster.cluster.name
      }
      serviceAccount = {
        annotations = {
          "eks.amazonaws.com/role-arn" = aws_iam_role.karpenter_controller.arn
        }
      }
    })
  ]

  depends_on = [
    aws_eks_cluster.cluster,
    aws_iam_role_policy_attachment.karpenter_controller_policy,
    aws_eks_addon.coredns,
    aws_eks_addon.kubeproxy,
    aws_eks_addon.vpc_cni
  ]
}

# ===========================================
# Karpenter NodePools (간소화)
# ===========================================
# ArgoCD NodePool
resource "kubectl_manifest" "karpenter_argocd_nodepool" {
  yaml_body = yamlencode({
    apiVersion = "karpenter.sh/v1"
    kind       = "NodePool"
    metadata = {
      name = "argocd-ondemand"
    }
    spec = {
      template = {
        spec = {
          nodeClassRef = {
            apiVersion = "karpenter.k8s.aws/v1"
            kind       = "EC2NodeClass"
            name       = "argocd-ondemand"
          }
          labels = {
            role = "argocd"
          }
          taints = [
            {
              key    = "dedicated"
              value  = "argocd"
              effect = "NoSchedule"
            }
          ]
          requirements = [
            {
              key      = "karpenter.sh/capacity-type"
              operator = "In"
              values   = ["on-demand"]
            },
            {
              key      = "kubernetes.io/arch"
              operator = "In"
              values   = ["amd64"]
            }
          ]
        }
      }
      disruption = {
        consolidationPolicy = "WhenEmpty"
        consolidateAfter    = "10m"
      }
      limits = {
        cpu = "4"
      }
    }
  })

  depends_on = [helm_release.karpenter]
}

# FE NodePool
resource "kubectl_manifest" "karpenter_fe_nodepool" {
  yaml_body = yamlencode({
    apiVersion = "karpenter.sh/v1"
    kind       = "NodePool"
    metadata = {
      name = "fe-ondemand"
    }
    spec = {
      template = {
        spec = {
          nodeClassRef = {
            apiVersion = "karpenter.k8s.aws/v1"
            kind       = "EC2NodeClass"
            name       = "fe-ondemand"
          }
          labels = {
            role = "fe"
          }
          requirements = [
            {
              key      = "karpenter.sh/capacity-type"
              operator = "In"
              values   = ["on-demand"]
            },
            {
              key      = "kubernetes.io/arch"
              operator = "In"
              values   = ["amd64"]
            }
          ]
        }
      }
      disruption = {
        consolidationPolicy = "WhenEmpty"
        consolidateAfter    = "5m"
      }
      limits = {
        cpu = "16"
      }
    }
  })

  depends_on = [helm_release.karpenter]
}

# ===========================================
# EC2NodeClass (간소화)
# ===========================================
# ArgoCD EC2NodeClass
resource "kubectl_manifest" "karpenter_argocd_nodeclass" {
  yaml_body = yamlencode({
    apiVersion = "karpenter.k8s.aws/v1"
    kind       = "EC2NodeClass"
    metadata = {
      name = "argocd-ondemand"
    }
    spec = {
      amiFamily       = "AL2023"
      instanceProfile = aws_iam_instance_profile.karpenter_node.name
      subnetSelectorTerms = [
        {
          tags = {
            "karpenter.sh/discovery" = "eks-cluster-prod"
          }
        }
      ]
      securityGroupSelectorTerms = [
        {
          tags = {
            "karpenter.sh/discovery" = "eks-cluster-prod"
          }
        }
      ]
    }
  })

  depends_on = [helm_release.karpenter]
}

# FE EC2NodeClass
resource "kubectl_manifest" "karpenter_fe_nodeclass" {
  yaml_body = yamlencode({
    apiVersion = "karpenter.k8s.aws/v1"
    kind       = "EC2NodeClass"
    metadata = {
      name = "fe-ondemand"
    }
    spec = {
      amiFamily       = "AL2023"
      instanceProfile = aws_iam_instance_profile.karpenter_node.name
      subnetSelectorTerms = [
        {
          tags = {
            "karpenter.sh/discovery" = "eks-cluster-prod"
          }
        }
      ]
      securityGroupSelectorTerms = [
        {
          tags = {
            "karpenter.sh/discovery" = "eks-cluster-prod"
          }
        }
      ]
    }
  })

  depends_on = [helm_release.karpenter]
}

############################################
# Node Group - CICD 전용 (최소화)
############################################
resource "aws_eks_node_group" "ng_cicd" {
  cluster_name    = aws_eks_cluster.cluster.name
  node_group_name = "ng-cicd"
  node_role_arn   = aws_iam_role.node.arn

  subnet_ids     = [data.aws_subnet.pvt_2a.id, data.aws_subnet.pvt_2c.id]
  instance_types = ["t3a.medium"]
  capacity_type  = "ON_DEMAND"

  labels = { role = "argocd" }

  taint {
    key    = "dedicated"
    value  = "argocd"
    effect = "NO_SCHEDULE"
  }

  scaling_config {
    desired_size = 1
    min_size     = 1
    max_size     = 3
  }

  remote_access {
    ec2_ssh_key               = "test_mh_bation_cicd"
    source_security_group_ids = ["sg-0a9213ae0931a3d04"]
  }

  depends_on = [
    aws_eks_cluster.cluster,
    aws_iam_role_policy_attachment.node_worker,
    aws_iam_role_policy_attachment.node_cni,
    aws_iam_role_policy_attachment.node_ecr
  ]
}

############################################
# EKS Add-ons
############################################
resource "aws_eks_addon" "coredns" {
  cluster_name = aws_eks_cluster.cluster.name
  addon_name   = "coredns"
  configuration_values = jsonencode({
    tolerations = [{
      key = "dedicated", operator = "Equal", value = "argocd", effect = "NoSchedule"
    }]
  })
}
resource "aws_eks_addon" "kubeproxy" {
  cluster_name = aws_eks_cluster.cluster.name
  addon_name   = "kube-proxy"
}
resource "aws_eks_addon" "vpc_cni" {
  cluster_name = aws_eks_cluster.cluster.name
  addon_name   = "vpc-cni"
}

############################################
# 출력
############################################
output "cluster_name" { value = aws_eks_cluster.cluster.name }
output "cluster_endpoint" { value = aws_eks_cluster.cluster.endpoint }
*/
