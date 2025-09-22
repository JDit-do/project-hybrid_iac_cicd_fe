# Optional toggle: create S3 Gateway VPC Endpoint (defaults to false since one often exists)
variable "create_s3_gw_endpoint" {
  type    = bool
  default = false
}

# Create NAT gateway for private egress (mirrors working config). Disable if your VPC already has NAT.
variable "create_nat_gw" {
  type    = bool
  default = false
}

# Optional: Bastion SG ID to allow access to private EKS API endpoint
variable "bastion_sg_id" {
  type    = string
  default = ""
}

# Public EKS API access CIDRs (set your bastion public IP/32)
variable "public_access_cidrs" {
  type    = list(string)
  default = ["0.0.0.0/0"]
}
terraform {
  required_version = ">= 1.4.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

###############################
# Providers
###############################

provider "aws" {
  region = "ap-northeast-2"
}

###############################
# Networking: VPC, Subnets, Routes
###############################

locals {
  name            = "eks-onprem"
  cluster_tag_key = "kubernetes.io/cluster/tmp-onpremise"
}

data "aws_vpc" "vpc" {
  filter {
    name   = "tag:Name"
    values = ["eks-memory-vpc"]
  }
}

# Subnets by Name tag within the VPC
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

###############################
# Private route tables (for S3 gateway endpoint)
###############################

data "aws_route_table" "rt_pvt_2a" {
  subnet_id = data.aws_subnet.pvt_2a.id
}

data "aws_route_table" "rt_pvt_2c" {
  subnet_id = data.aws_subnet.pvt_2c.id
}

###############################
# Node security group (open 80/443 within VPC)
###############################

resource "aws_security_group" "nodes_web" {
  name        = "tmp-onpremise-nodes-web"
  description = "Allow HTTP/HTTPS within VPC to worker nodes"
  vpc_id      = data.aws_vpc.vpc.id

  ingress {
    description = "HTTP from VPC"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.vpc.cidr_block]
  }

  ingress {
    description = "HTTPS from VPC"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.vpc.cidr_block]
  }

  ingress {
    description = "HTTP-alt (8080) from VPC"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.vpc.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

###############################
# Launch Template to attach node SG
###############################

resource "aws_launch_template" "nodes" {
  name_prefix = "tmp-onpremise-nodes-"
  key_name    = "test_mh_bation_cicd"

  network_interfaces {
    security_groups = [
      aws_security_group.nodes_web.id,
      aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
    ]
  }
  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "tmp-onpremise-node"
    }
  }
}

resource "aws_security_group" "vpce" {
  name        = "tmp-onpremise-vpce"
  description = "Allow HTTPS from VPC to Interface Endpoints"
  vpc_id      = data.aws_vpc.vpc.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [data.aws_vpc.vpc.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# S3 (Gateway endpoint) for image pulls/bootstrap assets
resource "aws_vpc_endpoint" "s3" {
  count             = var.create_s3_gw_endpoint ? 1 : 0
  vpc_id            = data.aws_vpc.vpc.id
  service_name      = "com.amazonaws.ap-northeast-2.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [data.aws_route_table.rt_pvt_2a.id, data.aws_route_table.rt_pvt_2c.id]
}

###############################
# NAT for private egress (public 2a)
###############################

resource "aws_eip" "nat" {
  count  = var.create_nat_gw ? 1 : 0
  domain = "vpc"
  tags   = { Name = "tmp-onpremise-nat-eip" }
}

resource "aws_nat_gateway" "nat" {
  count         = var.create_nat_gw ? 1 : 0
  allocation_id = aws_eip.nat[0].id
  subnet_id     = data.aws_subnet.pub_2a.id
  tags          = { Name = "tmp-onpremise-nat" }
}

resource "aws_route" "pvt_2a_default" {
  count                  = var.create_nat_gw ? 1 : 0
  route_table_id         = data.aws_route_table.rt_pvt_2a.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat[0].id
}

resource "aws_route" "pvt_2c_default" {
  count                  = var.create_nat_gw ? 1 : 0
  route_table_id         = data.aws_route_table.rt_pvt_2c.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat[0].id
}

# ECR API (Interface)
resource "aws_vpc_endpoint" "ecr_api" {
  vpc_id              = data.aws_vpc.vpc.id
  service_name        = "com.amazonaws.ap-northeast-2.ecr.api"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [data.aws_subnet.pvt_2a.id, data.aws_subnet.pvt_2c.id]
  security_group_ids  = [aws_security_group.vpce.id]
  private_dns_enabled = true
}

# ECR DKR (Interface)
resource "aws_vpc_endpoint" "ecr_dkr" {
  vpc_id              = data.aws_vpc.vpc.id
  service_name        = "com.amazonaws.ap-northeast-2.ecr.dkr"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [data.aws_subnet.pvt_2a.id, data.aws_subnet.pvt_2c.id]
  security_group_ids  = [aws_security_group.vpce.id]
  private_dns_enabled = true
}

# STS (Interface) for node auth
resource "aws_vpc_endpoint" "sts" {
  vpc_id              = data.aws_vpc.vpc.id
  service_name        = "com.amazonaws.ap-northeast-2.sts"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = [data.aws_subnet.pvt_2a.id, data.aws_subnet.pvt_2c.id]
  security_group_ids  = [aws_security_group.vpce.id]
  private_dns_enabled = true
}

###############################
# AWS Load Balancer Controller IRSA (policy + role)
###############################

data "aws_iam_policy" "alb_controller" {
  name = "AWSLoadBalancerControllerIAMPolicy"
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
  name               = "AmazonEKSLoadBalancerControllerRole-eks-onprem"
  assume_role_policy = data.aws_iam_policy_document.alb_irsa_trust.json
}

resource "aws_iam_role_policy_attachment" "alb_attach" {
  role       = aws_iam_role.alb_irsa.name
  policy_arn = data.aws_iam_policy.alb_controller.arn
}

###############################
# Allow Bastion to reach EKS private API (optional)
###############################

data "aws_security_group" "bastion" {
  count = var.bastion_sg_id != "" ? 1 : 0
  id    = var.bastion_sg_id
}

resource "aws_security_group_rule" "eks_api_from_bastion" {
  count                    = var.bastion_sg_id != "" ? 1 : 0
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  description              = "Allow Bastion to access EKS private API (443)"
  security_group_id        = aws_eks_cluster.this.vpc_config[0].cluster_security_group_id
  source_security_group_id = data.aws_security_group.bastion[0].id
}

###############################
# EKS IAM
###############################

resource "aws_iam_role" "eks_cluster" {
  name = "tmp-onpremise-cluster-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect    = "Allow",
      Principal = { Service = "eks.amazonaws.com" },
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy_attachment" "eks_vpc_rc" {
  role       = aws_iam_role.eks_cluster.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSVPCResourceController"
}

resource "aws_iam_role" "node" {
  name = "tmp-onpremise-node-role"
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

###############################
# EKS Cluster
###############################

resource "aws_eks_cluster" "this" {
  name     = local.name
  role_arn = aws_iam_role.eks_cluster.arn
  version  = "1.33"

  vpc_config {
    subnet_ids              = [data.aws_subnet.pvt_2a.id, data.aws_subnet.pvt_2c.id]
    endpoint_private_access = true
    endpoint_public_access  = true
    public_access_cidrs     = var.public_access_cidrs
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator"]

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_iam_role_policy_attachment.eks_vpc_rc
  ]
}

###############################
# IRSA OIDC Provider for cluster
###############################

resource "aws_iam_openid_connect_provider" "eks" {
  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da0ecd3f3d8"]
  depends_on      = [aws_eks_cluster.this]
}

###############################
# Managed Node Group (2 nodes, ~4vCPU/16GiB)
###############################

resource "aws_eks_node_group" "default" {
  cluster_name    = aws_eks_cluster.this.name
  node_group_name = "onpremise"
  node_role_arn   = aws_iam_role.node.arn

  subnet_ids     = [data.aws_subnet.pvt_2a.id, data.aws_subnet.pvt_2c.id]
  instance_types = ["t3a.xlarge"]
  ami_type       = "AL2023_x86_64_STANDARD"
  capacity_type  = "ON_DEMAND"

  update_config {
    max_unavailable = 1
  }

  scaling_config {
    desired_size = 2
    min_size     = 2
    max_size     = 3
  }

  labels = {
    role = "worker"
  }

  launch_template {
    id      = aws_launch_template.nodes.id
    version = "$Latest"
  }

  depends_on = [
    aws_eks_cluster.this,
    aws_iam_role_policy_attachment.node_worker,
    aws_iam_role_policy_attachment.node_cni,
    aws_iam_role_policy_attachment.node_ecr
  ]

  timeouts {
    create = "15m"
    update = "15m"
    delete = "15m"
  }
}

###############################
# EKS Add-ons
###############################

resource "aws_eks_addon" "coredns" {
  cluster_name = aws_eks_cluster.this.name
  addon_name   = "coredns"
  depends_on   = [aws_eks_node_group.default]
}

resource "aws_eks_addon" "kubeproxy" {
  cluster_name = aws_eks_cluster.this.name
  addon_name   = "kube-proxy"
  depends_on   = [aws_eks_node_group.default]
}

resource "aws_eks_addon" "vpc_cni" {
  cluster_name = aws_eks_cluster.this.name
  addon_name   = "vpc-cni"
  depends_on   = [aws_eks_node_group.default]
}

###############################
# Subnet cluster tags required by EKS/ALB (apply to existing subnets)
###############################

resource "aws_ec2_tag" "cluster_tag_public_2a" {
  resource_id = data.aws_subnet.pub_2a.id
  key         = "kubernetes.io/cluster/${aws_eks_cluster.this.name}"
  value       = "shared"
}
resource "aws_ec2_tag" "cluster_tag_public_2c" {
  resource_id = data.aws_subnet.pub_2c.id
  key         = "kubernetes.io/cluster/${aws_eks_cluster.this.name}"
  value       = "shared"
}
resource "aws_ec2_tag" "cluster_tag_private_2a" {
  resource_id = data.aws_subnet.pvt_2a.id
  key         = "kubernetes.io/cluster/${aws_eks_cluster.this.name}"
  value       = "shared"
}
resource "aws_ec2_tag" "cluster_tag_private_2c" {
  resource_id = data.aws_subnet.pvt_2c.id
  key         = "kubernetes.io/cluster/${aws_eks_cluster.this.name}"
  value       = "shared"
}

# 추가: ALB가 서브넷을 인식하도록 role 태그
resource "aws_ec2_tag" "pub_2a_role" {
  resource_id = data.aws_subnet.pub_2a.id
  key         = "kubernetes.io/role/elb"
  value       = "1"
}
resource "aws_ec2_tag" "pub_2c_role" {
  resource_id = data.aws_subnet.pub_2c.id
  key         = "kubernetes.io/role/elb"
  value       = "1"
}
resource "aws_ec2_tag" "pvt_2a_role" {
  resource_id = data.aws_subnet.pvt_2a.id
  key         = "kubernetes.io/role/internal-elb"
  value       = "1"
}
resource "aws_ec2_tag" "pvt_2c_role" {
  resource_id = data.aws_subnet.pvt_2c.id
  key         = "kubernetes.io/role/internal-elb"
  value       = "1"
}

###############################
# Outputs
###############################

output "vpc_id" { value = data.aws_vpc.vpc.id }
output "cluster_name" { value = aws_eks_cluster.this.name }
output "cluster_endpoint" { value = aws_eks_cluster.this.endpoint }
output "private_subnet_ids" { value = [data.aws_subnet.pvt_2a.id, data.aws_subnet.pvt_2c.id] }
