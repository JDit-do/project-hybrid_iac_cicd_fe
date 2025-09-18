# 라벨 role과 테인트 cicd에서 argocd로 변경

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

# 🔧 각 서브넷 Name 태그 (같은 VPC에 있어야 함)
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

# ===[ADD] Subnet/Cluster tags for ALB ===
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
# ===[END ADD]===

############################################
# NAT for private egress (퍼블릭 2a에 NAT, 프라이빗 2a/2b를 NAT로 라우팅)
############################################

# 프라이빗 서브넷에 실제 연결된 라우트 테이블 조회
data "aws_route_table" "rt_pvt_2a" {
  subnet_id = data.aws_subnet.pvt_2a.id
}
data "aws_route_table" "rt_pvt_2c" {
  subnet_id = data.aws_subnet.pvt_2c.id
}

# NAT용 EIP + NAT 게이트웨이 (퍼블릭 2a에 생성)
resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "eks-nat-eip-prod" }
}
resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = data.aws_subnet.pub_2a.id # 퍼블릭 2a
  tags          = { Name = "eks-nat-prod" }
}

# 프라이빗 RT에 기본 경로(0.0.0.0/0) → NAT 추가
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


# (선택) 클러스터에 추가로 달 보안그룹
# 없으면 아래 EKS vpc_config에서 security_group_ids 줄을 지워도 됩니다.
data "aws_security_group" "web" {
  name   = "eks-prod-sg" # 존재하면 사용
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
# EKS Cluster (프라이빗/퍼블릭 엔드포인트 선택)
############################################
resource "aws_eks_cluster" "cluster" {
  name     = "eks-cluster-prod"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = "1.33"

  enabled_cluster_log_types = ["api", "audit", "authenticator"]

  vpc_config {
    # 클러스터는 **서로 다른 AZ의 서브넷 2개 이상** 필요 → 프라이빗 2a, 2c 지정
    subnet_ids = [data.aws_subnet.pvt_2a.id, data.aws_subnet.pvt_2c.id]

    # (옵션) SG 추가하고 싶을 때만 사용
    # security_group_ids = [data.aws_security_group.web.id]

    # 엔드포인트 접근
    endpoint_private_access = true
    endpoint_public_access  = false
    # 노트북에서 바로 붙어서 테스트하고 싶으면 임시로:
    # endpoint_public_access  = true
    # public_access_cidrs     = ["내공인IP/32"]   # 필수로 IP 제한!
  }

  depends_on = [
    aws_iam_role_policy_attachment.eks_cluster_policy,
    aws_iam_role_policy_attachment.eks_vpc_rc
  ]
}

# ===[ADD] EKS data sources for Helm/Kubernetes providers ===
data "aws_eks_cluster" "this" {
  name       = aws_eks_cluster.cluster.name
  depends_on = [aws_eks_cluster.cluster]
}

data "aws_eks_cluster_auth" "this" {
  name       = aws_eks_cluster.cluster.name
  depends_on = [aws_eks_cluster.cluster]
}


# ===[ADD] IRSA OIDC Provider (static thumbprint OK) ===
resource "aws_iam_openid_connect_provider" "eks" {
  url             = aws_eks_cluster.cluster.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["9e99a48a9960b14926bb7f3b02e22da0ecd3f3d8"] # 폐쇄망이면 임시로 OK
  depends_on      = [aws_eks_cluster.cluster]
}
# ===[END ADD]===

# ===[ADD] ALB Controller IRSA (policy + role) ===
# 공식 정책 JSON 파일을 같은 디렉터리에 두고 파일명은 아래와 동일하게:
# https://docs.aws.amazon.com/eks/latest/userguide/lbc-helm.html?utm_source=chatgpt.com
# https://github.com/kubernetes-sigs/aws-load-balancer-controller?utm_source=chatgpt.com
#   ./alb-controller-iam-policy.json
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
# ===[END ADD]===


############################################
# EKS API(프라이빗 엔드포인트) ← Bastion 허용
############################################

# (1) 배스천 보안그룹 조회 - 네 SG ID로 바꿔주세요
data "aws_security_group" "bastion" {
  id = "sg-0a9213ae0931a3d04" # bastion SG ID ## 변경
}

# (2) 클러스터 SG에 443 인바운드 허용 (소스 = bastion SG)
resource "aws_security_group_rule" "eks_api_from_bastion" {
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  description              = "Allow Bastion to access EKS private API (443)"
  security_group_id        = aws_eks_cluster.cluster.vpc_config[0].cluster_security_group_id
  source_security_group_id = data.aws_security_group.bastion.id
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


############################################
# Node Group - CICD 전용 (ArgoCD 등)
############################################
resource "aws_eks_node_group" "ng_cicd" {
  cluster_name    = aws_eks_cluster.cluster.name
  node_group_name = "ng-cicd"
  node_role_arn   = aws_iam_role.node.arn

  # 작게 시작 + 한 AZ만 (원하면 2a/2b 모두 넣어도 OK)
  subnet_ids     = [data.aws_subnet.pvt_2a.id, data.aws_subnet.pvt_2c.id]
  instance_types = ["t3a.medium"] # t3.small에서 t3a.medium으로 변경. Memory 이슈 발생
  # 현재 기준 호환성 좋은거 사용하고 싶고, 10% 절감하고 싶으면 t4g.medium
  # m8g - 성능 예측이 가능할때 넘어가는 걸 고려.. Production..
  capacity_type = "ON_DEMAND"

  # "이 노드는 CICD용" 표시
  labels = { role = "argocd" }

  # CICD 전용으로 강제(다른 파드가 못 올라오게)
  taint {
    key    = "dedicated"
    value  = "argocd"
    effect = "NO_SCHEDULE" # 대문자 (NoSchedule 아님)
  }

  scaling_config { # memory 이슈 발생으로 1 -> 2로 변경(사양도 변경), t3 - 병렬로 처리와 HA(최소 3개 권장)
    desired_size = 3
    min_size     = 3
    max_size     = 4
  }

  # 필요 시 SSH 허용(기존 배스천 SG 재사용)
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
# Node Group - FE 전용
############################################
resource "aws_eks_node_group" "ng_fe" {
  cluster_name    = aws_eks_cluster.cluster.name
  node_group_name = "ng-fe"
  node_role_arn   = aws_iam_role.node.arn

  # 두 AZ 분산(가용성) — 원가 줄이려면 1개 AZ로도 시작 가능
  subnet_ids     = [data.aws_subnet.pvt_2a.id, data.aws_subnet.pvt_2c.id]
  instance_types = ["t3a.medium"]
  capacity_type  = "ON_DEMAND"

  labels = { role = "fe" }
  # (선택) FE만 허용하려면 주석 해제
  # taint {
  #   key    = "dedicated"
  #   value  = "fe"
  #   effect = "NO_SCHEDULE"
  # }

  scaling_config {
    desired_size = 2
    min_size     = 1
    max_size     = 4
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
# (선택) Add-ons
############################################
# ===[ADD] EKS Add-ons (optional, version pin later) ===
resource "aws_eks_addon" "coredns" {
  cluster_name = aws_eks_cluster.cluster.name
  addon_name   = "coredns"
}
resource "aws_eks_addon" "kubeproxy" {
  cluster_name = aws_eks_cluster.cluster.name
  addon_name   = "kube-proxy"
}
resource "aws_eks_addon" "vpc_cni" {
  cluster_name = aws_eks_cluster.cluster.name
  addon_name   = "vpc-cni"
}
# ===[END ADD]===


############################################
# 출력
############################################
output "cluster_name" { value = aws_eks_cluster.cluster.name }
output "cluster_endpoint" { value = aws_eks_cluster.cluster.endpoint }
