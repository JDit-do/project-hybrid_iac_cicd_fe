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
  }
}
provider "aws" {
  region = "ap-northeast-2"
}

############################################
# 네트워크: VPC/서브넷/SG "조회"
############################################
# VPC 태그
data "aws_vpc" "vpc" {
  filter {
    name = "tag:Name"
    values = ["test-mh-eks-vpc"] 
  }
}

# 각 서브넷 Name 태그
data "aws_subnet" "pub_2a" {
  filter {
    name = "tag:Name"
    values = ["test-mh-eks-subnet-public1-ap-northeast-2a"]
  }
  filter {
    name = "vpc-id"
    values = [data.aws_vpc.vpc.id]
  }
}
data "aws_subnet" "pub_2b" {
  filter {
    name = "tag:Name"
    values = ["test-mh-eks-subnet-public2-ap-northeast-2b"]
  }
  filter {
    name = "vpc-id"
    values = [data.aws_vpc.vpc.id]
  }
}
data "aws_subnet" "pvt_2a" {
  filter {
    name = "tag:Name"
    values = ["test-mh-eks-subnet-private1-ap-northeast-2a"]
  }
  filter {
    name = "vpc-id"
    values = [data.aws_vpc.vpc.id]
  }
}
data "aws_subnet" "pvt_2b" {
  filter {
    name = "tag:Name"
    values = ["test-mh-eks-subnet-private2-ap-northeast-2b"]
  }
  filter {
    name = "vpc-id"
    values = [data.aws_vpc.vpc.id]
  }
}


############################################
# NAT for private egress (퍼블릭 2a에 NAT, 프라이빗 2a/2b를 NAT로 라우팅)
############################################
# 프라이빗 서브넷에 실제 연결된 라우트 테이블 조회
data "aws_route_table" "rt_pvt_2a" {
  subnet_id = data.aws_subnet.pvt_2a.id
}
data "aws_route_table" "rt_pvt_2b" {
  subnet_id = data.aws_subnet.pvt_2b.id
}

# NAT용 EIP, NAT 게이트웨이 (퍼블릭 2a 생성)
resource "aws_eip" "nat" {
  domain = "vpc"
  tags   = { Name = "eks-nat-eip" }
}
resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = data.aws_subnet.pub_2a.id 
  tags          = { Name = "eks-nat" }
}

# 프라이빗 RT에 기본 경로(0.0.0.0/0) → NAT 추가
resource "aws_route" "pvt_2a_default" {
  route_table_id         = data.aws_route_table.rt_pvt_2a.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat.id
}
resource "aws_route" "pvt_2b_default" {
  route_table_id         = data.aws_route_table.rt_pvt_2b.id
  destination_cidr_block = "0.0.0.0/0"
  nat_gateway_id         = aws_nat_gateway.nat.id
}


# 클러스터에 추가로 달 보안그룹
# 없으면 아래 EKS vpc_config에서 security_group_ids 줄을 지워도 됩니다.
data "aws_security_group" "web" {
  name   = "test_mh_eks_sg" 
  vpc_id = data.aws_vpc.vpc.id
}

############################################
# IAM: 클러스터 롤
############################################
resource "aws_iam_role" "eks_cluster" {
  name = "eks-cluster-iam-role"
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
  name     = "test-mh-eks-cluster"
  role_arn = aws_iam_role.eks_cluster.arn
  version  = "1.33"           # EKS 참조하여 최신 지정

  enabled_cluster_log_types = ["api","audit","authenticator"]

  vpc_config {
    # 클러스터는 **서로 다른 AZ의 서브넷 2개 이상** 필요 → 프라이빗 2a, 2b 지정
    subnet_ids = [data.aws_subnet.pvt_2a.id, data.aws_subnet.pvt_2b.id]

    # (옵션) SG 추가하고 싶을 때 사용
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

############################################
# EKS API(프라이빗 엔드포인트) ← Bastion 허용
############################################

# (1) 배스천 보안그룹 조회 - 네 SG ID로 바꿔주세요
data "aws_security_group" "bastion" {
  id = "sg-0c9d5e2a89083a70a"  # bastion SG ID ## 변경
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
  name = "eks-node-iam-role"
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

  subnet_ids     = [data.aws_subnet.pvt_2a.id, data.aws_subnet.pvt_2b.id]
  instance_types = ["t3.small"] # 테스트 용으로 작은 사양 지정
  capacity_type  = "ON_DEMAND"

  # "이 노드는 CICD용" 표시
  labels = { role = "cicd" }

  # CICD 전용으로 강제(다른 파드가 못 올라오게)
  taint {
    key    = "dedicated"
    value  = "cicd"
    effect = "NO_SCHEDULE"   # 대문자 (NoSchedule 아님)
  }

  scaling_config { # 사양 선택한 이유와 동일: 테스트용으로 시작
    desired_size = 1
    min_size     = 1
    max_size     = 2
  }

  # SSH 허용(기존 배스천 SG 재사용)
  remote_access {
    ec2_ssh_key               = "test_mh_bation_cicd"
    source_security_group_ids = ["sg-0c9d5e2a89083a70a"]
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

  # 두 AZ 분산(가용성) — 원가 줄이려면 1개 AZ로 시작 가능
  subnet_ids     = [data.aws_subnet.pvt_2a.id, data.aws_subnet.pvt_2b.id]
  instance_types = ["t3.medium"]
  capacity_type  = "ON_DEMAND"

  labels = { role = "fe" }

  # FE만 허용하려면 주석 해제
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
    source_security_group_ids = ["sg-0c9d5e2a89083a70a"]
  }

  depends_on = [
    aws_eks_cluster.cluster,
    aws_iam_role_policy_attachment.node_worker,
    aws_iam_role_policy_attachment.node_cni,
    aws_iam_role_policy_attachment.node_ecr
  ]
}


############################################
# Add-ons
############################################
#resource "aws_eks_addon" "coredns"   { cluster_name = aws_eks_cluster.cluster.name; addon_name = "coredns" }
#resource "aws_eks_addon" "kubeproxy" { cluster_name = aws_eks_cluster.cluster.name; addon_name = "kube-proxy" }
#resource "aws_eks_addon" "vpc_cni"   { cluster_name = aws_eks_cluster.cluster.name; addon_name = "vpc-cni" }

############################################
# 출력
############################################
output "cluster_name"     { value = aws_eks_cluster.cluster.name }
output "cluster_endpoint" { value = aws_eks_cluster.cluster.endpoint }

