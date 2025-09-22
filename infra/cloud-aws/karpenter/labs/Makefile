AWS_REGION ?= ap-northeast-2
TF := terraform
ARGOCD_NS ?= argocd
ARGOCD_VALUES ?= ./apps/argocd/values.yaml
INGRESS_FILE ?= ./apps/argocd/ingress.yaml

# terraform output -raw cluster_name 을 여러 곳에서 쓰므로 함수처럼 사용
define TF_CLUSTER_NAME
$(shell $(TF) output -raw cluster_name 2>/dev/null)
endef

.PHONY: up kubeconfig install-argocd apply-ingress wait-argocd snapshot down all cluster argo lbc-install lbc-uninstall lbc-status lbc-kubeconfig

# EKS 클러스터 생성
up:
	$(TF) init -upgrade
	$(TF) apply -auto-approve

kubeconfig:
	@[ -n "$(call TF_CLUSTER_NAME)" ] || (echo "cluster_name output 이 비었습니다. terraform apply 먼저 실행하세요." && exit 1)
	aws eks update-kubeconfig --name $(call TF_CLUSTER_NAME) --region $(AWS_REGION)

# AWS Load Balancer Controller
LBC_VERSION ?= 1.8.1

lbc-kubeconfig:  ## EKS kubeconfig 갱신
	@[ -n "$(call TF_CLUSTER_NAME)" ] || (echo "cluster_name output 이 비었습니다. terraform apply 먼저 실행하세요." && exit 1)
	aws eks update-kubeconfig --name $(call TF_CLUSTER_NAME) --region $(AWS_REGION)

lbc-install: lbc-kubeconfig  ## ALB Controller 설치/업그레이드
	# 차트 리포 준비
	helm repo add eks https://aws.github.io/eks-charts >/dev/null 2>&1 || true
	helm repo update >/dev/null 2>&1 || true
	# 필요한 값 준비 (IRSA Role ARN, VPC ID)
	LBC_ROLE_ARN=$$(aws iam get-role --role-name AmazonEKSLoadBalancerControllerRole --query 'Role.Arn' --output text); \
	VPC_ID=$$(aws ec2 describe-vpcs --filters "Name=tag:Name,Values=eks-memory-vpc" --query 'Vpcs[0].VpcId' --output text); \
	helm upgrade --install aws-load-balancer-controller eks/aws-load-balancer-controller \
	  -n kube-system --create-namespace \
	  --version $(LBC_VERSION) \
	  --set clusterName=$(call TF_CLUSTER_NAME) \
	  --set region=$(AWS_REGION) \
	  --set vpcId=$$VPC_ID \
	  --set serviceAccount.create=true \
	  --set serviceAccount.name=aws-load-balancer-controller \
	  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"=$$LBC_ROLE_ARN

lbc-uninstall: lbc-kubeconfig  ## ALB Controller 제거
	helm uninstall aws-load-balancer-controller -n kube-system || true

lbc-status: lbc-kubeconfig  ## 상태 확인
	kubectl -n kube-system get deploy,po -l app.kubernetes.io/name=aws-load-balancer-controller

# argocd 설치
install-argocd: kubeconfig
	# 차트 리포 준비
	helm repo add argo https://argoproj.github.io/argo-helm >/dev/null 2>&1 || true
	helm repo update >/dev/null 2>&1 || true
	# 네임스페이스 생성(존재해도 통과)
	kubectl create ns $(ARGOCD_NS) --dry-run=client -o yaml | kubectl apply -f -
	# 비용 절감 전략:
	# - ArgoCD 서버 Service는 ClusterIP로 내부만 노출(외부 LB 미생성)
	# - 외부 접근이 필요할 때만 별도로 `make apply-ingress`를 실행해 ALB(Ingress) 생성
	helm upgrade --install argocd argo/argo-cd -n $(ARGOCD_NS) -f $(ARGOCD_VALUES)

wait-argocd:
	# 컨트롤 플레인 준비 대기(너무 엄격할 필요 없으니 server/redis 정도 확인)
	kubectl -n $(ARGOCD_NS) rollout status deploy/argocd-server --timeout=5m || true
	kubectl -n $(ARGOCD_NS) rollout status deploy/argocd-repo-server --timeout=5m || true


apply-ingress: kubeconfig
	@if [ -f "$(INGRESS_FILE)" ]; then \
	  echo "Applying Ingress from $(INGRESS_FILE)"; \
	  kubectl apply -f $(INGRESS_FILE); \
	else \
	  echo "WARNING: $(INGRESS_FILE) 없음. Ingress 적용 건너뜀"; \
	fi


# 스냅샷
snapshot:
	STACK=$(call TF_CLUSTER_NAME) AWS_REGION=$(AWS_REGION) bash ./scripts/snapshot.sh
	@echo "------ ArgoCD admin password ------"
	@kubectl -n $(ARGOCD_NS) get secret argocd-initial-admin-secret \
	  -o jsonpath="{.data.password}" | base64 -d; echo
	@echo "-----------------------------------"

# 삭제
down:
	# Ingress는 파괴 전에 지워두면 ALB 고아 방지에 도움
	@if [ -f "$(INGRESS_FILE)" ]; then kubectl delete -f $(INGRESS_FILE) --ignore-not-found; fi
	# argocd는 클러스터 파괴 시 함께 사라지므로 helm uninstall 은 생략 가능
	$(TF) destroy -auto-approve

# terraform 정리
clean-local:
	rm -rf .terraform .terraform.lock.hcl
	rm -rf ~/.terraform.d/plugin-cache ~/.terraform.d/plugins || true
	rm -rf /tmp/tfdata /tmp/tfplugins || true

# 전체 실행(스핀업 → LBC → ArgoCD → Ingress → 스냅샷)
all: up lbc-install install-argocd wait-argocd apply-ingress snapshot

# Convenience aliases
cluster: up kubeconfig

argo: install-argocd wait-argocd apply-ingress
