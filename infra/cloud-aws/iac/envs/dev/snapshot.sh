#!/usr/bin/env bash
set -euo pipefail

STACK="${STACK:-dev}"
AWS_REGION="${AWS_REGION:-ap-northeast-2}"
OUTDIR="${OUTDIR:-snapshots}"
STAMP="$(date +%Y%m%d-%H%M%S)"

mkdir -p "$OUTDIR"

meta_file="${OUTDIR}/${STAMP}_${STACK}_meta.txt"
state_file="${OUTDIR}/${STAMP}_${STACK}_k8s.txt"
helm_file="${OUTDIR}/${STAMP}_${STACK}_helm.txt"
ing_file="${OUTDIR}/${STAMP}_${STACK}_ingress.txt"
alb_file="${OUTDIR}/${STAMP}_${STACK}_alb.json"

# --- META ---
{
  echo "timestamp: $STAMP"
  echo "stack: $STACK"
  echo "aws_region: $AWS_REGION"
  echo "git_sha: $(git rev-parse --short HEAD 2>/dev/null || echo 'NA')"
  echo "terraform_workspace: $(cd infra/terraform && terraform workspace show 2>/dev/null || echo 'default')"
  echo "eks_cluster: ${STACK}-eks"
  echo "whoami: $(whoami)"
} | tee "$meta_file"

# kubeconfig 보장 (이미 되어 있으면 통과)
aws eks update-kubeconfig --name "${STACK}-eks" --region "$AWS_REGION" >/dev/null 2>&1 || true

# --- K8S STATE ---
{
  echo "=== NODES ==="
  kubectl get nodes -o wide || true
  echo
  echo "=== NAMESPACES ==="
  kubectl get ns || true
  echo
  echo "=== ALL RESOURCES (brief) ==="
  kubectl get all -A || true
  echo
  echo "=== PVC ==="
  kubectl get pvc -A || true
} | tee "$state_file"

# --- HELM RELEASES ---
helm ls -A | tee "$helm_file" || true

# --- INGRESS/SVC ---
{
  echo "=== INGRESS ==="
  kubectl get ingress -A -o wide || true
  echo
  echo "=== SVC ==="
  kubectl get svc -A -o wide || true
} | tee "$ing_file"

# --- ALB (optional; requires IAM perms) ---
aws elbv2 describe-load-balancers --region "$AWS_REGION" > "$alb_file" 2>/dev/null || echo '{"note":"no permission or no elbv2"}' > "$alb_file"

echo "Snapshot saved under: $OUTDIR (prefix: ${STAMP}_${STACK}_*)"
