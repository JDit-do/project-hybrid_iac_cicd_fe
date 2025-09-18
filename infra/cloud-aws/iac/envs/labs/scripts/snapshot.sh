#!/bin/bash
set -euo pipefail

STACK="${STACK:-$(terraform output -raw cluster_name 2>/dev/null || echo 'unknown')}"
AWS_REGION="${AWS_REGION:-ap-northeast-2}"
OUTDIR="${OUTDIR:-snapshots}"
STAMP="$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUTDIR"

FILE="${OUTDIR}/${STAMP}_${STACK}_snapshot.txt"

{
  echo "=== SNAPSHOT ==="
  echo "Timestamp : $STAMP"
  echo "Cluster   : $STACK"
  echo "Region    : $AWS_REGION"
  echo

  echo "--- Nodes ---"
  kubectl get nodes -o wide 2>/dev/null || echo "(kubectl not reachable)"
  echo

  echo "--- Pods (All NS) ---"
  kubectl get pods -A -o wide 2>/dev/null || echo "(kubectl not reachable)"
  echo

  echo "--- Services (All NS) ---"
  kubectl get svc -A 2>/dev/null || echo "(kubectl not reachable)"
  echo

  echo "--- Ingress (All NS) ---"
  kubectl get ingress -A -o wide 2>/dev/null || echo "(kubectl not reachable)"
  echo

  echo "--- Helm Releases ---"
  helm ls -A 2>/dev/null || echo "(helm not reachable)"
  echo

  echo "--- ALB Load Balancers ---"
  aws elbv2 describe-load-balancers --region "$AWS_REGION" \
    --query "LoadBalancers[].{Name:LoadBalancerName,DNS:DNSName,State:State.Code}" \
    --output table 2>/dev/null || echo "(no elbv2 perms or none)"
} | tee "$FILE"

echo "Snapshot saved to $FILE"

