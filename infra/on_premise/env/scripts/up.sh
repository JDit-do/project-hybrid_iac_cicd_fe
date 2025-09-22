#!/bin/bash
set -euo pipefail
make up
make install-argocd
make wait-argocd
make apply-ingress
make snapshot
