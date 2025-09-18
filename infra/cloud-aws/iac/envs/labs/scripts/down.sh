#!/bin/bash
set -euo pipefail
make snapshot || true
make down
