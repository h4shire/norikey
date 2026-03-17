#!/bin/bash
# NORIKEY DEPLOYMENT SCRIPT (Phase 1 placeholder)

set -euo pipefail

echo "[*] Launching NoriKey preflight..."
./norikey unlock --container vault.nk --config config.yaml
