#!/usr/bin/env bash
# Provisioning OS du bac AEGIS V3D — commandes EXACTES rejouables (admin/sudo).
# Conforme à THREAT_MODEL.md §1/§4/§5. Idempotent.
set -euo pipefail

# 1. Identités OS séparées (rôles du modèle de menace)
sudo useradd -r -M -s /usr/sbin/nologin aegis_pep 2>/dev/null || true
sudo useradd -r -M -s /usr/sbin/nologin aegis_witness 2>/dev/null || true
sudo useradd -r -M -s /usr/sbin/nologin aegis_agent 2>/dev/null || true

# 2. Traversée minimale du home pour exécuter le venv partagé sous UID distincts
sudo chmod 711 /home/user

# 3. Arborescence du bac à sable
sudo rm -rf /tmp/aegis_v3d_sandbox
sudo mkdir -p /tmp/aegis_v3d_sandbox/{config,effect,state,witness,logs,req,agent_out}
sudo chown root:root /tmp/aegis_v3d_sandbox/config
sudo chown aegis_pep:aegis_pep /tmp/aegis_v3d_sandbox/effect /tmp/aegis_v3d_sandbox/state /tmp/aegis_v3d_sandbox/logs
sudo chown aegis_witness:aegis_witness /tmp/aegis_v3d_sandbox/witness
sudo chown user:user /tmp/aegis_v3d_sandbox/req
sudo chown aegis_agent:aegis_agent /tmp/aegis_v3d_sandbox/agent_out
sudo chmod 755 /tmp/aegis_v3d_sandbox/config /tmp/aegis_v3d_sandbox/effect /tmp/aegis_v3d_sandbox/req
sudo chmod 700 /tmp/aegis_v3d_sandbox/state /tmp/aegis_v3d_sandbox/witness /tmp/aegis_v3d_sandbox/logs /tmp/aegis_v3d_sandbox/agent_out

# 4. Provisionnement crypto + politique (génère tests/keys/ + config root-owned)
python3 tests/provision_config.py

echo "sandbox ready: /tmp/aegis_v3d_sandbox"
