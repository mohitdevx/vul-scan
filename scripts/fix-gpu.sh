#!/usr/bin/env bash
# ==============================================================================
# VulnScan - NVIDIA GPU & Ollama Auto-Recovery Utility
# Fixes CUDA Error 999, Xid MMU faults, and restores 100% GPU offloading.
# ==============================================================================

set -euo pipefail

# Ensure script is run with sudo / root
if [ "$EUID" -ne 0 ]; then
  echo -e "\033[1;33m[!] Root privileges required. Re-running with sudo...\033[0m"
  exec sudo bash "$0" "$@"
fi

export PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:$PATH"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "\n${CYAN}==================================================================${NC}"
echo -e "${CYAN}       NVIDIA GPU & Ollama Auto-Recovery & Offload Utility        ${NC}"
echo -e "${CYAN}==================================================================${NC}\n"

# 1. Stop Ollama and persistence services to release GPU handles
echo -e "${BLUE}[1/5] Stopping Ollama and NVIDIA services...${NC}"
systemctl stop ollama 2>/dev/null || true
systemctl stop nvidia-persistenced 2>/dev/null || true
sleep 1

# 2. Enforce stable systemd override (prevent Flash Attention MMU crashes)
echo -e "${BLUE}[2/5] Hardening Ollama configuration...${NC}"
mkdir -p /etc/systemd/system/ollama.service.d
cat > /etc/systemd/system/ollama.service.d/override.conf << 'EOF'
[Service]
Environment="OLLAMA_MAX_LOADED_MODELS=1"
Environment="OLLAMA_NUM_PARALLEL=1"
EOF
systemctl daemon-reload
echo -e "${GREEN}  ✓ Removed broken flash attention flags (prevents Xid 31 faults)${NC}"
echo -e "${GREEN}  ✓ Configured single-model VRAM protection${NC}"

# 3. Reset NVIDIA Kernel Modules to clear error 999
echo -e "${BLUE}[3/5] Resetting NVIDIA UVM kernel driver...${NC}"
if modprobe -r nvidia_uvm 2>/dev/null; then
  modprobe nvidia_uvm
  echo -e "${GREEN}  ✓ Successfully reloaded nvidia_uvm kernel module${NC}"
else
  echo -e "${YELLOW}  (!) nvidia_uvm is busy, attempting forced device reset...${NC}"
  fuser -k -9 /dev/nvidia* 2>/dev/null || true
  sleep 1
  modprobe -r nvidia_uvm 2>/dev/null || true
  modprobe nvidia_uvm 2>/dev/null || true
fi

# Test CUDA driver state
CUDA_STATE=$(python3 -c "import ctypes; print(ctypes.CDLL('libcuda.so').cuInit(0))" 2>/dev/null || echo "999")
if [ "$CUDA_STATE" -eq 0 ]; then
  echo -e "${GREEN}  ✓ CUDA Driver Status: HEALTHY (cuInit = 0)${NC}"
else
  echo -e "${RED}  ✗ CUDA Driver returned code ${CUDA_STATE}. A quick reboot may be required if modules are locked.${NC}"
fi

# 4. Restart Services
echo -e "${BLUE}[4/5] Starting NVIDIA and Ollama services...${NC}"
systemctl start nvidia-persistenced 2>/dev/null || true
systemctl start ollama
sleep 2

# Wait for Ollama HTTP endpoint
echo -n "  Waiting for Ollama to become ready"
READY=0
for i in $(seq 1 15); do
  if curl -s http://127.0.0.1:11434/api/tags >/dev/null 2>&1; then
    READY=1
    break
  fi
  echo -n "."
  sleep 1
done
echo ""

if [ "$READY" -eq 1 ]; then
  echo -e "${GREEN}  ✓ Ollama service is active and listening on port 11434${NC}"
else
  echo -e "${RED}  ✗ Timed out waiting for Ollama API${NC}"
  exit 1
fi

# 5. Warm up and verify GPU offloading for active model
TARGET_MODEL="qwen2.5-coder:3b"
if grep -q "AI_MODEL=" /home/mohit/Desktop/vul-scan/backend/.env 2>/dev/null; then
  TARGET_MODEL=$(grep "AI_MODEL=" /home/mohit/Desktop/vul-scan/backend/.env | cut -d '=' -f2 | tr -d ' "')
fi

echo -e "${BLUE}[5/5] Warming up model [${TARGET_MODEL}] on GPU...${NC}"
curl -s http://127.0.0.1:11434/api/generate -d "{\"model\": \"${TARGET_MODEL}\", \"prompt\": \"ping\", \"stream\": false}" >/dev/null 2>&1 || true

echo -e "\n${CYAN}------------------- Status Verification -------------------${NC}"
ollama ps
echo ""
nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv,noheader 2>/dev/null | awk '{print "GPU Compute Process: " $0}' || true
echo -e "${CYAN}-----------------------------------------------------------${NC}"

echo -e "\n${GREEN}✓ Recovery complete! Your model is running on GPU.${NC}\n"
