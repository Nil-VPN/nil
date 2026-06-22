#!/usr/bin/env bash
# Phase 1b verification — the macOS-native datapath (utun + pf + scutil), run in a tart
# macOS VM so the host Mac is never touched. macOS analog of verify.sh (Linux/Docker).
#
# Prereqs (one-time):
#   brew trust cirruslabs/cli && brew install cirruslabs/cli/tart
#   tart clone ghcr.io/cirruslabs/macos-sequoia-base:latest nil-vm   # ~25-30 GB
#   tart run --no-graphics nil-vm &                                  # boot
#   ssh-copy-id -i ~/.ssh/nil_vm_ed25519.pub admin@$(tart ip nil-vm) # pw: admin
#
# Topology: the node is Linux, so it runs in Docker on the host with UDP 443 published;
# the macOS VM reaches it at the host's tart gateway (192.168.64.1).
#
# Note the kill-switch (pf "block all except node:443 + tun") cuts SSH into the VM while
# armed, so the checks run as a self-contained in-VM script that tears down at the end;
# we read the results afterward. The node is stopped from the host mid-run to test (c).
set -uo pipefail
VM=${VM:-nil-vm}
KEY=${KEY:-$HOME/.ssh/nil_vm_ed25519}
HOST_GW=${HOST_GW:-192.168.64.1}   # host as seen from the tart VM
SSH="ssh -i $KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null admin@$(tart ip "$VM")"
SCP="scp -i $KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
VMIP=$(tart ip "$VM")

echo "==> build macOS nil-cli (dev-insecure) + copy into VM"
( cd "$(dirname "$0")/.." && cargo build --release -p nil-cli --features dev-insecure )
$SCP "$(dirname "$0")/../target/release/nil-cli" "admin@$VMIP:/Users/admin/nil-cli"
$SCP "$(dirname "$0")/vm_verify.sh" "admin@$VMIP:/tmp/vm_verify.sh"
${=SSH} 'chmod +x ~/nil-cli /tmp/vm_verify.sh'

echo "==> start the Linux node on the host (Docker), UDP 443 published"
docker rm -f nil-node-vm >/dev/null 2>&1 || true
docker run -d --name nil-node-vm --cap-add=NET_ADMIN --device /dev/net/tun \
  --sysctl net.ipv4.ip_forward=1 -p 443:443/udp \
  -e NW_NODE_BIND=0.0.0.0:443 -e NW_NODE_EGRESS=eth0 deploy-node nil-node
sleep 3

echo "==> run the in-VM verification (detached) + stop node mid-window for the kill-switch test"
${=SSH} 'nohup bash /tmp/vm_verify.sh >/tmp/vm_verify.out 2>&1 & echo launched'
sleep 9; docker stop nil-node-vm; sleep 30

echo "==> results (networking restored, SSH back):"
${=SSH} 'cat /tmp/verify.log'
docker rm -f nil-node-vm >/dev/null 2>&1 || true
echo "(VM left running; 'tart stop $VM' to stop, 'tart delete $VM' to reclaim disk)"
