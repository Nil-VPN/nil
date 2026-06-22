#!/bin/bash
# Runs INSIDE the macOS VM (driven by verify-macos-vm.sh). Brings up the tunnel via the
# macOS datapath, checks tunneled HTTPS, tests the kill-switch (the host stops the node
# mid-window), then tears down — restoring networking (and SSH) at the end.
exec > /tmp/verify.log 2>&1
echo "[baseline] egress (no tunnel): $(curl -s --max-time 8 https://ifconfig.me)"
sudo env NW_NODE_HOST=192.168.64.1 NW_NODE_PORT=443 NW_DNS=1.1.1.1 \
  RUST_LOG=info,nil_datapath=debug,nil_transport=info /Users/admin/nil-cli > /tmp/cli.log 2>&1 &
trap 'sudo pkill -INT -x nil-cli 2>/dev/null; sleep 3' EXIT
for _ in $(seq 1 25); do grep -q "tunnel up" /tmp/cli.log 2>/dev/null && break; sleep 1; done
if ! grep -q "tunnel up" /tmp/cli.log; then
  echo "[FAIL] tunnel did not come up"; echo "--- cli.log ---"; tail -40 /tmp/cli.log; exit 1
fi
echo "[up] routes:"; netstat -rn -f inet 2>/dev/null | grep -E "^default|utun" | head
echo "[a] curl https://example.com -> HTTP $(curl -s -o /dev/null -w '%{http_code}' --max-time 15 https://example.com)"
echo "[b] tunnel egress IP: $(curl -s --max-time 15 https://ifconfig.me)"
echo "[ready] node-stop window open; sleeping 16s"
sleep 16
echo -n "[c] curl after expected node stop: "
if curl -s -o /dev/null --max-time 6 https://example.com; then echo "traffic FLOWED (LEAK - FAIL)"; else echo "BLOCKED fail-closed (PASS)"; fi
echo "[teardown] stopping nil-cli (restores networking)"
sudo pkill -INT -x nil-cli 2>/dev/null
sleep 3
echo "[restored] egress: $(curl -s --max-time 8 https://ifconfig.me)"
echo "DONE"
