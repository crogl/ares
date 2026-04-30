#!/bin/bash
# One-time ares EC2 setup: Redis, log dirs, systemd worker template
set -euo pipefail

echo "=== Installing Redis ==="
if command -v redis-server >/dev/null 2>&1; then
	redis-server --version
else
	if command -v apt-get >/dev/null 2>&1; then
		apt-get update -qq && apt-get install -y -qq redis-server
	elif command -v yum >/dev/null 2>&1; then
		yum install -y redis
	elif command -v dnf >/dev/null 2>&1; then
		dnf install -y redis
	else
		echo "ERROR: No supported package manager found"
		exit 1
	fi
fi

echo "=== Creating directories ==="
mkdir -p /var/log/ares /etc/ares

echo "=== Removing legacy ares-worker@ unit (renamed in PR #226) ==="
if [ -f /etc/systemd/system/ares-worker@.service ]; then
	for role in recon credential_access cracker acl privesc lateral coercion; do
		systemctl disable --now "ares-worker@${role}.service" 2>/dev/null || true
	done
	rm -f /etc/systemd/system/ares-worker@.service
fi

echo "=== Creating system-ares.slice with global memory cap ==="
cat >/etc/systemd/system/system-ares.slice <<'SLICE_EOF'
[Unit]
Description=Ares system slice (orchestrator + workers)
Before=slices.target

[Slice]
MemoryMax=12G
MemoryHigh=10G
TasksMax=8192
SLICE_EOF

echo "=== Ensuring 4G swap file (OOM cushion) ==="
if [ ! -f /swapfile ] || [ "$(stat -c%s /swapfile 2>/dev/null || echo 0)" -lt 4000000000 ]; then
	swapoff /swapfile 2>/dev/null || true
	rm -f /swapfile
	fallocate -l 4G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=4096
	chmod 600 /swapfile
	mkswap /swapfile
	swapon /swapfile
	if ! grep -q '^/swapfile' /etc/fstab; then
		echo '/swapfile none swap sw 0 0' >>/etc/fstab
	fi
fi

echo "=== Tuning OOM behavior (oom_kill_allocating_task, swappiness) ==="
cat >/etc/sysctl.d/90-ares.conf <<'SYSCTL_EOF'
vm.oom_kill_allocating_task = 1
vm.swappiness = 10
SYSCTL_EOF
sysctl -p /etc/sysctl.d/90-ares.conf >/dev/null

echo "=== Creating systemd worker template unit ==="
cat >/etc/systemd/system/ares@.service <<'UNIT_EOF'
[Unit]
Description=Ares Worker (%i)
After=redis.service
Wants=redis.service

[Service]
Type=simple
ExecStart=/usr/local/bin/ares worker
EnvironmentFile=-/etc/ares/env
Environment=ARES_REDIS_URL=redis://127.0.0.1:6379
Environment=ARES_WORKER_ROLE=%i
Environment=ARES_WORKER_MODE=tool_exec
Environment=RUST_LOG=info
Environment=OTEL_RESOURCE_ATTRIBUTES=deployment.environment=staging,attack.team=red
Restart=on-failure
RestartSec=5
StandardOutput=append:/var/log/ares/%i.log
StandardError=append:/var/log/ares/%i.log

# Contain child processes (netexec, hashcat, nmap, etc.) within this cgroup.
# Without these limits, runaway tool processes can OOM the entire system and
# take down the SSM agent (see: Apr 2026 incident).
Delegate=yes
Slice=system-ares.slice
MemoryHigh=1500M
MemoryMax=2G
TasksMax=256

[Install]
WantedBy=multi-user.target
UNIT_EOF
systemctl daemon-reload

echo "=== Installing cracking tools ==="
if ! command -v hashcat >/dev/null 2>&1 || ! command -v john >/dev/null 2>&1; then
	if command -v apt-get >/dev/null 2>&1; then
		apt-get install -y -qq hashcat john
	fi
fi

echo "=== Fixing pip/system impacket conflicts ==="
# Kali's system impacket has patches (regsecrets) that pip versions lack.
# Remove any pip-installed impacket that shadows the system package.
if [ -d /usr/local/lib/python3.13/dist-packages/impacket ]; then
	pip3 uninstall -y impacket --break-system-packages 2>/dev/null || true
	rm -rf /usr/local/lib/python3.13/dist-packages/impacket \
		/usr/local/lib/python3.13/dist-packages/impacket-*.dist-info
	echo "Removed pip impacket shadow — using system package"
fi

echo "=== Enabling Redis ==="
systemctl enable redis-server 2>/dev/null || systemctl enable redis 2>/dev/null || true
systemctl start redis-server 2>/dev/null || systemctl start redis 2>/dev/null || true
systemctl daemon-reload

echo "=== Setup complete ==="
redis-cli ping 2>/dev/null || echo "Redis not responding"
