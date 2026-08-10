#!/usr/bin/env bash
# HOST script — run this on your workstation. It boots a throwaway QEMU VM and
# runs the Linux integration backends inside it.
#
# Why a VM: the systemd backends (firewalld/ufw/iptables/csf/apf) need a booted
# systemd and, for real isolation between six backends that all fight over the same
# kernel netfilter/ipset state, a disposable environment we can freely reconfigure.
# We run a minimal Ubuntu server cloud-init image in qemu for that disposability,
# same as we would need even if the backends ran natively on bare metal.
#
# Usage:
#   ./host-linux-vm.sh                # all backends: nft firewalld ufw iptables apf csf
#   ./host-linux-vm.sh firewalld      # a subset
#
# The overlay disk is kept between runs by default: the first run creates it and
# provisions each requested backend on first use (package installs, third-party
# csf/apf downloads); later runs boot the same disk with those backends already
# provisioned and go straight to testing. Because provisioning is per-backend and
# keyed on each backend's clean-config snapshot, a fresh overlay only pays for the
# backends a given run actually touches, and a later run adds any not-yet-seen
# backend on demand. A fresh cloud-init seed is generated every run with a unique
# instance-id, so cloud-init executes the test payload on every boot. Backend
# firewall state does not persist across backends within a run — guest-linux-run.sh
# flushes and rsync-restores clean config between every backend. Set GOFW_VM_REUSE=0
# to force a fresh overlay each run; deleting .cache/overlay.qcow2 also resets it.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

backends=("$@")
if [[ ${#backends[@]} -eq 0 ]]; then
	backends=(nft firewalld ufw iptables apf csf)
fi

IMAGE_URL="${GOFW_VM_IMAGE_URL:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img}"
MEM="${GOFW_VM_MEM:-4096}"
CPUS="${GOFW_VM_CPUS:-2}"
CACHE="${GOFW_VM_CACHE:-$repo/.cache}"
REUSE="${GOFW_VM_REUSE:-1}"             # 1 = keep the overlay disk between runs (default)
BOOT_TIMEOUT="${GOFW_VM_TIMEOUT:-2400}" # seconds; covers apt installs, csf/apf downloads, and tests
SHUTDOWN_GRACE="${GOFW_VM_SHUTDOWN_GRACE:-60}" # seconds to wait for a clean poweroff before killing

mkdir -p "$CACHE"
base="$CACHE/base.img"
overlay="$CACHE/overlay.qcow2"
seed="$CACHE/seed.iso"
console="$CACHE/console.log"
bin="$CACHE/firewall.test"

command -v qemu-system-x86_64 >/dev/null || { echo "!! qemu-system-x86_64 not found"; exit 1; }
command -v genisoimage >/dev/null || { echo "!! genisoimage not found"; exit 1; }

echo ">> compiling test binary on host (Go toolchain lives here, not in the VM)"
# Write into $CACHE (shared into the guest as the writable gofwcache mount), not the
# repo tree — the repo is shared read-only and should stay free of build artifacts.
( cd "$repo" && CGO_ENABLED=0 go test -c -tags integration -o "$bin" . )

if [[ ! -f "$base" ]]; then
	echo ">> downloading base cloud image -> $base"
	curl -L --fail -o "$base.tmp" "$IMAGE_URL"
	mv "$base.tmp" "$base"
fi

# Reuse the overlay only when asked and one already exists; otherwise start fresh.
# guest-linux-run.sh provisions each backend lazily and keys the "already
# provisioned" check on its per-backend snapshot, so a reused overlay's snapshots
# simply cause it to skip re-provisioning — the host does not need to track or
# signal fresh-vs-reused at all.
if [[ "$REUSE" = 1 ]] && [[ -f "$overlay" ]]; then
	echo ">> reusing existing overlay disk (GOFW_VM_REUSE=1): $overlay"
else
	echo ">> creating a fresh overlay disk (base stays pristine)"
	rm -f "$overlay"
	qemu-img create -f qcow2 -b "$base" -F qcow2 "$overlay" 20G >/dev/null
fi

# A fresh cloud-init seed is generated for every run. The unique instance-id makes
# each boot look like a new instance to cloud-init, so per-instance modules
# (write_files and runcmd) execute on both the first and every reused boot.
run_id="$(date +%s)-${RANDOM}"
instance_id="gofw-it-${run_id}"

# --- cloud-init seed --------------------------------------------------------
work="$(mktemp -d "$CACHE/seed.XXXXXX")"
trap 'rm -rf "$work"' EXIT

cat >"$work/meta-data" <<EOF
instance-id: ${instance_id}
local-hostname: gofw-it
EOF

cat >"$work/user-data" <<EOF
#cloud-config
write_files:
  - path: /usr/local/bin/gofw-guest-payload.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      set -x
      # Authorize the in-VM guest script to run its destructive backend setup.
      # guest-linux-run.sh refuses to run without this (or the disposable-VM
      # marker below), so a workstation cannot execute it by accident.
      export GOFW_ALLOW_RUN=1
      mkdir -p /mnt/gofw /mnt/gofw-cache
      mount -t 9p -o trans=virtio,version=9p2000.L,ro gofwrepo /mnt/gofw
      mount -t 9p -o trans=virtio,version=9p2000.L,rw gofwcache /mnt/gofw-cache
      cd /mnt/gofw
      touch /etc/gofw-disposable-vm
      echo "GOFW_VM_BEGIN"
      ./test/integration/guest-linux-run.sh ${backends[*]}
      echo "GOFW_VM_DONE rc=\$?"
      sync
      poweroff
runcmd:
  - [ bash, /usr/local/bin/gofw-guest-payload.sh ]
EOF

genisoimage -quiet -output "$seed" -volid CIDATA -joliet -rock \
	"$work/user-data" "$work/meta-data"

# --- boot -------------------------------------------------------------------
echo ">> booting VM (serial console below; it powers off when finished)"
echo "   backends: ${backends[*]}"
echo "   Ctrl-C requests a clean ACPI shutdown (force-killed after ${SHUTDOWN_GRACE}s)."
echo "   ------------------------------------------------------------------"
: >"$console"

# HMP monitor on a localhost-only, transient TCP port so the interrupt/timeout
# handlers can ask the guest to power off cleanly, poked via bash /dev/tcp (no
# extra tools). A clean ACPI shutdown matters now that the overlay is persisted.
mon_port=$(( 20000 + RANDOM % 20000 ))

# Stream serial through a FIFO instead of a pipeline so we hold qemu's real PID
# (to signal it) and tee flushes the log deterministically before we read it.
fifo="$work/qemu.out"
mkfifo "$fifo"
tee "$console" <"$fifo" &
tee_pid=$!

qemu_pid=""
interrupted=0
timed_out=0

# stop_vm asks the guest for a clean ACPI poweroff, waits SHUTDOWN_GRACE seconds,
# then hard-kills if it overruns. Idempotent; safe to call more than once.
stop_vm() {
	kill -0 "$qemu_pid" 2>/dev/null || return 0
	if exec 3<>"/dev/tcp/127.0.0.1/$mon_port" 2>/dev/null; then
		printf 'system_powerdown\n' >&3
		exec 3<&- 3>&-
	fi
	for _ in $(seq 1 "$SHUTDOWN_GRACE"); do
		kill -0 "$qemu_pid" 2>/dev/null || return 0
		sleep 1
	done
	echo "!! VM did not power off within ${SHUTDOWN_GRACE}s; killing it" >&2
	kill -9 "$qemu_pid" 2>/dev/null || true
}

# on_interrupt drives a clean shutdown on Ctrl-C; further signals are ignored so a
# second Ctrl-C cannot abort mid-shutdown and orphan qemu. Invoked via the trap below.
# shellcheck disable=SC2329  # invoked indirectly by `trap on_interrupt INT TERM`.
on_interrupt() {
	trap '' INT TERM
	interrupted=1
	echo >&2
	echo ">> interrupt received; asking the VM to power off cleanly…" >&2
	stop_vm
}
trap on_interrupt INT TERM

# fs1/gofwcache is writable (unlike fs0/gofwrepo) and backed by the same host
# directory used for the VM images, so guest-linux-run.sh can cache downloaded
# csf/apf packages there during provisioning and reuse them across VM overlay
# rebuilds instead of re-fetching from the network every time.
set +e
qemu-system-x86_64 \
	-enable-kvm -cpu host -m "$MEM" -smp "$CPUS" \
	-drive file="$overlay",if=virtio,format=qcow2 \
	-drive file="$seed",if=virtio,format=raw \
	-netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
	-fsdev local,id=fs0,path="$repo",security_model=none,readonly=on \
	-device virtio-9p-pci,fsdev=fs0,mount_tag=gofwrepo \
	-fsdev local,id=fs1,path="$CACHE",security_model=none \
	-device virtio-9p-pci,fsdev=fs1,mount_tag=gofwcache \
	-monitor tcp:127.0.0.1:"$mon_port",server,nowait \
	-serial stdio -display none -no-reboot </dev/null >"$fifo" 2>&1 &
qemu_pid=$!

# Wait for the VM, enforcing the boot timeout. Sleeping in a backgrounded child we
# then wait on keeps the loop interruptible so the Ctrl-C trap fires promptly.
deadline=$(( SECONDS + BOOT_TIMEOUT ))
while kill -0 "$qemu_pid" 2>/dev/null; do
	if [[ "$SECONDS" -ge "$deadline" ]]; then
		timed_out=1
		echo >&2
		echo "!! VM exceeded ${BOOT_TIMEOUT}s; shutting it down" >&2
		stop_vm
		break
	fi
	sleep 2 & wait $! 2>/dev/null
done
wait "$qemu_pid" 2>/dev/null
trap - INT TERM
wait "$tee_pid" 2>/dev/null   # let tee drain the FIFO and flush the console log
set -e

echo "   ------------------------------------------------------------------"
if [[ "$interrupted" = 1 ]]; then
	echo "!! run interrupted; VM stopped. Partial serial log: $console"
	exit 130
fi
if [[ "$timed_out" = 1 ]]; then
	echo "!! VM timed out after ${BOOT_TIMEOUT}s (see $console)"
	exit 124
fi

# --- results ----------------------------------------------------------------
echo
echo "==== VM run summary ===="
if grep -q "GOFW_VM_DONE" "$console"; then
	sed -n '/==== integration results ====/,/GOFW_VM_DONE/p' "$console" | sed 's/\r$//'
	rc="$(grep -o 'GOFW_VM_DONE rc=[0-9]*' "$console" | tail -1 | grep -o '[0-9]*$')"
	echo "(full serial log: $console)"
	exit "${rc:-1}"
fi
echo "!! the in-VM run did not complete (no GOFW_VM_DONE marker). See $console"
exit 1
