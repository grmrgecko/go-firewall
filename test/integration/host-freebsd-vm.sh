#!/usr/bin/env bash
# HOST script — run this on your workstation. It boots a throwaway FreeBSD QEMU VM
# and runs the pf integration backend inside it.
#
# FreeBSD's pf runs natively, so the VM *is* the test environment: it
# enables pf with a minimal ruleset, mounts the freebsd-cross-compiled test binary
# from the host over a virtio-9p share, and runs it with FIREWALL_BACKEND=pf. The
# same pf backend serves macOS, which cannot be automated in a VM.
#
# Usage:
#   ./host-freebsd-vm.sh
#
# The overlay disk is kept between runs by default. pf state lives in the kernel and
# is cleared on every reboot (reloaded from /etc/pf.conf), so reuse just needs a
# fresh cloud-init seed with a unique instance-id each run so cloud-init executes
# the test payload on every boot. Set GOFW_VM_REUSE=0 to force a fresh overlay each
# run; deleting .cache/freebsd-overlay.qcow2 also resets it.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

IMAGE_URL="${GOFW_FBSD_IMAGE_URL:-https://download.freebsd.org/releases/VM-IMAGES/15.1-RELEASE/amd64/Latest/FreeBSD-15.1-RELEASE-amd64-BASIC-CLOUDINIT-ufs.qcow2.xz}"
MEM="${GOFW_VM_MEM:-2048}"
CPUS="${GOFW_VM_CPUS:-2}"
CACHE="${GOFW_VM_CACHE:-$repo/.cache}"
REUSE="${GOFW_VM_REUSE:-1}"             # 1 = keep the overlay disk between runs (default)
BOOT_TIMEOUT="${GOFW_VM_TIMEOUT:-1200}"
SHUTDOWN_GRACE="${GOFW_VM_SHUTDOWN_GRACE:-60}" # seconds to wait for a clean poweroff before killing

mkdir -p "$CACHE"
base="$CACHE/freebsd.qcow2"
overlay="$CACHE/freebsd-overlay.qcow2"
seed="$CACHE/freebsd-seed.iso"
console="$CACHE/freebsd-console.log"
bin="$CACHE/firewall.test.freebsd"

command -v qemu-system-x86_64 >/dev/null || { echo "!! qemu-system-x86_64 not found"; exit 1; }
command -v genisoimage >/dev/null || { echo "!! genisoimage not found"; exit 1; }

echo ">> cross-compiling freebsd test binary on host"
( cd "$repo" && GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go test -c -tags integration -o "$bin" . )

if [[ ! -f "$base" ]]; then
	echo ">> downloading FreeBSD cloud image -> $base"
	curl -L --fail -o "$base.xz" "$IMAGE_URL"
	xz -dc "$base.xz" >"$base"
	rm -f "$base.xz"
fi

# Reuse the overlay only when asked and one already exists; otherwise start fresh.
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
instance_id="gofw-it-fbsd-${run_id}"

work="$(mktemp -d "$CACHE/fbsd-seed.XXXXXX")"
trap 'rm -rf "$work"' EXIT

cat >"$work/meta-data" <<EOF
instance-id: ${instance_id}
local-hostname: gofw-it-fbsd
EOF

cat >"$work/user-data" <<EOF
#cloud-config
bootcmd:
  # Skip the FreeBSD cloud image's first-boot freebsd-update/pkg fetch — it adds
  # minutes of patch downloads and is irrelevant to the test. Runs before the
  # firstboot rc scripts (a fresh overlay re-triggers them every run otherwise).
  - [ rm, -f, /firstboot ]
write_files:
  - path: /etc/pf.conf
    content: |
      set skip on lo0
runcmd:
  - sysrc pf_enable=YES
  - service pf start
  - sh -c 'kldload virtio_p9fs 2>/dev/null || true'
  - mkdir -p /mnt/gofw-cache
  - mount -t p9fs gofwcache /mnt/gofw-cache
  - cp /mnt/gofw-cache/firewall.test.freebsd /root/firewall.test
  - chmod +x /root/firewall.test
  - sh -c 'echo GOFW_VM_BEGIN; env FIREWALL_BACKEND=pf /root/firewall.test -test.v -test.run TestIntegration; echo "GOFW_VM_DONE rc=\$?"'
  - poweroff
EOF

genisoimage -quiet -output "$seed" -volid CIDATA -joliet -rock \
	"$work/user-data" "$work/meta-data"

echo ">> booting FreeBSD VM (serial console below; it powers off when finished)"
echo "   Ctrl-C requests a clean ACPI shutdown (force-killed after ${SHUTDOWN_GRACE}s)."
echo "   ------------------------------------------------------------------"
: >"$console"

# HMP monitor on a localhost-only, transient TCP port so the interrupt/timeout
# handlers can ask the guest to power off cleanly, poked via bash /dev/tcp.
mon_port=$(( 20000 + RANDOM % 20000 ))

# Stream serial through a FIFO so we hold qemu's real PID and tee flushes the log
# deterministically before we read it.
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

set +e
qemu-system-x86_64 \
	-enable-kvm -cpu host -m "$MEM" -smp "$CPUS" \
	-drive file="$overlay",if=virtio,format=qcow2 \
	-drive file="$seed",if=virtio,format=raw \
	-netdev user,id=n0 -device virtio-net-pci,netdev=n0 \
	-fsdev local,id=fs0,path="$CACHE",security_model=none,readonly=on \
	-device virtio-9p-pci,fsdev=fs0,mount_tag=gofwcache \
	-monitor tcp:127.0.0.1:"$mon_port",server,nowait \
	-serial stdio -display none -no-reboot </dev/null >"$fifo" 2>&1 &
qemu_pid=$!

# Wait for the VM, enforcing the boot timeout, while staying interruptible.
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

echo
echo "==== FreeBSD pf run summary ===="
if grep -q "GOFW_VM_DONE" "$console"; then
	grep -E -- '--- (PASS|FAIL|SKIP): |^(PASS|FAIL|ok)\b|GOFW_VM_DONE' "$console" | sed 's/\r$//'
	rc="$(grep -o 'GOFW_VM_DONE rc=[0-9]*' "$console" | tail -1 | grep -o '[0-9]*$')"
	echo "(full serial log: $console)"
	exit "${rc:-1}"
fi
echo "!! the in-VM run did not complete (no GOFW_VM_DONE marker). See $console"
exit 1
