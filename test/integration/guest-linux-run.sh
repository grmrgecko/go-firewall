#!/usr/bin/env bash
# IN-VM script — runs inside the disposable VM, launched by cloud-init from
# host-linux-vm.sh. Do NOT run it on a workstation: it installs packages and
# enables/disables real backends, rewriting /etc/csf, /etc/apf, /etc/ufw, and
# iptables config, which would reconfigure a real host. A GOFW_ALLOW_RUN /
# disposable-VM-marker guard below refuses to run otherwise.
#
# Runs the go-firewall integration suite against real backends natively inside the
# disposable VM. This script loops sequentially over the requested backends (never
# in parallel — they all share the same kernel netfilter/ipset state) and for each
# one lazily provisions it on first use, then runs its test:
#
#   ensure_provisioned  — if the backend has no clean-config snapshot yet, install
#                         its packages, seed a minimal/clean config, and snapshot
#                         it under /root/gofw-base/<backend>/ (mirroring its real
#                         absolute path). Skipped once a snapshot exists, so a
#                         reused VM overlay provisions nothing.
#   flush_kernel_state  — clear leftover kernel netfilter/ipset state.
#   restore_config      — rsync the clean snapshot back over the live config.
#   enable_backend      — start the backend.
#   run the test binary — one backend at a time.
#   disable_backend     — stop it again, pass or fail, before the next backend.
#
# Provisioning per backend (rather than all backends up front) means a run limited
# to a subset only pays for the packages it needs — csf and apf in particular pull
# from third-party network sources (see fetch_cached), which is slow and flaky, so
# a run that never touches them never downloads them.
#
# To run, use the Makefile:
#
#   make test-integration-linux

set -u
export DEBIAN_FRONTEND=noninteractive

BASE=/root/gofw-base
CACHE_DIR=/mnt/gofw-cache

# Refuse to run unless the disposable-VM marker is present. Installing packages and
# enabling/disabling firewalld/ufw/csf/apf/iptables-persistent operates directly on
# the real host's firewall and systemd state, which is dangerous to do by accident
# on a workstation. host-linux-vm.sh writes the marker before invoking this script
# and exports GOFW_ALLOW_RUN=1 for the guest payload; either is accepted here.
MARKER=/etc/gofw-disposable-vm
if [[ ! -f "$MARKER" ]] && [[ "${GOFW_ALLOW_RUN:-0}" != "1" ]]; then
	echo "!! guest-linux-run.sh must be run from inside the disposable test VM, not on your machine." >&2
	echo "   It installs backend packages and enables/disables real backends (firewalld, ufw," >&2
	echo "   csf, apf, iptables-persistent), which would reconfigure a real host's firewall." >&2
	echo "   Use:  make test-integration-linux" >&2
	exit 1
fi

backends=("$@")
if [[ ${#backends[@]} -eq 0 ]]; then
	backends=(nft iptables firewalld ufw csf apf)
fi

# The host compiles the test binary into its .cache, shared here as the writable
# gofwcache mount (CACHE_DIR) — the repo share is read-only and holds no artifacts.
BIN="$CACHE_DIR/firewall.test"

# flush_kernel_state clears the shared netfilter/ipset state every backend reads
# and writes, so nothing one backend's test leaves behind can leak into the next
# backend's run. Run before AND after every backend: before, because a prior run
# in this same VM boot may have left rules behind if its test crashed; after,
# because none of these tools' own disable is guaranteed to fully clear it.
flush_kernel_state() {
	nft flush ruleset 2>/dev/null || true
	iptables -F 2>/dev/null || true
	iptables -t nat -F 2>/dev/null || true
	iptables -X 2>/dev/null || true
	ip6tables -F 2>/dev/null || true
	ip6tables -t nat -F 2>/dev/null || true
	ip6tables -X 2>/dev/null || true
	ipset destroy 2>/dev/null || true
}

# backend_config_dir prints the single config directory a backend snapshots, or
# nothing for nft (which has no persisted config).
backend_config_dir() {
	case "$1" in
	iptables) echo /etc/iptables ;;
	firewalld) echo /etc/firewalld ;;
	ufw) echo /etc/ufw ;;
	csf) echo /etc/csf ;;
	apf) echo /etc/apf ;;
	esac
}

# restore_config rsync-restores a backend's clean config snapshot onto its own
# live config directory — never onto / itself, which would make --delete treat
# every other file on the filesystem as "extraneous" and try to remove it.
# --delete removes anything a previous test iteration left behind that
# provisioning did not seed (e.g. a rule file rewritten by AddRule).
restore_config() {
	local b="$1"
	local dir
	dir="$(backend_config_dir "$b")"
	[[ -n "$dir" ]] || return 0
	if [[ -d "$BASE/$b$dir" ]]; then
		rsync -a --delete "$BASE/$b$dir/" "$dir/"
	fi
}

# snapshot copies each given absolute path into $BASE/<backend>/, preserving the
# absolute path underneath so restore_config can restore it with a single `rsync -a`
# scoped to that backend's own config directory (never onto / itself). Creating
# $BASE/<backend>/ also serves as the backend's "provisioned" marker.
snapshot() {
	local backend="$1"
	shift
	mkdir -p "$BASE/$backend"
	local p
	for p in "$@"; do
		mkdir -p "$BASE/$backend/$(dirname "$p")"
		cp -a "$p" "$BASE/$backend/$p"
	done
}

# pkg_installed reports whether a package is actually installed (dpkg status
# "install ok installed"), not merely known to dpkg — `dpkg -s` exits 0 even for
# a removed package whose config files remain (status "deinstall ok
# config-files"), which is exactly the state ufw and iptables-persistent leave
# each other in when their mutual apt Conflict removes one of them.
pkg_installed() {
	dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "^install ok installed"
}

# wait_active polls `systemctl is-active` for up to 15s so the test does not race
# a daemon that is still settling after `systemctl start` returns.
wait_active() {
	local unit="$1"
	for _ in $(seq 1 15); do
		systemctl is-active --quiet "$unit" && return 0
		sleep 1
	done
	return 1
}

# ---------------------------------------------------------------------------
# Provisioning (lazy, per backend)
#
# Two independent, idempotent concerns, each checked per backend before its test:
#   - packages: gated on backend_installed (dpkg/binary presence), so the
#     ufw/iptables-persistent package a conflicting backend's install removed is
#     reinstalled on demand — the package state, not the config snapshot, answers
#     "is it installed?".
#   - config:   gated on the $BASE/<backend>/ snapshot dir; seeded and snapshotted
#     once, then replayed by restore_config before every test.
# A reused VM overlay keeps both, so it provisions nothing; a fresh overlay does
# only the backends this run actually touches.
# ---------------------------------------------------------------------------

apt_updated=0

# apt_update_once refreshes the package index a single time per boot, before the
# first install. Guarded so provisioning several backends in one run does not
# re-run `apt-get update` for each.
apt_update_once() {
	[[ "$apt_updated" = 1 ]] && return 0
	apt-get update
	apt_updated=1
}

# fetch_cached downloads url to dest, retrying a few times with a backoff since
# csf's download host in particular is known to fail intermittently. A
# successful download is copied into CACHE_DIR (a writable 9p share backed by
# the host's .cache, vs. the read-only repo share) so a later re-provision — or
# a fresh VM overlay — reuses it instead of hitting the network again.
fetch_cached() {
	local url="$1" dest="$2" name="$3"
	local cached="$CACHE_DIR/$name"
	if [[ -f "$cached" ]]; then
		echo ">> using cached $name"
		cp "$cached" "$dest"
		return 0
	fi
	local attempt
	for attempt in $(seq 1 5); do
		if wget --tries=3 --timeout=30 -qO "$dest" "$url"; then
			mkdir -p "$CACHE_DIR"
			cp "$dest" "$cached"
			return 0
		fi
		echo "!! download of $name failed (attempt $attempt/5); retrying" >&2
		sleep $((attempt * 5))
	done
	echo "!! failed to download $name after 5 attempts" >&2
	return 1
}

# backend_installed reports whether a backend's packages are already present. It
# gates provision_backend on package state rather than on the config snapshot, so
# the ufw/iptables-persistent pair — which apt's mutual Conflict makes
# install-one-remove-the-other — is reinstalled by whichever test needs it, even
# though its config snapshot already exists. csf and apf are third-party and not
# dpkg packages, so they are probed by their installed binary instead.
backend_installed() {
	case "$1" in
	nft) pkg_installed nftables ;;
	iptables) pkg_installed netfilter-persistent ;;
	firewalld) pkg_installed firewalld ;;
	ufw) pkg_installed ufw ;;
	csf) command -v csf >/dev/null 2>&1 ;;
	apf) command -v apf >/dev/null 2>&1 ;;
	*) return 1 ;;
	esac
}

# provision_backend installs one backend's packages. Called only when
# backend_installed reports them missing — on first use, or to reinstall the
# ufw/iptables-persistent package a conflicting backend's install removed. It
# touches neither daemon state (enable_backend/disable_backend own that) nor config
# (ensure_config_snapshot owns that). Runs under `set -e` in a subshell (see
# ensure_provisioned) so any failing step fails the backend cleanly.
provision_backend() {
	case "$1" in
	nft)
		# nft: kernel-native, no persisted config.
		apt_update_once
		apt-get install -y --no-install-recommends nftables
		;;
	iptables)
		# iptables: installed via iptables-persistent. Preseed its debconf autosave
		# prompts so the noninteractive install does not block waiting for a "save
		# current rules?" answer. Install netfilter-persistent by name for clarity —
		# it ships the .service unit the constructor requires, and iptables-persistent
		# depends on it.
		#
		# ufw and iptables-persistent/netfilter-persistent mutually Conflict at the
		# apt level on this distro (Ubuntu ships ufw preinstalled by default, and
		# installing either package here auto-removes the other), so only one of the
		# pair can be installed at a time — hence backend_installed gates this per
		# test so the one a given backend needs is reinstalled on demand.
		apt_update_once
		echo "iptables-persistent iptables-persistent/autosave_v4 boolean false" | debconf-set-selections
		echo "iptables-persistent iptables-persistent/autosave_v6 boolean false" | debconf-set-selections
		# ipset-persistent ships the netfilter-persistent plugin the backend probes
		# for to decide it has somewhere to stage address sets. Without it the
		# backend falls back to creating sets live and the staged path — the one
		# Reload loads through `ipset restore` — never runs. ufw cannot have it (it
		# pulls netfilter-persistent, which conflicts with ufw as noted above), so
		# ufw is what covers the live-only fallback.
		apt-get install -y --no-install-recommends iptables iptables-persistent netfilter-persistent ipset ipset-persistent
		;;
	firewalld)
		# firewalld: available in Ubuntu's universe repo.
		apt_update_once
		apt-get install -y --no-install-recommends firewalld
		;;
	ufw)
		# ufw: Ubuntu's default firewall tool.
		apt_update_once
		apt-get install -y --no-install-recommends ufw ipset
		;;
	csf)
		# csf (ConfigServer Security & Firewall): third-party Perl package installed
		# from upstream.
		apt_update_once
		apt-get install -y --no-install-recommends perl libwww-perl libio-socket-ssl-perl iptables ipset ca-certificates wget
		fetch_cached https://download.configserver.dev/csf.tgz /tmp/csf.tgz csf.tgz
		tar -xzf /tmp/csf.tgz -C /tmp
		(cd /tmp/csf && sh install.sh)
		rm -rf /tmp/csf /tmp/csf.tgz
		;;
	apf)
		# apf (Advanced Policy Firewall): third-party package from rfxn upstream.
		apt_update_once
		apt-get install -y --no-install-recommends iproute2 kmod ca-certificates wget
		fetch_cached https://github.com/rfxn/advanced-policy-firewall/archive/refs/heads/master.tar.gz /tmp/apf.tar.gz apf.tar.gz
		tar -xzf /tmp/apf.tar.gz -C /tmp
		(cd /tmp/advanced-policy-firewall-master && bash install.sh)
		rm -rf /tmp/apf.tar.gz /tmp/advanced-policy-firewall-master
		;;
	*)
		echo "!! unknown backend '$1'" >&2
		return 1
		;;
	esac
}

# ensure_config_snapshot seeds a backend's minimal/clean config and snapshots it
# under $BASE/<backend>/ the first time it is needed, then is a no-op (the snapshot
# dir is the marker). Must run after provision_backend, since it edits config files
# the package install creates. restore_config replays this snapshot before every
# test, so a package reinstalled after a conflict always has its default config
# overwritten by the clean seed. Leaves every backend disabled — the loop's
# enable/disable owns daemon state, so nothing here starts or stops a service.
ensure_config_snapshot() {
	local b="$1"
	[[ -d "$BASE/$b" ]] && return 0
	echo ">> [$b] seeding and snapshotting clean config"
	case "$b" in
	nft)
		# nft has no persisted config; the snapshot dir is just a uniformity marker.
		mkdir -p "$BASE/nft"
		;;
	iptables)
		mkdir -p /etc/iptables
		printf '*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n*nat\n:PREROUTING ACCEPT [0:0]\n:INPUT ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n:POSTROUTING ACCEPT [0:0]\nCOMMIT\n' \
			| tee /etc/iptables/rules.v4 >/etc/iptables/rules.v6
		snapshot iptables /etc/iptables/rules.v4 /etc/iptables/rules.v6
		;;
	firewalld)
		snapshot firewalld /etc/firewalld
		;;
	ufw)
		sed -i 's/^ENABLED=.*/ENABLED=no/' /etc/ufw/ufw.conf
		snapshot ufw /etc/ufw
		;;
	csf)
		sed -i 's/^TESTING = .*/TESTING = "0"/' /etc/csf/csf.conf
		rm -f /etc/csf/csf.disable
		snapshot csf /etc/csf
		;;
	apf)
		sed -i 's/^DEVEL_MODE=.*/DEVEL_MODE="0"/' /etc/apf/conf.apf
		snapshot apf /etc/apf
		;;
	esac
}

# ensure_provisioned makes a backend ready to test: installs its packages if
# backend_installed reports them missing, then seeds+snapshots its clean config if
# that has not been done yet. Each step runs in a `set -e` subshell so a mid-step
# failure aborts that step as a unit under this script's loop-friendly `set -u`,
# while staying contained to the one backend rather than aborting the whole run.
ensure_provisioned() {
	local b="$1"
	if ! backend_installed "$b"; then
		echo ">> [$b] installing packages"
		( set -eo pipefail; provision_backend "$b" ) || return 1
	fi
	( set -eo pipefail; ensure_config_snapshot "$b" ) || return 1
}

# enable_backend starts a backend's daemon against the clean config just restored.
# It restarts (rather than starts) the daemon backends to ensure the restored
# config is re-read if the service was already in a running state.
enable_backend() {
	case "$1" in
	nft) : ;; # kernel-native; nothing to enable
	iptables)
		# The unit's constructor requires UnitFileState=="enabled", so enable before
		# restarting; daemon-reload picks up the generated unit for this SysV-only service.
		systemctl daemon-reload
		systemctl enable netfilter-persistent.service
		systemctl restart netfilter-persistent.service
		;;
	firewalld)
		# Debian/Ubuntu ships firewalld.service masked by default (it conflicts
		# with the distro's default iptables/ufw setup), so it must be unmasked
		# before it can start at all.
		systemctl unmask firewalld.service 2>/dev/null || true
		systemctl enable firewalld.service
		systemctl restart firewalld.service && wait_active firewalld.service
		;;
	ufw)
		# restore_config seeded ENABLED=no; flip it on for the test. No restart
		# needed: `ufw --force enable` runs a full flush-and-re-apply even when ufw
		# is already up, so it is already a restart.
		sed -i 's/^ENABLED=.*/ENABLED=yes/' /etc/ufw/ufw.conf
		systemctl enable ufw.service
		ufw --force enable
		;;
	csf)
		systemctl enable csf.service
		systemctl restart csf.service && wait_active csf.service
		;;
	apf)
		# Two stock settings keep apf from enforcing what the tests write, both set
		# here rather than in the config snapshot (which is seeded once and reused
		# across runs). EGF gates egress filtering as a whole: with it off apf stores
		# an EG_*_CPORTS entry but never puts it in the kernel, so an outbound rule
		# is never actually applied. BLK_RESNET drops traffic to the reserved
		# networks ahead of apf's own port rules, and the rule-counter subtest drives
		# packets at a TEST-NET address to make a rule's counter move.
		sed -i 's/^EGF=.*/EGF="1"/' /etc/apf/conf.apf
		sed -i 's/^BLK_RESNET=.*/BLK_RESNET="0"/' /etc/apf/conf.apf
		systemctl enable apf.service
		systemctl restart apf.service && wait_active apf.service
		;;
	esac
}

# disable_backend stops and disables a backend's daemon so it cannot interfere with
# the next backend's test. Called after every run, pass or fail, and errors are
# ignored since the goal is only to leave the daemon down.
disable_backend() {
	case "$1" in
	nft) : ;;
	iptables) systemctl disable --now netfilter-persistent.service 2>/dev/null || true ;;
	firewalld) systemctl disable --now firewalld.service 2>/dev/null || true ;;
	ufw)
		ufw disable 2>/dev/null || true
		systemctl disable ufw.service 2>/dev/null || true
		;;
	csf) systemctl disable --now csf.service lfd.service 2>/dev/null || true ;;
	apf) systemctl disable --now apf.service 2>/dev/null || true ;;
	esac
}

declare -A result
overall=0

# Loop through requested backends and test.
for b in "${backends[@]}"; do
	# Provision on first use; a provisioning failure is contained to this backend.
	if ! ensure_provisioned "$b"; then
		echo "!! [$b] provisioning failed"
		result[$b]="PROVISION-FAIL"
		overall=1
		continue
	fi

	echo ">> [$b] resetting kernel state and restoring clean config"
	flush_kernel_state
	restore_config "$b"

	echo ">> [$b] enabling backend"
	if ! enable_backend "$b"; then
		echo "!! [$b] enable failed"
		result[$b]="ENABLE-FAIL"
		overall=1
		disable_backend "$b"
		flush_kernel_state
		continue
	fi

	echo ">> [$b] running integration test"
	FIREWALL_BACKEND="$b" "$BIN" -test.v -test.run TestIntegration
	rc=$?

	# Always disable, even on test failure, so one backend's failure never leaves
	# it running to interfere with the next backend's test.
	echo ">> [$b] disabling backend"
	disable_backend "$b"
	flush_kernel_state

	if [[ $rc -eq 0 ]]; then
		result[$b]="PASS"
	else
		result[$b]="FAIL($rc)"
		overall=1
	fi
done

echo
echo "==== integration results ===="
for b in "${backends[@]}"; do
	printf "  %-10s %s\n" "$b" "${result[$b]:-SKIPPED}"
done
exit $overall
