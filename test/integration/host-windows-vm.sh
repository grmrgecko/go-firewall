#!/usr/bin/env bash
# HOST script — run this on your workstation. It boots a throwaway QEMU Windows VM
# and runs the Windows Firewall (wf) integration backend inside it.
#
# On first use it performs a fully unattended install of Windows Server 2022
# Evaluation into .cache/windows.qcow2 (downloads the ~5 GB eval ISO if absent),
# provisions OpenSSH + disables UAC via an Autounattend.xml answer file, then boots
# a fresh overlay of that image, copies in the windows-cross-compiled test binary,
# and runs it over SSH. Everything is disposable; the base install is reused.
#
# Requirements: qemu-system-x86_64, KVM, genisoimage, socat, ssh (key auth).
#
# A Windows host with Administrator rights can also run the suite directly:
#   go test -tags integration -run TestIntegration   (from an elevated prompt)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

MEM="${GOFW_VM_MEM:-4096}"
CPUS="${GOFW_VM_CPUS:-2}"
CACHE="${GOFW_VM_CACHE:-$repo/.cache}"
BOOT_TIMEOUT="${GOFW_VM_TIMEOUT:-3600}"
SSH_PORT="${GOFW_WIN_SSH_PORT:-2222}"
ISO_URL="${GOFW_WIN_ISO_URL:-https://software-static.download.prss.microsoft.com/sg/download/888969d5-f34g-4e03-ac9d-1f9786c66749/SERVER_EVAL_x64FRE_en-us.iso}"
PASS='Gofw!Test2024'
USER='Administrator'

mkdir -p "$CACHE"
iso="$CACHE/winserver.iso"
base="$CACHE/windows.qcow2"
overlay="$CACHE/windows-overlay.qcow2"
uaiso="$CACHE/autounattend.iso"
bin="$CACHE/firewall.test.exe"
mon="$CACHE/win-mon.sock"

for t in qemu-system-x86_64 genisoimage socat ssh ssh-keygen; do
	command -v "$t" >/dev/null || { echo "!! $t not found"; exit 1; }
done

# Key-based SSH (no sshpass dependency); the public key is injected into the guest
# via the Autounattend firstlogon commands.
key="$CACHE/win_key"
[[ -f "$key" ]] || ssh-keygen -q -t ed25519 -N '' -C gofw-win -f "$key"
pubkey="$(cat "$key.pub")"

ssh_opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 -o IdentitiesOnly=yes -i "$key")
run_ssh() { ssh "${ssh_opts[@]}" -p "$SSH_PORT" "$USER@127.0.0.1" "$@"; }
copy_in() { scp "${ssh_opts[@]}" -P "$SSH_PORT" "$1" "$USER@127.0.0.1:$2"; }

# wait_ssh <qemu_pid> — returns 0 once the guest answers SSH, 1 on timeout/death.
wait_ssh() {
	local pid="$1" deadline=$((SECONDS + BOOT_TIMEOUT))
	until run_ssh "echo ok" >/dev/null 2>&1; do
		kill -0 "$pid" 2>/dev/null || { echo "!! qemu exited before SSH came up"; return 1; }
		[[ $SECONDS -ge $deadline ]] && { echo "!! timed out waiting for SSH"; return 1; }
		sleep 10
	done
}

# --- one-time unattended install -------------------------------------------
install_windows() {
	if [[ ! -f "$iso" ]]; then
		echo ">> downloading Windows Server 2022 eval ISO (~5 GB) -> $iso"
		curl -L --fail -o "$iso.tmp" "$ISO_URL"
		mv "$iso.tmp" "$iso"
	fi

	echo ">> building Autounattend.xml seed"
	local work; work="$(mktemp -d "$CACHE/ua.XXXXXX")"
	cat >"$work/autounattend.xml" <<XML
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
      <InputLocale>en-US</InputLocale><SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage><UserLocale>en-US</UserLocale>
    </component>
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <DiskConfiguration>
        <Disk wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
          <DiskID>0</DiskID><WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add"><Order>1</Order><Type>Primary</Type><Extend>true</Extend></CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add"><Order>1</Order><PartitionID>1</PartitionID><Format>NTFS</Format><Active>true</Active><Label>Windows</Label></ModifyPartition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>
          <InstallTo><DiskID>0</DiskID><PartitionID>1</PartitionID></InstallTo>
          <InstallFrom><MetaData wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"><Key>/IMAGE/INDEX</Key><Value>3</Value></MetaData></InstallFrom>
        </OSImage>
      </ImageInstall>
      <UserData><AcceptEula>true</AcceptEula></UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>WINTEST</ComputerName>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <UserAccounts><AdministratorPassword><Value>$PASS</Value><PlainText>true</PlainText></AdministratorPassword></UserAccounts>
      <AutoLogon><Password><Value>$PASS</Value><PlainText>true</PlainText></Password><Enabled>true</Enabled><Username>$USER</Username><LogonCount>999</LogonCount></AutoLogon>
      <OOBE>
        <HideEULAPage>true</HideEULAPage><HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens><HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <NetworkLocation>Work</NetworkLocation><ProtectYourPC>3</ProtectYourPC>
        <SkipUserOOBE>true</SkipUserOOBE><SkipMachineOOBE>true</SkipMachineOOBE>
      </OOBE>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"><Order>1</Order><CommandLine>reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f</CommandLine></SynchronousCommand>
        <SynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"><Order>2</Order><CommandLine>reg add "HKLM\SOFTWARE\OpenSSH" /v DefaultShell /t REG_SZ /d "C:\Windows\System32\cmd.exe" /f</CommandLine></SynchronousCommand>
        <SynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"><Order>3</Order><CommandLine>powershell -NoProfile -Command "Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0"</CommandLine></SynchronousCommand>
        <SynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"><Order>4</Order><CommandLine>powershell -NoProfile -Command "New-Item -Force -ItemType Directory C:\ProgramData\ssh | Out-Null; Set-Content -Encoding ascii -Path C:\ProgramData\ssh\administrators_authorized_keys -Value '$pubkey'; icacls C:\ProgramData\ssh\administrators_authorized_keys /inheritance:r /grant SYSTEM:F /grant BUILTIN\Administrators:F"</CommandLine></SynchronousCommand>
        <SynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"><Order>5</Order><CommandLine>powershell -NoProfile -Command "Set-Service sshd -StartupType Automatic; Start-Service sshd"</CommandLine></SynchronousCommand>
        <SynchronousCommand wcm:action="add" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State"><Order>6</Order><CommandLine>netsh advfirewall firewall add rule name=OpenSSH dir=in action=allow protocol=TCP localport=22</CommandLine></SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
XML
	genisoimage -quiet -o "$uaiso" -V UNATTEND -J -r "$work/autounattend.xml"
	rm -rf "$work"

	echo ">> creating install disk"
	rm -f "$base.installing"
	qemu-img create -f qcow2 "$base.installing" 40G >/dev/null

	rm -f "$mon"
	echo ">> booting installer (unattended; this takes ~30-40 min)"
	qemu-system-x86_64 \
		-enable-kvm -cpu host -m "$MEM" -smp "$CPUS" \
		-drive file="$base.installing",if=none,id=disk,format=qcow2 \
		-device ahci,id=ahci -device ide-hd,drive=disk,bus=ahci.0 \
		-drive file="$iso",media=cdrom,if=none,id=inst -device ide-cd,drive=inst,bus=ahci.1 \
		-drive file="$uaiso",media=cdrom,if=none,id=ua -device ide-cd,drive=ua,bus=ahci.2 \
		-netdev "user,id=n0,hostfwd=tcp::${SSH_PORT}-:22" -device e1000,netdev=n0 \
		-boot once=d,menu=off -monitor "unix:$mon,server,nowait" -display none -serial null &
	local qpid=$!
	trap 'kill "$qpid" 2>/dev/null || true' RETURN

	# Bypass the "Press any key to boot from CD" prompt: tap Enter for the first
	# ~20 s via the QEMU monitor.
	( for _ in $(seq 1 20); do echo "sendkey ret"; sleep 1; done | socat - "unix-connect:$mon" >/dev/null 2>&1 || true ) &

	echo ">> waiting for the installed guest to answer SSH (up to ${BOOT_TIMEOUT}s)"
	if ! wait_ssh "$qpid"; then
		echo "!! install did not finish; see the console. Leaving $base.installing for inspection."
		return 1
	fi
	echo ">> install complete; shutting the guest down"
	run_ssh "shutdown /s /t 0" >/dev/null 2>&1 || true
	for _ in $(seq 1 30); do kill -0 "$qpid" 2>/dev/null || break; sleep 2; done
	kill "$qpid" 2>/dev/null || true
	trap - RETURN
	mv "$base.installing" "$base"
	echo ">> prepared image ready: $base"
}

[[ -f "$base" ]] || install_windows

# --- run the suite ----------------------------------------------------------
echo ">> cross-compiling windows test binary on host"
( cd "$repo" && GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go test -c -tags integration -o "$bin" . )

echo ">> creating a fresh overlay disk (base stays pristine)"
rm -f "$overlay"
qemu-img create -f qcow2 -b "$base" -F qcow2 "$overlay" 40G >/dev/null

echo ">> booting Windows VM (headless; SSH on localhost:$SSH_PORT)"
qemu-system-x86_64 \
	-enable-kvm -cpu host -m "$MEM" -smp "$CPUS" \
	-drive file="$overlay",if=none,id=disk,format=qcow2 \
	-device ahci,id=ahci -device ide-hd,drive=disk,bus=ahci.0 \
	-netdev "user,id=n0,hostfwd=tcp::${SSH_PORT}-:22" -device e1000,netdev=n0 \
	-monitor "unix:$mon,server,nowait" -display none -serial null &
qpid=$!
trap 'kill "$qpid" 2>/dev/null || true' EXIT

wait_ssh "$qpid" || exit 124

echo ">> copying test binary and running the suite (Administrator, UAC disabled)"
copy_in "$bin" "firewall.test.exe"
set +e
# Keep the SSH control channel alive independent of the port-22 rules the suite
# adds and removes. The guest sshd listens on :22 (host :2222 forwards to it), so a
# subtest that manages a bare TCP/22 rule would otherwise remove the OpenSSH allow
# and WFP would drop this session. This rule permits inbound TCP from the QEMU SLIRP
# gateway (10.0.2.2, the source the forwarded SSH appears from) on any local port;
# its shape (a source-only match, no local port) matches no test rule, so the suite
# never removes it, and it is not the bare TCP/22 rule the suite round-trips.
run_ssh 'netsh advfirewall firewall add rule name=gofw-keepalive dir=in action=allow protocol=TCP remoteip=10.0.2.0/24'
run_ssh 'set "FIREWALL_BACKEND=wf"&& firewall.test.exe -test.v -test.run TestIntegration'
rc=$?
set -e

run_ssh "shutdown /s /t 0" >/dev/null 2>&1 || true
echo "==== Windows wf run finished (rc=$rc) ===="
exit "$rc"
