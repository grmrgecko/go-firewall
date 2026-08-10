//go:build linux

package firewall

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	dbus "github.com/coreos/go-systemd/v22/dbus"
)

// systemdActive reports whether systemd is the running init (/run/systemd/system
// exists), the same marker systemctl uses to decide it can reach the manager.
func systemdActive() bool {
	_, err := os.Stat("/run/systemd/system")
	return err == nil
}

// commandExists reports whether name resolves on PATH or in the standard install
// directories, matching how runCommand resolves the tool it runs.
func commandExists(name string) bool {
	_, ok := resolveBinary(name)
	return ok
}

// systemdUnitEnabled reports whether systemd reports name's unit as set to
// start at boot. Only "enabled" and "enabled-runtime" count: a "generated"
// unit wraps a SysV init.d script and exists for every script regardless of
// its rc registration, so boot enablement for those is resolved through the
// SysV checks instead. Returns false when systemd is not running or the unit
// is absent.
func systemdUnitEnabled(ctx context.Context, name string) bool {
	conn, err := dbus.NewWithContext(ctx)
	if err != nil {
		return false
	}
	defer conn.Close()
	prop, err := conn.GetUnitPropertyContext(ctx, name+".service", "UnitFileState")
	if err != nil {
		return false
	}
	switch prop.Value.Value() {
	case "enabled", "enabled-runtime":
		return true
	}
	return false
}

// systemdUnitState returns name's unit-file state (e.g. "enabled", "disabled",
// "static") and whether its unit file is installed. It lists all unit files and
// filters by name rather than calling ListUnitFilesByPatterns, which older
// systemd (CentOS 7's v219) does not export over D-Bus. Used to tell
// installed-but-disabled units (which can be enabled) from absent ones (which
// cannot be). Returns "", false when systemd is not running.
func systemdUnitState(ctx context.Context, name string) (state string, present bool) {
	conn, err := dbus.NewWithContext(ctx)
	if err != nil {
		return "", false
	}
	defer conn.Close()
	files, err := conn.ListUnitFilesContext(ctx)
	if err != nil {
		return "", false
	}
	target := name + ".service"
	for _, uf := range files {
		if filepath.Base(uf.Path) == target {
			return uf.Type, true
		}
	}
	return "", false
}

// chkconfigOn reports whether `chkconfig --list name` shows any runlevel on,
// the RHEL-family enablement signal. Returns false when chkconfig is absent.
func chkconfigOn(ctx context.Context, name string) bool {
	results, err := runCommand(ctx, "chkconfig", "--list", name)
	if err != nil {
		return false
	}
	for _, line := range results {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != name {
			continue
		}
		for _, f := range fields[1:] {
			if _, status, found := strings.Cut(f, ":"); found && status == "on" {
				return true
			}
		}
	}
	return false
}

// rcSymlinksOn reports whether an S*name start symlink exists in any rcN.d
// tree, the enablement signal for both update-rc.d (Debian/Ubuntu, /etc/rcN.d)
// and Slackware (/etc/rc.d/rcN.d).
func rcSymlinksOn(name string) bool {
	for _, rl := range []string{"2", "3", "4", "5"} {
		for _, dir := range []string{"/etc/rc" + rl + ".d", "/etc/rc.d/rc" + rl + ".d"} {
			if matches, _ := filepath.Glob(filepath.Join(dir, "S*"+name)); len(matches) > 0 {
				return true
			}
		}
	}
	return false
}

// openrcOn reports whether name is linked into an OpenRC runlevel directory
// (default or boot), the enablement signal created by `rc-update add` on Gentoo.
func openrcOn(name string) bool {
	for _, rl := range []string{"default", "boot"} {
		if _, err := os.Lstat(filepath.Join("/etc/runlevels", rl, name)); err == nil {
			return true
		}
	}
	return false
}

// rcLocalOn reports whether name is invoked from an rc.local file, apf's
// last-resort enablement when neither systemd nor an init.d registration
// applies. Commented lines are ignored, and name must appear as its own token
// (bare or path-qualified) so an unrelated mention such as a log-file path
// does not count.
func rcLocalOn(name string) bool {
	for _, p := range []string{"/etc/rc.local", "/etc/rc.d/rc.local"} {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			for _, tok := range strings.Fields(line) {
				if tok == name || strings.HasSuffix(tok, "/"+name) {
					return true
				}
			}
		}
	}
	return false
}

// sysvServiceEnabled reports whether name is enabled under any SysV-family init
// system, the fallback when systemd is absent or does not report the service
// enabled. It checks chkconfig, Debian/Slackware rcN.d start symlinks, OpenRC
// runlevels, and rc.local in turn; the first to report it on wins.
func sysvServiceEnabled(ctx context.Context, name string) bool {
	if chkconfigOn(ctx, name) {
		return true
	}
	if rcSymlinksOn(name) {
		return true
	}
	if openrcOn(name) {
		return true
	}
	return rcLocalOn(name)
}

// serviceInstalled reports whether name's unit or init.d script is installed,
// regardless of whether it is enabled. Used to tell a merely-disabled service
// (which can be enabled) from an absent one (which cannot be).
func serviceInstalled(ctx context.Context, name string) bool {
	if systemdActive() {
		_, present := systemdUnitState(ctx, name)
		return present
	}
	for _, dir := range []string{"/etc/init.d", "/etc/rc.d/init.d"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return true
		}
	}
	return false
}

// serviceEnabled reports whether name is enabled to start, checking systemd
// first and then every SysV-family init mechanism the supported firewalls
// install under: chkconfig (RHEL), update-rc.d (Debian/Ubuntu, via /etc/rcN.d
// symlinks), rc-update (Gentoo/OpenRC, via /etc/runlevels), Slackware rc.d
// symlinks, and rc.local (apf's last resort). name is the service base name
// without a ".service" suffix (e.g. "csf", "apf", "netfilter-persistent"); any
// one mechanism reporting it on counts as enabled.
func serviceEnabled(ctx context.Context, name string) bool {
	if systemdUnitEnabled(ctx, name) {
		return true
	}
	return sysvServiceEnabled(ctx, name)
}

// enableService enables name to start at boot under whatever init system is
// active, mirroring how the firewalls' installers register themselves. It is a
// no-op (returns nil) when the service is not installed or already enabled. On
// systemd it runs `systemctl enable` (preceded by daemon-reload so a freshly
// installed unit is picked up); otherwise it uses chkconfig, update-rc.d, or
// rc-update, whichever is present.
func enableService(ctx context.Context, name string) error {
	if systemdActive() {
		state, present := systemdUnitState(ctx, name)
		if !present {
			return nil
		}
		switch state {
		case "enabled", "enabled-runtime", "static":
			// Static units have no install info and are pulled in by other
			// units, so there is nothing to enable.
			return nil
		case "generated":
			// A generated unit wraps a SysV init.d script whose enablement
			// lives in its rc registration, not the unit file. `systemctl
			// enable` reaches that registration through systemd-sysv-install.
			if sysvServiceEnabled(ctx, name) {
				return nil
			}
		}
		if _, err := runCommand(ctx, "systemctl", "daemon-reload"); err != nil {
			return fmt.Errorf("failed to reload systemd for %s: %s", name, err)
		}
		if _, err := runCommand(ctx, "systemctl", "enable", name+".service"); err != nil {
			return fmt.Errorf("failed to enable %s: %s", name, err)
		}
		return nil
	}
	if !serviceInstalled(ctx, name) {
		return nil
	}
	switch {
	case commandExists("chkconfig"):
		if _, err := runCommand(ctx, "chkconfig", "--add", name); err != nil {
			return fmt.Errorf("failed to enable %s: %s", name, err)
		}
		if _, err := runCommand(ctx, "chkconfig", name, "on"); err != nil {
			return fmt.Errorf("failed to enable %s: %s", name, err)
		}
	case commandExists("update-rc.d"):
		if _, err := runCommand(ctx, "update-rc.d", name, "defaults"); err != nil {
			return fmt.Errorf("failed to enable %s: %s", name, err)
		}
	case commandExists("rc-update"):
		if _, err := runCommand(ctx, "rc-update", "add", name, "default"); err != nil {
			return fmt.Errorf("failed to enable %s: %s", name, err)
		}
	default:
		return fmt.Errorf("no supported init system found to enable %s", name)
	}
	return nil
}

// restartService restarts name under whatever init system is active. On systemd
// it runs `systemctl restart`; otherwise it prefers the `service` wrapper, then
// OpenRC's `rc-service`, then the init.d script directly.
func restartService(ctx context.Context, name string) error {
	if systemdActive() {
		if _, err := runCommand(ctx, "systemctl", "restart", name+".service"); err != nil {
			// A burst of restarts (a caller reconciling several times in quick
			// succession) trips systemd's start rate limit and the unit lands in
			// a failed start-limit-hit state; clear it and retry once rather
			// than fail a reload the unit itself is healthy for.
			if _, rerr := runCommand(ctx, "systemctl", "reset-failed", name+".service"); rerr == nil {
				if _, err2 := runCommand(ctx, "systemctl", "restart", name+".service"); err2 == nil {
					return nil
				}
			}
			return fmt.Errorf("failed to restart %s: %s", name, err)
		}
		return nil
	}
	switch {
	case commandExists("service"):
		if _, err := runCommand(ctx, "service", name, "restart"); err != nil {
			return fmt.Errorf("failed to restart %s: %s", name, err)
		}
	case commandExists("rc-service"):
		if _, err := runCommand(ctx, "rc-service", name, "restart"); err != nil {
			return fmt.Errorf("failed to restart %s: %s", name, err)
		}
	default:
		if _, err := runCommand(ctx, filepath.Join("/etc/init.d", name), "restart"); err != nil {
			return fmt.Errorf("failed to restart %s: %s", name, err)
		}
	}
	return nil
}
