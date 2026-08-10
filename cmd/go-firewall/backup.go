package main

import (
	"context"
	"fmt"
	"os"

	fw "github.com/grmrgecko/go-firewall"
)

// This file holds the backup and restore subcommands. A backup captures the
// managed filter and NAT rules as a portable JSON snapshot (via the library's
// WriteBackup/ReadBackup/RestoreReader), so a snapshot taken on one host can
// be replayed on another or persisted for later.

// BackupSubcmd snapshots the managed rules to a file or stdout. The output is
// the portable JSON form the library's WriteBackup emits, so it round-trips
// across hosts and library versions.
type BackupSubcmd struct {
	Zone      string `name:"zone" short:"z" help:"Zone name or empty for the default."`
	Interface string `name:"interface" short:"i" help:"Resolve the zone for this interface."`
	File      string `name:"file" short:"o" help:"Write to this file (default: stdout)." placeholder:"FILE"`
}

// Run writes the managed-rule snapshot to the file or stdout.
func (c *BackupSubcmd) Run(g *Globals) error {
	mgr, cleanup, err := g.manager()
	if err != nil {
		return err
	}
	defer cleanup()

	zone, err := resolveZone(mgr, c.Zone, c.Interface)
	if err != nil {
		return err
	}
	backup, err := mgr.Backup(context.Background(), zone)
	if err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	// WriteBackup always emits JSON; --json here would be redundant, so we
	// ignore the global flag and just write the snapshot.
	w := os.Stdout
	if c.File != "" && c.File != "-" {
		f, err := os.Create(c.File)
		if err != nil {
			return fmt.Errorf("open %s: %w", c.File, err)
		}
		defer func() { _ = f.Close() }()
		w = f
	}
	if err := fw.WriteBackup(w, backup); err != nil {
		return fmt.Errorf("write backup: %w", err)
	}
	return nil
}

// RestoreSubcmd replays a backup from a file or stdin. Existing managed rules
// are removed before the backup rules are applied (the library's Restore
// semantics), so the managed set ends up exactly equal to the backup.
type RestoreSubcmd struct {
	Zone      string `name:"zone" short:"z" help:"Zone name or empty for the default."`
	Interface string `name:"interface" short:"i" help:"Resolve the zone for this interface."`
	File      string `name:"file" short:"f" help:"Read from this file (default: stdin)." placeholder:"FILE"`
}

// Run replays a backup snapshot read from the file or stdin.
func (c *RestoreSubcmd) Run(g *Globals) error {
	mgr, cleanup, err := g.manager()
	if err != nil {
		return err
	}
	defer cleanup()

	zone, err := resolveZone(mgr, c.Zone, c.Interface)
	if err != nil {
		return err
	}
	r := os.Stdin
	if c.File != "" && c.File != "-" {
		f, err := os.Open(c.File)
		if err != nil {
			return fmt.Errorf("open %s: %w", c.File, err)
		}
		defer func() { _ = f.Close() }()
		r = f
	}
	// RestoreReader decodes and applies in one step, failing before any rules
	// are touched if the file is malformed.
	if err := fw.RestoreReader(context.Background(), mgr, zone, r); err != nil {
		return fmt.Errorf("restore: %w", err)
	}
	if err := g.reload(mgr); err != nil {
		return fmt.Errorf("reload: %w", err)
	}
	return g.emitStatus("restored")
}
