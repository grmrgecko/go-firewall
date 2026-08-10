package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Backup JSON serialization so snapshots can be persisted to disk or moved
// between hosts. Enum values are marshaled as their stable string names to keep
// backups readable across library versions. The two generic helpers below keep
// the per-type boilerplate to one line.

// marshalEnum renders an enum value as its canonical string name.
func marshalEnum[T ~uint8](v T, str func(T) string) ([]byte, error) {
	return json.Marshal(str(v))
}

// unmarshalEnum parses an enum value from its canonical string name via parse.
func unmarshalEnum[T ~uint8](data []byte, parse func(string) (T, error)) (T, error) {
	var zero T
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return zero, err
	}
	return parse(s)
}

// MarshalJSON renders the action as its stable name (e.g. "accept").
func (a Action) MarshalJSON() ([]byte, error) { return marshalEnum(a, Action.String) }

// UnmarshalJSON parses an action from its stable name. The sentinel "invalid"
// (ActionInvalid) is accepted on the wire for round-trip fidelity even though
// ParseAction rejects it as caller input.
func (a *Action) UnmarshalJSON(data []byte) error {
	v, err := unmarshalEnum(data, func(s string) (Action, error) {
		if strings.EqualFold(strings.TrimSpace(s), "invalid") {
			return ActionInvalid, nil
		}
		return ParseAction(s)
	})
	if err != nil {
		return err
	}
	*a = v
	return nil
}

// MarshalJSON renders the family as its stable name (e.g. "ipv4").
func (f Family) MarshalJSON() ([]byte, error) { return marshalEnum(f, Family.String) }

// UnmarshalJSON parses a family from its stable name.
func (f *Family) UnmarshalJSON(data []byte) error {
	v, err := unmarshalEnum(data, ParseFamily)
	if err != nil {
		return err
	}
	*f = v
	return nil
}

// MarshalJSON renders the protocol as its stable name (e.g. "tcp").
func (p Protocol) MarshalJSON() ([]byte, error) { return marshalEnum(p, Protocol.String) }

// UnmarshalJSON parses a protocol from its stable name. An unrecognized token is
// rejected rather than silently widening the rule to ProtocolAny; only the
// wildcard spellings ("any" or empty) resolve to ProtocolAny.
func (p *Protocol) UnmarshalJSON(data []byte) error {
	v, err := unmarshalEnum(data, func(s string) (Protocol, error) {
		proto := GetProtocol(s)
		t := strings.TrimSpace(s)
		if proto == ProtocolAny && t != "" && !strings.EqualFold(t, "any") {
			return 0, fmt.Errorf("unknown protocol %q", s)
		}
		return proto, nil
	})
	if err != nil {
		return err
	}
	*p = v
	return nil
}

// MarshalJSON renders the connection-state set as a comma-joined name list.
func (s ConnState) MarshalJSON() ([]byte, error) { return marshalEnum(s, ConnState.String) }

// UnmarshalJSON parses a connection-state set from a comma-joined name list.
func (s *ConnState) UnmarshalJSON(data []byte) error {
	v, err := unmarshalEnum(data, func(tok string) (ConnState, error) { return ParseConnState(tok) })
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// MarshalJSON renders the rate unit as its stable name (e.g. "minute").
func (u RateUnit) MarshalJSON() ([]byte, error) { return marshalEnum(u, RateUnit.String) }

// UnmarshalJSON parses a rate unit from its stable name.
func (u *RateUnit) UnmarshalJSON(data []byte) error {
	v, err := unmarshalEnum(data, ParseRateUnit)
	if err != nil {
		return err
	}
	*u = v
	return nil
}

// MarshalJSON renders the NAT kind as its stable name (e.g. "dnat").
func (k NATKind) MarshalJSON() ([]byte, error) { return marshalEnum(k, NATKind.String) }

// UnmarshalJSON parses a NAT kind from its stable name. The sentinel "invalid"
// (NATInvalid) is accepted on the wire for round-trip fidelity even though
// ParseNATKind rejects it as caller input, mirroring Action.
func (k *NATKind) UnmarshalJSON(data []byte) error {
	v, err := unmarshalEnum(data, func(s string) (NATKind, error) {
		if strings.EqualFold(strings.TrimSpace(s), "invalid") {
			return NATInvalid, nil
		}
		return ParseNATKind(s)
	})
	if err != nil {
		return err
	}
	*k = v
	return nil
}

// MarshalJSON renders the direction as its stable name (e.g. "input").
func (d Direction) MarshalJSON() ([]byte, error) { return marshalEnum(d, Direction.String) }

// UnmarshalJSON parses a direction from its stable name.
func (d *Direction) UnmarshalJSON(data []byte) error {
	v, err := unmarshalEnum(data, ParseDirection)
	if err != nil {
		return err
	}
	*d = v
	return nil
}

// MarshalJSON renders the set type as its stable name (e.g. "hash:net").
func (t SetType) MarshalJSON() ([]byte, error) { return marshalEnum(t, SetType.String) }

// UnmarshalJSON parses a set type from its stable name.
func (t *SetType) UnmarshalJSON(data []byte) error {
	v, err := unmarshalEnum(data, ParseSetType)
	if err != nil {
		return err
	}
	*t = v
	return nil
}

// captureBackupState fills a backup's DefaultPolicy and AddressSets from the
// backend, for the backends that advertise those features. It is shared by every
// Backup implementation so a snapshot captures the full managed state — not just
// filter/NAT rules — without each backend re-probing capabilities. A backend that
// advertises neither feature leaves both fields nil, so the snapshot is unchanged.
func captureBackupState(ctx context.Context, mgr Manager, zoneName string, b *Backup) error {
	caps := mgr.Capabilities()
	if caps.DefaultPolicy {
		// Best-effort: a backend that cannot report a single coherent default policy
		// (iptables with out-of-band divergent IPv4/IPv6 chain policies) captures none
		// rather than failing the whole backup, and Restore then leaves the policy as
		// it finds it. A cancelled context is not that case — it would silently
		// produce a snapshot missing the policy a default-drop host depends on — so
		// it still fails the backup.
		policy, err := mgr.GetDefaultPolicy(ctx, zoneName)
		if err != nil && ctx.Err() != nil {
			return err
		}
		if err == nil {
			b.DefaultPolicy = policy
		}
	}
	if caps.AddressSets {
		sets, err := mgr.GetAddressSets(ctx)
		if err != nil {
			return err
		}
		b.AddressSets = sets
	}
	return nil
}

// restoreBackupSets recreates a backup's address sets so a set-referencing rule
// (@set) resolves on Restore. It runs before the filter rules are re-added. Only
// backends that advertise AddressSets act. cleanFirst removes each set before
// recreating it: a caller whose restore has already cleared the rules that could
// reference a set (a container backend that flushes its table/anchor) passes true
// so the set is rebuilt from a clean slate — needed for nftables, whose
// AddAddressSet is a no-op on an existing set and so would not reconcile its
// entries. A caller whose old rules are still loaded when sets are recreated
// (a tag/rewrite backend) passes false and relies on AddAddressSet's own
// idempotent create-or-reconcile (ipset -exist, pfctl -T replace).
func restoreBackupSets(ctx context.Context, mgr Manager, b *Backup, cleanFirst bool) error {
	if b == nil || !mgr.Capabilities().AddressSets {
		return nil
	}
	for _, set := range b.AddressSets {
		if cleanFirst {
			if err := mgr.RemoveAddressSet(ctx, set.Name); err != nil {
				return err
			}
		}
		if err := mgr.AddAddressSet(ctx, set); err != nil {
			return err
		}
	}
	return nil
}

// applyBackupPolicy re-asserts a backup's default policy, after the rules are
// restored (the policy is independent of rule order). Only backends that
// advertise DefaultPolicy act, and a nil snapshot policy (a backend that captured
// none) is left unchanged.
func applyBackupPolicy(ctx context.Context, mgr Manager, zoneName string, b *Backup) error {
	if b == nil || b.DefaultPolicy == nil || !mgr.Capabilities().DefaultPolicy {
		return nil
	}
	return mgr.SetDefaultPolicy(ctx, zoneName, b.DefaultPolicy)
}

// WriteBackup encodes backup as JSON to w so it can be persisted to disk (or
// moved to another host) and later replayed with ReadBackup or RestoreReader.
//
// The encoding is portable: enum fields are written as their stable string
// names, so a backup survives a reordering of the library's iota constants and
// is readable on a host running a different version of the library. Per-rule
// counters (Packets/Bytes) are carried through for the record but are ignored
// when a backup is restored (they are not part of rule identity).
//
//	f, _ := os.Create("backup.json")
//	_ = firewall.WriteBackup(f, backup)
func WriteBackup(w io.Writer, backup *Backup) error {
	if backup == nil {
		return fmt.Errorf("backup cannot be nil")
	}
	if w == nil {
		return fmt.Errorf("writer cannot be nil")
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(backup)
}

// ReadBackup decodes a backup previously written by WriteBackup from r.
//
//	f, _ := os.Open("backup.json")
//	backup, _ := firewall.ReadBackup(f)
//	_ = mgr.Restore(ctx, zone, backup)
func ReadBackup(r io.Reader) (*Backup, error) {
	if r == nil {
		return nil, fmt.Errorf("reader cannot be nil")
	}
	var backup Backup
	if err := json.NewDecoder(r).Decode(&backup); err != nil {
		return nil, err
	}
	return &backup, nil
}

// RestoreReader reads a backup from r and applies it via mgr.Restore. It is the
// streaming counterpart of Manager.Restore: a caller can replay a backup
// straight from a file or network reader without first buffering it into a
// *Backup. A read error is returned before any rules are touched.
//
//	f, _ := os.Open("backup.json")
//	_ = firewall.RestoreReader(ctx, mgr, zone, f)
func RestoreReader(ctx context.Context, mgr Manager, zoneName string, r io.Reader) error {
	backup, err := ReadBackup(r)
	if err != nil {
		return err
	}
	return mgr.Restore(ctx, zoneName, backup)
}
