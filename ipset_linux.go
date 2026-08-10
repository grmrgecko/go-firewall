package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// ipsetLayoutInstalled reports the ipset staging file and restore service a
// packaging uses, or empty strings when its persistence mechanism is not
// installed. The Debian layout restores sets through a netfilter-persistent
// plugin (proven by ipsetPlugin's presence); the RHEL and Arch layouts use a
// dedicated ipset service (proven by its unit or init.d script existing).
func ipsetLayoutInstalled(ctx context.Context, layout iptLayout) (path, service string) {
	if layout.ipsetPath == "" {
		return "", ""
	}
	if layout.ipsetPlugin != "" {
		if matches, _ := filepath.Glob(layout.ipsetPlugin); len(matches) == 0 {
			return "", ""
		}
		return layout.ipsetPath, layout.ipsetService
	}
	if !serviceInstalled(ctx, layout.ipsetService) {
		return "", ""
	}
	return layout.ipsetPath, layout.ipsetService
}

// detectIPSetPersistence reports the first installed ipset persistence mechanism
// among the known packagings, independent of which one manages the rules save
// files. It serves backends that keep their rules elsewhere but stage their sets
// as plain ipsets — ufw, whose host commonly carries the ipset package without
// iptables-persistent, so probing by rules layout would find nothing.
func detectIPSetPersistence(ctx context.Context) (path, service string) {
	for _, l := range iptLayouts {
		if p, s := ipsetLayoutInstalled(ctx, l); p != "" {
			return p, s
		}
	}
	return "", ""
}

// ipsetLiveFamily reports the family of a live kernel ipset by name: the shared
// set-family source for backends whose address sets are plain ipsets created
// live (iptables, and ufw through its iptables set helper). It is a variable so
// tests can substitute a fake kernel.
var ipsetLiveFamily = netlinkIPSetFamily

// ipsetRefFamily resolves the single family of the set(s) a rule references for
// every backend whose address sets are kernel ipsets: declared — the backend's
// own staged sets, its config file or hook — is consulted first, because those
// backends stage set changes and activate them on Reload, so a set staged but
// not yet loaded is the family the rule will actually match once both are
// applied. An unrelated live ipset sharing the name must not shadow it. The live
// kernel is the fallback, covering a set that exists only in the kernel (a host
// with no persistence mechanism, where sets are created live). declared runs
// lazily, at most once per resolve. A live query failure (netlink blocked, no
// privileges) just means not found live. Backends whose sets are not kernel
// ipsets (nftables named sets, firewalld's D-Bus ipsets) must not resolve
// through here.
func ipsetRefFamily(source, destination string, declared func() ([]*AddressSet, error)) (Family, error) {
	var sets []*AddressSet
	loaded := false
	return setRefFamilyFrom(func(name string) (Family, bool, error) {
		if !loaded {
			loaded = true
			var err error
			if sets, err = declared(); err != nil {
				return FamilyAny, false, err
			}
		}
		for _, s := range sets {
			if s.Name == name {
				return s.Family, true, nil
			}
		}
		if fam, found, err := ipsetLiveFamily(name); err == nil && found {
			return fam, true, nil
		}
		return FamilyAny, false, nil
	}, source, destination)
}

// --- live kernel ipsets -----------------------------------------------------
//
// Every kernel-side set operation but the staged bulk load goes through netlink
// here. The `ipset` binary is kept only for that load (ipset restore), where the
// tool owns the file format, parses the entries and negotiates each type's
// revision; doing that over netlink would mean reimplementing all three.
//
// Reading these back is deliberately kept in step with the save-format decode in
// iptables_linux.go: the same address set must look the same whether it was read
// from a staging file or from the kernel.

// ipsetCall runs a netlink ipset operation, turning the library's panic on a
// kernel error it cannot type-assert to syscall.Errno into an ordinary error.
// Every call into the library must be wrapped: the assertion is unchecked, so
// any non-Errno failure (a closed socket, a short read) would otherwise take the
// caller's process down.
func ipsetCall(op string, fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("ipset %s failed: %v", op, r)
		}
	}()
	return fn()
}

// ipsetNoSuchSet reports whether err is the kernel's answer for an operation on
// a set that does not exist, which every removal treats as already done.
func ipsetNoSuchSet(err error) bool {
	return errors.Is(err, syscall.ENOENT)
}

// ipsetInUse reports whether err is the kernel refusing to destroy a set that a
// loaded rule still matches on. The staged model reloads the rules before the
// destroys it owes, so this means a rule outside the staging file holds the set.
func ipsetInUse(err error) bool {
	var e nl.IPSetError
	return errors.As(err, &e) && (int(e) == nl.IPSET_ERR_BUSY || int(e) == nl.IPSET_ERR_REFERENCED)
}

// ipsetUnavailable reports whether err means the host has no ipset support at
// all — the kernel module is absent and nfnetlink has no subsystem to hand the
// request to. Read as no sets rather than an error, matching a host where the
// feature was never installed.
func ipsetUnavailable(err error) bool {
	return errors.Is(err, syscall.EOPNOTSUPP) || errors.Is(err, syscall.EPROTONOSUPPORT)
}

// ipsetNLFamily maps a family to the value the kernel's ipset API expects.
func ipsetNLFamily(f Family) uint8 {
	if f == IPv6 {
		return unix.AF_INET6
	}
	return unix.AF_INET
}

// ipsetEncodeEntry converts a set entry — a bare address or a CIDR — into the
// netlink form. Replace is set so add and delete carry the kernel's exist flag,
// the same idempotence `ipset -exist` gives.
func ipsetEncodeEntry(entry string) (*netlink.IPSetEntry, error) {
	if strings.Contains(entry, "/") {
		_, n, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("address set entry %q is not a valid cidr: %w", entry, err)
		}
		ones, _ := n.Mask.Size()
		return &netlink.IPSetEntry{IP: n.IP, CIDR: uint8(ones), Replace: true}, nil
	}
	ip := net.ParseIP(entry)
	if ip == nil {
		return nil, fmt.Errorf("address set entry %q is not an ip address or cidr", entry)
	}
	return &netlink.IPSetEntry{IP: ip, Replace: true}, nil
}

// ipsetDecodeEntry renders a kernel entry the way the save format writes it, so
// a set read live and the same set read from a staging file compare equal. A
// prefix covering the whole address is dropped, which is how `ipset save` emits
// a single host stored in a hash:net set.
func ipsetDecodeEntry(e netlink.IPSetEntry) string {
	if e.IP == nil {
		return ""
	}
	bits := 128
	if e.IP.To4() != nil {
		bits = 32
	}
	if e.CIDR == 0 || int(e.CIDR) == bits {
		return e.IP.String()
	}
	return e.IP.String() + "/" + strconv.Itoa(int(e.CIDR))
}

// ipsetCreate creates a kernel set, tolerating one that already exists with the
// same definition. The type revision is left to the netlink library, which maps
// hash:ip to its revision 1 and falls through to the base revision 0 for
// hash:net: every kernel carrying hash:net registers 0, and the revisions above
// it only add features (ranges, nomatch, counters, comments, forceadd, skbinfo)
// this library never asks for.
func ipsetCreate(name string, family Family, t SetType) error {
	return ipsetCall("create "+name, func() error {
		return netlink.IpsetCreate(name, t.String(), netlink.IpsetCreateOptions{
			Replace: true,
			Family:  ipsetNLFamily(family),
		})
	})
}

// ipsetDestroy removes a kernel set. A set that is already gone is success.
func ipsetDestroy(name string) error {
	err := ipsetCall("destroy "+name, func() error { return netlink.IpsetDestroy(name) })
	if err == nil || ipsetNoSuchSet(err) {
		return nil
	}
	if ipsetInUse(err) {
		return fmt.Errorf("address set %q is still referenced by a loaded rule: %w", name, err)
	}
	return err
}

// ipsetFlush empties a kernel set. A set that is already gone is success.
func ipsetFlush(name string) error {
	err := ipsetCall("flush "+name, func() error { return netlink.IpsetFlush(name) })
	if err != nil && !ipsetNoSuchSet(err) {
		return err
	}
	return nil
}

// ipsetAddEntry adds an entry to a kernel set. An entry already present is
// success; a set that does not exist is reported, since the caller asked to add
// to something that is not there.
func ipsetAddEntry(name, entry string) error {
	e, err := ipsetEncodeEntry(entry)
	if err != nil {
		return err
	}
	if err := ipsetCall("add "+name, func() error { return netlink.IpsetAdd(name, e) }); err != nil {
		if ipsetNoSuchSet(err) {
			return fmt.Errorf("address set %q does not exist", name)
		}
		return err
	}
	return nil
}

// ipsetDelEntry removes an entry from a kernel set. A missing entry, or a
// missing set, is success.
func ipsetDelEntry(name, entry string) error {
	e, err := ipsetEncodeEntry(entry)
	if err != nil {
		return err
	}
	err = ipsetCall("del "+name, func() error { return netlink.IpsetDel(name, e) })
	if err != nil && !ipsetNoSuchSet(err) {
		return err
	}
	return nil
}

// ipsetLiveSets reports every set the kernel holds, decoded into address sets.
// A host with no ipset support has no sets to report rather than an error, which
// keeps a Backup on such a host from failing over a feature it never had.
func ipsetLiveSets() ([]*AddressSet, error) {
	var res []netlink.IPSetResult
	err := ipsetCall("list", func() error {
		var e error
		res, e = netlink.IpsetListAll()
		return e
	})
	if err != nil {
		if ipsetUnavailable(err) {
			return nil, nil
		}
		return nil, err
	}
	sets := make([]*AddressSet, 0, len(res))
	for _, r := range res {
		if r.SetName == "" {
			continue
		}
		set := &AddressSet{Name: r.SetName, Family: IPv4, Type: SetHashIP}
		if r.Family == unix.NFPROTO_IPV6 {
			set.Family = IPv6
		}
		// An unmodeled type reads as hash:ip, matching how the save-format decode
		// treats a create line it does not recognize.
		if r.TypeName == SetHashNet.String() {
			set.Type = SetHashNet
		}
		for _, e := range r.Entries {
			if s := ipsetDecodeEntry(e); s != "" {
				set.Entries = append(set.Entries, s)
			}
		}
		sets = append(sets, set)
	}
	return sets, nil
}

// netlinkIPSetFamily queries the kernel's ipset subsystem over netlink for a
// set's family. A set that does not exist reports found=false; any other
// failure (netlink unavailable, insufficient privileges) is an error the caller
// can fall back from.
func netlinkIPSetFamily(name string) (fam Family, found bool, err error) {
	var res *netlink.IPSetResult
	err = ipsetCall("list "+name, func() error {
		var e error
		res, e = netlink.IpsetList(name)
		return e
	})
	if err != nil {
		if ipsetNoSuchSet(err) {
			return FamilyAny, false, nil
		}
		return FamilyAny, false, err
	}
	if res.Family == unix.NFPROTO_IPV6 {
		return IPv6, true, nil
	}
	return IPv4, true, nil
}
