//go:build integration

// Package firewall integration tests exercise the real firewall backends
// end-to-end (add a rule, read it back, remove it) rather than the marshal
// helpers the other _test.go files cover. They are gated behind the `integration`
// build tag so a normal `go test ./...` never touches a live firewall; run them
// with `go test -tags integration`.
//
// This file holds the platform-independent core — the capability-driven
// runManagerSuite and its helpers. Each OS has an integration_<goos>_test.go with a
// TestIntegration that lists the backends available there (nft/iptables/firewalld/
// ufw/csf/apf on Linux, pf on freebsd/darwin, wf on windows) and hands them to
// runIntegration. The suite is capability-driven: for each backend it inspects
// Capabilities() and exercises exactly the features that backend advertises,
// skipping the rest.
//
// These tests need privileges and the backend's real tooling, and they mutate the
// live firewall state of the machine they run on, so they are meant to run inside
// the throwaway VMs/containers under test/integration/, not on a workstation. Set
// FIREWALL_BACKEND to target one backend (a construction failure is then fatal,
// since the environment is expected to provide it); leave it unset to run whatever
// backends are present, skipping the rest.
package firewall

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// integrationPrefix namespaces every rule, set and table this suite creates so
// its writes are distinguishable from anything else on the box and, combined with
// the isolated container netns, are safe to clean up.
const integrationPrefix = "gofwit"

// backendFactory pairs a backend's name with its constructor so a platform's
// TestIntegration can build them from a single table.
type backendFactory struct {
	name string
	new  func(ctx context.Context, rulePrefix string) (Manager, error)
}

// foreignSeed is a rule planted out of band with a backend's own tooling, standing
// in for a rule a human operator added, plus what the library should observe for
// it. Each platform's foreignSeeder produces one; see integration_linux_test.go.
type foreignSeed struct {
	// rule is what GetRules should report for the seeded rule.
	rule *Rule
	// hasPrefix is what the informational HasPrefix flag should read: false on the
	// tag-based backends (no library comment/tag on the seeded rule) and for a
	// foreign nft table, true on firewalld, whose container is the zone itself, so
	// every rule read from it carries the flag.
	hasPrefix bool
	// inScope reports whether the backend's mutations reach the seeded rule. A
	// foreign nft table and a foreign pf anchor are out of scope: the backend
	// reports them but writes only to its own table or anchor, so RemoveRule
	// refuses them with ErrForeignTable and Sync skips them.
	inScope bool
	// narrow is a rule the seed covers but which does not cover the seed, set only
	// for an out-of-scope seed. Sync must still add it to the backend's own table
	// or anchor: a foreign rule elsewhere does not stand in for one of ours.
	narrow *Rule
	// undo unseeds, best effort — the suite's RemoveRule normally already has.
	undo func()
}

// foreignNATSeed is a translation rule planted out of band in a table or anchor the
// backend reports but does not write to. Each platform's foreignNATSeeder produces
// one; see integration_linux_test.go.
type foreignNATSeed struct {
	// rule is what GetNATRules should report for the seeded rule.
	rule *NATRule
	// undo unseeds, best effort.
	undo func()
}

// runIntegration constructs each backend in backends and runs the capability suite
// against it. It honors FIREWALL_BACKEND: when set, only that backend runs and a
// construction failure is fatal (the environment is expected to provide it); when
// unset, backends that fail to construct are skipped. Each platform's
// TestIntegration (in the per-OS integration_<goos>_test.go files) calls this with
// the backends available there.
func runIntegration(t *testing.T, backends []backendFactory) {
	// Trim whitespace: a value passed through a Windows `set VAR=x && ...` picks up
	// a trailing space, and a shell may add a stray CR.
	want := strings.TrimSpace(os.Getenv("FIREWALL_BACKEND"))

	ran := 0
	for _, b := range backends {
		if want != "" && b.name != want {
			continue
		}
		t.Run(b.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			mgr, err := b.new(ctx, integrationPrefix)
			if err != nil {
				if want != "" {
					t.Fatalf("construct %s backend: %v", b.name, err)
				}
				t.Skipf("%s backend not available: %v", b.name, err)
			}
			// reconstruct builds a fresh manager of the same backend, simulating a
			// process restart against firewall state that outlives the process. Some
			// invariants (a set default policy surviving a later mutation) only hold
			// across a fresh instance, so the suite needs to build one on demand.
			reconstruct := func(ctx context.Context) (Manager, error) {
				return b.new(ctx, integrationPrefix)
			}
			runManagerSuite(t, mgr, reconstruct)
		})
		ran++
	}

	if want != "" && ran == 0 {
		t.Fatalf("FIREWALL_BACKEND=%q does not name a known backend", want)
	}
}

// runManagerSuite runs the capability-driven feature suite against a constructed
// manager. Each feature is a subtest gated on the backend's advertised
// Capabilities(); unsupported features are skipped rather than exercised.
// reconstruct builds a fresh manager of the same backend for invariants that only
// hold across a simulated process restart.
func runManagerSuite(t *testing.T, mgr Manager, reconstruct func(context.Context) (Manager, error)) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	caps := mgr.Capabilities()
	t.Logf("backend %s output=%v capabilities=%+v", mgr.Type(), caps.Output, caps)

	// Resolve the zone once. firewalld returns its default zone; the others
	// return "" and ignore the argument.
	zone, err := mgr.GetZone(ctx, "")
	if err != nil {
		zone = ""
	}

	defer func() {
		// Best-effort: activate whatever the suite left behind, then close. Both are
		// part of the Manager contract and worth exercising once per backend.
		_ = mgr.Reload(ctx)
		_ = mgr.Close(ctx)
	}()

	// --- filter-rule features -------------------------------------------------

	t.Run("basic", func(t *testing.T) {
		roundTripRule(t, ctx, mgr, zone, &Rule{Proto: TCP, Port: 22, Action: Accept})
	})

	t.Run("protoonly", func(t *testing.T) {
		// A bare protocol match with no port and no address ("allow all TCP inbound").
		// ufw must carry the protocol rather than emit a bare `allow in`, which ufw
		// rejects. Backends that cannot express a portless, address-less protocol match
		// skip via the ErrUnsupported sentinel.
		rule := &Rule{Proto: TCP, Action: Accept}
		err := mgr.AddRule(ctx, zone, rule)
		if errors.Is(err, ErrUnsupported) {
			t.Skip("backend cannot express a portless, address-less protocol match")
		}
		require.NoError(t, err)
		t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, rule) })

		rules := rulesOf(t, ctx, mgr, zone)
		require.True(t, containsRule(rules, rule, mgr.Capabilities().Output),
			"bare TCP rule not found in %s", dumpRules(rules))
		require.NoError(t, mgr.RemoveRule(ctx, zone, rule))
		require.False(t, containsRule(rulesOf(t, ctx, mgr, zone), rule, mgr.Capabilities().Output),
			"bare TCP rule still present after removal")
	})

	t.Run("hasprefix", func(t *testing.T) {
		// A rule this library adds must read back exactly once — nft and pf also
		// list foreign tables/anchors and must not re-list their own — and report
		// HasPrefix: the suite runs with a non-empty prefix, so every backend either
		// tags its rules with that prefix or isolates them in its own container.
		//
		// The rule carries a source address on purpose. An address-less port accept
		// lands in apf/csf's native shared port lists (conf.apf IG_TCP_CPORTS,
		// csf.conf TCP_IN) — a comma-separated value on a single config line with
		// nowhere to attach a per-rule prefix, so HasPrefix is legitimately false
		// there (documented in apf_linux.go/csf_linux.go). A host+port accept instead
		// routes those backends into their taggable allow files, exercising the
		// HasPrefix contract on a rule form every backend can tag or isolate.
		rule := &Rule{Proto: TCP, Port: 3456, Source: "192.0.2.10/32", Action: Accept}
		require.NoError(t, mgr.AddRule(ctx, zone, rule))
		t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, rule) })

		var matches []*Rule
		for _, r := range rulesOf(t, ctx, mgr, zone) {
			if r.EqualBase(rule, mgr.Capabilities().Output) {
				matches = append(matches, r)
			}
		}
		require.Len(t, matches, 1, "an added rule must read back exactly once, got %s", dumpRules(matches))
		require.True(t, matches[0].HasPrefix, "a rule this library added must report HasPrefix")
	})

	t.Run("foreignrule", func(t *testing.T) {
		// The library manages the ACTUAL firewall, not only its own rules: a rule
		// created out of band with the backend's own tooling must surface in
		// GetRules and be removable with RemoveRule, or Sync/Backup/Restore could
		// never converge on real firewall state. Each platform provides a seeder
		// that plants a rule the way an operator would (foreignSeeder); a backend
		// with no seeder skips.
		seeder := foreignSeeder(mgr)
		if seeder == nil {
			t.Skip("no out-of-band seeder for this backend")
		}
		seed, err := seeder(zone)
		if err != nil {
			t.Skipf("could not seed a foreign rule: %v", err)
		}
		t.Cleanup(seed.undo)

		rules := rulesOf(t, ctx, mgr, zone)
		require.True(t, containsRule(rules, seed.rule, caps.Output),
			"a rule seeded out of band must surface in GetRules, got %s", dumpRules(rules))
		got := findRule(t, ctx, mgr, zone, seed.rule)
		require.Equal(t, seed.hasPrefix, got.HasPrefix,
			"HasPrefix must reflect how the backend namespaces its rules (informational only, never an ownership filter)")

		if !seed.inScope {
			// Reported but outside the backend's mutation scope (a foreign nft table
			// or pf anchor): RemoveRule must say so rather than report a removal that
			// did not happen, and must leave the rule alone.
			err := mgr.RemoveRule(ctx, zone, seed.rule)
			require.ErrorIs(t, err, ErrForeignTable,
				"removing a reported out-of-scope rule must return ErrForeignTable, got %v", err)
			require.True(t, containsRule(rulesOf(t, ctx, mgr, zone), seed.rule, caps.Output),
				"an out-of-scope foreign rule must survive the refused removal")

			// A DirAny target whose input half is the foreign seed and whose output
			// half is in the backend's own table or anchor: the own half is removed
			// and the foreign half still reports ErrForeignTable.
			if caps.Output {
				both := *seed.rule
				both.Direction = DirAny
				var own *Rule
				for _, half := range expandDirections(&both) {
					if half.Direction == DirOutput {
						own = half
					}
				}
				require.NotNil(t, own, "a DirAny rule must expand to an output half")
				require.NoError(t, mgr.AddRule(ctx, zone, own))
				t.Cleanup(func() { _ = mgr.RemoveRule(context.Background(), zone, own) })
				err = mgr.RemoveRule(ctx, zone, &both)
				assert.ErrorIs(t, err, ErrForeignTable,
					"a DirAny target with a foreign half must report it, got %v", err)
				rules := rulesOf(t, ctx, mgr, zone)
				assert.False(t, containsRule(rules, own, caps.Output),
					"the output half in the backend's own table must be removed despite the foreign input half")
				assert.True(t, containsRule(rules, seed.rule, caps.Output),
					"the foreign input half must survive")
			}

			// Removing a rule that exists nowhere stays an idempotent no-op.
			absent := &Rule{Family: IPv4, Source: "192.0.2.99", Proto: TCP, Port: 8999, Action: Accept}
			require.NoError(t, mgr.RemoveRule(ctx, zone, absent),
				"removing an absent rule must no-op, not error")

			// Sync toward a desired set that omits the seed but wants a narrower rule
			// the seed covers. The seed is skipped, not counted as removed, and does
			// not count as covering the narrow rule, so the narrow rule lands in the
			// backend's own table or anchor.
			var desired []*Rule
			for _, r := range rulesOf(t, ctx, mgr, zone) {
				if !r.EqualBase(seed.rule, caps.Output) {
					desired = append(desired, r)
				}
			}
			desired = append(desired, seed.narrow)
			t.Cleanup(func() { _ = mgr.RemoveRule(context.Background(), zone, seed.narrow) })
			added, removed, err := Sync(ctx, mgr, zone, desired)
			require.NoError(t, err, "Sync must skip an out-of-scope rule, not fail on it")
			assert.Zero(t, removed, "a skipped out-of-scope rule must not count as removed")
			assert.Equal(t, 1, added, "the narrow rule must be added despite the broader foreign rule")
			assert.True(t, containsRule(rulesOf(t, ctx, mgr, zone), seed.rule, caps.Output),
				"Sync must leave the out-of-scope rule in place")
			got := findRule(t, ctx, mgr, zone, seed.narrow)
			assert.True(t, got.HasPrefix, "the narrow rule must land in the backend's own table or anchor")
			require.NoError(t, mgr.RemoveRule(ctx, zone, seed.narrow),
				"the narrow rule lives in the backend's own table and must be removable")
			return
		}
		require.NoError(t, mgr.RemoveRule(ctx, zone, seed.rule),
			"a foreign rule is managed like any other and must be removable")
		require.False(t, containsRule(rulesOf(t, ctx, mgr, zone), seed.rule, caps.Output),
			"foreign rule still present after removal")
	})

	t.Run("output", func(t *testing.T) {
		requireCap(t, caps.Output)
		roundTripRule(t, ctx, mgr, zone, &Rule{Direction: DirOutput, Proto: TCP, Port: 8080, Action: Accept})
	})

	t.Run("forward", func(t *testing.T) {
		requireCap(t, caps.Forward)
		// A classic routed-traffic filter: allow forwarding TCP from one network to
		// another through the host. It binds no interface, so it does not depend on
		// the test host having a particular NIC.
		roundTripRule(t, ctx, mgr, zone, &Rule{
			Direction: DirForward, Family: IPv4, Proto: TCP, Port: 8080,
			Source: "192.0.2.0/24", Destination: "198.51.100.0/24", Action: Accept,
		})
	})

	t.Run("hostaddress", func(t *testing.T) {
		// A rule matching a single host address, written with an explicit /32.
		// Backends re-spell an address on read — nft and ufw strip the /32,
		// firewalld requires and stores a family, iptables-save adds the /32 — so
		// this is where a rule silently fails to read back or reconcile. Left
		// FamilyAny so the backend must resolve the family from the address itself.
		roundTripRule(t, ctx, mgr, zone, &Rule{Proto: TCP, Port: 22, Source: "192.0.2.10/32", Action: Accept})
	})

	t.Run("hostnoport", func(t *testing.T) {
		// Portless host shapes. csf/apf trust files store a single all-protocol
		// address and their advanced rule holds a single port, so a portless
		// concrete-protocol host, a source+destination pair, and (for apf) a
		// multi-port list have no trust-file form there and route to the
		// raw-iptables hook (shapeNeedsHook / needsHook), while csf expresses a
		// multi-port list natively as a comma list. The chain backends express the
		// same shapes natively. Every backend runs every shape so a bug in
		// whichever path expresses it shows up; a backend that cannot express a
		// shape at all skips via the ErrUnsupported sentinel.
		t.Run("protohost", func(t *testing.T) {
			// A concrete-protocol host with no port.
			roundTripRuleOrSkip(t, ctx, mgr, zone, &Rule{Proto: TCP, Source: "192.0.2.40/32", Action: Accept})
		})
		t.Run("srcdstpair", func(t *testing.T) {
			// A source+destination pair with no port.
			roundTripRuleOrSkip(t, ctx, mgr, zone, &Rule{Source: "192.0.2.41/32", Destination: "192.0.2.42/32", Action: Accept})
		})
		t.Run("multiportdeny", func(t *testing.T) {
			// A multi-port list as a deny: apf writes it to the hook with its literal
			// action, while csf writes it to csf.deny, whose action follows csf.conf
			// (stock DROP). Probe both actions and round-trip the first the backend
			// accepts, mirroring the denyaddress case. firewalld/pf fan the list
			// into one row per port and ufw coalesces adjacent ports into a range,
			// so the read-back is checked by coverage.
			var rule *Rule
			for _, v := range []*Rule{
				{Proto: TCP, Ports: []PortRange{{Start: 5001, End: 5001}, {Start: 5002, End: 5002}}, Action: Reject},
				{Proto: TCP, Ports: []PortRange{{Start: 5001, End: 5001}, {Start: 5002, End: 5002}}, Action: Drop},
			} {
				err := mgr.AddRule(ctx, zone, v)
				if errors.Is(err, ErrUnsupported) {
					continue
				}
				require.NoError(t, err)
				require.NoError(t, mgr.RemoveRule(ctx, zone, v))
				rule = v
				break
			}
			if rule == nil {
				t.Skip("backend cannot express this shape in any probed form")
			}
			roundTripPortSet(t, ctx, mgr, zone, rule)
		})
		t.Run("multiporthost", func(t *testing.T) {
			// A multi-port list as a host accept: apf hooks it, csf writes an
			// advanced rule, firewalld/pf fan it into one row per port, and ufw
			// coalesces adjacent discrete ports into a range; coverage checks the
			// read-back in every form.
			roundTripPortSet(t, ctx, mgr, zone, &Rule{Proto: TCP, Ports: []PortRange{{Start: 6001, End: 6001}, {Start: 6002, End: 6002}}, Source: "192.0.2.43/32", Action: Accept})
		})
	})

	t.Run("matchcombos", func(t *testing.T) {
		// Combined matches that overflow a csf/apf advanced line — it holds exactly
		// one address field and one port-flow field — so both route them to their
		// raw-iptables hook (shapeNeedsHook); the chain backends match -s with -d
		// and --sport with --dport directly. Every backend runs every combo; the
		// only capability in play is PortPair (firewalld's rich rules carry a
		// single port element). Port 22 is avoided in every field so an SSH-driven
		// run keeps its session.
		t.Run("portedpair", func(t *testing.T) {
			// A source+destination pair carrying a destination port: the second address
			// overflows the advanced line on csf/apf, reaching MarshalAdvRule. Every
			// backend expresses it; no capability gates it, so the round trip is
			// unconditional.
			roundTripRule(t, ctx, mgr, zone, &Rule{Proto: TCP, Port: 8443, Source: "192.0.2.50/32", Destination: "198.51.100.50/32", Action: Accept})
		})
		t.Run("sourceportpair", func(t *testing.T) {
			// The same pair on a source port.
			roundTripRule(t, ctx, mgr, zone, &Rule{Proto: UDP, SourcePort: 5353, Source: "192.0.2.51/32", Destination: "198.51.100.51/32", Action: Accept})
		})
		t.Run("icmppair", func(t *testing.T) {
			// The same pair on a typed ICMP match.
			roundTripRule(t, ctx, mgr, zone, &Rule{Proto: ICMP, ICMPType: Ptr[uint8](13), Source: "192.0.2.52/32", Destination: "198.51.100.52/32", Action: Accept})
		})
		t.Run("bothports", func(t *testing.T) {
			// A source port matched together with a destination port, with an
			// address. firewalld advertises PortPair false (a rich rule carries a
			// single port element) and is gated out; everyone else must express it.
			requireCap(t, caps.PortPair)
			roundTripRule(t, ctx, mgr, zone, &Rule{Proto: TCP, Port: 8444, SourcePort: 5354, Source: "192.0.2.53/32", Action: Accept})
		})
		t.Run("bothportsbare", func(t *testing.T) {
			// The same source+destination port match without an address.
			requireCap(t, caps.PortPair)
			roundTripRule(t, ctx, mgr, zone, &Rule{Proto: TCP, Port: 8445, SourcePort: 5355, Action: Accept})
		})
	})

	t.Run("negatedaddress", func(t *testing.T) {
		requireCap(t, caps.Negation)
		// A negated source must round-trip through whatever path expresses it:
		// iptables/nft/pf/firewalld negate natively, ufw's tuple grammar cannot so
		// it reroutes to the before.rules raw path (iptables `! -s`), and csf/apf
		// route it to their raw-iptables hook. wf advertises Negation false (WFP
		// has no negated address condition) and is gated out; everyone else must
		// express it.
		roundTripRule(t, ctx, mgr, zone, &Rule{Proto: TCP, Port: 22, Source: "!192.0.2.50/32", Action: Accept})
	})

	t.Run("denyaddress", func(t *testing.T) {
		// A deny rule carrying a host address exercises the deny-list address path
		// (csf.deny / apf deny_hosts, and the reject chains elsewhere). Reject is
		// used because the address-list backends canonicalize a deny to it; Windows
		// Filtering Platform has no reject action and falls back to Drop.
		roundTripVariants(t, ctx, mgr, zone,
			&Rule{Family: IPv4, Proto: TCP, Port: 3389, Source: "192.0.2.20/32", Action: Reject},
			&Rule{Family: IPv4, Proto: TCP, Port: 3389, Source: "192.0.2.20/32", Action: Drop},
		)
	})

	t.Run("denyexactaction", func(t *testing.T) {
		// A deny must read back with the exact action it was added with, or a
		// caller managing it sees churn on every Sync (read back as one action,
		// never equal to the desired other). The stakes are highest on csf/apf,
		// whose deny stores encode no action of their own — the tool applies an
		// action taken from config (csf.conf DROP / conf.apf ALL_STOP, stock
		// default DROP), so a deny whose action matches config is stored natively
		// and one that differs is injected through their pre-hook rather than
		// refused — but the property holds for every backend, so both actions run
		// everywhere. A backend with no reject action at all (wf) advertises
		// RejectAction false and skips that action by capability.
		for _, tc := range []struct {
			name string
			deny *Rule
		}{
			{"drop", &Rule{Family: IPv4, Proto: TCP, Port: 3390, Source: "192.0.2.30/32", Action: Drop}},
			{"reject", &Rule{Family: IPv4, Proto: TCP, Port: 3390, Source: "192.0.2.31/32", Action: Reject}},
		} {
			deny := tc.deny
			t.Run(tc.name, func(t *testing.T) {
				if deny.Action == Reject {
					requireCap(t, caps.RejectAction)
				}
				require.NoError(t, mgr.AddRule(ctx, zone, deny))
				t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, deny) })

				// The rule must read back with its exact action so it compares equal to the
				// desired rule and Sync leaves it in place rather than churning it.
				got := findRule(t, ctx, mgr, zone, deny)
				require.Equal(t, deny.Action, got.Action,
					"a deny must read back with its exact action, not a config default: %+v", deny)
				require.True(t, got.Equal(deny, mgr.Capabilities().Output),
					"the read-back deny must equal the desired rule so Sync does not churn it: %+v", deny)

				require.NoError(t, mgr.RemoveRule(ctx, zone, deny))
				require.False(t, containsRule(rulesOf(t, ctx, mgr, zone), deny, mgr.Capabilities().Output),
					"deny rule still present after removal: %+v", deny)
			})
		}
	})

	t.Run("removeclearscustomerrawcopy", func(t *testing.T) {
		// A backend that keeps a raw-iptables side store alongside its native store —
		// the csf/apf pre-hook, ufw's before.rules — can hold a hand-added copy of a
		// rule it could just as well express natively: a customer editing csfpre.sh /
		// hook_pre.sh / before.rules. RemoveRule must clear that copy too: routing such
		// a rule only to the native path would remove it from the config while leaving
		// it running in the raw store. Plant the rule directly in the store to stand in
		// for the hand-added copy; a backend with no side store skips.
		plant := rawCopyPlanter(mgr)
		if plant == nil {
			t.Skip("backend has no raw side store")
		}

		// A host+port accept is a natively expressible shape, so RemoveRule routes
		// it to the native store and must look in the raw store too.
		r := &Rule{Family: IPv4, Proto: TCP, Port: 4567, Source: "192.0.2.60/32", Action: Accept}
		require.NoError(t, plant(r), "planting the customer raw copy must succeed")
		require.True(t, containsRule(rulesOf(t, ctx, mgr, zone), r, mgr.Capabilities().Output),
			"the planted raw rule must read back")

		require.NoError(t, mgr.RemoveRule(ctx, zone, r))
		require.False(t, containsRule(rulesOf(t, ctx, mgr, zone), r, mgr.Capabilities().Output),
			"RemoveRule must clear a native-shaped rule's raw-store copy, not leave it running")
	})

	t.Run("denyport", func(t *testing.T) {
		// A port-only deny (a port with no address) exercises the address-less deny
		// path. Native backends write it directly; the csf/apf address-list backends
		// have no way to carry a bare port, so they must synthesize the "any" network
		// (0.0.0.0/0 // ::/0) as a placeholder address — otherwise the line is parsed
		// but silently never applied by the tool, leaving the port open while AddRule
		// reports success. The deny action follows config on those backends (csf.conf
		// DROP / apf ALL_STOP, stock default Drop), so try Reject first (native reject
		// backends) then Drop (the address-list default); roundTripVariants asserts the
		// accepted form is actually present after add, which fails if nothing was written.
		roundTripVariants(t, ctx, mgr, zone,
			&Rule{Proto: TCP, Port: 3391, Action: Reject},
			&Rule{Proto: TCP, Port: 3391, Action: Drop},
		)
	})

	t.Run("familypairremove", func(t *testing.T) {
		// A v4 rule and its v6 twin are two rows on most backends. Removing every rule
		// the backend reports must clear them all. The remove must match a
		// family-agnostic rule (not no-op and leave the port open) and must clear both
		// rows, not just one. Gated on FamilyWithoutAddress (the probe rules are
		// family-pinned bare ports); the per-family sentinel-continue below covers
		// only the environment case
		// of a backend whose own IPv6 handling is off (csf/apf).
		requireCap(t, caps.FamilyWithoutAddress)
		const port = 3492
		v4 := &Rule{Family: IPv4, Proto: TCP, Port: port, Action: Accept}
		v6 := &Rule{Family: IPv6, Proto: TCP, Port: port, Action: Accept}
		added := 0
		for _, r := range []*Rule{v4, v6} {
			err := mgr.AddRule(ctx, zone, r)
			if errors.Is(err, ErrUnsupported) {
				continue // the backend cannot express this family of a bare-port accept.
			}
			require.NoError(t, err)
			added++
		}
		if added == 0 {
			t.Skip("backend expresses neither family of a bare-port accept")
		}
		t.Cleanup(func() {
			_ = mgr.RemoveRule(ctx, zone, v4)
			_ = mgr.RemoveRule(ctx, zone, v6)
		})

		portRule := func(r *Rule) bool { return r.Proto == TCP && r.Port == port }

		// With both families expressible, GetRules must report coverage for BOTH. A
		// cross-family dedup that matches on a family-agnostic Equal would drop the
		// v6 add and leave IPv6 unprotected; a concrete-family removal must then clear
		// only its own family and leave the twin in place.
		if added == 2 {
			familyCoverage := func() (v4Cov, v6Cov bool) {
				for _, r := range rulesOf(t, ctx, mgr, zone) {
					if !portRule(r) {
						continue
					}
					switch r.Family {
					case FamilyAny:
						v4Cov, v6Cov = true, true
					case IPv4:
						v4Cov = true
					case IPv6:
						v6Cov = true
					}
				}
				return
			}
			has4, has6 := familyCoverage()
			require.True(t, has4 && has6,
				"both families must be present after adding the v4/v6 pair; a missing family means a cross-family add was silently dropped")

			require.NoError(t, mgr.RemoveRule(ctx, zone, v4))
			has4, has6 = familyCoverage()
			require.True(t, has6, "removing the v4 twin must leave the v6 twin in place")
			require.False(t, has4, "removing the v4 twin must not leave a v4 row behind")

			// Restore the pair so the remove-all phase below starts from both rows.
			require.NoError(t, mgr.AddRule(ctx, zone, v4))
		}

		// Remove each rule the backend reports for this port (one family-agnostic rule,
		// or one per family), then confirm none remain — a removal must not leave a
		// twin row behind.
		for _, r := range rulesOf(t, ctx, mgr, zone) {
			if portRule(r) {
				require.NoError(t, mgr.RemoveRule(ctx, zone, r))
			}
		}
		for _, r := range rulesOf(t, ctx, mgr, zone) {
			require.False(t, portRule(r), "port %d rule still present after removal: %+v", port, r)
		}
	})

	t.Run("familyanysplitremove", func(t *testing.T) {
		// Unlike familypairremove (which adds a v4/v6 PAIR), this adds ONE FamilyAny
		// rule. A FamilyAny rule with no address is stored as a single dual-family
		// object by the unified backends (nft inet, pf without af, firewalld's
		// dual-stack zone entries) and as one row per family by the separated backends;
		// either way GetRules reports coverage for both families. Removing a single
		// family must leave the other in place — the backend splits the dual object
		// (apf splits its dual-stack port list through the raw-iptables hook). The
		// split is gated on FamilyWithoutAddress: wf's address-less filters cannot
		// pin one family, so it advertises the capability false. A concrete-family
		// removal must drop only the targeted family (nft/pf must not over-remove
		// both; firewalld zone entries must not under-remove and leave both).

		// splitCase is one dual-family rule shape plus a matcher over GetRules output.
		type splitCase struct {
			anyRule, v4, v6 *Rule
			match           func(*Rule) bool
		}

		// runSplit exercises a shape: add the FamilyAny rule, remove each family in
		// turn, and confirm the other survives. A single-family removal implies
		// expressing a single-family rule of the shape, so the split is gated on
		// FamilyWithoutAddress (wf cannot pin a family without an address).
		runSplit := func(t *testing.T, c splitCase) {
			requireCap(t, caps.FamilyWithoutAddress)
			// Each family must survive the other's removal, so the backend must
			// manage IPv6 at all (apf/csf with their own IPv6 handling off do not).
			requireCap(t, caps.IPv6)
			coverage := func() (v4Cov, v6Cov bool) {
				for _, r := range rulesOf(t, ctx, mgr, zone) {
					if !c.match(r) {
						continue
					}
					switch r.Family {
					case FamilyAny:
						v4Cov, v6Cov = true, true
					case IPv4:
						v4Cov = true
					case IPv6:
						v6Cov = true
					}
				}
				return
			}
			clear := func() {
				for _, r := range rulesOf(t, ctx, mgr, zone) {
					if c.match(r) {
						require.NoError(t, mgr.RemoveRule(ctx, zone, r))
					}
				}
			}

			// The backend must express this FamilyAny shape with dual coverage; skip
			// where it cannot (csf/apf need an address, etc.).
			if err := mgr.AddRule(ctx, zone, c.anyRule); errors.Is(err, ErrUnsupported) {
				t.Skip("backend cannot express this bare FamilyAny shape")
			} else {
				require.NoError(t, err)
			}
			t.Cleanup(clear)
			if has4, has6 := coverage(); !(has4 && has6) {
				clear()
				t.Skipf("backend does not give this FamilyAny shape dual coverage (v4=%v v6=%v)", has4, has6)
			}

			// Remove IPv4; IPv6 must survive. FamilyWithoutAddress is required
			// above, so a single-family removal of the shape must be expressible.
			require.NoError(t, mgr.RemoveRule(ctx, zone, c.v4))
			has4, has6 := coverage()
			require.False(t, has4, "removing IPv4 must clear IPv4 coverage")
			require.True(t, has6, "removing IPv4 from a FamilyAny rule must leave IPv6 in place")

			// Opposite direction from a clean slate: remove IPv6, IPv4 must survive.
			clear()
			require.NoError(t, mgr.AddRule(ctx, zone, c.anyRule))
			if has4, has6 := coverage(); !(has4 && has6) {
				t.Fatalf("re-adding the FamilyAny rule must restore both families (v4=%v v6=%v)", has4, has6)
			}
			require.NoError(t, mgr.RemoveRule(ctx, zone, c.v6))
			has4, has6 = coverage()
			require.False(t, has6, "removing IPv6 must clear IPv6 coverage")
			require.True(t, has4, "removing IPv6 from a FamilyAny rule must leave IPv4 in place")
		}

		t.Run("destport", func(t *testing.T) {
			const p uint16 = 3493
			runSplit(t, splitCase{
				anyRule: &Rule{Family: FamilyAny, Proto: TCP, Port: p, Action: Accept},
				v4:      &Rule{Family: IPv4, Proto: TCP, Port: p, Action: Accept},
				v6:      &Rule{Family: IPv6, Proto: TCP, Port: p, Action: Accept},
				match: func(r *Rule) bool {
					s := r.PortSpecs()
					return r.Proto == TCP && len(s) == 1 && s[0].Start == p && !r.HasSourcePorts()
				},
			})
		})

		t.Run("sourceport", func(t *testing.T) {
			const p uint16 = 3494
			runSplit(t, splitCase{
				anyRule: &Rule{Family: FamilyAny, Proto: TCP, SourcePort: p, Action: Accept},
				v4:      &Rule{Family: IPv4, Proto: TCP, SourcePort: p, Action: Accept},
				v6:      &Rule{Family: IPv6, Proto: TCP, SourcePort: p, Action: Accept},
				match: func(r *Rule) bool {
					s := r.SourcePortSpecs()
					return r.Proto == TCP && len(s) == 1 && s[0].Start == p && !r.HasPorts()
				},
			})
		})

		t.Run("ordering", func(t *testing.T) {
			requireCap(t, caps.RuleOrdering)
			// On an ordered backend the surviving family must keep the dual rule's place
			// in the chain, not jump to the end after the split re-adds it. AddRule order
			// is backend-specific (nft appends, iptables prepends), so read the actual
			// order rather than assume it, then assert the split leaves it unchanged. The
			// split removes IPv6 and every probe rule's survivor is IPv4, so a
			// family-separated backend (iptables/ufw read their v4 chain first) keeps the
			// survivor in its slot too — no false failure there.
			const before, dual, after uint16 = 3496, 3497, 3498
			rBefore := &Rule{Family: IPv4, Proto: TCP, Port: before, Action: Accept}
			rDual := &Rule{Family: FamilyAny, Proto: TCP, Port: dual, Action: Accept}
			rAfter := &Rule{Family: IPv4, Proto: TCP, Port: after, Action: Accept}
			for _, r := range []*Rule{rBefore, rDual, rAfter} {
				if err := mgr.AddRule(ctx, zone, r); errors.Is(err, ErrUnsupported) {
					t.Skip("backend cannot express one of the ordering probe rules")
				} else {
					require.NoError(t, err)
				}
				t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, r) })
			}
			// A family-separated backend stores the dual rule as a v4 row and a v6 row, so
			// read the order of the rows that survive the split — everything but IPv6 —
			// and require the split to leave exactly that sequence in place.
			ports := map[uint16]bool{before: true, dual: true, after: true}
			survivingOrder := func() []uint16 {
				var out []uint16
				for _, r := range rulesOf(t, ctx, mgr, zone) {
					if ports[r.Port] && r.impliedFamily() != IPv6 {
						out = append(out, r.Port)
					}
				}
				return out
			}
			order0 := survivingOrder()
			require.Len(t, order0, 3, "all three probe rules should be present before the split")

			// Split off IPv6; the surviving IPv4 row must keep the dual rule's position.
			require.NoError(t, mgr.RemoveRule(ctx, zone, &Rule{Family: IPv6, Proto: TCP, Port: dual, Action: Accept}))
			require.Equal(t, order0, survivingOrder(),
				"the re-added surviving family must keep the dual rule's position")
		})
	})

	t.Run("tcpudproundtrip", func(t *testing.T) {
		// A TCPUDP rule matches both transports. Backends with no both-transports form
		// (iptables, pf, firewalld, wf, csf/apf's per-transport config lists) store it
		// as a tcp row plus a udp row; nftables stores it as one `meta l4proto
		// { tcp, udp }` row; ufw as one any-protocol tuple. GetRules reports whichever
		// rows the backend actually holds, so the read-back is checked by coverage: the
		// rows must cover the rule and none may widen it. Re-adding must not duplicate,
		// and one remove must clear every transport.
		const p uint16 = 3494
		rule := &Rule{Proto: TCPUDP, Port: p, Action: Accept}
		match := func(r *Rule) bool { return r.Port == p && onProtocolAxis(r.Proto) }

		if err := mgr.AddRule(ctx, zone, rule); errors.Is(err, ErrUnsupported) {
			t.Skip("backend cannot express a both-transports port rule")
		} else {
			require.NoError(t, err)
		}
		t.Cleanup(func() {
			for _, r := range rulesOf(t, ctx, mgr, zone) {
				if match(r) {
					_ = mgr.RemoveRule(ctx, zone, r)
				}
			}
		})

		found := func() []*Rule {
			var out []*Rule
			for _, r := range rulesOf(t, ctx, mgr, zone) {
				if match(r) {
					out = append(out, r)
				}
			}
			return out
		}

		got := found()
		require.NotEmpty(t, got, "the rule must read back")
		require.True(t, rule.CoveredBy(got), "the stored rows must cover both transports, got %+v", got)
		for _, r := range got {
			require.True(t, rule.Covers(r), "a stored row must not widen the rule: %+v", r)
		}

		// Re-adding the same rule is a no-op: every row it fans into dedups against
		// what is already stored.
		require.NoError(t, mgr.AddRule(ctx, zone, rule))
		require.Len(t, found(), len(got), "re-adding the rule must not duplicate its rows")

		// One remove clears both transports.
		require.NoError(t, mgr.RemoveRule(ctx, zone, rule))
		require.Empty(t, found(), "removing the rule must clear both transports")
	})

	t.Run("tcpudpsplitremove", func(t *testing.T) {
		// The protocol analog of familyanysplitremove: removing ONE transport of a
		// both-transports rule must leave the other in place. Backends that store the
		// pair as two rows drop only the targeted row; nftables splits its single
		// `meta l4proto { tcp, udp }` row and re-adds the survivor.
		const p uint16 = 3495
		both := &Rule{Proto: TCPUDP, Port: p, Action: Accept}
		tcp := &Rule{Proto: TCP, Port: p, Action: Accept}
		udp := &Rule{Proto: UDP, Port: p, Action: Accept}
		match := func(r *Rule) bool { return r.Port == p && onProtocolAxis(r.Proto) }

		coverage := func() (tcpCov, udpCov bool) {
			for _, r := range rulesOf(t, ctx, mgr, zone) {
				if !match(r) {
					continue
				}
				switch r.Proto {
				case TCPUDP:
					tcpCov, udpCov = true, true
				case TCP:
					tcpCov = true
				case UDP:
					udpCov = true
				}
			}
			return
		}
		clear := func() {
			for _, r := range rulesOf(t, ctx, mgr, zone) {
				if match(r) {
					_ = mgr.RemoveRule(ctx, zone, r)
				}
			}
		}

		if err := mgr.AddRule(ctx, zone, both); errors.Is(err, ErrUnsupported) {
			t.Skip("backend cannot express a both-transports port rule")
		} else {
			require.NoError(t, err)
		}
		t.Cleanup(clear)
		if hasT, hasU := coverage(); !(hasT && hasU) {
			clear()
			t.Skipf("backend does not give this rule both-transport coverage (tcp=%v udp=%v)", hasT, hasU)
		}

		// Remove TCP; UDP must survive.
		if err := mgr.RemoveRule(ctx, zone, tcp); errors.Is(err, ErrUnsupported) {
			t.Skip("backend cannot express a single-transport removal of this rule")
		} else {
			require.NoError(t, err)
		}
		hasT, hasU := coverage()
		require.False(t, hasT, "removing tcp must clear tcp coverage")
		require.True(t, hasU, "removing tcp from a tcpudp rule must leave udp in place")

		// Opposite direction from a clean slate: remove UDP, TCP must survive.
		clear()
		require.NoError(t, mgr.AddRule(ctx, zone, both))
		if hasT, hasU := coverage(); !(hasT && hasU) {
			t.Fatalf("re-adding the tcpudp rule must restore both transports (tcp=%v udp=%v)", hasT, hasU)
		}
		require.NoError(t, mgr.RemoveRule(ctx, zone, udp))
		hasT, hasU = coverage()
		require.False(t, hasU, "removing udp must clear udp coverage")
		require.True(t, hasT, "removing udp from a tcpudp rule must leave tcp in place")
	})

	t.Run("diranysplitremove", func(t *testing.T) {
		// A DirAny rule applies in BOTH directions. On the chain backends it is stored
		// as an inbound rule plus a role-swapped outbound rule (two physical rows); on
		// csf/apf a bare host is one bidirectional plain csf.allow/allow_hosts line and
		// any ported shape fans out into two hook rules. Either way GetRules collapses
		// it back to one DirAny rule. Removing a single direction must leave the other
		// in place — the chain backends drop only that direction's row, while csf/apf
		// either split their plain line and re-express the survivor through the
		// raw-iptables hook (bare host) or drop just that direction's hook rule
		// (ported). Backends with no output concept (firewalld) reject the DirAny add
		// with ErrUnsupported and skip. This is the direction analog of
		// familyanysplitremove: removing the input half of a DirAny rule must never
		// drop the output half, mirroring a concrete-family removal leaving the other
		// family in place.
		requireCap(t, caps.Output)

		// splitCase is one dual-direction rule shape, the concrete-direction removal
		// targets (inbound framed as a source match, outbound as the role-swapped
		// destination match), and a matcher reporting which directions a read-back rule
		// covers for the shape.
		type splitCase struct {
			anyRule, inTarget, outTarget *Rule
			cover                        func(*Rule) (inCov, outCov bool)
		}

		// runSplit exercises a shape: add the DirAny rule, remove each direction in
		// turn, and confirm the other survives (or the backend rejects the removal).
		runSplit := func(t *testing.T, c splitCase) {
			coverage := func() (inCov, outCov bool) {
				for _, r := range rulesOf(t, ctx, mgr, zone) {
					in, out := c.cover(r)
					inCov = inCov || in
					outCov = outCov || out
				}
				return
			}
			clear := func() {
				_ = mgr.RemoveRule(ctx, zone, c.anyRule)
				_ = mgr.RemoveRule(ctx, zone, c.inTarget)
				_ = mgr.RemoveRule(ctx, zone, c.outTarget)
			}

			// The backend must express this bidirectional shape; skip where it cannot.
			if err := mgr.AddRule(ctx, zone, c.anyRule); errors.Is(err, ErrUnsupported) {
				t.Skip("backend cannot express this DirAny shape")
			} else {
				require.NoError(t, err)
			}
			t.Cleanup(clear)
			if inCov, outCov := coverage(); !(inCov && outCov) {
				clear()
				t.Skipf("backend does not give this DirAny shape dual-direction coverage (in=%v out=%v)", inCov, outCov)
			}

			// Remove the input direction; output must survive.
			if err := mgr.RemoveRule(ctx, zone, c.inTarget); errors.Is(err, ErrUnsupported) {
				t.Skip("backend cannot express a single-direction removal of this DirAny shape")
			} else {
				require.NoError(t, err)
			}
			inCov, outCov := coverage()
			require.False(t, inCov, "removing the input direction must clear input coverage")
			require.True(t, outCov, "removing the input direction from a DirAny rule must leave output in place")

			// Opposite direction from a clean slate: remove output, input must survive.
			clear()
			require.NoError(t, mgr.AddRule(ctx, zone, c.anyRule))
			if inCov, outCov := coverage(); !(inCov && outCov) {
				t.Fatalf("re-adding the DirAny rule must restore both directions (in=%v out=%v)", inCov, outCov)
			}
			require.NoError(t, mgr.RemoveRule(ctx, zone, c.outTarget))
			inCov, outCov = coverage()
			require.False(t, outCov, "removing the output direction must clear output coverage")
			require.True(t, inCov, "removing the output direction from a DirAny rule must leave input in place")
		}

		t.Run("barehost", func(t *testing.T) {
			// A bare host allow: on csf/apf this is the single-plain-line shape whose
			// single-direction removal splits the line and re-adds the survivor via the
			// hook (splitDualRowDirection).
			const host = "192.0.2.77"
			runSplit(t, splitCase{
				anyRule:   &Rule{Direction: DirAny, Source: host, Action: Accept},
				inTarget:  &Rule{Direction: DirInput, Source: host, Action: Accept},
				outTarget: &Rule{Direction: DirOutput, Destination: host, Action: Accept},
				cover: func(r *Rule) (inCov, outCov bool) {
					switch r.Direction {
					case DirAny:
						if addrEqual(r.Source, host) {
							return true, true
						}
					case DirInput:
						if addrEqual(r.Source, host) {
							return true, false
						}
					case DirOutput:
						if addrEqual(r.Destination, host) {
							return false, true
						}
					}
					return false, false
				},
			})
		})

		t.Run("portedhost", func(t *testing.T) {
			// A ported DirAny rule is NOT a bare-host plain line: it fans out into an
			// inbound dport row and its role-swapped outbound sport twin — two physical
			// rows on the chain backends, two hook rules on csf/apf. The two rows share
			// an identical inbound-frame match, so only the direction guard in
			// EqualForRemoval keeps a single-direction removal from taking the twin as
			// well. This is the direction analog of the family split's destport/
			// sourceport cases.
			const host = "192.0.2.81"
			const p uint16 = 3499
			runSplit(t, splitCase{
				anyRule:   &Rule{Direction: DirAny, Proto: TCP, Port: p, Source: host, Action: Accept},
				inTarget:  &Rule{Direction: DirInput, Proto: TCP, Port: p, Source: host, Action: Accept},
				outTarget: &Rule{Direction: DirOutput, Proto: TCP, SourcePort: p, Destination: host, Action: Accept},
				cover: func(r *Rule) (inCov, outCov bool) {
					if r.Proto != TCP {
						return false, false
					}
					soleDest := func() bool {
						s := r.PortSpecs()
						return len(s) == 1 && s[0].Start == p && !r.HasSourcePorts()
					}
					soleSource := func() bool {
						s := r.SourcePortSpecs()
						return len(s) == 1 && s[0].Start == p && !r.HasPorts()
					}
					switch r.Direction {
					case DirAny:
						// A bidirectional row, stated in the inbound frame: dport p from
						// the host.
						if addrEqual(r.Source, host) && soleDest() {
							return true, true
						}
					case DirInput:
						if addrEqual(r.Source, host) && soleDest() {
							return true, false
						}
					case DirOutput:
						// The surviving outbound twin: sport p to the host.
						if addrEqual(r.Destination, host) && soleSource() {
							return false, true
						}
					}
					return false, false
				},
			})
		})
	})

	t.Run("diranyroundtrip", func(t *testing.T) {
		// A DirAny rule reads back as whatever the backend stores: one bidirectional
		// line where its config has that form (csf.allow, apf's allow_hosts), otherwise
		// an inbound row plus its role-swapped outbound row. Either way the rows must
		// cover the rule and none may widen it, and a second add must be an idempotent
		// no-op rather than doubling the rows.
		requireCap(t, caps.Output)
		rule := &Rule{Direction: DirAny, Source: "192.0.2.78", Action: Accept}
		if err := mgr.AddRule(ctx, zone, rule); errors.Is(err, ErrUnsupported) {
			t.Skip("backend cannot express a bidirectional bare host allow")
		} else {
			require.NoError(t, err)
		}
		t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, rule) })

		matches := func() []*Rule {
			var out []*Rule
			for _, r := range rulesOf(t, ctx, mgr, zone) {
				if addrEqual(r.Source, "192.0.2.78") || addrEqual(r.Destination, "192.0.2.78") {
					out = append(out, r)
				}
			}
			return out
		}
		got := matches()
		require.True(t, rule.CoveredBy(got), "the stored rows must cover both directions, got %+v", got)
		for _, r := range got {
			require.True(t, rule.Covers(r), "a stored row must not widen the rule: %+v", r)
		}

		// A redundant add must not create a second copy of any row.
		require.NoError(t, mgr.AddRule(ctx, zone, rule))
		require.Len(t, matches(), len(got), "re-adding an existing DirAny rule must be a no-op")
	})

	t.Run("diranyported", func(t *testing.T) {
		// A DirAny rule that is NOT a bare host — here a host + destination port — must
		// still round-trip: it fans out into an inbound (dport) rule and its role-
		// swapped outbound (sport) twin, which together cover the rule on read. This
		// exercises the fan-out path that a plain csf.allow/apf line (bare host) does
		// not use. Skip where the backend cannot express the shape.
		requireCap(t, caps.Output)
		rule := &Rule{Direction: DirAny, Proto: TCP, Port: 22, Source: "192.0.2.80", Action: Accept}
		if err := mgr.AddRule(ctx, zone, rule); errors.Is(err, ErrUnsupported) {
			t.Skip("backend cannot express this DirAny ported host rule")
		} else {
			require.NoError(t, err)
		}
		t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, rule) })
		require.True(t, rule.CoveredBy(rulesOf(t, ctx, mgr, zone)),
			"the stored rows must cover both directions of the ported host rule")

		require.NoError(t, mgr.RemoveRule(ctx, zone, rule))
		require.False(t, rule.CoveredBy(rulesOf(t, ctx, mgr, zone)),
			"DirAny ported host rule still present after removal")
	})

	t.Run("diranynooutputfallback", func(t *testing.T) {
		// On a backend with no output concept (firewalld), a DirAny rule cannot be a
		// both-directions rule, so it must degrade to its input half rather than error:
		// the add succeeds and reads back as an input rule, and the same DirAny target
		// removes it.
		if caps.Output {
			t.Skip("backend distinguishes output; DirAny fans out instead of degrading")
		}
		const host = "192.0.2.79"
		rule := &Rule{Direction: DirAny, Source: host, Action: Accept}
		if err := mgr.AddRule(ctx, zone, rule); errors.Is(err, ErrUnsupported) {
			t.Skip("backend cannot express this host allow at all")
		} else {
			require.NoError(t, err, "a DirAny rule must degrade to input, not error, on a no-output backend")
		}
		t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, rule) })

		found := false
		for _, r := range rulesOf(t, ctx, mgr, zone) {
			if r.Direction == DirInput && addrEqual(r.Source, host) {
				found = true
			}
		}
		require.True(t, found, "the degraded DirAny rule must read back as an input rule")

		// Removal by the same DirAny target must clear it.
		require.NoError(t, mgr.RemoveRule(ctx, zone, rule))
		for _, r := range rulesOf(t, ctx, mgr, zone) {
			require.Falsef(t, addrEqual(r.Source, host), "degraded DirAny rule still present: %+v", r)
		}
	})

	t.Run("icmp", func(t *testing.T) {
		// ICMP has genuinely different shapes per backend: nft/iptables/ufw accept a
		// bare rule; apf models ICMP as a list of allowed types, so a rule with an
		// address or a non-accept action goes to its hook; csf builds native ICMP on
		// host-based advanced rules needing an address AND a type (the advanced-rule
		// format carries the type in the single port-flow field), so every other shape
		// goes to its hook. Both hook forms are plain iptables rules, so the bare
		// variant is what csf and apf match here. Offer all forms and use the first the
		// backend accepts.
		roundTripVariants(t, ctx, mgr, zone,
			&Rule{Family: IPv4, Proto: ICMP, Action: Accept},
			&Rule{Family: IPv4, Proto: ICMP, ICMPType: Ptr[uint8](8), Action: Accept},
			&Rule{Family: IPv4, Proto: ICMP, ICMPType: Ptr[uint8](8), Source: "192.0.2.0/24", Action: Accept},
		)
	})

	t.Run("icmpv6", func(t *testing.T) {
		requireCap(t, caps.IPv6)
		roundTripRule(t, ctx, mgr, zone, &Rule{Family: IPv6, Proto: ICMPv6, Action: Accept})
	})

	t.Run("reload", func(t *testing.T) {
		// Every backend must survive an actual reload/apply with a managed rule in
		// place: csf must ride out its restart lock, apf must be able to run
		// `apf --restart`. The v6 variant below covers the backends that keep IPv6
		// rules in a separate file, but it is gated on IPv6 support — which csf and
		// apf drop when their own IPv6 handling is off — so exercise Reload here for
		// everyone with a plain IPv4-expressible rule.
		r := &Rule{Proto: TCP, Port: 3530, Action: Accept}
		require.NoError(t, mgr.AddRule(ctx, zone, r))
		t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, r) })
		require.NoError(t, mgr.Reload(ctx), "reload must succeed with a managed rule present")
		require.True(t, containsRule(rulesOf(t, ctx, mgr, zone), r, mgr.Capabilities().Output), "rule missing after reload")
		require.NoError(t, mgr.RemoveRule(ctx, zone, r))
		require.NoError(t, mgr.Reload(ctx), "reload must succeed after removing the rule")
	})

	t.Run("reloadv6raw", func(t *testing.T) {
		requireCap(t, caps.IPv6)
		// An IPv6 rule a backend keeps in its own IPv6 rule file must survive an
		// actual reload/apply. ufw re-applies before6.rules through ip6tables-restore
		// on `ufw reload`, so the file must reference the correct `ufw6-` chain names;
		// apf must be able to run `apf --restart`; csf must ride out its restart lock.
		r := &Rule{Family: IPv6, Proto: ICMPv6, Action: Accept}
		require.NoError(t, mgr.AddRule(ctx, zone, r))
		t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, r) })
		require.NoError(t, mgr.Reload(ctx), "reload must succeed with an IPv6 raw rule present")
		require.True(t, containsRule(rulesOf(t, ctx, mgr, zone), r, mgr.Capabilities().Output), "rule missing after reload")
		require.NoError(t, mgr.RemoveRule(ctx, zone, r))
		require.NoError(t, mgr.Reload(ctx), "reload must succeed after removing the IPv6 raw rule")
	})

	t.Run("icmptype", func(t *testing.T) {
		// A specific ICMP type, with an addressed fallback for a backend whose native
		// type list cannot carry the bare form. Use type 13 (Timestamp) rather than the
		// more common echo-request type 8 to avoid colliding with Windows' built-in
		// echo-request rules, which cannot be removed and would make the round-trip
		// assertions match the wrong rule.
		roundTripVariants(t, ctx, mgr, zone,
			&Rule{Family: IPv4, Proto: ICMP, ICMPType: Ptr[uint8](13), Action: Accept},
			&Rule{Family: IPv4, Proto: ICMP, ICMPType: Ptr[uint8](13), Source: "192.0.2.0/24", Action: Accept},
		)
	})

	t.Run("icmptypedhost", func(t *testing.T) {
		// A typed ICMP match carrying a host address. The shared icmp/icmptype
		// probes stop at the first form a backend accepts, which hides this one:
		// it is csf's only NATIVE ICMP form (a csf.allow advanced line carries
		// exactly one address and a concrete type; every other shape routes to its
		// hook, see CSF.needsHook), and on apf — whose native ICMP is the address-less
		// IG_ICMP_TYPES list — the shape that routes to the hook (needsHook). Every
		// backend runs it so both paths, and everyone else's addressed ICMP match,
		// stay covered. Type 13 (Timestamp) avoids colliding with Windows'
		// unremovable built-in echo-request rules.
		roundTripRuleOrSkip(t, ctx, mgr, zone, &Rule{Family: IPv4, Proto: ICMP, ICMPType: Ptr[uint8](13), Source: "192.0.2.70/32", Action: Accept})
	})

	t.Run("icmptypeddrop", func(t *testing.T) {
		// A typed ICMP drop with no address. A non-accept action has no place in
		// apf's allowed-type list, so it routes to apf's hook; the other backends
		// express it directly or skip via the ErrUnsupported sentinel.
		roundTripRuleOrSkip(t, ctx, mgr, zone, &Rule{Family: IPv4, Proto: ICMP, ICMPType: Ptr[uint8](13), Action: Drop})
	})

	t.Run("singlefamilyport", func(t *testing.T) {
		requireCap(t, caps.FamilyWithoutAddress)
		// A single-family bare port accept. Most backends store it directly; apf's
		// CPORTS port lists are dual-stack, so it has no native form there and is
		// written per-family through the hook (dualStackPortNeedsHook) rather than
		// rejected. wf advertises FamilyWithoutAddress false (a WFP filter scopes
		// family through its address conditions) and is gated out. The
		// FamilyAny→single-family split is exercised by the destport split test.
		roundTripRule(t, ctx, mgr, zone, &Rule{Family: IPv4, Proto: TCP, Port: 8090, Action: Accept})
	})

	t.Run("portrange", func(t *testing.T) {
		roundTripRule(t, ctx, mgr, zone, &Rule{Proto: TCP, Ports: []PortRange{{Start: 1000, End: 2000}}, Action: Accept})
	})

	t.Run("portlist", func(t *testing.T) {
		// Every backend honors a discrete port list: nftables/iptables/ufw/wf and
		// the csf/apf hooks store it as one multi-port row (ufw coalescing
		// adjacent discrete ports into a range); firewalld and pf fan it into one
		// row per port. Uncommon ports keep the match clear of any pre-existing
		// port list (csf's default TCP_IN).
		roundTripPortSet(t, ctx, mgr, zone, &Rule{Proto: TCP, Ports: []PortRange{{Start: 8480, End: 8480}, {Start: 8443, End: 8443}}, Action: Accept})
	})

	t.Run("sourceport", func(t *testing.T) {
		// Source-port alone where supported (note firewalld rich rules can match a
		// source port but not together with a destination port, so the probe never
		// combines the two). csf/apf have no address-less advanced-rule form, so they
		// route this through the raw-iptables hook; the addressed fallback remains for
		// any backend that needs an address on a source-port rule.
		roundTripVariants(t, ctx, mgr, zone,
			&Rule{Proto: TCP, SourcePort: 1234, Action: Accept},
			&Rule{Proto: TCP, SourcePort: 1234, Source: "192.0.2.0/24", Action: Accept},
		)
	})

	t.Run("connstate", func(t *testing.T) {
		requireCap(t, caps.ConnState)
		roundTripRule(t, ctx, mgr, zone, &Rule{Proto: TCP, Port: 22, State: StateEstablished | StateRelated, Action: Accept})
	})

	t.Run("interface", func(t *testing.T) {
		requireCap(t, caps.InterfaceMatch)
		roundTripRule(t, ctx, mgr, zone, &Rule{Proto: TCP, Port: 22, InInterface: "eth0", Action: Accept})
	})

	t.Run("logging", func(t *testing.T) {
		requireCap(t, caps.Logging)
		// pf logs but has no text prefix on the `log` keyword, so fall back to a
		// prefix-less logged rule there.
		roundTripVariants(t, ctx, mgr, zone,
			&Rule{Proto: TCP, Port: 22, Action: Accept, Log: true, LogPrefix: "it"},
			&Rule{Proto: TCP, Port: 22, Action: Accept, Log: true},
		)
	})

	t.Run("ratelimit", func(t *testing.T) {
		requireCap(t, caps.RateLimit)
		roundTripRule(t, ctx, mgr, zone, &Rule{Proto: TCP, Port: 22, Action: Accept, RateLimit: &RateLimit{Rate: 10, Unit: PerMinute}})
	})

	t.Run("connlimit", func(t *testing.T) {
		requireCap(t, caps.ConnLimit)
		// Connection limiting splits across backends: nft expresses only a global
		// cap; pf a per-source one only on an accept rule (single inbound tcp port, no
		// address); iptables does the global form. csf and apf carry one native shape
		// each in their config and route every other shape to their hook, whose
		// iptables rule does the global form too. Try each and round-trip the first the
		// backend accepts.
		roundTripVariants(t, ctx, mgr, zone,
			&Rule{Proto: TCP, Port: 80, Action: Drop, ConnLimit: &ConnLimit{Count: 20}},
			&Rule{Proto: TCP, Port: 80, Action: Reject, ConnLimit: &ConnLimit{Count: 20, PerSource: true}},
			&Rule{Proto: TCP, Port: 80, Action: Drop, ConnLimit: &ConnLimit{Count: 20, PerSource: true}},
			&Rule{Proto: TCP, Port: 80, Action: Accept, ConnLimit: &ConnLimit{Count: 20, PerSource: true}},
		)
	})

	t.Run("connlimitpersource", func(t *testing.T) {
		requireCap(t, caps.ConnLimit)
		// A per-source connection cap on a single address-less inbound tcp port,
		// rejecting the excess. The shared connlimit probe stops at the first form
		// a backend accepts, which hides this one wherever a global form matched
		// first: on csf and apf it is the single NATIVE connection-limit shape
		// (csf.conf CONNLIMIT / conf.apf CLIMIT) while every other shape routes to
		// their hook, and nft counts it in a named meter set. Every
		// connlimit-capable backend runs it; pf alone skips via the ErrUnsupported
		// sentinel (its max-src-conn applies only to a pass rule, so a rejecting
		// per-source cap has no pf form).
		roundTripRuleOrSkip(t, ctx, mgr, zone, &Rule{Proto: TCP, Port: 8081, Action: Reject, ConnLimit: &ConnLimit{Count: 15, PerSource: true}})
	})

	t.Run("denyremovedanyaction", func(t *testing.T) {
		requireCap(t, caps.DenyActionFromConfig)
		// On a backend whose native deny store carries no per-entry action (the
		// tool applies its config's action — see DenyActionFromConfig), the deny of
		// an address is a single entry (csf.deny, apf deny_hosts.rules) and must be
		// removable whatever action the caller names. Otherwise RemoveRule reports
		// success while the tool keeps enforcing the entry. The stock config action
		// is DROP on both, so Drop is the native deny action and Reject the
		// differing one.
		host := "192.0.2.72/32"
		added := &Rule{Family: IPv4, Proto: TCP, Port: 8084, Source: host, Action: Drop}
		require.NoError(t, mgr.AddRule(ctx, zone, added))
		t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, added) })
		require.True(t, containsRule(rulesOf(t, ctx, mgr, zone), added, mgr.Capabilities().Output),
			"the native deny must be present before removal")

		// The same rule, named with the other deny action, must still clear the entry.
		differing := *added
		differing.Action = Reject
		require.NoError(t, mgr.RemoveRule(ctx, zone, &differing))
		for _, r := range rulesOf(t, ctx, mgr, zone) {
			require.Falsef(t, addrEqual(r.Source, host) && r.Port == 8084,
				"the deny entry must be removed whatever action the target names: %+v", r)
		}
	})

	t.Run("comment", func(t *testing.T) {
		requireCap(t, caps.Comments)
		// Most backends carry a comment on a bare port rule; CSF and APF can only
		// attach one to an address-based (IP-list) rule, so fall back to that
		// form when the first probe succeeds but drops the comment.
		variants := []*Rule{
			{Proto: TCP, Port: 22, Action: Accept, Comment: "it-comment"},
			{Family: IPv4, Proto: TCP, Port: 22, Source: "192.0.2.0/24", Action: Accept, Comment: "it-comment"},
		}
		for _, rule := range variants {
			rule := rule
			require.NoError(t, mgr.AddRule(ctx, zone, rule))
			got := findRule(t, ctx, mgr, zone, rule)
			if got.Comment == rule.Comment {
				require.NoError(t, mgr.RemoveRule(ctx, zone, rule))
				require.False(t, containsRule(rulesOf(t, ctx, mgr, zone), rule, mgr.Capabilities().Output), "rule still present after removal")
				return
			}
			// Comment did not round-trip on this form; remove and try the next.
			require.NoError(t, mgr.RemoveRule(ctx, zone, rule))
		}
		t.Fatal("comment did not round-trip on any probe form")
	})

	t.Run("priority", func(t *testing.T) {
		requireCap(t, caps.Priority)
		// A rule reads back carrying its priority, and priority is part of rule
		// identity: an otherwise-identical rule at a different priority is a
		// distinct rule, so a reconcile can actually change a rule's priority.
		r := &Rule{Family: IPv4, Proto: TCP, Port: 5100, Action: Accept, Priority: 10}
		require.NoError(t, mgr.AddRule(ctx, zone, r))
		t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, r) })

		require.True(t, containsRule(rulesOf(t, ctx, mgr, zone), r, mgr.Capabilities().Output),
			"a rule must read back carrying its priority")
		other := &Rule{Family: IPv4, Proto: TCP, Port: 5100, Action: Accept, Priority: 20}
		require.False(t, containsRule(rulesOf(t, ctx, mgr, zone), other, mgr.Capabilities().Output),
			"a rule differing only in priority must be a distinct rule")

		require.NoError(t, mgr.RemoveRule(ctx, zone, r))
		require.False(t, containsRule(rulesOf(t, ctx, mgr, zone), r, mgr.Capabilities().Output), "rule still present after removal")
	})

	// --- NAT ------------------------------------------------------------------

	t.Run("nat", func(t *testing.T) {
		requireCap(t, caps.NAT)
		// Each entry is a kind with one or more forms; the first the backend accepts
		// (not rejected with ErrUnsupportedNAT) is round-tripped. A kind no backend
		// form accepts is skipped — e.g. pf has no standalone Redirect, and masquerade
		// takes an interface on pf/nft/iptables but firewalld forbids one.
		natVariants := [][]*NATRule{
			{{Kind: DNAT, Proto: TCP, Port: 80, ToAddress: "10.0.0.5", ToPort: 8080}},
			{{Kind: Redirect, Proto: TCP, Port: 80, ToPort: 8080}},
			{{Kind: SNAT, Source: "10.0.0.0/24", ToAddress: "1.2.3.4"}},
			{
				{Kind: Masquerade, Interface: "eth1"},
				{Kind: Masquerade},
			},
		}
		for _, variants := range natVariants {
			variants := variants
			t.Run(variants[0].Kind.String(), func(t *testing.T) {
				roundTripNATVariants(t, ctx, mgr, zone, variants)
			})
		}
	})

	t.Run("natportlist", func(t *testing.T) {
		requireCap(t, caps.NAT)
		// A DNAT matching a discrete port list: nftables/iptables store it as one
		// multi-port row; firewalld and pf fan it into one translation per port,
		// each to the same target; ufw coalesces adjacent ports into a range. The
		// read-back is checked by coverage: the rows must cover the rule and none
		// may widen it; one remove clears every port.
		rule := &NATRule{Kind: DNAT, Proto: TCP, Ports: []PortRange{{Start: 6401, End: 6401}, {Start: 6402, End: 6402}}, ToAddress: "10.9.1.5", ToPort: 8443}
		match := func(r *NATRule) bool {
			return len(r.PortSpecs()) > 0 && rule.Covers(r)
		}

		if err := mgr.AddNATRule(ctx, zone, rule); errors.Is(err, ErrUnsupportedNAT) {
			t.Skip("backend cannot express a multi-port dnat")
		} else {
			require.NoError(t, err)
		}
		t.Cleanup(func() {
			for _, r := range natRulesOf(t, ctx, mgr, zone) {
				if match(r) {
					_ = mgr.RemoveNATRule(ctx, zone, r)
				}
			}
		})

		found := func() []*NATRule {
			var out []*NATRule
			for _, r := range natRulesOf(t, ctx, mgr, zone) {
				if match(r) {
					out = append(out, r)
				}
			}
			return out
		}

		got := found()
		require.NotEmpty(t, got, "the rule must read back")
		require.True(t, rule.CoveredBy(got), "the stored rows must cover every port, got %+v", got)
		for _, r := range got {
			require.True(t, rule.Covers(r), "a stored row must not widen the rule: %+v", r)
		}

		require.NoError(t, mgr.AddNATRule(ctx, zone, rule))
		require.Len(t, found(), len(got), "re-adding the rule must not duplicate its rows")

		require.NoError(t, mgr.RemoveNATRule(ctx, zone, rule))
		require.Empty(t, found(), "removing the rule must clear every port")
	})

	t.Run("natfamilypairremove", func(t *testing.T) {
		requireCap(t, caps.NAT)
		// A v4 masquerade and its v6 twin on the same interface may be one row (nft's
		// inet table, a pf rule with no af) or two. Removing every rule the backend
		// reports must clear them all, not stop at the first match and leave the IPv6
		// twin loaded (pf), mirroring the filter-side familypairremove probe.
		v4 := &NATRule{Kind: Masquerade, Family: IPv4, Interface: "eth1"}
		v6 := &NATRule{Kind: Masquerade, Family: IPv6, Interface: "eth1"}
		added := 0
		for _, r := range []*NATRule{v4, v6} {
			err := mgr.AddNATRule(ctx, zone, r)
			if errors.Is(err, ErrUnsupportedNAT) {
				continue // the backend cannot express this family of an interface masquerade.
			}
			require.NoError(t, err)
			added++
		}
		if added < 2 {
			t.Skip("backend does not express both families of an interface masquerade")
		}
		t.Cleanup(func() {
			_ = mgr.RemoveNATRule(ctx, zone, v4)
			_ = mgr.RemoveNATRule(ctx, zone, v6)
		})

		// Remove every masquerade the backend reports for this interface (one
		// family-agnostic rule, or one per family), then confirm none remain.
		isMasq := func(r *NATRule) bool { return r.Kind == Masquerade && r.Interface == "eth1" }
		nats, err := mgr.GetNATRules(ctx, zone)
		require.NoError(t, err)
		for _, r := range nats {
			if isMasq(r) {
				require.NoError(t, mgr.RemoveNATRule(ctx, zone, r))
			}
		}
		nats, err = mgr.GetNATRules(ctx, zone)
		require.NoError(t, err)
		for _, r := range nats {
			require.False(t, isMasq(r), "masquerade still present after removal: %+v", r)
		}
	})

	// --- rule ordering --------------------------------------------------------

	t.Run("ordering", func(t *testing.T) {
		requireCap(t, caps.RuleOrdering)
		r1 := &Rule{Family: IPv4, Proto: TCP, Port: 3001, Action: Accept}
		r2 := &Rule{Family: IPv4, Proto: TCP, Port: 3002, Action: Accept}
		r3 := &Rule{Family: IPv4, Proto: TCP, Port: 3003, Action: Accept}
		byPort := map[uint16]*Rule{3001: r1, 3002: r2, 3003: r3}
		for _, r := range []*Rule{r1, r2, r3} {
			require.NoError(t, mgr.AddRule(ctx, zone, r))
			t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, r) })
		}

		// Whether AddRule appends or prepends is backend-specific (nft appends,
		// iptables inserts at the top), so read the actual order rather than assume
		// it, then verify MoveRule relocates a rule relative to that order.
		order0 := managedPorts(t, ctx, mgr, zone, []uint16{3001, 3002, 3003})
		require.Len(t, order0, 3)

		// Move the currently-first rule to the end: it should land last while the
		// other two keep their relative order.
		require.NoError(t, mgr.MoveRule(ctx, zone, byPort[order0[0]], 3))
		want := []uint16{order0[1], order0[2], order0[0]}
		got := managedPorts(t, ctx, mgr, zone, []uint16{3001, 3002, 3003})
		require.Equal(t, want, got, "MoveRule to the end should relocate the first rule")

		// Insert a new rule at the front.
		r0 := &Rule{Family: IPv4, Proto: TCP, Port: 3000, Action: Accept}
		require.NoError(t, mgr.InsertRule(ctx, zone, 1, r0))
		t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, r0) })
		ports := managedPorts(t, ctx, mgr, zone, []uint16{3000, 3001, 3002, 3003})
		require.Equal(t, uint16(3000), ports[0], "InsertRule at position 1 should place the rule first")

		// GetRules populates a 1-based Number that increases in chain order, so a
		// caller can read a rule's position from the returned set.
		requireAscendingNumbers(t, managedNumbers(t, ctx, mgr, zone, []uint16{3000, 3001, 3002, 3003}))
	})

	t.Run("familyanymove", func(t *testing.T) {
		requireCap(t, caps.RuleOrdering)
		// A v4 rule and its v6 twin may occupy two physical rows. Moving them with one
		// FamilyAny target must relocate BOTH as a unit: a naive move drags only one
		// row and orphans the twin at its old position.
		const port = 3510
		v4 := &Rule{Family: IPv4, Proto: TCP, Port: port, Action: Accept}
		v6 := &Rule{Family: IPv6, Proto: TCP, Port: port, Action: Accept}
		added := 0
		for _, r := range []*Rule{v4, v6} {
			err := mgr.AddRule(ctx, zone, r)
			if errors.Is(err, ErrUnsupported) {
				continue
			}
			require.NoError(t, err)
			added++
		}
		if added < 2 {
			t.Skip("backend does not express both families of a bare-port accept (no twin to move)")
		}
		b := &Rule{Family: IPv4, Proto: TCP, Port: 3511, Action: Accept}
		require.NoError(t, mgr.AddRule(ctx, zone, b))
		t.Cleanup(func() {
			_ = mgr.RemoveRule(ctx, zone, v4)
			_ = mgr.RemoveRule(ctx, zone, v6)
			_ = mgr.RemoveRule(ctx, zone, b)
		})

		before := managedPorts(t, ctx, mgr, zone, []uint16{port})
		require.NotEmpty(t, before)

		// Move every row of the pair to the end with one FamilyAny target. The chain
		// holds b plus the pair's rows, so a position past the last row appends. A
		// backend that can store one family-agnostic row (nft's inet table) re-adds the
		// target as that single row rather than the two it replaced, so the row count
		// may shrink — what must hold is that b now leads, no row of the pair is left
		// behind it, and both families still have coverage.
		twin := &Rule{Family: FamilyAny, Proto: TCP, Port: port, Action: Accept}
		require.NoError(t, mgr.MoveRule(ctx, zone, twin, len(before)+2))

		order := managedPorts(t, ctx, mgr, zone, []uint16{port, 3511})
		require.NotEmpty(t, order)
		require.Equal(t, uint16(3511), order[0],
			"b must now be first: every row of the pair moved past it")
		for _, p := range order[1:] {
			require.EqualValues(t, port, p, "no row of the pair may be left before b")
		}
		require.True(t, twin.CoveredBy(rulesOf(t, ctx, mgr, zone)),
			"both families must survive the move")
	})

	t.Run("insertposition", func(t *testing.T) {
		requireCap(t, caps.RuleOrdering)
		// GetRules reports one rule per stored row, each with the Number of its own
		// position. Inserting before a rule's reported Number must land exactly there,
		// whatever rows precede it.
		a4 := &Rule{Family: IPv4, Proto: TCP, Port: 3520, Action: Accept}
		a6 := &Rule{Family: IPv6, Proto: TCP, Port: 3520, Action: Accept}
		b4 := &Rule{Family: IPv4, Proto: TCP, Port: 3521, Action: Accept}
		b6 := &Rule{Family: IPv6, Proto: TCP, Port: 3521, Action: Accept}
		added := 0
		for _, r := range []*Rule{a4, a6, b4, b6} {
			err := mgr.AddRule(ctx, zone, r)
			if errors.Is(err, ErrUnsupported) {
				continue
			}
			require.NoError(t, err)
			added++
		}
		if added < 4 {
			t.Skip("backend does not express both families of both bare-port pairs")
		}
		c := &Rule{Family: IPv4, Proto: TCP, Port: 3522, Action: Accept}
		require.NoError(t, mgr.AddRule(ctx, zone, c))
		t.Cleanup(func() {
			for _, r := range []*Rule{a4, a6, b4, b6, c} {
				_ = mgr.RemoveRule(ctx, zone, r)
			}
		})

		// Read c's Number (its position, whatever the backend's add order) and insert
		// d there. c is IPv4-only, so it reads back as exactly one rule.
		nums := managedNumbers(t, ctx, mgr, zone, []uint16{3522})
		require.Len(t, nums, 1, "c is IPv4-only and reads back as one rule")
		cNum := nums[0]

		d := &Rule{Family: IPv4, Proto: TCP, Port: 3523, Action: Accept}
		require.NoError(t, mgr.InsertRule(ctx, zone, cNum, d))
		t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, d) })

		// d must land immediately before c.
		order := managedPorts(t, ctx, mgr, zone, []uint16{3520, 3521, 3522, 3523})
		var ci int
		for i, p := range order {
			if p == 3522 {
				ci = i
			}
		}
		require.Greater(t, ci, 0, "d must be inserted before c, so c is not first")
		require.Equal(t, uint16(3523), order[ci-1], "d must land immediately before c")
	})

	// --- NAT ordering ---------------------------------------------------------

	t.Run("natordering", func(t *testing.T) {
		requireCap(t, caps.NAT)
		requireCap(t, caps.RuleOrdering)

		// DNAT rules share the prerouting chain and differ only by matched port, so
		// their read-back order reflects the requested positions.
		n1 := &NATRule{Kind: DNAT, Family: IPv4, Proto: TCP, Port: 4001, ToAddress: "10.9.0.1", ToPort: 5001}
		n2 := &NATRule{Kind: DNAT, Family: IPv4, Proto: TCP, Port: 4002, ToAddress: "10.9.0.2", ToPort: 5002}
		for _, n := range []*NATRule{n1, n2} {
			require.NoError(t, mgr.AddNATRule(ctx, zone, n))
			t.Cleanup(func() { _ = mgr.RemoveNATRule(ctx, zone, n) })
		}

		// Insert a third DNAT rule at the front of the chain.
		n0 := &NATRule{Kind: DNAT, Family: IPv4, Proto: TCP, Port: 4000, ToAddress: "10.9.0.0", ToPort: 5000}
		require.NoError(t, mgr.InsertNATRule(ctx, zone, 1, n0))
		t.Cleanup(func() { _ = mgr.RemoveNATRule(ctx, zone, n0) })

		got := managedNATPorts(t, ctx, mgr, zone, []uint16{4000, 4001, 4002})
		require.Equal(t, uint16(4000), got[0], "InsertNATRule at position 1 should place the rule first")

		// GetNATRules populates a 1-based Number that increases in chain order.
		requireAscendingNumbers(t, managedNATNumbers(t, ctx, mgr, zone, []uint16{4000, 4001, 4002}))

		// MoveNATRule relocates a rule relative to that order. Move n0 (currently
		// first) to the end: it should land last while the other two keep their
		// relative order, mirroring MoveRule on the filter side.
		byPort := map[uint16]*NATRule{4000: n0, 4001: n1, 4002: n2}
		order0 := managedNATPorts(t, ctx, mgr, zone, []uint16{4000, 4001, 4002})
		require.Len(t, order0, 3)
		require.NoError(t, mgr.MoveNATRule(ctx, zone, byPort[order0[0]], 3))
		want := []uint16{order0[1], order0[2], order0[0]}
		gotOrder := managedNATPorts(t, ctx, mgr, zone, []uint16{4000, 4001, 4002})
		require.Equal(t, want, gotOrder, "MoveNATRule to the end should relocate the first rule")

		// Numbers stay ascending after the move.
		requireAscendingNumbers(t, managedNATNumbers(t, ctx, mgr, zone, []uint16{4000, 4001, 4002}))
	})

	// --- default policy -------------------------------------------------------

	t.Run("defaultpolicy", func(t *testing.T) {
		requireCap(t, caps.DefaultPolicy)
		orig, err := mgr.GetDefaultPolicy(ctx, zone)
		require.NoError(t, err)
		require.NotNil(t, orig)
		// Restore whatever was there before, no matter how the assertions go.
		t.Cleanup(func() { _ = mgr.SetDefaultPolicy(ctx, zone, orig) })

		// Flip the input policy to the opposite of its current value and read back.
		target := Drop
		if orig.Input == Drop {
			target = Accept
		}
		require.NoError(t, mgr.SetDefaultPolicy(ctx, zone, &DefaultPolicy{Input: target}))
		got, err := mgr.GetDefaultPolicy(ctx, zone)
		require.NoError(t, err)
		require.Equal(t, target, got.Input, "input default policy should reflect the set value")

		// Also exercise the forward direction on a backend that models one
		// (firewalld reports only input, so it is left ActionInvalid and skipped).
		if orig.Forward != ActionInvalid {
			ftarget := Drop
			if orig.Forward == Drop {
				ftarget = Accept
			}
			require.NoError(t, mgr.SetDefaultPolicy(ctx, zone, &DefaultPolicy{Forward: ftarget}))
			got, err := mgr.GetDefaultPolicy(ctx, zone)
			require.NoError(t, err)
			require.Equal(t, ftarget, got.Forward, "forward default policy should reflect the set value")
		}
	})

	// A default policy set by one manager must survive a later mutation by a fresh
	// manager instance (a process restart). nftables state outlives the process but a
	// backend's per-instance "table ensured" flag does not, so a backend that
	// re-declares its base chains on first use must not re-assert a policy and revert
	// a configured default-drop — that would silently turn a default-deny firewall
	// fail-open. The nft ensureTable path must preserve an existing policy.
	t.Run("defaultpolicypersists", func(t *testing.T) {
		requireCap(t, caps.DefaultPolicy)
		orig, err := mgr.GetDefaultPolicy(ctx, zone)
		require.NoError(t, err)
		require.NotNil(t, orig)
		t.Cleanup(func() { _ = mgr.SetDefaultPolicy(ctx, zone, orig) })

		// Set input to the opposite of its current value, then reconcile via a fresh
		// manager whose first act is a mutating call (which triggers any lazy
		// table/chain setup).
		target := Drop
		if orig.Input == Drop {
			target = Accept
		}
		require.NoError(t, mgr.SetDefaultPolicy(ctx, zone, &DefaultPolicy{Input: target}))

		fresh, err := reconstruct(ctx)
		require.NoError(t, err)
		defer func() { _ = fresh.Close(ctx) }()

		probe := &Rule{Proto: TCP, Port: 65510, Action: Accept}
		require.NoError(t, fresh.AddRule(ctx, zone, probe))
		t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, probe) })

		got, err := fresh.GetDefaultPolicy(ctx, zone)
		require.NoError(t, err)
		require.Equal(t, target, got.Input,
			"a mutating call on a fresh manager must not revert the configured input default policy")
	})

	// --- address sets ---------------------------------------------------------

	t.Run("addresssets", func(t *testing.T) {
		requireCap(t, caps.AddressSets)
		set := &AddressSet{Name: integrationPrefix + "set", Family: IPv4, Type: SetHashIP}
		require.NoError(t, mgr.AddAddressSet(ctx, set))
		t.Cleanup(func() { _ = mgr.RemoveAddressSet(ctx, set.Name) })

		require.NoError(t, mgr.AddAddressSetEntry(ctx, set.Name, "192.0.2.10"))
		sets, err := mgr.GetAddressSets(ctx)
		require.NoError(t, err)
		got := findSet(sets, set.Name)
		require.NotNil(t, got, "created set %q not found in %+v", set.Name, sets)
		require.Contains(t, got.Entries, "192.0.2.10")

		// A backend that stages its sets only programs the kernel here, so this is
		// what proves the staged form actually loads (iptables/ufw feed an `ipset
		// restore` script; csf/apf source their hook). The set must still read back
		// exactly as staged afterwards: a reload that rebuilt the staged state from
		// the live kernel would drag in every unrelated set the host happens to hold.
		require.NoError(t, mgr.Reload(ctx), "reload must succeed with a staged address set present")
		sets, err = mgr.GetAddressSets(ctx)
		require.NoError(t, err)
		got = findSet(sets, set.Name)
		require.NotNil(t, got, "set %q missing after reload", set.Name)
		require.Equal(t, []string{"192.0.2.10"}, got.Entries,
			"the set must read back exactly as staged after a reload")

		// A rule may match on the set by naming it in Source: a non-address token is
		// translated to the backend's set-match syntax and round-trips.
		setRule := &Rule{Family: IPv4, Proto: TCP, Port: 4200, Source: set.Name, Action: Accept}
		require.NoError(t, mgr.AddRule(ctx, zone, setRule))
		require.True(t, containsRule(rulesOf(t, ctx, mgr, zone), setRule, mgr.Capabilities().Output),
			"rule matching on set %q not found", set.Name)
		require.NoError(t, mgr.RemoveRule(ctx, zone, setRule))
		require.False(t, containsRule(rulesOf(t, ctx, mgr, zone), setRule, mgr.Capabilities().Output),
			"set-matching rule still present after removal")

		// A FamilyAny set reference is accepted and pinned to the set's own family
		// rather than rejected: the set is family-typed, so the rule could never
		// match the other family anyway. containsRule compares family-agnostically,
		// so the pinned read-back still satisfies the FamilyAny target, and the
		// same target removes it.
		anyRule := &Rule{Proto: TCP, Port: 4202, Source: set.Name, Action: Accept}
		require.NoError(t, mgr.AddRule(ctx, zone, anyRule),
			"a FamilyAny set reference must be pinned to the set's family, not rejected")
		require.True(t, containsRule(rulesOf(t, ctx, mgr, zone), anyRule, mgr.Capabilities().Output),
			"FamilyAny rule matching on set %q not found", set.Name)
		require.NoError(t, mgr.RemoveRule(ctx, zone, anyRule))
		require.False(t, containsRule(rulesOf(t, ctx, mgr, zone), anyRule, mgr.Capabilities().Output),
			"FamilyAny set-matching rule still present after removal")

		require.NoError(t, mgr.RemoveAddressSetEntry(ctx, set.Name, "192.0.2.10"))
		sets, err = mgr.GetAddressSets(ctx)
		require.NoError(t, err)
		if got = findSet(sets, set.Name); got != nil {
			require.NotContains(t, got.Entries, "192.0.2.10", "entry should be gone after removal")
		}

		require.NoError(t, mgr.RemoveAddressSet(ctx, set.Name))
		sets, err = mgr.GetAddressSets(ctx)
		require.NoError(t, err)
		require.Nil(t, findSet(sets, set.Name), "set should be gone after removal")

		// The kernel-side destroy a staging backend owes for a removed set is
		// performed here, after the rules that could reference it are reloaded.
		require.NoError(t, mgr.Reload(ctx), "reload must succeed after removing a staged address set")
		sets, err = mgr.GetAddressSets(ctx)
		require.NoError(t, err)
		require.Nil(t, findSet(sets, set.Name), "set came back after the reload that should have destroyed it")

		// A missing set is a well-defined not-found condition, not a generic
		// error: GetAddressSet must report it, RemoveAddressSet/entry ops on it
		// must not spuriously fail, and re-removing an already-gone set is a
		// no-op rather than an error.
		_, err = mgr.GetAddressSet(ctx, set.Name)
		require.Error(t, err, "GetAddressSet on a nonexistent set must report not-found")
		require.NoError(t, mgr.RemoveAddressSet(ctx, set.Name),
			"removing an already-gone set must be a no-op")

		// Removing a set that is still referenced by a rule must not falsely report
		// success. Either the backend removes the set (and it is gone) or it returns
		// an error — it must never return nil while the set remains. A backend that
		// stages sets unstages this one cleanly, since the rule referencing it is
		// staged too and neither is live yet; one acting on the kernel directly has
		// to surface `ipset destroy`'s "in use by a kernel component" rather than
		// swallow it.
		inuse := &AddressSet{Name: integrationPrefix + "inuse", Family: IPv4, Type: SetHashIP}
		require.NoError(t, mgr.AddAddressSet(ctx, inuse))
		t.Cleanup(func() { _ = mgr.RemoveAddressSet(ctx, inuse.Name) })
		ref := &Rule{Family: IPv4, Proto: TCP, Port: 4201, Source: inuse.Name, Action: Accept}
		require.NoError(t, mgr.AddRule(ctx, zone, ref))
		t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, ref) })
		if err := mgr.RemoveAddressSet(ctx, inuse.Name); err == nil {
			sets, err = mgr.GetAddressSets(ctx)
			require.NoError(t, err)
			require.Nil(t, findSet(sets, inuse.Name),
				"RemoveAddressSet reported success while the referenced set is still present")
		}
		// With the referencing rule gone, the set removes cleanly.
		require.NoError(t, mgr.RemoveRule(ctx, zone, ref))
		require.NoError(t, mgr.RemoveAddressSet(ctx, inuse.Name))
	})

	// --- sync -------------------------------------------------------------------

	t.Run("sync", func(t *testing.T) {
		// Sync reconciles the zone toward a desired set. Desired is built as the
		// CURRENT state plus two new rules, so the test never strips rules the
		// environment depends on (a run may arrive over SSH), and the three
		// contract points run end-to-end: missing rules are added, a second Sync
		// is a no-op whatever rows the backend fanned the rules into (the diff is
		// the coverage relation, not row equality), and a rule outside desired —
		// freshly added here, but a foreign rule is reconciled the same way — is
		// removed.
		r1 := &Rule{Proto: TCP, Port: 5601, Action: Accept}
		r2 := &Rule{Proto: TCP, Port: 5602, Action: Accept}
		t.Cleanup(func() {
			_ = mgr.RemoveRule(ctx, zone, r1)
			_ = mgr.RemoveRule(ctx, zone, r2)
		})
		desired := append(rulesOf(t, ctx, mgr, zone), r1, r2)

		added, removed, err := Sync(ctx, mgr, zone, desired)
		require.NoError(t, err)
		require.Equal(t, 2, added, "Sync must add exactly the two missing rules")
		require.Zero(t, removed, "Sync must keep every rule desired covers")
		rules := rulesOf(t, ctx, mgr, zone)
		require.True(t, containsRule(rules, r1, caps.Output), "r1 missing after Sync")
		require.True(t, containsRule(rules, r2, caps.Output), "r2 missing after Sync")

		// Sync against its own output is a no-op, whichever rows the backend chose
		// to store the rules as.
		added, removed, err = Sync(ctx, mgr, zone, desired)
		require.NoError(t, err)
		require.Zero(t, added, "a second Sync must add nothing, or every run churns")
		require.Zero(t, removed, "a second Sync must remove nothing, or every run churns")

		// A rule desired does not cover is removed.
		r3 := &Rule{Proto: TCP, Port: 5603, Action: Accept}
		require.NoError(t, mgr.AddRule(ctx, zone, r3))
		t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, r3) })
		added, removed, err = Sync(ctx, mgr, zone, desired)
		require.NoError(t, err)
		require.Zero(t, added, "reconciling away an undesired rule must not re-add anything")
		require.NotZero(t, removed, "Sync must remove the rule desired does not cover")
		rules = rulesOf(t, ctx, mgr, zone)
		require.False(t, containsRule(rules, r3, caps.Output), "undesired rule still present after Sync")
		require.True(t, containsRule(rules, r1, caps.Output), "r1 must survive the reconcile")
		require.True(t, containsRule(rules, r2, caps.Output), "r2 must survive the reconcile")
	})

	// A full replace is just Sync toward the desired set, which the sync subtest
	// above covers non-destructively; a destructive full replace against the shared
	// integration environment would strip rules other subtests depend on.

	// --- backup / restore -----------------------------------------------------

	t.Run("backup", func(t *testing.T) {
		r1 := &Rule{Proto: TCP, Port: 4001, Action: Accept}
		r2 := &Rule{Proto: TCP, Port: 4002, Action: Accept}
		require.NoError(t, mgr.AddRule(ctx, zone, r1))
		require.NoError(t, mgr.AddRule(ctx, zone, r2))
		t.Cleanup(func() {
			_ = mgr.RemoveRule(ctx, zone, r1)
			_ = mgr.RemoveRule(ctx, zone, r2)
		})

		backup, err := mgr.Backup(ctx, zone)
		require.NoError(t, err)
		require.NotNil(t, backup)

		// Drop one rule, then restore and confirm it is back.
		require.NoError(t, mgr.RemoveRule(ctx, zone, r1))
		require.False(t, containsRule(rulesOf(t, ctx, mgr, zone), r1, mgr.Capabilities().Output))

		require.NoError(t, mgr.Restore(ctx, zone, backup))
		rules := rulesOf(t, ctx, mgr, zone)
		require.True(t, containsRule(rules, r1, mgr.Capabilities().Output), "restored rule r1 missing")
		require.True(t, containsRule(rules, r2, mgr.Capabilities().Output), "restored rule r2 missing")

		// Restore reconciles to the backup: a rule added after the snapshot (and so
		// absent from it) must be removed, not left in place. This guards the ufw
		// Restore touching both the backup's own rules and any current rule missing
		// from the backup.
		r3 := &Rule{Proto: TCP, Port: 4003, Action: Accept}
		require.NoError(t, mgr.AddRule(ctx, zone, r3))
		t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, r3) })
		require.True(t, containsRule(rulesOf(t, ctx, mgr, zone), r3, mgr.Capabilities().Output), "r3 should be present before reconcile restore")

		require.NoError(t, mgr.Restore(ctx, zone, backup))
		rules = rulesOf(t, ctx, mgr, zone)
		require.True(t, containsRule(rules, r1, mgr.Capabilities().Output), "r1 missing after reconcile restore")
		require.True(t, containsRule(rules, r2, mgr.Capabilities().Output), "r2 missing after reconcile restore")
		require.False(t, containsRule(rules, r3, mgr.Capabilities().Output), "r3 was not in the backup and must be removed by Restore")
	})

	t.Run("restoreorder", func(t *testing.T) {
		// Restore must reproduce the backed-up rule order on backends whose filter
		// rules evaluate first-match in chain order. ufw's Restore re-added rules in
		// forward order while AddRule prepends, silently reversing them — so a
		// specific deny backed up above a broad allow came back below it and never
		// fired. Compare each backend against itself: the order right after the adds
		// must equal the order after a backup/remove/restore cycle. Gated on
		// RuleOrdering: a backend whose filter rules form a first-match chain
		// advertises it, while the list/zone-model backends (csf, apf, firewalld,
		// wf) do not order rules this way.
		requireCap(t, caps.RuleOrdering)
		ports := []uint16{4101, 4102, 4103}
		var rules []*Rule
		for _, p := range ports {
			r := &Rule{Family: IPv4, Proto: TCP, Port: p, Action: Accept}
			rules = append(rules, r)
			require.NoError(t, mgr.AddRule(ctx, zone, r))
			t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, r) })
		}

		before := managedPorts(t, ctx, mgr, zone, ports)
		require.Len(t, before, 3, "all three rules should be present before backup")

		backup, err := mgr.Backup(ctx, zone)
		require.NoError(t, err)
		for _, r := range rules {
			require.NoError(t, mgr.RemoveRule(ctx, zone, r))
		}
		require.NoError(t, mgr.Restore(ctx, zone, backup))

		after := managedPorts(t, ctx, mgr, zone, ports)
		require.Equal(t, before, after, "Restore must preserve the backed-up rule order")
	})

	t.Run("backupstate", func(t *testing.T) {
		// Backup must capture — and Restore must reconstruct — more than filter/NAT
		// rules: the default policy and the managed address sets. Dropping either
		// loses a restrictive default policy on a restore onto a fresh host and
		// leaves a set-referencing rule dangling.
		if !caps.AddressSets && !caps.DefaultPolicy {
			t.Skip("backend captures neither an address set nor a default policy")
		}

		// Seed an address set (with an entry) so the backup has one to capture.
		var set *AddressSet
		if caps.AddressSets {
			set = &AddressSet{Name: integrationPrefix + "bk", Family: IPv4, Type: SetHashNet, Entries: []string{"192.0.2.0/24"}}
			require.NoError(t, mgr.AddAddressSet(ctx, set))
			t.Cleanup(func() { _ = mgr.RemoveAddressSet(ctx, set.Name) })
		}

		// Set a known default policy (the opposite of the current input action, so the
		// later assertion is meaningful) and remember the original to restore.
		var policyTarget Action
		if caps.DefaultPolicy {
			orig, err := mgr.GetDefaultPolicy(ctx, zone)
			require.NoError(t, err)
			require.NotNil(t, orig)
			t.Cleanup(func() { _ = mgr.SetDefaultPolicy(ctx, zone, orig) })
			policyTarget = Drop
			if orig.Input == Drop {
				policyTarget = Accept
			}
			require.NoError(t, mgr.SetDefaultPolicy(ctx, zone, &DefaultPolicy{Input: policyTarget}))
		}

		backup, err := mgr.Backup(ctx, zone)
		require.NoError(t, err)
		require.NotNil(t, backup)

		// Mutate the state away from the snapshot: delete the set, flip the policy.
		if caps.AddressSets {
			require.NotNil(t, findSet(backup.AddressSets, set.Name), "backup did not capture the address set")
			require.NoError(t, mgr.RemoveAddressSet(ctx, set.Name))
		}
		if caps.DefaultPolicy {
			require.NotNil(t, backup.DefaultPolicy, "backup did not capture the default policy")
			flip := Accept
			if policyTarget == Accept {
				flip = Drop
			}
			require.NoError(t, mgr.SetDefaultPolicy(ctx, zone, &DefaultPolicy{Input: flip}))
		}

		// Restore must bring both back.
		require.NoError(t, mgr.Restore(ctx, zone, backup))

		if caps.AddressSets {
			got, err := mgr.GetAddressSet(ctx, set.Name)
			require.NoError(t, err, "restored address set missing")
			require.ElementsMatch(t, set.Entries, got.Entries, "restored address set entries mismatch")
		}
		if caps.DefaultPolicy {
			got, err := mgr.GetDefaultPolicy(ctx, zone)
			require.NoError(t, err)
			require.Equal(t, policyTarget, got.Input, "restored default input policy mismatch")
		}
	})

	t.Run("zones", func(t *testing.T) {
		requireCap(t, caps.Zones)
		// A zones backend maps interfaces to zones: GetZone with no interface
		// names the default zone, an interface bound to another zone (seeded out
		// of band, permanent config only) resolves to that zone, and an unbound
		// interface keeps resolving to the default. The binding targets the
		// trusted zone so an accidental runtime activation cannot filter
		// anything away.
		def, err := mgr.GetZone(ctx, "")
		require.NoError(t, err)
		require.NotEmpty(t, def, "a zones backend must name its default zone")

		seeder := zoneInterfaceSeeder(mgr)
		if seeder == nil {
			t.Skip("no out-of-band interface-to-zone seeder for this backend")
		}
		target := "trusted"
		if def == target {
			target = "work"
		}
		undo, err := seeder("lo", target)
		if err != nil {
			t.Skipf("could not bind an interface to zone %q: %v", target, err)
		}
		t.Cleanup(undo)

		got, err := mgr.GetZone(ctx, "lo")
		require.NoError(t, err)
		require.Equal(t, target, got, "GetZone must resolve a bound interface to its zone")

		unbound, err := mgr.GetZone(ctx, "gofwit0")
		require.NoError(t, err)
		require.Equal(t, def, unbound, "an unbound interface must resolve to the default zone")
	})

	t.Run("rulecounters", func(t *testing.T) {
		requireCap(t, caps.RuleCounters)
		// A backend advertising RuleCounters must populate Packets/Bytes from the
		// live firewall. Drive real traffic through a managed rule: an egress
		// accept toward a TEST-NET address, dialed with a short timeout — the SYN
		// leaves through the real interface, so it traverses the egress path even
		// where loopback is exempt from filtering (the FreeBSD harness pf.conf
		// skips lo0). Counting on an egress rule needs the direction, and every
		// RuleCounters backend also distinguishes output.
		requireCap(t, caps.Output)
		r := &Rule{Direction: DirOutput, Family: IPv4, Proto: TCP, Port: 39321, Action: Accept}
		require.NoError(t, mgr.AddRule(ctx, zone, r))
		t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, r) })
		// Activate the rule where the backend programs the kernel on reload
		// (iptables' save files load through its restore service).
		require.NoError(t, mgr.Reload(ctx))

		counted := func() bool {
			for _, got := range rulesOf(t, ctx, mgr, zone) {
				if got.EqualBase(r, mgr.Capabilities().Output) && got.Packets > 0 {
					return true
				}
			}
			return false
		}
		// The dial itself fails — nothing answers a TEST-NET address — and only
		// the attempt matters: each SYN that leaves must hit the rule's counter.
		// Retry until the deadline, since a backend may report counters with some
		// latency.
		deadline := time.Now().Add(10 * time.Second)
		for !counted() {
			conn, derr := net.DialTimeout("tcp", "192.0.2.1:39321", 500*time.Millisecond)
			if derr == nil {
				_ = conn.Close()
			}
			require.False(t, time.Now().After(deadline),
				"the managed rule's Packets counter never became non-zero after driving traffic at it")
		}
	})

	t.Run("zonescope", func(t *testing.T) {
		// A zone-scoped backend keeps a separate rule space per zone — firewalld's
		// zones, wf's firewall profiles. AddRule and GetRules scope to the named
		// zone, so RemoveRule must too: removing a rule from one zone must not
		// delete an identical rule in another. The scoping is probed rather than
		// gated on a backend: the first candidate zone name the backend accepts is
		// the base, and a second qualifies only if the base zone's rule is not
		// already visible there — a backend with one shared rule space (everything
		// but firewalld and wf) never finds a distinct second zone and skips.
		r := &Rule{Proto: TCP, Port: 5303, Action: Accept}
		candidates := []string{"public", "private", "home", "work", "domain", "internal", "dmz"}

		var zoneA, zoneB string
		for i, z := range candidates {
			if err := mgr.AddRule(ctx, z, r); err != nil {
				continue
			}
			zoneA = z
			t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zoneA, r) })
			for _, z2 := range candidates[i+1:] {
				rs, err := mgr.GetRules(ctx, z2)
				if err != nil || containsRule(rs, r, caps.Output) {
					continue // an unknown zone, or one sharing zoneA's rule space.
				}
				if err := mgr.AddRule(ctx, z2, r); err != nil {
					continue
				}
				zoneB = z2
				t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zoneB, r) })
				break
			}
			break
		}
		if zoneA == "" || zoneB == "" {
			t.Skip("backend does not scope rules to two distinct zones")
		}

		require.True(t, containsRule(rulesOf(t, ctx, mgr, zoneA), r, caps.Output), "rule should be present in zone %q", zoneA)
		require.True(t, containsRule(rulesOf(t, ctx, mgr, zoneB), r, caps.Output), "rule should be present in zone %q", zoneB)

		// Remove from the second zone only; the first zone's copy must survive.
		require.NoError(t, mgr.RemoveRule(ctx, zoneB, r))
		require.False(t, containsRule(rulesOf(t, ctx, mgr, zoneB), r, caps.Output), "rule should be gone from zone %q", zoneB)
		require.True(t, containsRule(rulesOf(t, ctx, mgr, zoneA), r, caps.Output),
			"removing the rule from zone %q must not delete the copy in zone %q", zoneB, zoneA)
	})

	t.Run("foreignnat", func(t *testing.T) {
		// The NAT half of the out-of-scope contract in foreignrule: a translation rule
		// in a table or anchor the backend reports but does not write to must not
		// read as removed.
		requireCap(t, caps.NAT)
		seeder := foreignNATSeeder(mgr)
		if seeder == nil {
			t.Skip("no out-of-scope NAT seeder for this backend")
		}
		seed, err := seeder()
		if err != nil {
			t.Skipf("could not seed a foreign NAT rule: %v", err)
		}
		t.Cleanup(seed.undo)

		require.True(t, containsNAT(natRulesOf(t, ctx, mgr, zone), seed.rule),
			"a NAT rule seeded out of band must surface in GetNATRules, got %+v", natRulesOf(t, ctx, mgr, zone))

		err = mgr.RemoveNATRule(ctx, zone, seed.rule)
		require.ErrorIs(t, err, ErrForeignTable,
			"removing a reported out-of-scope NAT rule must return ErrForeignTable, got %v", err)
		require.True(t, containsNAT(natRulesOf(t, ctx, mgr, zone), seed.rule),
			"an out-of-scope NAT rule must survive the refused removal")

		absent := &NATRule{Kind: DNAT, Family: IPv4, Proto: TCP, Port: 8999, ToAddress: "192.0.2.99", ToPort: 80}
		require.NoError(t, mgr.RemoveNATRule(ctx, zone, absent),
			"removing an absent NAT rule must no-op, not error")

		// An identical rule in the backend's own table or anchor is the one removed:
		// the removal succeeds and the foreign copy is left alone.
		require.NoError(t, mgr.AddNATRule(ctx, zone, seed.rule))
		t.Cleanup(func() { _ = mgr.RemoveNATRule(context.Background(), zone, seed.rule) })
		own := 0
		for _, r := range natRulesOf(t, ctx, mgr, zone) {
			if r.EqualBase(seed.rule) && r.HasPrefix {
				own++
			}
		}
		require.Equal(t, 1, own, "AddNATRule must write its own copy beside the foreign rule")
		require.NoError(t, mgr.RemoveNATRule(ctx, zone, seed.rule),
			"a NAT rule in the backend's own table must be removable while a foreign copy exists")
		rules := natRulesOf(t, ctx, mgr, zone)
		for _, r := range rules {
			assert.False(t, r.EqualBase(seed.rule) && r.HasPrefix, "the backend's own copy must be removed")
		}
		assert.True(t, containsNAT(rules, seed.rule), "the foreign copy must survive")
	})

	t.Run("foreignmacsource", func(t *testing.T) {
		// A backend may store a MAC zone source (firewalld), which GetRules reports
		// as a bare-source rule. RemoveRule's source shortcut must handle a MAC
		// address, not only an IP/CIDR, so a foreign MAC source can be removed and
		// Sync/Restore converge on it. Seed one out of band in the permanent config the
		// backend reads and confirm the library both surfaces and removes it. The
		// generic foreign-rule sweep is the foreignrule subtest; the seeding
		// commands are inherently backend-specific (foreignMACSeeder), so a backend
		// without a seeder skips, exactly like foreignrule.
		seeder := foreignMACSeeder(mgr)
		if seeder == nil {
			t.Skip("no out-of-band MAC zone-source seeder for this backend")
		}
		seed, err := seeder(zone)
		if err != nil {
			t.Skipf("could not seed a foreign MAC source: %v", err)
		}
		t.Cleanup(seed.undo)

		require.True(t, containsRule(rulesOf(t, ctx, mgr, zone), seed.rule, mgr.Capabilities().Output),
			"a foreign MAC zone source should surface in GetRules")

		require.NoError(t, mgr.RemoveRule(ctx, zone, seed.rule))
		require.False(t, containsRule(rulesOf(t, ctx, mgr, zone), seed.rule, mgr.Capabilities().Output),
			"RemoveRule must remove a foreign MAC zone source")
	})

	t.Run("foreignprotocol", func(t *testing.T) {
		// A backend may store a bare-protocol allow as its own construct distinct
		// from the rule form the library writes (firewalld's zone protocol entries,
		// seeded with firewall-cmd --add-protocol). GetRules must surface it and
		// RemoveRule must remove it, or a foreign protocol allow is invisible to
		// Sync/Restore. Like foreignmacsource, the seeding is backend-specific
		// (foreignProtocolSeeder) and a backend without a seeder skips.
		seeder := foreignProtocolSeeder(mgr)
		if seeder == nil {
			t.Skip("no out-of-band protocol-entry seeder for this backend")
		}
		seed, err := seeder(zone)
		if err != nil {
			t.Skipf("could not seed a foreign protocol: %v", err)
		}
		t.Cleanup(seed.undo)

		require.True(t, containsRule(rulesOf(t, ctx, mgr, zone), seed.rule, mgr.Capabilities().Output),
			"a foreign zone protocol should surface in GetRules")

		require.NoError(t, mgr.RemoveRule(ctx, zone, seed.rule))
		require.False(t, containsRule(rulesOf(t, ctx, mgr, zone), seed.rule, mgr.Capabilities().Output),
			"RemoveRule must remove a foreign zone protocol")
	})

	t.Run("afterrulesexcluded", func(t *testing.T) {
		// A backend may keep a raw rules file it deliberately does not manage (ufw's
		// after.rules; the library writes raw rules only into before.rules). GetRules
		// must not surface a rule from it — otherwise Backup captures it and Restore
		// re-adds it into the managed file, duplicating it. The seeding edits the
		// backend's own file (unmanagedRawRuleSeeder), so a backend without one skips.
		seeder := unmanagedRawRuleSeeder(mgr)
		if seeder == nil {
			t.Skip("backend has no unmanaged raw rules file to seed")
		}
		probe, undo, err := seeder()
		if err != nil {
			t.Skipf("could not seed the unmanaged raw rule: %v", err)
		}
		t.Cleanup(undo)

		require.False(t, containsRule(rulesOf(t, ctx, mgr, zone), probe, mgr.Capabilities().Output),
			"a rule in an unmanaged raw rules file must not be surfaced by GetRules")
	})
}

// --- helpers ----------------------------------------------------------------

// requireCap skips the current subtest when the backend does not advertise the
// feature under test.
func requireCap(t *testing.T, supported bool) {
	t.Helper()
	if !supported {
		t.Skip("feature not supported by this backend")
	}
}

// roundTripRule adds a rule, confirms it reads back, removes it, and confirms it
// is gone. A t.Cleanup guards against a mid-test failure leaving the rule behind.
func roundTripRule(t *testing.T, ctx context.Context, mgr Manager, zone string, rule *Rule) {
	t.Helper()
	require.NoError(t, mgr.AddRule(ctx, zone, rule))
	roundTripAdded(t, ctx, mgr, zone, rule)
}

// roundTripRuleOrSkip is roundTripRule for a shape not every backend can express:
// a rejection with the ErrUnsupported sentinel skips the subtest instead of
// failing it. A skip marks a real expressiveness gap — a feature the backend
// might expose (or a capability that should advertise it) — while any other
// failure is still a bug.
func roundTripRuleOrSkip(t *testing.T, ctx context.Context, mgr Manager, zone string, rule *Rule) {
	t.Helper()
	err := mgr.AddRule(ctx, zone, rule)
	if errors.Is(err, ErrUnsupported) {
		t.Skipf("backend cannot express this shape: %v", err)
	}
	require.NoError(t, err)
	roundTripAdded(t, ctx, mgr, zone, rule)
}

// roundTripAdded finishes a round trip for a rule AddRule already accepted: it
// must read back, remove, and read back as gone.
func roundTripAdded(t *testing.T, ctx context.Context, mgr Manager, zone string, rule *Rule) {
	t.Helper()
	t.Cleanup(func() { _ = mgr.RemoveRule(ctx, zone, rule) })

	rules := rulesOf(t, ctx, mgr, zone)
	require.True(t, containsRule(rules, rule, mgr.Capabilities().Output), "added rule %+v not found in %s", rule, dumpRules(rules))

	require.NoError(t, mgr.RemoveRule(ctx, zone, rule))
	require.False(t, containsRule(rulesOf(t, ctx, mgr, zone), rule, mgr.Capabilities().Output), "rule still present after removal")
}

// portCovers reports whether the row r is one the port-set rule spans: the
// rule's coverage contains it (its ports lie within the rule's port set and its
// other match fields match), so a row reads back the same whether the backend
// stored the list as one multi-port row, fanned it into one row per port, or
// (ufw) coalesced adjacent discrete ports into a range. A foreign rule the
// port set happens to contain would also match, so the probe ports are kept
// uncommon.
func portSetMatches(rule, r *Rule) bool {
	return len(r.PortSpecs()) > 0 && rule.Covers(r)
}

// roundTripPortSet round-trips a rule whose port list a backend may store as
// one multi-port row (nftables, iptables, ufw, wf, the csf/apf hooks), fan into
// one row per port (firewalld, pf), or coalesce adjacent discrete ports into a
// range (ufw). GetRules reports whichever rows the backend actually holds, so
// the read-back is checked by coverage: the rows must cover the rule and none
// may widen it. Coverage honors the backend's capabilities as Sync does, so a
// family-agnostic rule on a backend that does not manage IPv6 is covered by its
// IPv4 rows. Re-adding must not duplicate, and one remove must clear every row
// the rule spans.
func roundTripPortSet(t *testing.T, ctx context.Context, mgr Manager, zone string, rule *Rule) {
	t.Helper()
	match := func(r *Rule) bool { return portSetMatches(rule, r) }
	require.NoError(t, mgr.AddRule(ctx, zone, rule))
	t.Cleanup(func() {
		for _, r := range rulesOf(t, ctx, mgr, zone) {
			if match(r) {
				_ = mgr.RemoveRule(ctx, zone, r)
			}
		}
	})

	found := func() []*Rule {
		var out []*Rule
		for _, r := range rulesOf(t, ctx, mgr, zone) {
			if match(r) {
				out = append(out, r)
			}
		}
		return out
	}

	got := found()
	require.NotEmpty(t, got, "the rule must read back")
	caps := mgr.Capabilities()
	require.True(t, rule.coveredBy(got, caps.Output, caps.IPv6), "the stored rows must cover every port, got %s", dumpRules(got))
	for _, r := range got {
		require.True(t, rule.Covers(r), "a stored row must not widen the rule: %+v", r)
	}

	// Re-adding the same rule is a no-op: every row it spans dedups against what
	// is already stored.
	require.NoError(t, mgr.AddRule(ctx, zone, rule))
	require.Len(t, found(), len(got), "re-adding the rule must not duplicate its rows")

	// One remove clears every port the rule spans.
	require.NoError(t, mgr.RemoveRule(ctx, zone, rule))
	require.Empty(t, found(), "removing the rule must clear every port")
}

// roundTripVariants tries each rule form in order and round-trips the first one
// the backend accepts, skipping a form the backend rejects with an ErrUnsupported
// sentinel. It lets a single probe cover backends that express the same
// capability in different forms — e.g. nft matches a global connection limit while
// apf only expresses a per-source one, and nft matches bare ICMP while apf
// requires a type. It fails if the backend rejects every form as unsupported,
// since the capability under test claimed the feature works.
func roundTripVariants(t *testing.T, ctx context.Context, mgr Manager, zone string, variants ...*Rule) {
	t.Helper()
	if !tryRoundTripVariants(t, ctx, mgr, zone, variants...) {
		t.Fatal("backend advertised the capability but rejected every probe form as unsupported")
	}
}

// tryRoundTripVariants round-trips the first variant the backend accepts and
// reports whether any was accepted. A variant rejected with an ErrUnsupported
// sentinel moves on to the next; any other add error fails the test.
func tryRoundTripVariants(t *testing.T, ctx context.Context, mgr Manager, zone string, variants ...*Rule) bool {
	t.Helper()
	for _, rule := range variants {
		err := mgr.AddRule(ctx, zone, rule)
		if errors.Is(err, ErrUnsupported) {
			continue // the backend cannot express this form; try the next.
		}
		require.NoError(t, err)
		roundTripAdded(t, ctx, mgr, zone, rule)
		return true
	}
	return false
}

// roundTripNATVariants tries each NAT rule form and round-trips the first the
// backend accepts (not rejected with ErrUnsupportedNAT), mirroring
// roundTripVariants for filter rules. It skips the kind when the backend accepts
// no form (e.g. pf has no standalone Redirect).
func roundTripNATVariants(t *testing.T, ctx context.Context, mgr Manager, zone string, variants []*NATRule) {
	t.Helper()
	for _, nat := range variants {
		err := mgr.AddNATRule(ctx, zone, nat)
		if errors.Is(err, ErrUnsupportedNAT) {
			continue
		}
		require.NoError(t, err)
		t.Cleanup(func() { _ = mgr.RemoveNATRule(ctx, zone, nat) })

		rules, err := mgr.GetNATRules(ctx, zone)
		require.NoError(t, err)
		require.True(t, containsNAT(rules, nat), "added NAT rule %+v not found in %+v", nat, rules)

		require.NoError(t, mgr.RemoveNATRule(ctx, zone, nat))
		rules, err = mgr.GetNATRules(ctx, zone)
		require.NoError(t, err)
		require.False(t, containsNAT(rules, nat), "NAT rule still present after removal")
		return
	}
	t.Skipf("%s does not support the %s NAT kind in any probed form", mgr.Type(), variants[0].Kind)
}

// rulesOf reads the managed rules or fails the test.
func rulesOf(t *testing.T, ctx context.Context, mgr Manager, zone string) []*Rule {
	t.Helper()
	rules, err := mgr.GetRules(ctx, zone)
	require.NoError(t, err)
	return rules
}

// natRulesOf reads the managed NAT rules or fails the test.
func natRulesOf(t *testing.T, ctx context.Context, mgr Manager, zone string) []*NATRule {
	t.Helper()
	rules, err := mgr.GetNATRules(ctx, zone)
	require.NoError(t, err)
	return rules
}

// containsRule reports whether want appears in rules, compared family-agnostically
// (EqualBase) so a FamilyAny rule matches a backend that stored it under a concrete
// family, and vice versa. A DirAny read-back rule also satisfies a concrete-
// direction want: a backend whose config already covers the opposite direction
// (e.g. apf's default egress ICMP list) collapses a concrete-direction add into one
// DirAny rule, and the added rule is still present as one direction of it.
func containsRule(rules []*Rule, want *Rule, outputSupported bool) bool {
	for _, r := range rules {
		if r.EqualBase(want, outputSupported) {
			return true
		}
		if outputSupported && r.Direction == DirAny &&
			(want.Direction == DirInput || want.Direction == DirOutput) &&
			r.canonicalMatch().EqualBase(want.canonicalMatch(), false) {
			return true
		}
	}
	return false
}

// findRule returns the first managed rule matching want, failing if none do.
func findRule(t *testing.T, ctx context.Context, mgr Manager, zone string, want *Rule) *Rule {
	t.Helper()
	for _, r := range rulesOf(t, ctx, mgr, zone) {
		if r.EqualBase(want, mgr.Capabilities().Output) {
			return r
		}
	}
	t.Fatalf("rule %+v not found", want)
	return nil
}

// managedPorts returns, in backend order, the destination ports of the managed
// rules whose port is in the wanted set. It lets ordering assertions ignore any
// unrelated rules that share the zone.
func managedPorts(t *testing.T, ctx context.Context, mgr Manager, zone string, wanted []uint16) []uint16 {
	t.Helper()
	want := make(map[uint16]bool, len(wanted))
	for _, p := range wanted {
		want[p] = true
	}
	var out []uint16
	for _, r := range rulesOf(t, ctx, mgr, zone) {
		if want[r.Port] {
			out = append(out, r.Port)
		}
	}
	return out
}

// managedNATPorts returns, in backend order, the matched ports of the NAT rules
// whose port is in the wanted set, mirroring managedPorts for NAT ordering.
func managedNATPorts(t *testing.T, ctx context.Context, mgr Manager, zone string, wanted []uint16) []uint16 {
	t.Helper()
	want := make(map[uint16]bool, len(wanted))
	for _, p := range wanted {
		want[p] = true
	}
	rules, err := mgr.GetNATRules(ctx, zone)
	require.NoError(t, err)
	var out []uint16
	for _, r := range rules {
		if want[r.Port] {
			out = append(out, r.Port)
		}
	}
	return out
}

// managedNumbers returns, in backend order, the Number of each managed rule whose
// port is in the wanted set, so an ordering assertion can check that GetRules
// populated a rule's position.
func managedNumbers(t *testing.T, ctx context.Context, mgr Manager, zone string, wanted []uint16) []int {
	t.Helper()
	want := make(map[uint16]bool, len(wanted))
	for _, p := range wanted {
		want[p] = true
	}
	var out []int
	for _, r := range rulesOf(t, ctx, mgr, zone) {
		if want[r.Port] {
			out = append(out, r.Number)
		}
	}
	return out
}

// managedNATNumbers is managedNumbers for NAT rules.
func managedNATNumbers(t *testing.T, ctx context.Context, mgr Manager, zone string, wanted []uint16) []int {
	t.Helper()
	want := make(map[uint16]bool, len(wanted))
	for _, p := range wanted {
		want[p] = true
	}
	rules, err := mgr.GetNATRules(ctx, zone)
	require.NoError(t, err)
	var out []int
	for _, r := range rules {
		if want[r.Port] {
			out = append(out, r.Number)
		}
	}
	return out
}

// requireAscendingNumbers asserts every number is non-zero (an ordered backend
// populates Number) and strictly increases in the given order.
func requireAscendingNumbers(t *testing.T, nums []int) {
	t.Helper()
	require.NotEmpty(t, nums)
	for i, num := range nums {
		require.NotZero(t, num, "an ordered backend must populate a rule's Number")
		if i > 0 {
			require.Greater(t, num, nums[i-1], "Number must increase in chain order")
		}
	}
}

// containsNAT reports whether want appears in rules (family-agnostic).
func containsNAT(rules []*NATRule, want *NATRule) bool {
	for _, r := range rules {
		if r.EqualBase(want) {
			return true
		}
	}
	return false
}

// dumpRules renders rules as readable multi-line %+v for failure messages.
func dumpRules(rules []*Rule) string {
	if len(rules) == 0 {
		return "[] (no managed rules)"
	}
	out := ""
	for _, r := range rules {
		out += fmt.Sprintf("\n  %+v", r)
	}
	return out
}

// findSet returns the address set with the given name, or nil.
func findSet(sets []*AddressSet, name string) *AddressSet {
	for _, s := range sets {
		if s.Name == name {
			return s
		}
	}
	return nil
}
