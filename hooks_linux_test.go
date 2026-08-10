package firewall

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Two rules that are Equal (port-set order is not part of rule identity) must
// dedup against each other, so a second add is a no-op and a remove using a
// reordered port set still finds the rule. The hook script matches on the
// parsed rule, which the marshal/parse round trip normalizes.
func TestHookScriptPortOrderIdempotent(t *testing.T) {
	dir := t.TempDir()
	h := &hookScript{
		rulePrefix: "go_firewall",
		hookPath:   filepath.Join(dir, "csfpre.sh"),
		hookPerm:   0700,
	}

	// SCTP has no native CSF/APF config path, so a multi-port SCTP rule routes
	// through the hook. These two differ only in port order, so they are Equal.
	a := &Rule{Family: IPv4, Proto: SCTP, Ports: []PortRange{{Start: 80}, {Start: 443}}, Action: Accept}
	b := &Rule{Family: IPv4, Proto: SCTP, Ports: []PortRange{{Start: 443}, {Start: 80}}, Action: Accept}
	require.True(t, a.Equal(b, true), "the two rules must be Equal (order-independent)")

	changed, err := h.edit(a, false)
	require.NoError(t, err)
	require.True(t, changed)

	changed, err = h.edit(b, false)
	require.NoError(t, err)
	require.False(t, changed, "an Equal rule with reordered ports must not inject a duplicate")

	// Removing via the reordered form must still find and drop the rule.
	changed, err = h.edit(b, true)
	require.NoError(t, err)
	require.True(t, changed, "removing an Equal rule with reordered ports must drop it")

	got, err := h.getRules()
	require.NoError(t, err)
	require.Empty(t, got, "the rule must be gone after removal")
}

// A TCPUDP rule has no single iptables form — one line matches one -p — so the hook
// fans it out into a tcp line and a udp line, mirroring the tcp+udp fan-out csf/apf
// write in their native config. Both add and remove must fan out and never reject
// the rule for want of a concrete protocol. A Backup may hold a TCPUDP rule, so
// Restore's hook-copy clear must marshal it rather than abort the whole restore.
func TestHookScriptTCPUDPPortFansOut(t *testing.T) {
	dir := t.TempDir()
	h := &hookScript{
		rulePrefix: "go_firewall",
		hookPath:   filepath.Join(dir, "csfpre.sh"),
		hookPerm:   0700,
	}

	// Adding a TCPUDP port rule injects a tcp line and a udp line.
	any := &Rule{Family: IPv4, Proto: TCPUDP, Port: 20, Action: Accept}
	changed, err := h.edit(any, false)
	require.NoError(t, err, "a TCPUDP port rule must marshal, not be rejected")
	require.True(t, changed)

	got, err := h.getRules()
	require.NoError(t, err)
	require.Len(t, got, 2, "a TCPUDP port rule fans out into a tcp and a udp hook line")
	protos := map[Protocol]bool{}
	for _, g := range got {
		protos[g.Proto] = true
	}
	require.True(t, protos[TCP] && protos[UDP], "the fan-out must cover both tcp and udp: %+v", got)

	// Removing the TCPUDP form clears both concrete copies in one call, without
	// erroring on the port-without-concrete-protocol shape.
	changed, err = h.edit(any, true)
	require.NoError(t, err, "removing a TCPUDP port rule must not fail to marshal")
	require.True(t, changed, "the TCPUDP remove must clear the tcp and udp copies")

	got, err = h.getRules()
	require.NoError(t, err)
	require.Empty(t, got, "both fanned-out copies must be gone after the TCPUDP remove")
}

// A deny whose action differs from the CSF/APF config's STOP action has no native
// form (deny_hosts/csf.deny encode no action of their own), so those backends
// inject it through the hook, whose iptables rule carries the exact action. The
// hook must marshal and read back the precise action, not coerce it — otherwise a
// Reject deny would read back as Drop and churn on every Sync.
func TestHookScriptCarriesExactDenyAction(t *testing.T) {
	dir := t.TempDir()
	h := &hookScript{
		rulePrefix: "go_firewall",
		hookPath:   filepath.Join(dir, "csfpre.sh"),
		hookPerm:   0700,
	}

	for _, deny := range []*Rule{
		{Family: IPv4, Proto: TCP, Port: 22, Source: "192.0.2.31/32", Action: Reject},
		{Family: IPv4, Proto: TCP, Port: 22, Source: "192.0.2.32/32", Action: Drop},
	} {
		changed, err := h.edit(deny, false)
		require.NoError(t, err)
		require.True(t, changed, "the deny must be injected: %+v", deny)

		got, err := h.getRules()
		require.NoError(t, err)
		var match *Rule
		for _, g := range got {
			if g.Equal(deny, true) {
				match = g
			}
		}
		require.NotNil(t, match, "the deny must read back from the hook: %+v", deny)
		require.Equal(t, deny.Action, match.Action,
			"the hook must carry the deny's exact action, not coerce it: %+v", deny)

		changed, err = h.edit(deny, true)
		require.NoError(t, err)
		require.True(t, changed, "the deny must be removable: %+v", deny)
	}
}

// A hook written by an older library version embeds the comment in the command
// line via `-m comment`. The embedded text takes read precedence and its prefix
// tag still marks the rule, a re-add is satisfied by the legacy line, and a
// removal clears it — so an existing hook migrates without duplicate lines.
func TestHookLegacyEmbeddedCommentMigrates(t *testing.T) {
	h := newTestHook(t)
	r := &Rule{Family: IPv4, Proto: TCP, Port: 8443, Action: Accept, State: StateNew, Comment: "web tier"}

	// Recreate the legacy spelling: the current line with the comment tokens
	// spliced back in ahead of the action, single-quoted as the old writer did.
	lines, err := h.ruleLines(r, false)
	require.NoError(t, err)
	require.Len(t, lines, 1)
	legacy := strings.Replace(lines[0], "-j ACCEPT", "-m comment --comment 'go_firewall web tier' -j ACCEPT", 1)
	require.NoError(t, os.WriteFile(h.hookPath, []byte("#!/bin/sh\n"+legacy+"\n"), 0700))

	got, err := h.getRules()
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, "web tier", got[0].Comment)
	require.True(t, got[0].HasPrefix, "the embedded prefix tag must still mark the rule")

	changed, err := h.edit(r, false)
	require.NoError(t, err)
	require.False(t, changed, "the legacy line must satisfy the add")

	changed, err = h.edit(r, true)
	require.NoError(t, err)
	require.True(t, changed, "the legacy line must be removable")
	got, err = h.getRules()
	require.NoError(t, err)
	require.Empty(t, got)
}

// Comment attachment follows the trust-file scanners: a blank line detaches a
// comment from the rule below, a prefix tag starts a fresh block so a section
// header above it survives the rule's removal, and an embedded iptables comment
// keeps its text over the script comment while the prefix counts from either.
func TestHookScriptCommentAttachment(t *testing.T) {
	h := newTestHook(t)
	body := "#!/bin/sh\n" +
		"# detached note\n" +
		"\n" +
		"iptables -A INPUT -p tcp -m tcp --dport 2020 -j ACCEPT\n" +
		"# section header\n" +
		"# go_firewall tagged\n" +
		"iptables -A INPUT -p tcp -m tcp --dport 2021 -j ACCEPT\n" +
		"# go_firewall script note\n" +
		"iptables -A INPUT -p tcp -m tcp --dport 2022 -m comment --comment 'acme note' -j ACCEPT\n"
	require.NoError(t, os.WriteFile(h.hookPath, []byte(body), 0700))

	got, err := h.getRules()
	require.NoError(t, err)
	require.Len(t, got, 3)
	byPort := map[uint16]*Rule{}
	for _, g := range got {
		byPort[g.Port] = g
	}
	require.Empty(t, byPort[2020].Comment, "a blank line must detach a comment from the rule below")
	require.False(t, byPort[2020].HasPrefix)
	require.Equal(t, "tagged", byPort[2021].Comment, "the prefix tag starts the rule's comment block")
	require.True(t, byPort[2021].HasPrefix)
	require.Equal(t, "acme note", byPort[2022].Comment,
		"an embedded iptables comment must take precedence over the script comment")
	require.True(t, byPort[2022].HasPrefix, "the prefix must count from the script comment too")

	// Removing the tagged rule drops its tag comment but keeps the section
	// header above it and the detached note.
	_, err = h.edit(&Rule{Family: IPv4, Proto: TCP, Port: 2021, Action: Accept}, true)
	require.NoError(t, err)
	data, err := os.ReadFile(h.hookPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "# section header")
	require.Contains(t, string(data), "# detached note")
	require.NotContains(t, string(data), "# go_firewall tagged")
}

func TestHookScriptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	h := &hookScript{
		rulePrefix:  "go_firewall",
		hookPath:    filepath.Join(dir, "csfpre.sh"),
		hookPerm:    0700,
		ipv6Enabled: true,
	}

	// A family-agnostic rule is injected for both v4 and v6 when the backend enforces
	// IPv6.
	lines, err := h.ruleLines(&Rule{Proto: TCP, Port: 8080, Action: Accept, State: StateNew}, false)
	require.NoError(t, err)
	require.Len(t, lines, 2)
	require.True(t, strings.HasPrefix(lines[0], "iptables "), "want iptables line, got %q", lines[0])
	require.True(t, strings.HasPrefix(lines[1], "ip6tables "), "want ip6tables line, got %q", lines[1])

	// Family-pinned rules covering each non-native feature round-trip through the
	// hook.
	rules := []*Rule{
		{Family: IPv4, Proto: TCP, Port: 22, Action: Accept, State: StateNew | StateEstablished},
		{Family: IPv4, Proto: TCP, Port: 80, Action: Accept, Log: true, LogPrefix: "web"},
		{Family: IPv4, Proto: TCP, Port: 443, Action: Accept, InInterface: "eth0"},
		{Family: IPv6, Proto: ICMPv6, ICMPType: Ptr[uint8](128), Action: Accept},
		{Family: IPv4, Proto: TCP, Port: 25, Action: Drop, RateLimit: &RateLimit{Rate: 5, Unit: PerMinute, Burst: 3}},
	}
	for _, r := range rules {
		changed, err := h.edit(r, false)
		require.NoError(t, err, "add %+v", *r)
		require.True(t, changed, "expected add to change the script: %+v", *r)
	}

	// Adding again is idempotent.
	changed, err := h.edit(rules[0], false)
	require.NoError(t, err)
	require.False(t, changed, "expected a duplicate add to be a no-op")

	// The command lines live in the hook itself, under a single shebang.
	hookData, err := os.ReadFile(h.hookPath)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(hookData), "#!/bin/sh"), "hook should carry one shebang")
	require.Contains(t, string(hookData), "iptables ")

	// Every rule reads back equal (family ignored, as the hook stores per-family).
	got, err := h.getRules()
	require.NoError(t, err)
	require.Len(t, got, len(rules))
	for _, want := range rules {
		found := false
		for _, g := range got {
			if g.EqualBase(want, true) {
				found = true
				break
			}
		}
		require.True(t, found, "rule not read back: %+v", *want)
	}

	// The logged rule round-trips with its prefix intact.
	for _, g := range got {
		if g.Port == 80 {
			require.True(t, g.Log, "expected the port 80 rule to be logged")
			require.Equal(t, "web", g.LogPrefix)
		}
	}

	// Removing one drops it (both its LOG and action lines) and leaves the rest.
	changed, err = h.edit(rules[1], true)
	require.NoError(t, err)
	require.True(t, changed)
	got, err = h.getRules()
	require.NoError(t, err)
	require.Len(t, got, len(rules)-1)
	for _, g := range got {
		require.False(t, g.EqualBase(rules[1], true), "removed rule still present")
	}

	// Removing an absent rule is a no-op.
	changed, err = h.edit(rules[1], true)
	require.NoError(t, err)
	require.False(t, changed, "expected removing an absent rule to be a no-op")
}

// Writing command lines into the existing hook must leave user-authored content
// untouched: arbitrary shell survives an add and a remove, and an iptables rule a
// user added by hand both survives edits and surfaces in getRules (the library
// reconciles the hook's actual state, not just the lines it wrote).
func TestHookPreservesUserContent(t *testing.T) {
	dir := t.TempDir()
	hookPath := filepath.Join(dir, "csfpre.sh")
	userContent := "#!/bin/sh\n" +
		"# operator's own pre-hook logic\n" +
		"logger firewall reloading\n" +
		"iptables -A INPUT -p tcp --dport 2222 -j ACCEPT\n"
	require.NoError(t, os.WriteFile(hookPath, []byte(userContent), 0700))

	h := &hookScript{rulePrefix: "go_firewall", hookPath: hookPath, hookPerm: 0700}

	// A hand-added iptables rule the library never wrote surfaces in getRules,
	// reported as foreign (no prefix tag).
	got, err := h.getRules()
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, uint16(2222), got[0].Port)
	require.False(t, got[0].HasPrefix, "a user-authored rule must read back as foreign")

	// Adding our rule keeps every user line in place.
	added := &Rule{Family: IPv4, Proto: TCP, Port: 80, Action: Accept, State: StateNew}
	changed, err := h.edit(added, false)
	require.NoError(t, err)
	require.True(t, changed)
	data, err := os.ReadFile(hookPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "logger firewall reloading")
	require.Contains(t, string(data), "iptables -A INPUT -p tcp --dport 2222 -j ACCEPT")
	require.Equal(t, 1, strings.Count(string(data), "#!/bin/sh"), "must not add a second shebang")

	// Removing our rule leaves the user's shell and rule behind.
	changed, err = h.edit(added, true)
	require.NoError(t, err)
	require.True(t, changed)
	data, err = os.ReadFile(hookPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "logger firewall reloading")
	require.Contains(t, string(data), "iptables -A INPUT -p tcp --dport 2222 -j ACCEPT")

	// The user's rule still reads back after our churn.
	got, err = h.getRules()
	require.NoError(t, err)
	require.Len(t, got, 1)
	require.Equal(t, uint16(2222), got[0].Port)
}

// A hook line is sourced by /bin/sh, so a comment or log prefix containing $ or a
// backtick must be single-quoted (a literal), not left in strconv.Quote's double
// quotes where the shell would expand it. And it must still parse back intact.
func TestHookShellSafeLogPrefix(t *testing.T) {
	require.Equal(t, "-A", shellSafeToken("-A"))
	require.Equal(t, "INPUT", shellSafeToken("INPUT"))
	require.Equal(t, `'web $USER'`, shellSafeToken("web $USER"))
	require.Equal(t, `'a'\''b'`, shellSafeToken("a'b"))

	h := &hookScript{rulePrefix: "myapp"}
	lines, err := h.ruleLines(&Rule{Family: IPv4, Proto: TCP, Port: 22, Action: Drop, Log: true, LogPrefix: "drop $x"}, false)
	require.NoError(t, err)
	joined := strings.Join(lines, "\n")
	require.NotContains(t, joined, `"drop $x"`, "a $-bearing prefix must not stay double-quoted for the shell")
	require.Contains(t, joined, `'drop $x'`)

	found := false
	for _, l := range lines {
		if r, ok := h.parseLine(l); ok && r.Log {
			require.Equal(t, "drop $x", r.LogPrefix)
			found = true
		}
	}
	require.True(t, found, "the log line must parse back to the original prefix")
}

// A protocol CSF/APF cannot express natively (SCTP and the portless IP
// protocols) is routed through the raw-iptables hook and round-trips there.
func TestHookProtocolExtras(t *testing.T) {
	for _, p := range []Protocol{SCTP, GRE, ESP, AH} {
		require.True(t, hookOnlyProto(p), "%s should route through the hook", p)
		require.True(t, ruleNeedsHook(&Rule{Proto: p, Action: Accept}))
	}
	require.False(t, hookOnlyProto(TCP))
	require.False(t, ruleNeedsHook(&Rule{Proto: TCP, Port: 22, Action: Accept}))

	h := &hookScript{hookPath: "/tmp/unused", rulePrefix: "go_firewall"}
	cases := []*Rule{
		{Family: IPv4, Proto: GRE, Action: Accept},
		{Family: IPv4, Proto: SCTP, Port: 9000, Action: Accept},
	}
	for _, orig := range cases {
		lines, err := h.ruleLines(orig, false)
		require.NoError(t, err, "%+v", orig)
		require.NotEmpty(t, lines)
		got, ok := h.parseLine(lines[len(lines)-1])
		require.True(t, ok, "line %q", lines[len(lines)-1])
		require.True(t, got.EqualBase(orig, true), "want %+v got %+v", orig, got)
	}
}

func newTestHook(t *testing.T) *hookScript {
	t.Helper()
	return &hookScript{
		rulePrefix: "go_firewall",
		hookPath:   filepath.Join(t.TempDir(), "csfpre.sh"),
		hookPerm:   0700,
	}
}

// A set written to the hook round-trips through getAddressSets with its family,
// type and entries intact, for both IPv4 and IPv6, and re-adding an identical set
// is idempotent.
func TestHookAddressSetRoundTrip(t *testing.T) {
	h := newTestHook(t)

	v4 := &AddressSet{Name: "blocklist", Family: IPv4, Type: SetHashNet, Entries: []string{"192.0.2.0/24", "198.51.100.7"}}
	changed, err := h.editAddressSet(v4, false)
	require.NoError(t, err)
	require.True(t, changed)

	// Re-adding the identical set does not rewrite the hook.
	changed, err = h.editAddressSet(v4, false)
	require.NoError(t, err)
	require.False(t, changed, "re-adding an identical set must be idempotent")

	v6 := &AddressSet{Name: "v6drop", Family: IPv6, Type: SetHashIP, Entries: []string{"2001:db8::1"}}
	_, err = h.editAddressSet(v6, false)
	require.NoError(t, err)

	sets, err := h.getAddressSets()
	require.NoError(t, err)
	require.Len(t, sets, 2)
	byName := map[string]*AddressSet{}
	for _, s := range sets {
		byName[s.Name] = s
	}
	require.Equal(t, IPv4, byName["blocklist"].Family)
	require.Equal(t, SetHashNet, byName["blocklist"].Type)
	require.ElementsMatch(t, []string{"192.0.2.0/24", "198.51.100.7"}, byName["blocklist"].Entries)
	require.Equal(t, IPv6, byName["v6drop"].Family)
	require.Equal(t, SetHashIP, byName["v6drop"].Type)
	require.Equal(t, []string{"2001:db8::1"}, byName["v6drop"].Entries)
}

// The ipset commands for a set must be written ahead of any rule that references
// it, even when the rule was added first, so the set exists when the hook runs.
func TestHookAddressSetOrderedBeforeRules(t *testing.T) {
	h := newTestHook(t)

	// Add the referencing rule first — edit appends it at the end of the hook.
	_, err := h.edit(&Rule{Family: IPv4, Source: "blocklist", Action: Drop}, false)
	require.NoError(t, err)
	// Then add the set; its block must be spliced in before the rule line.
	_, err = h.editAddressSet(&AddressSet{Name: "blocklist", Family: IPv4, Type: SetHashIP, Entries: []string{"203.0.113.5"}}, false)
	require.NoError(t, err)

	data, err := os.ReadFile(h.hookPath)
	require.NoError(t, err)
	body := string(data)
	ipsetAt := strings.Index(body, "ipset create blocklist")
	ruleAt := strings.Index(body, "--match-set blocklist")
	require.GreaterOrEqual(t, ipsetAt, 0, "the create command must be present")
	require.GreaterOrEqual(t, ruleAt, 0, "the referencing rule must be present")
	require.Less(t, ipsetAt, ruleAt, "ipset commands must precede the rule that references the set")
}

// Removing a set a rule still references is refused (the kernel enforces the same
// on a live destroy); once the rule is gone the removal succeeds.
func TestHookAddressSetInUseGuard(t *testing.T) {
	h := newTestHook(t)
	_, err := h.editAddressSet(&AddressSet{Name: "blocklist", Family: IPv4, Type: SetHashIP, Entries: []string{"203.0.113.5"}}, false)
	require.NoError(t, err)
	_, err = h.edit(&Rule{Family: IPv4, Source: "blocklist", Action: Drop}, false)
	require.NoError(t, err)

	_, err = h.editAddressSet(&AddressSet{Name: "blocklist"}, true)
	require.Error(t, err, "removing a set a rule references must fail")

	_, err = h.edit(&Rule{Family: IPv4, Source: "blocklist", Action: Drop}, true)
	require.NoError(t, err)
	changed, err := h.editAddressSet(&AddressSet{Name: "blocklist"}, true)
	require.NoError(t, err)
	require.True(t, changed)
	sets, err := h.getAddressSets()
	require.NoError(t, err)
	require.Empty(t, sets, "the set must be gone after removal")
}

// Entry edits add and remove a single address in an existing set idempotently,
// and editing a set that does not exist is an error.
func TestHookAddressSetEntryEdits(t *testing.T) {
	h := newTestHook(t)
	_, err := h.editAddressSet(&AddressSet{Name: "blocklist", Family: IPv4, Type: SetHashIP, Entries: []string{"203.0.113.5"}}, false)
	require.NoError(t, err)

	changed, err := h.editAddressSetEntry("blocklist", "203.0.113.9", false)
	require.NoError(t, err)
	require.True(t, changed)
	changed, err = h.editAddressSetEntry("blocklist", "203.0.113.9", false)
	require.NoError(t, err)
	require.False(t, changed, "adding an existing entry must be idempotent")

	sets, err := h.getAddressSets()
	require.NoError(t, err)
	require.Len(t, sets, 1)
	require.ElementsMatch(t, []string{"203.0.113.5", "203.0.113.9"}, sets[0].Entries)

	changed, err = h.editAddressSetEntry("blocklist", "203.0.113.5", true)
	require.NoError(t, err)
	require.True(t, changed)
	sets, err = h.getAddressSets()
	require.NoError(t, err)
	require.Equal(t, []string{"203.0.113.9"}, sets[0].Entries)

	_, err = h.editAddressSetEntry("missing", "1.2.3.4", false)
	require.Error(t, err, "editing an entry in a set that does not exist must fail")
}

// With the backend's own IPv6 handling off, a family-agnostic rule must be injected
// as an IPv4 line only. The pre-hook runs on every (re)load regardless, but csf/apf
// never flush ip6tables while IPv6 is disabled, so an injected ip6tables line would
// be re-appended on each reload and would outlive its removal from the hook. The
// AddRule IPv6 gate only stops a *concrete* IPv6 rule; a FamilyAny rule reaches
// the hook and must be narrowed here instead.
func TestHookScriptIPv6DisabledSkipsV6Family(t *testing.T) {
	dir := t.TempDir()
	h := &hookScript{
		rulePrefix: "go_firewall",
		hookPath:   filepath.Join(dir, "csfpre.sh"),
		hookPerm:   0700,
	}

	anyFam := &Rule{Proto: TCP, Port: 8080, Action: Accept, State: StateNew}
	lines, err := h.ruleLines(anyFam, false)
	require.NoError(t, err)
	require.Len(t, lines, 1, "a family-agnostic rule must not be written for ipv6 when ipv6 is off")
	require.True(t, strings.HasPrefix(lines[0], "iptables "), "want an iptables line, got %q", lines[0])

	// It is written to the hook the same way, so no ip6tables command is ever injected.
	changed, err := h.edit(anyFam, false)
	require.NoError(t, err)
	require.True(t, changed)
	data, err := os.ReadFile(h.hookPath)
	require.NoError(t, err)
	require.NotContains(t, string(data), "ip6tables ",
		"an ip6tables line csf/apf never flush must not be injected while ipv6 is off")

	// A rule pinned to a concrete family keeps it: the AddRule IPv6 gate stops a
	// fresh concrete-IPv6 add, and Restore bypasses that gate on purpose to reproduce a
	// snapshot's entries verbatim, so the hook must still be able to render one.
	v6 := &Rule{Family: IPv6, Proto: TCP, Port: 8080, Action: Accept, State: StateNew}
	lines, err = h.ruleLines(v6, false)
	require.NoError(t, err)
	require.Len(t, lines, 1)
	require.True(t, strings.HasPrefix(lines[0], "ip6tables "), "want an ip6tables line, got %q", lines[0])
}

// Switching IPv6 off must not strand the ip6tables lines written while it was on:
// removal sweeps both families even though an add only writes the enforced one.
func TestHookScriptRemoveSweepsV6AfterIPv6Disabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csfpre.sh")

	// Written while the backend's IPv6 handling was on: an iptables and an ip6tables line.
	on := &hookScript{rulePrefix: "go_firewall", hookPath: path, hookPerm: 0700, ipv6Enabled: true}
	rule := &Rule{Proto: TCP, Port: 8080, Action: Accept, State: StateNew}
	changed, err := on.edit(rule, false)
	require.NoError(t, err)
	require.True(t, changed)
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(data), "ip6tables ")

	// IPv6 is now off. Removing the same rule must still clear the stale ip6tables line.
	off := &hookScript{rulePrefix: "go_firewall", hookPath: path, hookPerm: 0700}
	changed, err = off.edit(rule, true)
	require.NoError(t, err)
	require.True(t, changed)
	data, err = os.ReadFile(path)
	require.NoError(t, err)
	require.NotContains(t, string(data), "ip6tables ",
		"a stale ip6tables line must be swept on removal, not stranded in the hook")
	require.NotContains(t, string(data), "iptables -A ")
}

// An unnamed set must be refused outright: hookIPSetName reports "" for every
// non-ipset line, so an empty name would match — and a rewrite would drop — every
// rule and user-authored line in the hook.
func TestHookAddressSetEmptyNamePreservesHook(t *testing.T) {
	h := newTestHook(t)
	_, err := h.editAddressSet(&AddressSet{Name: "keepme", Family: IPv4, Type: SetHashIP, Entries: []string{"192.0.2.1"}}, false)
	require.NoError(t, err)
	_, err = h.edit(&Rule{Family: IPv4, Proto: TCP, Port: 2299, Action: Accept, State: StateNew}, false)
	require.NoError(t, err)
	before, err := os.ReadFile(h.hookPath)
	require.NoError(t, err)

	for _, remove := range []bool{true, false} {
		changed, err := h.editAddressSet(&AddressSet{Name: ""}, remove)
		require.Error(t, err, "an unnamed set must be refused (remove=%v)", remove)
		require.False(t, changed)
	}
	after, err := os.ReadFile(h.hookPath)
	require.NoError(t, err)
	require.Equal(t, string(before), string(after), "the hook must be untouched after a refused edit")
}

// A logged rule and its unlogged twin are distinct rules: removing one must not
// strip the other's lines. The LOG line and its action line are matched as the one
// logged rule they encode, so the unlogged target matches neither.
func TestHookRemoveLoggedAndUnloggedAreDistinct(t *testing.T) {
	logged := &Rule{Family: IPv4, Proto: TCP, Port: 80, Action: Accept, Log: true, LogPrefix: "web"}
	unlogged := &Rule{Family: IPv4, Proto: TCP, Port: 80, Action: Accept, State: StateNew}

	// Hook holds only the logged pair; removing the unlogged twin is a no-op.
	h := newTestHook(t)
	_, err := h.edit(logged, false)
	require.NoError(t, err)
	unloggedTwin := &Rule{Family: IPv4, Proto: TCP, Port: 80, Action: Accept}
	changed, err := h.edit(unloggedTwin, true)
	require.NoError(t, err)
	require.False(t, changed, "removing the unlogged twin must not touch the logged pair")
	rules, err := h.getRules()
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.True(t, rules[0].Log, "the logged rule must survive intact")

	// Hook holds only the unlogged rule; removing the logged twin is a no-op.
	h2 := newTestHook(t)
	_, err = h2.edit(unlogged, false)
	require.NoError(t, err)
	changed, err = h2.edit(logged, true)
	require.NoError(t, err)
	require.False(t, changed, "removing the logged twin must not touch the unlogged rule")

	// Removing the logged rule itself clears both of its lines.
	changed, err = h.edit(logged, true)
	require.NoError(t, err)
	require.True(t, changed)
	rules, err = h.getRules()
	require.NoError(t, err)
	require.Empty(t, rules)
	data, err := os.ReadFile(h.hookPath)
	require.NoError(t, err)
	require.NotContains(t, string(data), "-j LOG", "the LOG line must be removed with its action line")
}

// A stray LOG line whose action partner was hand-edited away still belongs to the
// logged rule, so removing that rule sweeps it rather than stranding a live kernel
// LOG rule the library does not report.
func TestHookRemoveSweepsOrphanLogLine(t *testing.T) {
	h := newTestHook(t)
	logged := &Rule{Family: IPv4, Proto: TCP, Port: 80, Action: Accept, Log: true, LogPrefix: "web"}
	_, err := h.edit(logged, false)
	require.NoError(t, err)

	// Hand-remove the action line, leaving the LOG line orphaned.
	data, err := os.ReadFile(h.hookPath)
	require.NoError(t, err)
	var kept []string
	for _, l := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
		if strings.Contains(l, "-j ACCEPT") {
			continue
		}
		kept = append(kept, l)
	}
	require.NoError(t, os.WriteFile(h.hookPath, []byte(strings.Join(kept, "\n")+"\n"), 0700))

	changed, err := h.edit(logged, true)
	require.NoError(t, err)
	require.True(t, changed, "the orphan LOG line must be swept")
	data, err = os.ReadFile(h.hookPath)
	require.NoError(t, err)
	require.NotContains(t, string(data), "-j LOG")
}

// A hand-authored add line may carry trailing options (`timeout 300`, `-exist`);
// the entry is still captured, so a rewrite of the set's block re-emits it instead
// of silently dropping the user's entry.
func TestHookAddressSetOptionedAddLineKeepsEntry(t *testing.T) {
	h := newTestHook(t)
	body := "#!/bin/sh\n" +
		"ipset create blocklist hash:ip family inet -exist\n" +
		"ipset flush blocklist\n" +
		"ipset add blocklist 203.0.113.9 timeout 300\n"
	require.NoError(t, os.WriteFile(h.hookPath, []byte(body), 0700))

	sets, err := h.getAddressSets()
	require.NoError(t, err)
	require.Len(t, sets, 1)
	require.Equal(t, []string{"203.0.113.9"}, sets[0].Entries)

	// A rewrite of the block (adding a second entry) keeps the optioned entry.
	changed, err := h.editAddressSetEntry("blocklist", "198.51.100.7", false)
	require.NoError(t, err)
	require.True(t, changed)
	sets, err = h.getAddressSets()
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"203.0.113.9", "198.51.100.7"}, sets[0].Entries)
}

// A family-agnostic set-referencing rule is pinned to the set's family: an ipset
// is single-family, so the opposite-family line would fail every time the firewall
// sources the hook. A reference to a set the hook does not carry is an error, and
// an IPv6 set is unusable while the backend's IPv6 handling is off.
func TestHookSetRefPinsFamilyAnyToSetFamily(t *testing.T) {
	h := newTestHook(t)
	h.ipv6Enabled = true
	_, err := h.editAddressSet(&AddressSet{Name: "v6drop", Family: IPv6, Type: SetHashIP, Entries: []string{"2001:db8::1"}}, false)
	require.NoError(t, err)

	lines, err := h.ruleLines(&Rule{Source: "v6drop", Action: Drop}, false)
	require.NoError(t, err)
	require.Len(t, lines, 1, "a family-agnostic set rule must be written for the set's family only")
	require.True(t, strings.HasPrefix(lines[0], "ip6tables "), "want an ip6tables line, got %q", lines[0])

	_, err = h.ruleLines(&Rule{Source: "missing", Action: Drop}, false)
	require.Error(t, err, "a reference to an unknown set must be an error")

	h.ipv6Enabled = false
	_, err = h.ruleLines(&Rule{Source: "v6drop", Action: Drop}, false)
	require.ErrorIs(t, err, ErrUnsupported, "an IPv6 set is unusable while IPv6 is off")
}

// The hook carries NAT rules csf.redirect cannot hold as raw `-t nat` command
// lines: an add round-trips through getNATRules, a re-add is idempotent, and a
// removal drops the line while leaving filter rules and user shell in place.
func TestHookScriptNATRoundTrip(t *testing.T) {
	dir := t.TempDir()
	h := &hookScript{
		rulePrefix:  "go_firewall",
		hookPath:    filepath.Join(dir, "csfpre.sh"),
		hookPerm:    0700,
		ipv6Enabled: true,
	}

	cases := []*NATRule{
		{Kind: SNAT, Family: IPv4, Source: "10.0.0.0/24", ToAddress: "1.2.3.4"},
		{Kind: Masquerade, Family: IPv4, Interface: "eth1"},
		{Kind: DNAT, Family: IPv4, Proto: TCP, Ports: []PortRange{{Start: 80, End: 90}}, ToAddress: "10.0.0.5"},
		{Kind: Redirect, Family: IPv4, Proto: TCP, Port: 8080, Source: "192.0.2.0/24", ToPort: 80},
	}
	for _, r := range cases {
		changed, err := h.editNAT(r, false)
		require.NoError(t, err, "add %+v", *r)
		require.True(t, changed)

		changed, err = h.editNAT(r, false)
		require.NoError(t, err)
		require.False(t, changed, "re-adding %+v must be idempotent", *r)

		got, err := h.getNATRules()
		require.NoError(t, err)
		require.Len(t, got, 1, "the added rule must read back exactly once")
		require.True(t, got[0].Equal(r), "read-back mismatch: want %+v got %+v", *r, *got[0])
		require.True(t, got[0].HasPrefix, "a hook NAT line this library wrote must report HasPrefix")

		changed, err = h.editNAT(r, true)
		require.NoError(t, err)
		require.True(t, changed, "removal must drop %+v", *r)
		got, err = h.getNATRules()
		require.NoError(t, err)
		require.Empty(t, got, "the rule must be gone after removal")
	}
}

// A family-agnostic NAT rule fans out into an iptables and an ip6tables line
// with IPv6 on, narrows to IPv4 with it off, and a removal sweeps both families
// either way so a stale v6 line does not survive an IPv6 switch-off.
func TestHookScriptNATFamilyFanOut(t *testing.T) {
	dir := t.TempDir()
	h := &hookScript{
		rulePrefix:  "go_firewall",
		hookPath:    filepath.Join(dir, "csfpre.sh"),
		hookPerm:    0700,
		ipv6Enabled: true,
	}

	masq := &NATRule{Kind: Masquerade, Interface: "eth1"}
	_, err := h.editNAT(masq, false)
	require.NoError(t, err)
	data, err := os.ReadFile(h.hookPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "iptables -t nat -A POSTROUTING")
	require.Contains(t, string(data), "ip6tables -t nat -A POSTROUTING")

	// One family-agnostic removal clears both lines.
	changed, err := h.editNAT(masq, true)
	require.NoError(t, err)
	require.True(t, changed)
	got, err := h.getNATRules()
	require.NoError(t, err)
	require.Empty(t, got)

	// With IPv6 off the write narrows to IPv4 only.
	h.ipv6Enabled = false
	_, err = h.editNAT(masq, false)
	require.NoError(t, err)
	data, err = os.ReadFile(h.hookPath)
	require.NoError(t, err)
	require.Contains(t, string(data), "iptables -t nat -A POSTROUTING")
	require.NotContains(t, string(data), "ip6tables -t nat",
		"a family-agnostic write must narrow to IPv4 while IPv6 is off")

	// A stale v6 line (written while IPv6 was on, or by hand) is still swept.
	v6 := *masq
	v6.Family = IPv6
	v6line, err := h.natLine(&v6)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(h.hookPath, []byte("#!/bin/sh\n"+v6line+"\n"), 0700))
	changed, err = h.editNAT(masq, true)
	require.NoError(t, err)
	require.True(t, changed, "removal must sweep the stale IPv6 line even with IPv6 off")
	got, err = h.getNATRules()
	require.NoError(t, err)
	require.Empty(t, got)
}

// NAT lines share the hook with filter rules, ipset commands and user shell;
// each kind must be read by its own parser only and edits must leave the others
// byte-for-byte in place. A hand-added equivalent NAT line (different comment)
// satisfies an add and is cleared by a removal, mirroring filter-rule edits.
func TestHookScriptNATCoexistsWithFilterLines(t *testing.T) {
	dir := t.TempDir()
	h := &hookScript{
		rulePrefix:  "go_firewall",
		hookPath:    filepath.Join(dir, "csfpre.sh"),
		hookPerm:    0700,
		ipv6Enabled: true,
	}

	filter := &Rule{Family: IPv4, Proto: TCP, Port: 22, State: StateEstablished, Action: Accept}
	_, err := h.edit(filter, false)
	require.NoError(t, err)
	snat := &NATRule{Kind: SNAT, Family: IPv4, Source: "10.0.0.0/24", ToAddress: "1.2.3.4"}
	_, err = h.editNAT(snat, false)
	require.NoError(t, err)

	// Each parser sees only its own lines.
	frules, err := h.getRules()
	require.NoError(t, err)
	require.Len(t, frules, 1, "the NAT line must not surface as a filter rule")
	nrules, err := h.getNATRules()
	require.NoError(t, err)
	require.Len(t, nrules, 1, "the filter line must not surface as a NAT rule")

	// Removing the NAT rule leaves the filter rule in place, and vice versa.
	_, err = h.editNAT(snat, true)
	require.NoError(t, err)
	frules, err = h.getRules()
	require.NoError(t, err)
	require.Len(t, frules, 1, "a NAT removal must not touch filter lines")

	// A hand-added equivalent line under a different comment dedups an add and is
	// cleared by a removal: the comment is not part of rule identity.
	foreign := &hookScript{rulePrefix: "acme", hookPath: h.hookPath, hookPerm: 0700, ipv6Enabled: true}
	_, err = foreign.editNAT(snat, false)
	require.NoError(t, err)
	changed, err := h.editNAT(snat, false)
	require.NoError(t, err)
	require.False(t, changed, "an equivalent hand-added NAT line must satisfy the add")
	changed, err = h.editNAT(snat, true)
	require.NoError(t, err)
	require.True(t, changed, "removal must clear the equivalent hand-added NAT line")
	nrules, err = h.getNATRules()
	require.NoError(t, err)
	require.Empty(t, nrules)
}

// Set-family resolution asks the hook's own ipset lines first — sets are staged
// there and created when the firewall reloads, so the hook is what the rule will
// actually match against, and an unrelated live set of the same name must not
// shadow it — and falls back to the live kernel for a set that exists only
// there. A set found in neither place errors.
func TestHookScriptSetRefFamilyDeclaredFirst(t *testing.T) {
	dir := t.TempDir()
	h := &hookScript{
		rulePrefix:  "go_firewall",
		hookPath:    filepath.Join(dir, "csfpre.sh"),
		hookPerm:    0700,
		ipv6Enabled: true,
	}

	prev := ipsetLiveFamily
	t.Cleanup(func() { ipsetLiveFamily = prev })
	// The kernel reports inet6 for both names; only "liveset" is ever declared in
	// the hook, so the two arms below are told apart by precedence alone.
	ipsetLiveFamily = func(name string) (Family, bool, error) {
		if name == "liveset" || name == "hookset" {
			return IPv6, true, nil
		}
		return FamilyAny, false, nil
	}

	// Live only: resolved from the kernel, since the hook declares nothing.
	lines, err := h.ruleLines(&Rule{Source: "liveset", Proto: TCP, Port: 22, Action: Accept}, false)
	require.NoError(t, err)
	require.Len(t, lines, 1)
	require.True(t, strings.HasPrefix(lines[0], "ip6tables "),
		"a live inet6 set must pin the rule to ip6tables, got %q", lines[0])

	// Declared in the hook (just written, firewall not reloaded yet): the hook
	// supplies the family even though a live set of that name says otherwise.
	set := &AddressSet{Name: "hookset", Family: IPv4, Type: SetHashIP, Entries: []string{"192.0.2.1"}}
	changed, err := h.editAddressSet(set, false)
	require.NoError(t, err)
	require.True(t, changed)
	lines, err = h.ruleLines(&Rule{Source: "hookset", Proto: TCP, Port: 22, Action: Accept}, false)
	require.NoError(t, err)
	require.Len(t, lines, 1)
	require.True(t, strings.HasPrefix(lines[0], "iptables "),
		"a set staged inet in the hook must pin the rule to iptables even when a live set of the same name is inet6, got %q", lines[0])

	// Known nowhere: an error, not a guessed family.
	_, err = h.ruleLines(&Rule{Source: "ghost", Proto: TCP, Port: 22, Action: Accept}, false)
	require.ErrorContains(t, err, `"ghost"`)
}

// Every line the hook writes — rule, NAT and ipset — must invoke the resolved
// absolute path of its command, so the hook applies even when the firewall sources
// it with a PATH that omits the sbin directories. The lines still read back as the
// rules they encode.
func TestHookResolvedCommandPaths(t *testing.T) {
	dir := t.TempDir()
	h := &hookScript{
		rulePrefix:  "go_firewall",
		hookPath:    filepath.Join(dir, "csfpre.sh"),
		hookPerm:    0700,
		ipv6Enabled: true,
		ip4Cmd:      "/usr/sbin/iptables",
		ip6Cmd:      "/usr/sbin/ip6tables",
		ipsetCmd:    "/usr/sbin/ipset",
	}

	_, err := h.editAddressSet(&AddressSet{Name: "blocklist", Family: IPv4, Type: SetHashIP, Entries: []string{"203.0.113.5"}}, false)
	require.NoError(t, err)
	rule := &Rule{Family: IPv6, Proto: TCP, Port: 443, Action: Accept, State: StateNew}
	_, err = h.edit(rule, false)
	require.NoError(t, err)
	nat := &NATRule{Family: IPv4, Kind: Masquerade, Interface: "eth1"}
	_, err = h.editNAT(nat, false)
	require.NoError(t, err)

	data, err := os.ReadFile(h.hookPath)
	require.NoError(t, err)
	body := string(data)
	require.Contains(t, body, "/usr/sbin/ipset create blocklist")
	require.Contains(t, body, "/usr/sbin/ip6tables -A INPUT")
	require.Contains(t, body, "/usr/sbin/iptables -t nat -A POSTROUTING")
	for _, line := range strings.Split(body, "\n") {
		require.False(t, strings.HasPrefix(line, "iptables ") || strings.HasPrefix(line, "ip6tables ") ||
			strings.HasPrefix(line, "ipset "), "line must invoke a resolved path, got %q", line)
	}

	// A path-spelled line parses back into the rule it encodes.
	rules, err := h.getRules()
	require.NoError(t, err)
	require.Len(t, rules, 1)
	require.True(t, rules[0].Equal(rule, true))
	require.True(t, rules[0].HasPrefix)
	nats, err := h.getNATRules()
	require.NoError(t, err)
	require.Len(t, nats, 1)
	require.True(t, nats[0].EqualForRemoval(nat))
	sets, err := h.getAddressSets()
	require.NoError(t, err)
	require.Len(t, sets, 1)
	require.Equal(t, []string{"203.0.113.5"}, sets[0].Entries)
}

// A command may be spelled any way in an existing hook — bare, under a path that
// differs from the one this manager resolved, quoted, or as an
// update-alternatives variant — and must still read back as the rule it encodes
// and satisfy a resolved-path hook's adds and removals, so a reconcile neither
// duplicates the line nor churns the hook.
func TestHookCommandSpellingsSatisfyResolvedHook(t *testing.T) {
	dir := t.TempDir()
	hookPath := filepath.Join(dir, "csfpre.sh")
	require.NoError(t, os.WriteFile(hookPath, []byte("#!/bin/sh\n"+
		"iptables -A INPUT -p tcp -m tcp --dport 2222 -j ACCEPT\n"+
		"/sbin/iptables -A INPUT -p tcp -m tcp --dport 2223 -j ACCEPT\n"+
		"iptables-nft -A INPUT -p tcp -m tcp --dport 2224 -j ACCEPT\n"+
		"'/sbin/ip6tables' -A INPUT -p tcp -m tcp --dport 2225 -j ACCEPT\n"+
		"/sbin/ipset create blocklist hash:ip family inet -exist\n"+
		"ipset flush blocklist\n"+
		"/sbin/ipset add blocklist 203.0.113.5\n"+
		"/sbin/iptables -t nat -A POSTROUTING -o eth1 -j MASQUERADE\n"), 0700))
	h := &hookScript{
		rulePrefix: "go_firewall",
		hookPath:   hookPath,
		hookPerm:   0700,
		ip4Cmd:     "/usr/sbin/iptables",
		ip6Cmd:     "/usr/sbin/ip6tables",
		ipsetCmd:   "/usr/sbin/ipset",
	}

	// Every spelling reads back, with the family its command selects.
	rules, err := h.getRules()
	require.NoError(t, err)
	byPort := map[uint16]*Rule{}
	for _, r := range rules {
		byPort[r.Port] = r
	}
	require.Len(t, byPort, 4)
	for _, port := range []uint16{2222, 2223, 2224} {
		require.Equal(t, IPv4, byPort[port].Family, "port %d", port)
	}
	require.Equal(t, IPv6, byPort[2225].Family, "a quoted ip6tables path selects IPv6")
	nats, err := h.getNATRules()
	require.NoError(t, err)
	require.Len(t, nats, 1)
	sets, err := h.getAddressSets()
	require.NoError(t, err)
	require.Len(t, sets, 1)
	require.Equal(t, []string{"203.0.113.5"}, sets[0].Entries)

	// Re-adding those rules is a no-op: matching is on the parsed rule, not the
	// command spelling, so the hook is not rewritten with duplicate lines.
	for _, port := range []uint16{2222, 2223, 2224} {
		changed, err := h.edit(&Rule{Family: IPv4, Proto: TCP, Port: port, Action: Accept}, false)
		require.NoError(t, err)
		require.False(t, changed, "an existing line for port %d must satisfy the add", port)
	}
	changed, err := h.editNAT(&NATRule{Family: IPv4, Kind: Masquerade, Interface: "eth1"}, false)
	require.NoError(t, err)
	require.False(t, changed, "an existing path-spelled nat line must satisfy the add")

	// Removal finds a differently spelled line too.
	changed, err = h.edit(&Rule{Family: IPv4, Proto: TCP, Port: 2223, Action: Accept}, true)
	require.NoError(t, err)
	require.True(t, changed)
	data, err := os.ReadFile(hookPath)
	require.NoError(t, err)
	require.NotContains(t, string(data), "--dport 2223")
	require.Contains(t, string(data), "--dport 2222", "an unrelated line must survive")
}

// resolveBinary — shared by the hook lines and every command the backends run —
// prefers PATH, falls back to the standard install directories when PATH misses
// the tool, and leaves a tool it cannot find bare (reporting not-found) so exec or
// the shell resolves it.
func TestResolveBinary(t *testing.T) {
	dir := t.TempDir()
	onPath := filepath.Join(dir, "gofwpathbin")
	require.NoError(t, os.WriteFile(onPath, []byte("#!/bin/sh\n"), 0755))
	sbin := t.TempDir()
	offPath := filepath.Join(sbin, "gofwsbinbin")
	require.NoError(t, os.WriteFile(offPath, []byte("#!/bin/sh\n"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(sbin, "gofwnoexecbin"), []byte("#!/bin/sh\n"), 0644))

	saved := binSearchDirs
	t.Cleanup(func() { binSearchDirs = saved })
	binSearchDirs = []string{sbin}
	t.Setenv("PATH", dir)

	got, ok := resolveBinary("gofwpathbin")
	require.True(t, ok)
	require.Equal(t, onPath, got)
	got, ok = resolveBinary("gofwsbinbin")
	require.True(t, ok, "a tool off PATH resolves from the install directories")
	require.Equal(t, offPath, got)
	got, ok = resolveBinary("gofwnoexecbin")
	require.False(t, ok, "a non-executable file is not a tool")
	require.Equal(t, "gofwnoexecbin", got)
	got, ok = resolveBinary("gofwabsentbin")
	require.False(t, ok, "an unresolvable tool stays bare")
	require.Equal(t, "gofwabsentbin", got)

	// An explicit path is taken as given, so a caller can pin a tool.
	got, ok = resolveBinary("/opt/sbin/gofwabsentbin")
	require.True(t, ok)
	require.Equal(t, "/opt/sbin/gofwabsentbin", got)

	// The hook wrapper reports the same path, bare when unresolvable.
	require.Equal(t, offPath, resolveHookBinary("gofwsbinbin"))
	require.Equal(t, "gofwabsentbin", resolveHookBinary("gofwabsentbin"))
}

// TestHookStaysExecutable verifies a hook the firewall already ships stays
// runnable after the library edits it. apf installs hook_pre.sh non-executable
// and only runs it when the execute bit is set, and an atomic write otherwise
// preserves the existing mode — so without this the injected lines read back
// from the file correctly while never reaching the kernel. The rest of the mode
// is left alone.
func TestHookStaysExecutable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hook_pre.sh")
	// The shipped file: readable by owner and group, executable by neither.
	require.NoError(t, os.WriteFile(path, []byte("#!/bin/bash\n"), 0640))

	h := &hookScript{rulePrefix: "go_firewall", hookPath: path, hookPerm: 0750}
	r := &Rule{Family: IPv4, Proto: SCTP, Port: 9000, Action: Accept}
	changed, err := h.edit(r, false)
	require.NoError(t, err)
	require.True(t, changed)

	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.EqualValues(t, 0740, fi.Mode().Perm(),
		"only the owner-execute bit is added; the rest of the shipped mode is kept")

	// A hook already executable keeps exactly the mode it had.
	require.NoError(t, os.Chmod(path, 0755))
	_, err = h.edit(&Rule{Family: IPv4, Proto: SCTP, Port: 9001, Action: Accept}, false)
	require.NoError(t, err)
	fi, err = os.Stat(path)
	require.NoError(t, err)
	require.EqualValues(t, 0755, fi.Mode().Perm())
}

// TestHookNewFileUsesBackendMode verifies a hook the library creates itself still
// gets the backend's own mode (csf's csfpre.sh does not ship with the product).
func TestHookNewFileUsesBackendMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csfpre.sh")
	h := &hookScript{rulePrefix: "go_firewall", hookPath: path, hookPerm: 0700}

	changed, err := h.edit(&Rule{Family: IPv4, Proto: SCTP, Port: 9000, Action: Accept}, false)
	require.NoError(t, err)
	require.True(t, changed)

	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.EqualValues(t, 0700, fi.Mode().Perm())
}
