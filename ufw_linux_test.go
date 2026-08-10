package firewall

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestUFWParseTupleRowsModelsRouteRows verifies a route/forward tuple is now
// decoded as a forward-direction rule (occupying its physical row), and ParseRules
// returns it alongside the ordinary rules.
func TestUFWParseTupleRowsModelsRouteRows(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "user.rules")
	content := "### tuple ### route:allow tcp 23 0.0.0.0/0 any 0.0.0.0/0 in\n" +
		"### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n" +
		"### tuple ### allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in\n"
	require.NoError(t, os.WriteFile(p, []byte(content), 0644))
	fw := new(UFW)

	rows, err := fw.parseTupleRows(p, IPv4)
	require.NoError(t, err)
	require.Len(t, rows, 3, "every tuple line occupies a physical row, including the route rule")
	require.NotNil(t, rows[0], "the route (forward) tuple is now modeled as a forward rule")
	require.Equal(t, DirForward, rows[0].Direction)
	require.EqualValues(t, 23, rows[0].Port)
	require.NotNil(t, rows[1])
	require.EqualValues(t, 22, rows[1].Port)
	require.NotNil(t, rows[2])
	require.EqualValues(t, 80, rows[2].Port)

	reps, err := fw.ParseRules(p, IPv4)
	require.NoError(t, err)
	require.Len(t, reps, 3, "ParseRules returns every rule, the forward one included")
}

// TestUFWNativeInsertPositionCountsRouteRows verifies a preceding route rule shifts
// the native `ufw insert` position, since ufw counts route rules in its numbered
// list. Ignoring them would insert the rule one slot too early.
func TestUFWNativeInsertPositionCountsRouteRows(t *testing.T) {
	fw := new(UFW)
	a := &Rule{Proto: TCP, Port: 22, Action: Accept}
	b := &Rule{Proto: TCP, Port: 80, Action: Accept}
	// Physical order: route(nil) is #1, A is #2, B is #3. GetRules reports A=1, B=2.
	rows := []*Rule{nil, a, b}
	require.Equal(t, 2, fw.nativeInsertPositionFromRows(rows, 1), "insert before A lands at A's physical slot 2")
	require.Equal(t, 3, fw.nativeInsertPositionFromRows(rows, 2), "insert before B lands at B's physical slot 3, not 2")
	require.Equal(t, 4, fw.nativeInsertPositionFromRows(rows, 3), "past the end appends past the last physical tuple")

	// With no un-representable rows the mapping is the plain physical index.
	plain := []*Rule{a, b}
	require.Equal(t, 1, fw.nativeInsertPositionFromRows(plain, 1))
	require.Equal(t, 2, fw.nativeInsertPositionFromRows(plain, 2))
	require.Equal(t, 3, fw.nativeInsertPositionFromRows(plain, 3))
}

func TestUFWRules(t *testing.T) {
	fw := new(UFW)

	// Parse a rule that is expected to parse right.
	rule, err := fw.UnmarshalRule(`allow udp 23 0.0.0.0/0 any 192.168.0.0/24 in`, IPv4)
	require.NoError(t, err)

	// Re-encode the rule which should result in expected rich rule.
	args := fw.MarshalRule(rule)
	require.Equal(t, `allow in proto udp from 192.168.0.0/24 to 0.0.0.0/0 port 23`, args,
		"the rule did not encode as expected")

	// Try encoding a bunch of invalid rules.
	invalidRules := []string{
		`log udp 23 0.0.0.0/0 any 192.168.0.0/24 in`, // unsupported action
		`allow udp 23 0.0.0.0/0 any`,                 // too few fields
	}
	for _, richRule := range invalidRules {
		_, err := fw.UnmarshalRule(richRule, IPv4)
		require.Error(t, err, "this rule was parsed when it should be invalid: %s", richRule)
	}

	// A `route:` (forward) tuple decodes to a forward-direction rule. The `route:`
	// prefix is stripped from the action, the direction is forward, and the trailing
	// interface field(s) populate the in/out interfaces (a bare direction leaves
	// both empty).
	routeCases := []struct {
		tuple  string
		action Action
		port   uint16
		in     string
		out    string
	}{
		{`route:allow tcp 23 0.0.0.0/0 any 0.0.0.0/0 in`, Accept, 23, "", ""},
		{`route:deny tcp 25 192.168.0.1 any 10.0.0.0/8 in_eth0`, Drop, 25, "eth0", ""},
		// ufw stores a dual-interface route rule as one "!"-joined trailing token.
		{`route:allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in_eth0!out_eth1`, Accept, 80, "eth0", "eth1"},
	}
	for _, rc := range routeCases {
		got, err := fw.UnmarshalRule(rc.tuple, IPv4)
		require.NoError(t, err, "a route (forward) rule must decode: %s", rc.tuple)
		require.Equal(t, DirForward, got.Direction, "route rule is forward: %s", rc.tuple)
		require.Equal(t, rc.action, got.Action, rc.tuple)
		require.EqualValues(t, rc.port, got.Port, rc.tuple)
		require.Equal(t, rc.in, got.InInterface, rc.tuple)
		require.Equal(t, rc.out, got.OutInterface, rc.tuple)
	}

	// An application-profile tuple (9 fields, with a dapp/sapp name before the
	// trailing direction field) decodes like an ordinary tuple: ufw's real tuples
	// carry the app's concrete protocol/port in the six core fields — e.g. ufw's own
	// recorded output for "ufw allow Apache" is
	// `allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 Apache - in` — so the dapp/sapp name
	// tokens are simply skipped to reach the direction field; they carry no
	// independent match information the model needs to represent.
	appRule, err := fw.UnmarshalRule(`allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 Apache - in`, IPv4)
	require.NoError(t, err, "a real application-profile tuple must decode")
	require.Equal(t, Accept, appRule.Action)
	require.Equal(t, TCP, appRule.Proto)
	require.EqualValues(t, 80, appRule.Port)
	require.False(t, appRule.IsOutput())

	// A multi-port app profile (Samba's "137,138") and a sapp-only form (source app,
	// dapp placeholder "-") both decode the same way.
	sambaRule, err := fw.UnmarshalRule(`allow udp 137,138 0.0.0.0/0 any 0.0.0.0/0 Samba - in`, IPv4)
	require.NoError(t, err)
	require.Equal(t, UDP, sambaRule.Proto)
	require.Len(t, sambaRule.Ports, 2)
	require.Equal(t, PortRange{Start: 137, End: 137}, sambaRule.Ports[0])
	require.Equal(t, PortRange{Start: 138, End: 138}, sambaRule.Ports[1])

	sappRule, err := fw.UnmarshalRule(`allow udp any 10.0.0.1 137,138 0.0.0.0/0 - Samba in`, IPv4)
	require.NoError(t, err)
	require.Equal(t, UDP, sappRule.Proto)
	require.Len(t, sappRule.SourcePorts, 2)
	require.Equal(t, PortRange{Start: 137, End: 137}, sappRule.SourcePorts[0])
	require.Equal(t, PortRange{Start: 138, End: 138}, sappRule.SourcePorts[1])
	require.Equal(t, "10.0.0.1", sappRule.Destination)

	// An 8-field tuple never occurs in a real ufw file (ufw always writes both dapp
	// and sapp, using "-" for whichever is absent), so it is rejected as malformed.
	_, err = fw.UnmarshalRule(`allow any any 0.0.0.0/0 any 0.0.0.0/0 Apache -`, IPv4)
	require.Error(t, err, "an 8-field tuple is not a real ufw shape and must be rejected")

	// Source ports round-trip through the tuple's sport field.
	srcTuple, err := fw.UnmarshalRule(`allow tcp any 0.0.0.0/0 1024:65535 192.168.0.0/24 in`, IPv4)
	require.NoError(t, err)
	require.Len(t, srcTuple.SourcePorts, 1)
	require.Equal(t, PortRange{Start: 1024, End: 65535}, srcTuple.SourcePorts[0])
	require.Equal(t, "192.168.0.0/24", srcTuple.Source)

	srcMarshal := fw.MarshalRule(&Rule{Family: IPv4, Proto: TCP, Source: "192.168.0.0/24", SourcePort: 1234, Port: 22, Action: Accept})
	require.Equal(t, "allow in proto tcp from 192.168.0.0/24 port 1234 to 0.0.0.0/0 port 22", srcMarshal,
		"unexpected source-port marshal")

	// A single source port needs a port-carrying protocol. TCPUDP (ufw's ported `any`,
	// tcp+udp) marshals to the native form with no proto clause; ProtocolAny (every
	// protocol) is rejected by Rule.validate, since ufw cannot match a port across every
	// protocol. A source-port range still needs a concrete tcp/udp, so a TCPUDP range
	// fans out into concrete tcp+udp rules instead of taking the tuple path.
	anySrc := fw.MarshalRule(&Rule{Family: IPv4, Proto: TCPUDP, SourcePort: 1234, Action: Accept})
	require.Contains(t, anySrc, "port 1234")
	require.NotContains(t, anySrc, "proto", "a tcpudp rule omits the proto clause")
	require.Error(t, (&Rule{Family: IPv4, Proto: ProtocolAny, SourcePort: 1234, Action: Accept}).validate(),
		"a source port across every protocol has no ufw form")
	require.True(t, fw.tcpudpNeedsExpand(&Rule{Family: IPv4, Proto: TCPUDP, SourcePorts: []PortRange{{Start: 1000, End: 2000}}, Action: Accept}),
		"a source-port range without a concrete tcp/udp must fan out")

	// Test rules we typically set.
	validRules := []string{
		`allow udp 4789 ::/0 any ::/0 in`,
		`allow udp 4789 ::/0 any ::/0 out`,
		`allow tcp 4789 0.0.0.0/0 any 203.0.113.10 in`,
		`allow tcp 4791 203.0.113.10 any 0.0.0.0/0 out`,
	}
	for _, richRule := range validRules {
		_, err := fw.UnmarshalRule(richRule, IPv4)
		require.NoError(t, err, "this rich rule was not parsed when it should be valid: %s", richRule)
	}

	// MarshalRule must not mutate the caller's rule while inferring the
	// family and normalizing the destination.
	orig := &Rule{Direction: DirInput, Family: IPv4, Port: 4789, Proto: TCP, Action: Accept}
	before := *orig
	fw.MarshalRule(orig)
	require.Equal(t, before, *orig, "MarshalRule mutated the caller's rule")

	// An interface-bound tuple parses the interface back out of the direction.
	ifRule, err := fw.UnmarshalRule(`allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in_eth0`, IPv4)
	require.NoError(t, err)
	require.Equal(t, "eth0", ifRule.InInterface, "unexpected interface parse: %+v", *ifRule)
	require.False(t, ifRule.IsOutput(), "unexpected interface parse: %+v", *ifRule)

	// Marshalling an interface-bound rule emits `in on <iface>`.
	spec := fw.MarshalRule(&Rule{InInterface: "eth0", Family: IPv4, Proto: TCP, Port: 22, Action: Accept})
	require.Equal(t, "allow in on eth0 proto tcp to 0.0.0.0/0 port 22", spec, "unexpected interface marshal")

	// Shapes the tuple form cannot hold never reach MarshalRule: ICMP and a state
	// match are routed to the before.rules files, and a TCPUDP port list — a bare
	// multiport, which ufw itself rejects — fans out into concrete tcp+udp rules.
	// A multiport ProtocolAny match ("every protocol on this port") has no
	// port-carrying transport at all, so Rule.validate rejects it outright.
	require.True(t, fw.needsIPTablesRules(&Rule{Proto: ICMP, Action: Accept}))
	require.True(t, fw.needsIPTablesRules(&Rule{Proto: TCP, Port: 22, State: StateEstablished, Action: Accept}))
	require.True(t, fw.tcpudpNeedsExpand(&Rule{Proto: TCPUDP, Ports: []PortRange{{Start: 80}, {Start: 443}}, Action: Accept}))
	require.Error(t, (&Rule{Proto: ProtocolAny, Ports: []PortRange{{Start: 80}, {Start: 443}}, Action: Accept}).validate())

	// ufw supports port lists and colon ranges on tcp/udp.
	portCases := []struct {
		rule *Rule
		want string
	}{
		{&Rule{Proto: TCP, Ports: []PortRange{{Start: 80}, {Start: 443}}, Family: IPv4, Action: Accept}, "allow in proto tcp to 0.0.0.0/0 port 80,443"},
		{&Rule{Proto: TCP, Ports: []PortRange{{Start: 80}, {Start: 443}}, Action: Accept}, "allow in 80,443/tcp"},
		{&Rule{Proto: UDP, Ports: []PortRange{{Start: 1000, End: 2000}}, Action: Accept}, "allow in 1000:2000/udp"},
	}
	for _, c := range portCases {
		require.Equal(t, c.want, fw.MarshalRule(c.rule), "marshal %+v", *c.rule)
	}

	// A tuple with a multiport list and a colon range parses into port specs.
	multi, err := fw.UnmarshalRule("allow tcp 80,443 0.0.0.0/0 any 0.0.0.0/0 in", IPv4)
	require.NoError(t, err)
	require.Len(t, multi.Ports, 2, "unexpected multiport parse: %+v", *multi)
	require.Equal(t, PortRange{Start: 80, End: 80}, multi.Ports[0], "unexpected multiport parse: %+v", *multi)
	require.Equal(t, PortRange{Start: 443, End: 443}, multi.Ports[1], "unexpected multiport parse: %+v", *multi)

	ran, err := fw.UnmarshalRule("allow tcp 1000:2000 0.0.0.0/0 any 0.0.0.0/0 in", IPv4)
	require.NoError(t, err)
	require.Len(t, ran.Ports, 1, "unexpected range parse: %+v", *ran)
	require.Equal(t, PortRange{Start: 1000, End: 2000}, ran.Ports[0], "unexpected range parse: %+v", *ran)
}

// ufw expresses per-rule logging natively with its `log` keyword (placed after
// the direction and any interface clause), rather than diverting a logged rule to
// before.rules where it could not be removed. Only a custom log prefix — which
// ufw cannot set — still needs the raw path.
func TestUFWNativeLogging(t *testing.T) {
	fw := new(UFW)

	// A plain logged rule stays on the CLI/tuple path and emits `log`.
	logged := &Rule{Family: IPv4, Proto: TCP, Port: 22, Log: true, Action: Accept}
	require.False(t, fw.needsIPTablesRules(logged), "a plain logged rule must not be routed to before.rules")
	require.Equal(t, "allow in log proto tcp to 0.0.0.0/0 port 22", fw.MarshalRule(logged))

	// The keyword follows the interface clause.
	ifLogged := &Rule{Family: IPv4, Proto: TCP, Port: 22, InInterface: "eth0", Log: true, Action: Accept}
	require.Equal(t, "allow in on eth0 log proto tcp to 0.0.0.0/0 port 22", fw.MarshalRule(ifLogged))

	// A custom log prefix cannot be set in a tuple, so such a rule is routed raw.
	prefixed := &Rule{Family: IPv4, Proto: TCP, Port: 22, Log: true, LogPrefix: "DROP22", Action: Drop}
	require.True(t, fw.needsIPTablesRules(prefixed), "a custom-prefix log must go to before.rules")
}

// A forward rule marshals into a ufw route rule: the spec carries `in on`/`out on`
// interface clauses (no bare direction, which ufw rejects on a route rule) and the
// command args place the `route` keyword before the verb.
func TestUFWForwardRouteMarshal(t *testing.T) {
	fw := new(UFW)

	r := &Rule{Direction: DirForward, InInterface: "eth0", OutInterface: "eth1", Proto: TCP, Port: 80, Action: Accept}
	spec := fw.MarshalRule(r)
	require.Contains(t, spec, "allow in on eth0 out on eth1", "route spec must carry both interface clauses: %q", spec)
	require.Contains(t, spec, "80", "the destination port must be present: %q", spec)
	require.NotContains(t, spec, "route", "MarshalRule leaves the route keyword to the command builder: %q", spec)

	// The command builder prepends `route` before the verb.
	args := fw.ruleArgs(r, []string{"prepend"}, spec)
	require.Equal(t, "route", args[0], "forward command starts with route")
	require.Equal(t, "prepend", args[1], "the verb follows route")

	// An ordinary rule carries neither the route keyword nor an out-interface clause.
	ordinary := fw.MarshalRule(&Rule{Proto: TCP, Port: 22, Action: Accept})
	inArgs := fw.ruleArgs(&Rule{Proto: TCP, Port: 22, Action: Accept}, []string{"prepend"}, ordinary)
	require.Equal(t, "prepend", inArgs[0], "a non-forward rule has no leading route keyword")
}

func TestUFWParseIPTablesRules(t *testing.T) {
	fw := new(UFW)

	content := `# rules.before
*filter
:ufw-before-input - [0:0]
:ufw-before-output - [0:0]
# allow all on loopback
-A ufw-before-input -i lo -j ACCEPT
# quickly process packets for which we already have a connection
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
# ok icmp codes for INPUT
-A ufw-before-input -p icmp --icmp-type echo-request -j ACCEPT
-A ufw-before-input -p icmp --icmp-type destination-unreachable -j ACCEPT
# a jump to an internal chain must be skipped
-A ufw-before-input -j ufw-not-local
-A ufw-not-local -m addrtype --dst-type LOCAL -j RETURN
# the forward chain is now a modeled direction
-A ufw-before-forward -p icmp --icmp-type echo-request -j ACCEPT
COMMIT
`
	dir := t.TempDir()
	path := filepath.Join(dir, "before.rules")
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	rules, err := fw.ParseIPTablesRules(path, IPv4)
	require.NoError(t, err)

	// Expect: loopback interface, conntrack established/related, the two input ICMP
	// rules, and the forward ICMP rule. The chain jump and internal chain are
	// skipped.
	require.Len(t, rules, 5, "expected 5 parsed iptables rules, got %+v", rules)

	var foundEcho, foundForward bool
	for _, r := range rules {
		if r.Proto == ICMP && r.ICMPType != nil && *r.ICMPType == 8 && r.Action == Accept {
			foundEcho = true
			if r.IsForward() {
				foundForward = true
			}
		}
	}
	require.True(t, foundEcho, "expected an icmp echo-request accept rule, got %+v", rules)
	require.True(t, foundForward, "expected the forward-chain icmp rule to be modeled, got %+v", rules)

	// A missing iptables rules file contributes no rules and no error.
	missing, err := fw.ParseIPTablesRules(filepath.Join(dir, "nope.rules"), IPv4)
	require.NoError(t, err, "expected no error for a missing file")
	require.Nil(t, missing, "expected no rules for a missing file")
}

func TestUFWIPTablesRulesWrite(t *testing.T) {
	fw := new(UFW)

	// needsIPTablesRules routes ICMP and state rules to the iptables rules files.
	require.True(t, fw.needsIPTablesRules(&Rule{Proto: ICMP, Action: Accept}),
		"expected an icmp rule to need the iptables rules files")
	require.True(t, fw.needsIPTablesRules(&Rule{State: StateEstablished, Action: Accept}),
		"expected a state rule to need the iptables rules files")
	require.False(t, fw.needsIPTablesRules(&Rule{Proto: TCP, Port: 22, Action: Accept}),
		"a plain tcp rule should use the ufw cli")

	// marshalIPTablesLines rewrites the iptables chain to ufw's own chain. IPv4
	// rules use the `ufw-*` chains; IPv6 rules must use the `ufw6-*` chains, since
	// that is what before6.rules declares.
	specs, err := fw.marshalIPTablesLines(&Rule{Proto: ICMP, ICMPType: Ptr[uint8](8), Action: Accept}, IPv4)
	require.NoError(t, err)
	require.Equal(t, []string{"-A ufw-before-input -p icmp -m icmp --icmp-type 8 -j ACCEPT"}, specs,
		"unexpected iptables rules spec")

	v6specs, err := fw.marshalIPTablesLines(&Rule{Proto: ICMPv6, ICMPType: Ptr[uint8](128), Action: Accept}, IPv6)
	require.NoError(t, err)
	require.Equal(t, []string{"-A ufw6-before-input -p icmpv6 -m icmp6 --icmpv6-type 128 -j ACCEPT"}, v6specs,
		"an IPv6 rule must target the ufw6- chain so ip6tables-restore accepts before6.rules")

	scaffold := "*filter\n:ufw-before-input - [0:0]\n:ufw-before-output - [0:0]\nCOMMIT\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "before.rules")
	require.NoError(t, os.WriteFile(path, []byte(scaffold), 0644))

	icmp := &Rule{Proto: ICMP, ICMPType: Ptr[uint8](8), Action: Accept}

	// Adding inserts the rule before COMMIT and it parses back equal.
	changed, err := fw.editIPTablesRulesFile(path, icmp, IPv4, false)
	require.NoError(t, err)
	require.True(t, changed, "expected add to change the file")

	rules, err := fw.ParseIPTablesRules(path, IPv4)
	require.NoError(t, err)
	// The parsed rule is family-tagged from the file (IPv4), so compare with
	// EqualBase, which ignores family.
	require.Len(t, rules, 1)
	require.True(t, rules[0].EqualBase(icmp, true), "expected the icmp rule to be present, got %+v", rules[0])

	// Adding again is idempotent.
	changed, err = fw.editIPTablesRulesFile(path, icmp, IPv4, false)
	require.NoError(t, err)
	require.False(t, changed, "expected a duplicate add to be a no-op")

	// A different (state) rule adds alongside it.
	state := &Rule{State: StateEstablished | StateRelated, Action: Accept}
	_, err = fw.editIPTablesRulesFile(path, state, IPv4, false)
	require.NoError(t, err)
	rules, _ = fw.ParseIPTablesRules(path, IPv4)
	require.Len(t, rules, 2, "expected 2 rules after adding a state rule, got %+v", rules)

	// Removing the icmp rule leaves only the state rule.
	changed, err = fw.editIPTablesRulesFile(path, icmp, IPv4, true)
	require.NoError(t, err)
	require.True(t, changed, "expected remove to change the file")
	rules, _ = fw.ParseIPTablesRules(path, IPv4)
	require.Len(t, rules, 1, "expected only the state rule to remain, got %+v", rules)
	require.Equal(t, StateEstablished|StateRelated, rules[0].State,
		"expected only the state rule to remain, got %+v", rules)

	// Removing a rule that is not present is a no-op.
	changed, err = fw.editIPTablesRulesFile(path, icmp, IPv4, true)
	require.NoError(t, err)
	require.False(t, changed, "expected removing an absent rule to be a no-op")
}

// A family-agnostic source-port rule must emit the literal "any" address so ufw
// installs both the IPv4 and IPv6 rule, not a v4-only zero network.
func TestUFWFamilyAnySourcePortUsesAny(t *testing.T) {
	fw := new(UFW)
	spec := fw.MarshalRule(&Rule{Proto: TCP, SourcePort: 1024, Action: Accept})
	require.Contains(t, spec, "from any port 1024")
	require.NotContains(t, spec, "0.0.0.0/0", "a FamilyAny rule must not be pinned to an IPv4 zero network")
}

// GetRules must read tuples whose action carries a `_log` suffix or is `limit`
// rather than dropping them.
func TestUFWLimitAndLogTupleParse(t *testing.T) {
	fw := new(UFW)

	limit, err := fw.UnmarshalRule("limit tcp 22 0.0.0.0/0 any 0.0.0.0/0 in", IPv4)
	require.NoError(t, err)
	require.Equal(t, Accept, limit.Action)
	require.NotNil(t, limit.RateLimit, "a limit tuple must carry a rate limit")

	logged, err := fw.UnmarshalRule("allow_log tcp 80 0.0.0.0/0 any 0.0.0.0/0 in", IPv4)
	require.NoError(t, err)
	require.Equal(t, Accept, logged.Action)
	require.True(t, logged.Log, "an allow_log tuple must be read as a logged rule")
}

// ufw's native `limit` action can carry logging (`ufw limit log ...` -> a
// `limit_log` tuple in user.rules). Such a rule must stay on the tuple path, not
// be routed to before.rules, or Restore removes it from the wrong file and
// duplicates it.
func TestUFWLimitLogStaysNative(t *testing.T) {
	f := new(UFW)
	r, err := f.UnmarshalRule("limit_log tcp 22 0.0.0.0/0 any 0.0.0.0/0 in", IPv4)
	require.NoError(t, err)
	require.True(t, r.Log, "limit_log carries logging")
	require.NotNil(t, r.RateLimit)
	require.Equal(t, RateLimit{Rate: 12, Unit: PerMinute, Burst: 6}, *r.RateLimit)

	require.True(t, f.isNativeLimit(r), "a logged native limit is still native")
	require.False(t, f.needsIPTablesRules(r),
		"a logged native limit must stay on the tuple path, not go to before.rules")

	// It marshals to a tuple carrying both the limit verb and the log keyword.
	out := f.MarshalRule(r)
	require.Contains(t, out, "limit")
	require.Contains(t, out, "log")

	// A native limit carrying a *custom* prefix cannot be a tuple, so it must still
	// route to before.rules.
	prefixed := &Rule{Action: Accept, Proto: TCP, Port: 22, Log: true, LogPrefix: "MINE",
		RateLimit: &RateLimit{Rate: 12, Unit: PerMinute, Burst: 6}}
	require.False(t, f.isNativeLimit(prefixed), "a custom-prefix limit is not tuple-expressible")
	require.True(t, f.needsIPTablesRules(prefixed), "a custom-prefix limit goes to before.rules")
}

// UFW editIPTablesRulesFile remove must preserve an adjacent foreign LOG line that
// is not the removal target's own LOG half, rather than discarding it unflushed.
func TestUFWRemovePreservesForeignLogLine(t *testing.T) {
	fw := new(UFW)
	dir := t.TempDir()
	path := filepath.Join(dir, "before.rules")
	content := "*filter\n:ufw-before-input - [0:0]\n" +
		"-A ufw-before-input -p tcp --dport 4000 -j LOG --log-prefix \"[FOREIGN] \"\n" +
		"-A ufw-before-input -p icmp --icmp-type 8 -j DROP\n" +
		"COMMIT\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o644))

	icmp := &Rule{Proto: ICMP, ICMPType: Ptr[uint8](8), Action: Drop}
	_, err := fw.editIPTablesRulesFile(path, icmp, IPv4, true)
	require.NoError(t, err)

	out, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Contains(t, string(out), "[FOREIGN]", "the unrelated foreign LOG line must survive removal")
	require.NotContains(t, string(out), "icmp", "the icmp rule must be removed")
}

// The before.rules scan is table-scoped, as the iptables backend's is: a line on
// a ufw chain sitting in the nat table is not a filter rule, so it is neither
// reported by GetRules nor a removal target — a removal that dropped it would
// silently rewrite the host's NAT block. Every untouched line, that one
// included, streams back through the rewrite verbatim.
func TestUFWBeforeRulesTableScoping(t *testing.T) {
	fw := new(UFW)
	dir := t.TempDir()
	path := filepath.Join(dir, "before.rules")
	content := "*nat\n:POSTROUTING ACCEPT [0:0]\n" +
		"-A ufw-before-input -p icmp --icmp-type 8 -j DROP\n" +
		"COMMIT\n" +
		"# the filter section\n" +
		"*filter\n:ufw-before-input - [0:0]\n" +
		"-A ufw-before-input -p icmp --icmp-type 8 -j DROP\n" +
		"COMMIT\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	// Only the filter table's copy is a rule.
	rules, err := fw.ParseIPTablesRules(path, IPv4)
	require.NoError(t, err)
	require.Len(t, rules, 1, "only the *filter copy is a filter rule, got %+v", rules)

	icmp := &Rule{Proto: ICMP, ICMPType: Ptr[uint8](8), Action: Drop}
	changed, err := fw.editIPTablesRulesFile(path, icmp, IPv4, true)
	require.NoError(t, err)
	require.True(t, changed)

	out, err := os.ReadFile(path)
	require.NoError(t, err)
	body := string(out)
	filterAt := strings.Index(body, "*filter")
	require.Contains(t, body[:filterAt], "--icmp-type 8", "the nat table's line must survive the removal")
	require.NotContains(t, body[filterAt:], "--icmp-type 8", "the filter rule must be removed")
	require.Contains(t, body, "# the filter section", "untouched lines stream through verbatim")

	// The staged rewrite keeps the file's own mode.
	fi, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), fi.Mode().Perm())
}

// ParseRules reads a ufw user.rules file, decoding the `### tuple ###` lines and
// the hex-encoded trailing comment (with the configured prefix split off).
func TestUFWParseRulesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "user.rules")
	// A plain allow, and a deny carrying a prefixed comment "myapp dns".
	comment := hex.EncodeToString([]byte("myapp dns"))
	content := "*filter\n" +
		"### tuple ### allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in\n" +
		"### tuple ### deny udp 53 0.0.0.0/0 any 0.0.0.0/0 in comment=" + comment + "\n" +
		"### RULES ###\n" +
		"-A ufw-user-input -p tcp --dport 22 -j ACCEPT\n" +
		"COMMIT\n"
	require.NoError(t, os.WriteFile(path, []byte(content), 0644))

	f := &UFW{rulePrefix: "myapp"}
	rules, err := f.ParseRules(path, IPv4)
	require.NoError(t, err)
	require.Len(t, rules, 2, "only the two ### tuple ### lines are parsed")

	require.Equal(t, Accept, rules[0].Action)
	require.Equal(t, TCP, rules[0].Proto)
	require.EqualValues(t, 22, rules[0].Port)
	require.Empty(t, rules[0].Comment)
	require.False(t, rules[0].HasPrefix, "an un-commented rule is not flagged as ours")

	require.Equal(t, Drop, rules[1].Action)
	require.Equal(t, UDP, rules[1].Proto)
	require.EqualValues(t, 53, rules[1].Port)
	require.Equal(t, "dns", rules[1].Comment, "the configured prefix is split off the comment")
	require.True(t, rules[1].HasPrefix, "the prefixed comment marks the rule as ours")
}

// ufw's `any` protocol means two different things depending on whether the rule
// carries a port: on a ported rule it is tcp+udp together (TCPUDP, ufw's native
// both-transports form), and on a portless rule it is every IP protocol
// (ProtocolAny). TestUFWTCPUDPMarshal exercises the write side of that split.
func TestUFWTCPUDPMarshal(t *testing.T) {
	fw := new(UFW)

	// A single-port TCPUDP rule emits ufw's bare-port short form (proto rides along as
	// ufw's `any`, so no `/proto` suffix and no proto clause).
	spec := fw.MarshalRule(&Rule{Port: 80, Proto: TCPUDP, Action: Accept})
	require.Equal(t, "allow in 80", spec, "a single-port TCPUDP rule uses ufw's bare-port short form")

	// The same port with ProtocolAny is rejected at the entry points: a port across
	// every protocol has no ufw form.
	require.Error(t, (&Rule{Port: 80, Proto: ProtocolAny, Action: Accept}).validate(),
		"a ProtocolAny rule carrying a port has no ufw form")

	// A portless ProtocolAny rule is ufw's real `any` and still marshals fine.
	spec = fw.MarshalRule(&Rule{Proto: ProtocolAny, Source: "1.2.3.4", Action: Accept})
	require.Contains(t, spec, "from 1.2.3.4")
	require.NotContains(t, spec, "proto", "ufw's `any` protocol carries no proto clause")

	// A family-specific single-port TCPUDP rule uses the full grammar with no proto
	// clause (ufw's `any` on a ported rule), covering both tcp and udp.
	spec = fw.MarshalRule(&Rule{Family: IPv4, Port: 80, Proto: TCPUDP, Action: Accept})
	require.Equal(t, "allow in to 0.0.0.0/0 port 80", spec)
}

// TestUFWTCPUDPTupleRoundTrip verifies the read side of ufw's `any`-protocol split:
// an `any` tuple with a port decodes to TCPUDP, one without a port to ProtocolAny.
func TestUFWTCPUDPTupleRoundTrip(t *testing.T) {
	fw := new(UFW)

	// A ported `any` tuple is tcp+udp together.
	ported, err := fw.UnmarshalRule("allow any 80 0.0.0.0/0 any 0.0.0.0/0 in", IPv4)
	require.NoError(t, err)
	require.Equal(t, TCPUDP, ported.Proto, "a ported `any` tuple decodes to TCPUDP")
	require.EqualValues(t, 80, ported.Port)

	// A source-port-only `any` tuple is likewise tcp+udp.
	sported, err := fw.UnmarshalRule("allow any any 0.0.0.0/0 1024 0.0.0.0/0 in", IPv4)
	require.NoError(t, err)
	require.Equal(t, TCPUDP, sported.Proto, "an `any` tuple with a source port decodes to TCPUDP")
	require.True(t, sported.HasSourcePorts(), "the source port must be parsed")
	require.EqualValues(t, 1024, sported.SourcePort)

	// A portless `any` tuple is every IP protocol.
	portless, err := fw.UnmarshalRule("allow any any 0.0.0.0/0 any 1.2.3.4 in", IPv4)
	require.NoError(t, err)
	require.Equal(t, ProtocolAny, portless.Proto, "a portless `any` tuple decodes to ProtocolAny")
	require.Equal(t, "1.2.3.4", portless.Source)

	// A native single-port TCPUDP rule round-trips through marshal + unmarshal.
	require.Equal(t, "allow in to 0.0.0.0/0 port 443",
		fw.MarshalRule(&Rule{Family: IPv4, Port: 443, Proto: TCPUDP, Action: Accept}))
}

// Every modeled tuple is its own rule, so a logical position maps straight to ufw's
// native slot. An unmodeled tuple (a route rule, kept as a nil row) still occupies a
// physical slot and shifts the ones after it.
func TestUFWNativeInsertPositionSkipsUnmodeledRows(t *testing.T) {
	fw := new(UFW)
	tcp80 := &Rule{Family: IPv4, Proto: TCP, Port: 80, Action: Accept}
	udp80 := &Rule{Family: IPv4, Proto: UDP, Port: 80, Action: Accept}
	tcp22 := &Rule{Family: IPv4, Proto: TCP, Port: 22, Action: Accept}

	// With every tuple modeled, position N is native slot N.
	rows := []*Rule{tcp80, udp80, tcp22}
	require.Equal(t, 1, fw.nativeInsertPositionFromRows(rows, 1))
	require.Equal(t, 2, fw.nativeInsertPositionFromRows(rows, 2))
	require.Equal(t, 3, fw.nativeInsertPositionFromRows(rows, 3))
	require.Equal(t, 4, fw.nativeInsertPositionFromRows(rows, 4),
		"past the end appends past the last physical tuple")

	// A route rule ufw counts but this backend cannot model sits at physical slot 2,
	// so the second reported rule lives at slot 3.
	withRoute := []*Rule{tcp80, nil, udp80, tcp22}
	require.Equal(t, 1, fw.nativeInsertPositionFromRows(withRoute, 1))
	require.Equal(t, 3, fw.nativeInsertPositionFromRows(withRoute, 2),
		"the unmodeled route tuple shifts the native slot")
	require.Equal(t, 4, fw.nativeInsertPositionFromRows(withRoute, 3))
	require.Equal(t, 5, fw.nativeInsertPositionFromRows(withRoute, 4))
}

// TestUFWEditIPTablesRulesAnchorsFilterCommit pins that the raw-path add splices
// its rule into the *filter section's COMMIT, not the file's first COMMIT: the
// canonical ufw NAT setup puts a *nat block above *filter, and a filter rule in
// that block references an undeclared chain, failing the reload.
func TestUFWEditIPTablesRulesAnchorsFilterCommit(t *testing.T) {
	fw := new(UFW)
	natFirst := "*nat\n:POSTROUTING ACCEPT [0:0]\n-A POSTROUTING -s 10.0.0.0/8 -o eth0 -j MASQUERADE\nCOMMIT\n" +
		"*filter\n:ufw-before-input - [0:0]\nCOMMIT\n"
	dir := t.TempDir()
	path := filepath.Join(dir, "before.rules")
	require.NoError(t, os.WriteFile(path, []byte(natFirst), 0644))

	icmp := &Rule{Proto: ICMP, ICMPType: Ptr[uint8](8), Action: Accept}
	changed, err := fw.editIPTablesRulesFile(path, icmp, IPv4, false)
	require.NoError(t, err)
	require.True(t, changed)

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	body := string(data)
	natEnd := strings.Index(body, "*filter")
	require.NotContains(t, body[:natEnd], "--icmp-type",
		"the rule must not land inside the *nat block")
	require.Contains(t, body[natEnd:], "--icmp-type",
		"the rule must land inside the *filter block")
	// The rule sits before *filter's COMMIT.
	filterPart := body[natEnd:]
	require.Less(t, strings.Index(filterPart, "--icmp-type"), strings.Index(filterPart, "COMMIT"))
}

// TestUFWOldFormatTupleStaysOpaque pins that ufw's old 8-field storage format
// (six core fields plus dapp/sapp, no direction field) is rejected by the tuple
// parser, so parseTupleRows holds it as a nil row rather than mis-reading it.
func TestUFWOldFormatTupleStaysOpaque(t *testing.T) {
	fw := new(UFW)
	_, err := fw.UnmarshalRule("allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 Apache -", IPv4)
	require.Error(t, err, "the old 8-field format must stay opaque")

	// A non-route tuple must not carry a "!"-joined interface pair.
	_, err = fw.UnmarshalRule("allow tcp 80 0.0.0.0/0 any 0.0.0.0/0 in_eth0!out_eth1", IPv4)
	require.Error(t, err, "a dual-interface token is only valid on a route rule")
}

// ufwLiveSave is a trimmed `iptables-save -c -t filter` capture from a host
// running ufw, covering each shape ufw expands a rule into: a plain action line,
// the tcp+udp pair a ported `any` tuple becomes, the logging-chain jump that
// precedes a logged rule's action line, the three-line `limit` sequence, and a
// raw before.rules rule written as a LOG line plus its action line.
var ufwLiveSave = []string{
	"# Generated by iptables-save",
	"*filter",
	":INPUT DROP [0:0]",
	":ufw-user-input - [0:0]",
	"[9:540] -A INPUT -j ufw-before-input",
	"[3:180] -A ufw-before-output -p tcp -m tcp --dport 39323 -m comment --comment gofw -j LOG --log-prefix \"probe: \"",
	"[3:180] -A ufw-before-output -p tcp -m tcp --dport 39323 -m comment --comment gofw -j ACCEPT",
	"[7:420] -A ufw-user-input -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name DEFAULT --mask 255.255.255.255 --rsource",
	"[1:60] -A ufw-user-input -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 30 --hitcount 6 --name DEFAULT --mask 255.255.255.255 --rsource -j ufw-user-limit",
	"[6:360] -A ufw-user-input -p tcp -m tcp --dport 22 -j ufw-user-limit-accept",
	"[2:120] -A ufw-user-input -p tcp -m tcp --dport 53 -j ACCEPT",
	"[5:405] -A ufw-user-input -p udp -m udp --dport 53 -j ACCEPT",
	"[4:240] -A ufw-user-input -p tcp -m tcp --dport 8080 -j ufw-user-logging-input",
	"[4:240] -A ufw-user-input -p tcp -m tcp --dport 8080 -j ACCEPT",
	"[4:240] -A ufw-user-logging-input -p tcp -m tcp --dport 8080 -m conntrack --ctstate NEW -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix \"[UFW ALLOW] \"",
	"[4:240] -A ufw-user-logging-input -p tcp -m tcp --dport 8080 -j RETURN",
	"[6:360] -A ufw-user-limit-accept -j ACCEPT",
	"COMMIT",
}

// TestUFWParseLiveRules verifies the live ruleset is read back as the rules that
// produced it: ufw's logging-chain jump and its three-line `limit` sequence are
// folded back into the single rule each stands for, its internal chains and
// accounting rows contribute nothing, and every row keeps the kernel's counters.
func TestUFWParseLiveRules(t *testing.T) {
	fw := new(UFW)
	rules := fw.parseLiveRules(ufwLiveSave, IPv4)
	require.Len(t, rules, 5, "the internal-chain rows and the limit accounting rows model no rule of their own")

	// The raw before.rules rule: its LOG line and action line are one logged rule
	// carrying the action line's counters.
	require.True(t, rules[0].Log)
	require.Equal(t, "probe: ", rules[0].LogPrefix)
	require.EqualValues(t, 39323, rules[0].Port)
	require.EqualValues(t, 3, rules[0].Packets)
	require.EqualValues(t, 180, rules[0].Bytes)

	// The `limit` tuple: read back as an accept carrying ufw's built-in rate, with
	// the counters of the row that accepts.
	require.EqualValues(t, 22, rules[1].Port)
	require.Equal(t, Accept, rules[1].Action)
	require.NotNil(t, rules[1].RateLimit)
	require.Equal(t, fw.nativeLimit(), *rules[1].RateLimit)
	require.EqualValues(t, 6, rules[1].Packets)

	// The ported `any` tuple stays two rows here; only the merge sums them.
	require.Equal(t, TCP, rules[2].Proto)
	require.EqualValues(t, 2, rules[2].Packets)
	require.Equal(t, UDP, rules[3].Proto)
	require.EqualValues(t, 5, rules[3].Packets)

	// The logged tuple: the jump into ufw's logging chain sets Log on the action
	// row beneath it, and ufw's own log prefix is not a rule field.
	require.EqualValues(t, 8080, rules[4].Port)
	require.True(t, rules[4].Log)
	require.Empty(t, rules[4].LogPrefix)
	require.EqualValues(t, 4, rules[4].Packets)
}

// TestUFWApplyCounters verifies counters land on the rule that owns them: an
// exact match wins over a wider rule, a ported `any` tuple sums the tcp and udp
// rows ufw writes for it, and a rule with no live row keeps zero.
func TestUFWApplyCounters(t *testing.T) {
	fw := new(UFW)
	live := fw.parseLiveRules(ufwLiveSave, IPv4)

	limit := fw.nativeLimit()
	targets := []*Rule{
		{Direction: DirInput, Family: IPv4, Proto: TCP, Port: 22, Action: Accept, RateLimit: &limit},
		{Direction: DirInput, Family: IPv4, Proto: TCPUDP, Port: 53, Action: Accept},
		{Direction: DirInput, Family: IPv4, Proto: TCP, Port: 8080, Action: Accept, Log: true},
		{Direction: DirInput, Family: IPv4, Proto: TCP, Port: 9999, Action: Accept},
	}
	applyLiveCounters(targets, live)

	require.EqualValues(t, 6, targets[0].Packets, "a limit rule counts the row that accepts")
	require.EqualValues(t, 7, targets[1].Packets, "a ported any tuple sums its tcp and udp rows")
	require.EqualValues(t, 525, targets[1].Bytes)
	require.EqualValues(t, 4, targets[2].Packets, "a logged rule counts its action row")
	require.Zero(t, targets[3].Packets, "a rule the live ruleset does not hold keeps zero counters")
}

// TestUFWApplyCountersExactMatchWins verifies a rule that has a row of its own is
// matched to it before a wider rule can absorb that row, so the narrow rule is
// not left at zero.
func TestUFWApplyCountersExactMatchWins(t *testing.T) {
	fw := new(UFW)
	live := fw.parseLiveRules(ufwLiveSave, IPv4)

	wide := &Rule{Direction: DirInput, Family: IPv4, Proto: TCPUDP, Port: 53, Action: Accept}
	narrow := &Rule{Direction: DirInput, Family: IPv4, Proto: TCP, Port: 53, Action: Accept}
	applyLiveCounters([]*Rule{wide, narrow}, live)

	require.EqualValues(t, 2, narrow.Packets, "the tcp rule keeps the tcp row it matches exactly")
	require.EqualValues(t, 5, wide.Packets, "the wider rule sums only the rows left over")
}

// TestUFWParseLiveRulesLimitLog verifies a `limit_log` tuple, whose live rows put
// ufw's logging jump above the three-line rate-limit sequence, is read back as
// one logged and rate-limited rule: the accounting row between them carries no
// jump and must not consume the pending logging jump.
func TestUFWParseLiveRulesLimitLog(t *testing.T) {
	fw := new(UFW)
	out := []string{
		"[4:240] -A ufw-user-input -p tcp -m tcp --dport 22 -j ufw-user-logging-input",
		"[4:240] -A ufw-user-input -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name DEFAULT --mask 255.255.255.255 --rsource",
		"[1:60] -A ufw-user-input -p tcp -m tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 30 --hitcount 6 --name DEFAULT --mask 255.255.255.255 --rsource -j ufw-user-limit",
		"[3:180] -A ufw-user-input -p tcp -m tcp --dport 22 -j ufw-user-limit-accept",
	}
	rules := fw.parseLiveRules(out, IPv4)
	require.Len(t, rules, 1)
	require.True(t, rules[0].Log, "the logging jump above the rate-limit sequence still marks the rule as logged")
	require.NotNil(t, rules[0].RateLimit)
	require.Equal(t, fw.nativeLimit(), *rules[0].RateLimit)
	require.EqualValues(t, 3, rules[0].Packets, "a limit rule counts the row that accepts")

	// The tuple ufw stores for that rule must match the row it was read back as.
	tuple, err := fw.UnmarshalRule("limit_log tcp 22 0.0.0.0/0 any 0.0.0.0/0 in", IPv4)
	require.NoError(t, err)
	applyLiveCounters([]*Rule{tuple}, rules)
	require.EqualValues(t, 3, tuple.Packets)
	require.EqualValues(t, 180, tuple.Bytes)
}
