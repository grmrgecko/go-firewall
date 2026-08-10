package main

import (
	"strings"
	"testing"

	fw "github.com/grmrgecko/go-firewall"
)

// These tests cover the CLI's pure logic — flag parsing, rate/ICMP token
// parsing, and the human-readable renderers. They never open a firewall
// manager and never touch the host, so they run anywhere `go test` does.

func TestParseRateToken(t *testing.T) {
	cases := []struct {
		in      string
		rate    uint
		unit    fw.RateUnit
		wantErr bool
	}{
		{"10/second", 10, fw.PerSecond, false},
		{"20/m", 20, fw.PerMinute, false},
		{"5/hour", 5, fw.PerHour, false},
		{"1/d", 1, fw.PerDay, false},
		{"10", 0, 0, true},           // missing unit
		{"abc/minute", 0, 0, true},   // non-numeric rate
		{"10/fortnight", 0, 0, true}, // unknown unit
	}
	for _, c := range cases {
		rate, unit, err := parseRateToken(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseRateToken(%q): want error, got nil", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseRateToken(%q): unexpected error: %v", c.in, err)
			continue
		}
		if rate != c.rate || unit != c.unit {
			t.Errorf("parseRateToken(%q): got %d/%v, want %d/%v", c.in, rate, unit, c.rate, c.unit)
		}
	}
}

func TestParseICMPType(t *testing.T) {
	cases := []struct {
		in   string
		v6   bool
		want uint8
		ok   bool
	}{
		{"8", false, 8, true},
		{"echo-request", false, 8, true},
		{"ping", false, 8, true},
		{"ECHO-REQUEST", false, 8, true}, // case-insensitive
		{"destination-unreachable", false, 3, true},
		{"255", false, 255, true},
		{"echo_boop", false, 0, false}, // unknown name
		// ICMPv6 resolves the same names to different numbers.
		{"echo-request", true, 128, true},
		{"ping", true, 128, true},
		{"destination-unreachable", true, 1, true},
		{"nd-neighbor-solicit", true, 135, true},
		{"128", true, 128, true},
		// A name that only exists in the v4 table is unknown under v6.
		{"source-quench", true, 0, false},
	}
	for _, c := range cases {
		got, ok := fw.ParseICMPType(c.in, c.v6)
		if ok != c.ok {
			t.Errorf("fw.ParseICMPType(%q, v6=%v): ok=%v want %v", c.in, c.v6, ok, c.ok)
			continue
		}
		if ok && got != c.want {
			t.Errorf("fw.ParseICMPType(%q, v6=%v): got %d want %d", c.in, c.v6, got, c.want)
		}
	}
}

func TestRuleFlagsToRule(t *testing.T) {
	// A representative rule exercising most flag-driven fields. The point is
	// to confirm the string flags route through the library's Parse* helpers
	// into the right struct fields.
	flags := ruleFlags{
		Action:      "drop",
		Family:      "ipv4",
		Proto:       "tcp",
		Source:      "192.168.0.0/24",
		Destination: "10.0.0.1",
		Port:        443,
		Ports:       "80,443,1000-2000",
		ICMPType:    "echo-request",
		State:       "new,established",
		Log:         true,
		LogPrefix:   "https",
		RateLimit:   "10/minute",
		RateBurst:   5,
		ConnLimit:   100,
		ConnPerSrc:  true,
		InInterface: "eth0",
		Comment:     "web",
	}
	rule, err := flags.toRule()
	if err != nil {
		t.Fatalf("toRule: unexpected error: %v", err)
	}
	if rule.Action != fw.Drop {
		t.Errorf("Action: got %v want drop", rule.Action)
	}
	if rule.Family != fw.IPv4 {
		t.Errorf("Family: got %v want ipv4", rule.Family)
	}
	if rule.Proto != fw.TCP {
		t.Errorf("Proto: got %v want tcp", rule.Proto)
	}
	if rule.Source != "192.168.0.0/24" {
		t.Errorf("Source: got %q", rule.Source)
	}
	if len(rule.Ports) != 3 || rule.Ports[2].Start != 1000 || rule.Ports[2].End != 2000 {
		t.Errorf("Ports: got %+v", rule.Ports)
	}
	if rule.ICMPType == nil || *rule.ICMPType != 8 {
		t.Errorf("ICMPType: got %+v", rule.ICMPType)
	}
	if rule.State != (fw.StateNew | fw.StateEstablished) {
		t.Errorf("State: got %v", rule.State)
	}
	if !rule.Log || rule.LogPrefix != "https" {
		t.Errorf("Log: got %v/%q", rule.Log, rule.LogPrefix)
	}
	if rule.RateLimit == nil || rule.RateLimit.Rate != 10 || rule.RateLimit.Unit != fw.PerMinute || rule.RateLimit.Burst != 5 {
		t.Errorf("RateLimit: got %+v", rule.RateLimit)
	}
	if rule.ConnLimit == nil || rule.ConnLimit.Count != 100 || !rule.ConnLimit.PerSource {
		t.Errorf("ConnLimit: got %+v", rule.ConnLimit)
	}
	if rule.InInterface != "eth0" {
		t.Errorf("InInterface: got %q", rule.InInterface)
	}
	if rule.Comment != "web" {
		t.Errorf("Comment: got %q", rule.Comment)
	}
}

func TestRuleFlagsToRuleErrors(t *testing.T) {
	// Each malformed flag should surface as an error rather than a silent
	// default — the CLI must never author a broader rule than the user asked.
	bad := []ruleFlags{
		{Action: "explode"},
		{Family: "ipv9"},
		{Proto: "tpc"}, // typo must not silently widen to any
		{Ports: "80,abc"},
		{State: "new,bogus"},
		{RateLimit: "10"},
	}
	for _, f := range bad {
		if _, err := f.toRule(); err == nil {
			t.Errorf("toRule(%+v): want error, got nil", f)
		}
	}

	// The same unknown-protocol rejection applies to NAT rules via toNATRule.
	if _, err := (&natFlags{Kind: "dnat", Family: "any", Proto: "tpc"}).toNATRule(); err == nil {
		t.Errorf("toNATRule with bad proto: want error, got nil")
	}
}

func TestDescribeRule(t *testing.T) {
	r := &fw.Rule{
		Direction: fw.DirInput,
		Action:    fw.Accept,
		Family:    fw.IPv4,
		Proto:     fw.TCP,
		Source:    "192.168.1.0/24",
		Port:      443,
		Log:       true,
		LogPrefix: "https",
		Comment:   "web",
	}
	got := describeRule(r)
	// Spot-check a few segments rather than the whole string, so the test
	// does not break on cosmetic wording changes.
	for _, want := range []string{"in", "accept", "ipv4", "tcp", "from 192.168.1.0/24", "port 443", "log=https", "# web"} {
		if !strings.Contains(got, want) {
			t.Errorf("describeRule: missing %q in %q", want, got)
		}
	}
}

func TestDescribeNATRule(t *testing.T) {
	r := &fw.NATRule{
		Kind:      fw.DNAT,
		Family:    fw.IPv4,
		Proto:     fw.TCP,
		Port:      8080,
		ToAddress: "10.0.0.5",
		ToPort:    80,
	}
	got := describeNATRule(r)
	for _, want := range []string{"dnat", "ipv4", "tcp", "port 8080", "-> 10.0.0.5:80"} {
		if !strings.Contains(got, want) {
			t.Errorf("describeNATRule: missing %q in %q", want, got)
		}
	}
}

func TestPrintSet(t *testing.T) {
	var buf strings.Builder
	set := &fw.AddressSet{
		Name:    "blocklist",
		Family:  fw.IPv4,
		Type:    fw.SetHashNet,
		Entries: []string{"203.0.113.0/24", "198.51.100.7"},
	}
	printSet(&buf, set)
	got := buf.String()
	for _, want := range []string{"blocklist", "family=ipv4", "type=hash:net", "entries=2", "203.0.113.0/24", "198.51.100.7"} {
		if !strings.Contains(got, want) {
			t.Errorf("printSet: missing %q in %q", want, got)
		}
	}

	// A zero Type defaults to hash:ip, and an empty set is rendered explicitly
	// rather than as a blank line.
	buf.Reset()
	printSet(&buf, &fw.AddressSet{Name: "empty"})
	got = buf.String()
	for _, want := range []string{"type=hash:ip", "(no entries)"} {
		if !strings.Contains(got, want) {
			t.Errorf("printSet(empty): missing %q in %q", want, got)
		}
	}
}

func TestPrintRulesHonorsWriter(t *testing.T) {
	// printRules/printNATRules/printSets must write to the writer they are
	// given, not an implicit os.Stdout — a bytes buffer here would stay empty
	// if the writer were ignored.
	var buf strings.Builder
	printRules(&buf, []*fw.Rule{{Action: fw.Accept, Proto: fw.TCP, Port: 22}})
	if !strings.Contains(buf.String(), "port 22") {
		t.Errorf("printRules did not write to the provided writer: %q", buf.String())
	}
}

func TestResolveZone(t *testing.T) {
	// resolveZone never touches a real manager when zone is explicit: it
	// short-circuits before calling GetZone. A nil manager is therefore fine
	// for the explicit-zone case (and only that case).
	zone, err := resolveZone(nil, "public", "")
	if err != nil {
		t.Fatalf("resolveZone: unexpected error: %v", err)
	}
	if zone != "public" {
		t.Errorf("resolveZone: got %q want public", zone)
	}

	// An explicit --zone takes precedence over --interface (the documented
	// contract). With a nil manager this passes only because resolveZone returns
	// the zone before it would resolve the interface; if the precedence were
	// reversed it would dereference the nil manager and panic.
	zone, err = resolveZone(nil, "public", "eth0")
	if err != nil {
		t.Fatalf("resolveZone with both zone and interface: unexpected error: %v", err)
	}
	if zone != "public" {
		t.Errorf("resolveZone: --zone must win over --interface; got %q want public", zone)
	}
}

// A redirect NAT rule needs a port-bearing protocol and a destination port; the
// CLI must reject the ambiguous defaults up front rather than deferring to the
// backend.
func TestNATFlagsRedirectValidation(t *testing.T) {
	// Redirect with proto any and no --to-port is rejected on the protocol.
	if _, err := (&natFlags{Kind: "redirect", Family: "any", Proto: "any"}).toNATRule(); err == nil {
		t.Errorf("redirect with proto any / no to-port: want error, got nil")
	}
	// Redirect with a port-bearing proto but still no --to-port is rejected.
	if _, err := (&natFlags{Kind: "redirect", Family: "any", Proto: "tcp"}).toNATRule(); err == nil {
		t.Errorf("redirect without to-port: want error, got nil")
	}
	// A complete redirect is accepted.
	r, err := (&natFlags{Kind: "redirect", Family: "any", Proto: "tcp", ToPort: 8080, Port: 80}).toNATRule()
	if err != nil {
		t.Fatalf("valid redirect: unexpected error %v", err)
	}
	if r.Kind != fw.Redirect || r.ToPort != 8080 {
		t.Errorf("unexpected redirect rule: %+v", r)
	}
	// A dnat still accepts the default proto (validation is redirect-specific).
	if _, err := (&natFlags{Kind: "dnat", Family: "any", Proto: "any", ToAddr: "10.0.0.1"}).toNATRule(); err != nil {
		t.Errorf("dnat with default proto: unexpected error %v", err)
	}
}

// Interface matches are direction-specific: toRule must reject an outbound
// interface on an input rule and an inbound interface on an output rule.
func TestRuleFlagsInterfaceDirection(t *testing.T) {
	// --out-interface on an input (default) rule is rejected.
	if _, err := (&ruleFlags{Action: "accept", Family: "any", Proto: "any", OutInterface: "eth0"}).toRule(); err == nil {
		t.Errorf("out-interface on input rule: want error, got nil")
	}
	// --in-interface on an output rule is rejected.
	if _, err := (&ruleFlags{Action: "accept", Family: "any", Proto: "any", Output: true, InInterface: "eth0"}).toRule(); err == nil {
		t.Errorf("in-interface on output rule: want error, got nil")
	}
	// The matching combinations are accepted.
	if _, err := (&ruleFlags{Action: "accept", Family: "any", Proto: "any", InInterface: "eth0"}).toRule(); err != nil {
		t.Errorf("in-interface on input rule: unexpected error %v", err)
	}
	if _, err := (&ruleFlags{Action: "accept", Family: "any", Proto: "any", Output: true, OutInterface: "eth0"}).toRule(); err != nil {
		t.Errorf("out-interface on output rule: unexpected error %v", err)
	}
}
