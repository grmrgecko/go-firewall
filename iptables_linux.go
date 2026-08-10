package firewall

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/anmitsu/go-shlex"
)

const (
	// IPTablesNoSave is the error text returned when no iptables save path is found.
	IPTablesNoSave = "unable to find iptables save path"
	// IPTablesNoService is the error text returned when no iptables service is found.
	IPTablesNoService = "unable to find iptables service"
)

// IPTables manages filter and NAT rules through iptables save files and the service that restores them.
type IPTables struct {
	IP4Path, IP6Path string
	// IP6Path and IP6Service are empty on a host whose packaging ships no
	// ip6tables save file — a system built without IPv6, or one where the
	// ip6tables package was never installed — and on one whose IPv6 restore
	// service is not enabled, since nothing would replay the file at boot. Such a
	// host is managed IPv4-only; see managesIPv6 for what that changes.
	IP4Service, IP6Service string
	// IPSetPath and IPSetService describe the optional ipset persistence
	// mechanism detected for this host. IPSetPath is the file address sets are
	// staged in — the authority for the sets this backend manages, loaded into the
	// kernel by Reload and by IPSetService at boot, before the rules that
	// reference them. Both are empty when no mechanism is installed, in which case
	// address sets are created live and do not survive a reboot.
	IPSetPath, IPSetService string
	// pendingSetRemovals names the sets dropped from the staging file this session
	// whose kernel-side destroy is still owed. Reload performs them after the rules
	// services restart, so nothing references the set by then; a set that will not
	// destroy stays queued. The queue is session state, so a removal staged by a
	// process that exits before Reload leaves the set live until the next boot.
	pendingSetRemovals []string
	// rulePrefix, when set, is written as an iptables comment on rules this
	// library creates so they can be told apart from pre-existing rules.
	rulePrefix string
}

// iptLayout names the save-file paths and restore services a supported iptables
// packaging uses. The Debian layout carries the same service for both families
// (netfilter-persistent restores both rules.v4 and rules.v6), so ip4Service and
// ip6Service are equal there.
type iptLayout struct {
	ip4Path, ip6Path string
	// ip6Path and ip6Service are cleared by probeIPTLayout when the packaging's
	// IPv6 save file is absent, marking the host IPv4-only. NewIPTables clears
	// them the same way when the IPv6 restore service is not enabled.
	ip4Service, ip6Service string
	// ipsetPath is the save file the ipset restore service reads on boot, and
	// ipsetService is the service that restores it before the rules service
	// loads the -m set rules that reference the sets. Persisting sets is optional
	// (a missing mechanism is not fatal, unlike a missing rules save file), so
	// these describe the packaging's convention; NewIPTables confirms the
	// mechanism is installed.
	ipsetPath, ipsetService string
	// ipsetPlugin, when set, is a glob whose presence proves the restore mechanism
	// is installed. The Debian layout persists sets through a netfilter-persistent
	// plugin rather than a dedicated service, so its absence means the saved file
	// would never be restored and the sets are left live-only.
	ipsetPlugin string
}

// iptLayouts lists the iptables packagings this backend understands, in probe
// order. Debian precedes Arch because both keep their save files in
// /etc/iptables under different names, so the order only decides which wins on
// a host that somehow carries both.
var iptLayouts = []iptLayout{
	// RHEL/iptables-services: per-family save files and services, sets restored
	// by a dedicated ipset service.
	{
		ip4Path: "/etc/sysconfig/iptables", ip6Path: "/etc/sysconfig/ip6tables",
		ip4Service: "iptables", ip6Service: "ip6tables",
		ipsetPath: "/etc/sysconfig/ipset", ipsetService: "ipset",
	},
	// Debian/Ubuntu iptables-persistent: the single netfilter-persistent service
	// restores both families, and sets ride one of its plugins.
	{
		ip4Path: "/etc/iptables/rules.v4", ip6Path: "/etc/iptables/rules.v6",
		ip4Service: "netfilter-persistent", ip6Service: "netfilter-persistent",
		ipsetPath: "/etc/iptables/ipsets", ipsetService: "netfilter-persistent",
		ipsetPlugin: "/usr/share/netfilter-persistent/plugins.d/*ipset*",
	},
	// Arch/Manjaro: the iptables package's own per-family units restore
	// /etc/iptables/*.rules, and the ipset package's unit restores
	// /etc/ipset.conf.
	{
		ip4Path: "/etc/iptables/iptables.rules", ip6Path: "/etc/iptables/ip6tables.rules",
		ip4Service: "iptables", ip6Service: "ip6tables",
		ipsetPath: "/etc/ipset.conf", ipsetService: "ipset",
	},
}

// managesIPv6 reports whether this host has an ip6tables save file to manage and
// a service to restore it. When it does not, the backend runs IPv4-only: reads
// report IPv4 rows only, FamilyAny writes narrow to the IPv4 file, and a
// concrete-IPv6 write is rejected through checkFamilyManaged. Removals are not
// gated — with no v6 file there is nothing v6 to remove, so they are no-ops
// rather than errors.
func (f *IPTables) managesIPv6() bool {
	return f.IP6Path != ""
}

// probeIPTLayout reports the first layout in iptLayouts whose v4 save file is
// present under root. The v4 file alone decides the match: a layout whose v6
// partner is absent is reported with its ip6Path and ip6Service cleared, marking
// the host IPv4-only, since a system built without IPv6 still has an IPv4
// firewall worth managing.
func probeIPTLayout(root string) (iptLayout, bool) {
	for _, l := range iptLayouts {
		if _, err := os.Stat(root + l.ip4Path); err != nil {
			continue
		}
		if _, err := os.Stat(root + l.ip6Path); err != nil {
			l.ip6Path, l.ip6Service = "", ""
		}
		return l, true
	}
	return iptLayout{}, false
}

// NewIPTables creates an iptables manager, detecting the save-file layout and
// confirming its IPv4 restore service is enabled. An IPv6 half that has no save
// file, or whose restore service is not enabled, is left unmanaged rather than
// failing.
func NewIPTables(ctx context.Context, rulePrefix string) (*IPTables, error) {
	ipt := new(IPTables)
	ipt.rulePrefix = rulePrefix

	// Detect which packaging manages the save files on this host.
	layout, ok := probeIPTLayout("")
	if !ok {
		return nil, errors.New(IPTablesNoSave)
	}
	ipt.IP4Path, ipt.IP6Path = layout.ip4Path, layout.ip6Path

	// Confirm the service that restores the rules is enabled, under whatever
	// init system the host uses.
	ipt.IP4Service = layout.ip4Service
	if !serviceEnabled(ctx, ipt.IP4Service) {
		return nil, errors.New(IPTablesNoService)
	}

	// With no v6 save file there is no v6 restore service to confirm; the host is
	// managed IPv4-only from here on. A save file whose restore service is not
	// enabled is the same situation: writes to it would never be applied at boot,
	// so IPv6 is left unmanaged rather than failing the whole backend, which still
	// has a working IPv4 firewall to manage. Skip the redundant check when it is
	// the same service already confirmed enabled above (the Debian layout uses one
	// service for both families).
	ipt.IP6Service = layout.ip6Service
	if !ipt.managesIPv6() {
		log.Printf("firewall: iptables found no IPv6 save file alongside %s; managing IPv4 only", ipt.IP4Path)
	} else if ipt.IP6Service != ipt.IP4Service && !serviceEnabled(ctx, ipt.IP6Service) {
		log.Printf("firewall: iptables service %s is not enabled; managing IPv4 only", ipt.IP6Service)
		ipt.IP6Path, ipt.IP6Service = "", ""
	}

	// Detect the optional ipset persistence mechanism belonging to this packaging.
	// Unlike the rules save file, a missing mechanism is not fatal: address sets
	// still work live, they just are not staged and do not survive a reboot
	// (AddAddressSet warns when a set is added in that case).
	ipt.IPSetPath, ipt.IPSetService = ipsetLayoutInstalled(ctx, layout)

	return ipt, nil
}

// Type returns the manager type.
func (f *IPTables) Type() string {
	return IPTablesType
}

// Capabilities returns the set of features this backend can express.
func (f *IPTables) Capabilities() Capabilities {
	return Capabilities{
		Output:  true,
		Forward: true,
		// IPv6 mirrors managesIPv6: with no managed ip6tables save file on this
		// host there is nowhere to write an IPv6 rule of any kind.
		IPv6:                 f.managesIPv6(),
		PortPair:             true,
		ConnState:            true,
		InterfaceMatch:       true,
		Logging:              true,
		RateLimit:            true,
		ConnLimit:            true,
		NAT:                  true,
		RuleOrdering:         true,
		DefaultPolicy:        true,
		RuleCounters:         true,
		AddressSets:          true,
		Comments:             true,
		Negation:             true,
		RejectAction:         true,
		FamilyWithoutAddress: true,
	}
}

// GetZone reports no zone: iptables has only policy groups, and rules are
// inserted at the top of the INPUT/OUTPUT policies.
func (f *IPTables) GetZone(ctx context.Context, iface string) (zoneName string, err error) {
	return "", nil
}

// iptParsePorts parses a multiport value list (comma-separated "p" or "lo:hi")
// into PortRange values.
func iptParsePorts(val string) ([]PortRange, error) {
	return ParsePortRanges(val, ",")
}

// unmarshalIPTablesRule decodes an iptables rulespec (e.g. an `-A CHAIN ...`
// line) into a rule. It is shared by the iptables backend and the ufw backend,
// whose before/after iptables rules files are in this format.
func unmarshalIPTablesRule(ruleSpec string, family Family) (r *Rule, err error) {
	r = &Rule{
		Family: family,
	}
	not := false
	tokens, err := shlex.Split(ruleSpec, true)
	if err != nil {
		return nil, err
	}

	// An iptables-save line may carry a leading [pkts:bytes] counter prefix.
	// Capture the counters onto the rule and strip the prefix before parsing.
	if len(tokens) > 0 && strings.HasPrefix(tokens[0], "[") && strings.HasSuffix(tokens[0], "]") {
		inner := strings.TrimSuffix(strings.TrimPrefix(tokens[0], "["), "]")
		if pk, bs, ok := strings.Cut(inner, ":"); ok {
			if n, e := strconv.ParseUint(pk, 10, 64); e == nil {
				r.Packets = n
			}
			if n, e := strconv.ParseUint(bs, 10, 64); e == nil {
				r.Bytes = n
			}
		}
		tokens = tokens[1:]
	}

	// Start at 2, the command and the chain.
	i := 2
	if i >= len(tokens) {
		return nil, fmt.Errorf("unexpected token length")
	}

	// Check the chain.
	switch tokens[1] {
	case "INPUT":
		r.Direction = DirInput
	case "OUTPUT":
		r.Direction = DirOutput
	case "FORWARD":
		r.Direction = DirForward
	default:
		return nil, fmt.Errorf("the chain is not INPUT, OUTPUT or FORWARD")
	}

	// Check the command.
	switch tokens[0] {
	case "-A", "--append":
	case "-I", "--insert":
		// If insert rule has an integer rule number, increment i.
		if i < len(tokens) {
			_, err := strconv.Atoi(tokens[i])
			if err == nil {
				i++
			}
		}
	case "-R", "--replace":
		_, err := strconv.Atoi(tokens[i])
		if err != nil {
			return nil, fmt.Errorf("the replace command requires an integer rule number")
		}
		i++
	default:
		return nil, fmt.Errorf("unsupported command provided")
	}

	// Process the rule.
	for ; i < len(tokens); i++ {
		switch tokens[i] {
		// A leading "!" negates the match that follows it.
		case "!":
			not = true
			// Continue so the negation is not cleared before the match token is read.
			continue
		case "-p", "--protocol":
			// Negation is unsupported on this parameter.
			if not {
				return nil, fmt.Errorf("negation is defined for protocol, which our limited rule structure does not support")
			}

			// Verify the protocol is specified.
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("invalid protocol parameter")
			}

			// Verify the protocol value is valid.
			r.Proto = GetProtocol(tokens[i])
			if r.Proto == ProtocolAny && !strings.EqualFold(tokens[i], "all") {
				return nil, fmt.Errorf("invalid protocol parameter")
			}
		case "-s", "--source":
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("invalid source parameter")
			}

			// Confirm the address parses.
			_, _, err := net.ParseCIDR(tokens[i])
			ip := net.ParseIP(tokens[i])
			if err != nil && ip == nil {
				return nil, fmt.Errorf("invalid source parameter")
			}

			// Set the source address.
			if not {
				r.Source = "!" + tokens[i]
			} else {
				r.Source = tokens[i]
			}
		case "-d", "--destination":
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("invalid destination parameter")
			}

			// Confirm the address parses.
			_, _, err := net.ParseCIDR(tokens[i])
			ip := net.ParseIP(tokens[i])
			if err != nil && ip == nil {
				return nil, fmt.Errorf("invalid destination parameter")
			}

			// Set the destination address.
			if not {
				r.Destination = "!" + tokens[i]
			} else {
				r.Destination = tokens[i]
			}
		case "--icmp-type", "--icmpv6-type":
			// A bare icmp-type match (as in `-p icmp --icmp-type echo-request`,
			// without an explicit `-m icmp`), common in ufw's iptables rules files.
			if not {
				return nil, fmt.Errorf("a negated icmp type is not supported")
			}
			// The flag names the family: --icmpv6-type resolves names through the
			// ICMPv6 table, where reused names (e.g. echo-request) map to different
			// numbers than in ICMPv4.
			v6 := tokens[i] == "--icmpv6-type"
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("invalid icmp-type parameter")
			}
			n, ok := parseICMPTypeFamily(tokens[i], v6)
			if !ok {
				return nil, fmt.Errorf("invalid icmp type %q", tokens[i])
			}
			r.ICMPType = Ptr(n)
		case "--sport", "--source-port":
			// A bare source-port match (as in `-p udp --sport 5353`).
			if not {
				return nil, fmt.Errorf("a negated source port is not supported")
			}
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("invalid sport parameter")
			}
			pr, perr := ParsePortRange(tokens[i])
			if perr != nil {
				return nil, perr
			}
			if pr.Start == pr.End {
				r.SourcePort = pr.Start
			} else {
				r.SourcePorts = []PortRange{pr}
			}
		case "--dport", "--destination-port":
			// A bare destination-port match (as in `-p udp --dport 5353`).
			if not {
				return nil, fmt.Errorf("a negated port is not supported")
			}
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("invalid dport parameter")
			}
			pr, perr := ParsePortRange(tokens[i])
			if perr != nil {
				return nil, perr
			}
			if pr.Start == pr.End {
				r.Port = pr.Start
			} else {
				r.Ports = []PortRange{pr}
			}
		case "-i", "--in-interface":
			if not {
				return nil, fmt.Errorf("a negated interface match is not supported")
			}
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("invalid in-interface parameter")
			}
			r.InInterface = tokens[i]
		case "-o", "--out-interface":
			if not {
				return nil, fmt.Errorf("a negated interface match is not supported")
			}
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("invalid out-interface parameter")
			}
			r.OutInterface = tokens[i]
		case "-j", "--jump":
			// Negation is unsupported on this parameter.
			if not {
				return nil, fmt.Errorf("negation is defined for jump, which our limited rule structure does not support")
			}

			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("invalid jump parameter")
			}

			// Parse the valid options.
			switch tokens[i] {
			case "DROP":
				r.Action = Drop
			case "REJECT":
				r.Action = Reject
				// The Rule model carries no reject type, so a `--reject-with` detail is
				// consumed and a rewrite re-emits a plain REJECT (iptables' default
				// icmp-port-unreachable). Rejecting the line instead would leave common
				// stock rules (RHEL's icmp-host-prohibited REJECT) foreign and
				// unmanageable, which costs more than the reject-code drift.
				if i+2 < len(tokens) {
					if tokens[i+1] == "--reject-with" {
						i += 2
					}
				}
			case "ACCEPT":
				r.Action = Accept
			case "LOG":
				// A LOG target is non-terminal: a logged rule is written as a
				// LOG line followed by the action line, coalesced on read. This
				// line contributes only the Log flag and prefix.
				r.Log = true
				for i+1 < len(tokens) {
					if tokens[i+1] == "--log-prefix" && i+2 < len(tokens) {
						r.LogPrefix = tokens[i+2]
						i += 2
					} else if tokens[i+1] == "--log-level" && i+2 < len(tokens) {
						i += 2
					} else {
						break
					}
				}
			default:
				return nil, fmt.Errorf("unsupported jump option: %s", tokens[i])
			}
		case "-m", "--match":
			// Negation is unsupported on this parameter (the set match negates
			// internally, after `-m set`, so it is handled inside its case).
			if not {
				return nil, fmt.Errorf("negation is defined for match, which our limited rule structure does not support")
			}

			// Verify options are set.
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("invalid match parameter")
			}

			// Parse the valid options.
			switch tokens[i] {
			case "set":
				// -m set [!] --match-set <name> src|dst names an ipset in place of an
				// address; the optional `!` negates it. A combined `src,dst` flag
				// matches on both, which the Rule model (one set per direction) cannot
				// represent, so it is rejected.
				i++
				setNot := false
				if i < len(tokens) && tokens[i] == "!" {
					setNot = true
					i++
				}
				if i+2 >= len(tokens) || tokens[i] != "--match-set" {
					return nil, fmt.Errorf("unsupported set match")
				}
				name := tokens[i+1]
				dir := tokens[i+2]
				i += 2
				if setNot {
					name = "!" + name
				}
				switch dir {
				case "src":
					r.Source = name
				case "dst":
					r.Destination = name
				default:
					return nil, fmt.Errorf("unsupported set match direction: %s", dir)
				}
			case "comment":
				if i+2 >= len(tokens) {
					return nil, fmt.Errorf("invalid match parameter")
				}
				if tokens[i+1] != "--comment" {
					return nil, fmt.Errorf("invalid match parameter")
				}
				i += 2
				// Capture the comment text. The caller strips it when it is the
				// configured prefix rather than a user-supplied label.
				r.Comment = tokens[i]
			case "conntrack":
				// Only the conntrack state option is modeled.
				if i+2 >= len(tokens) || tokens[i+1] != "--ctstate" {
					return nil, fmt.Errorf("unsupported conntrack match")
				}
				i += 2
				state, serr := ParseConnState(tokens[i])
				if serr != nil {
					return nil, serr
				}
				r.State = state
			case "state":
				// Legacy state match: -m state --state NEW,ESTABLISHED.
				if i+2 >= len(tokens) || tokens[i+1] != "--state" {
					return nil, fmt.Errorf("unsupported state match")
				}
				i += 2
				state, serr := ParseConnState(tokens[i])
				if serr != nil {
					return nil, serr
				}
				r.State = state
			case "limit":
				// -m limit --limit N/unit [--limit-burst B]
				if i+2 >= len(tokens) || tokens[i+1] != "--limit" {
					return nil, fmt.Errorf("unsupported limit match")
				}
				i += 2
				rate, unit, rerr := parseRateToken(tokens[i])
				if rerr != nil {
					return nil, rerr
				}
				rl := &RateLimit{Rate: rate, Unit: unit}
				if i+2 < len(tokens) && tokens[i+1] == "--limit-burst" {
					b, berr := strconv.ParseUint(tokens[i+2], 10, 32)
					if berr != nil {
						return nil, fmt.Errorf("invalid limit burst %q", tokens[i+2])
					}
					rl.Burst = uint(b)
					i += 2
				}
				// Legacy (xtables) iptables prints a default --limit-burst of 5 on
				// every -m limit match; treat it as unset so a Burst-0 rule still
				// matches on a legacy host (an explicit 5 collapses to 0 too).
				if rl.Burst == 5 {
					rl.Burst = 0
				}
				r.RateLimit = rl
			case "connlimit":
				// -m connlimit --connlimit-above N [--connlimit-mask M]
				if i+2 >= len(tokens) || tokens[i+1] != "--connlimit-above" {
					return nil, fmt.Errorf("unsupported connlimit match")
				}
				i += 2
				n, nerr := strconv.ParseUint(tokens[i], 10, 32)
				if nerr != nil {
					return nil, fmt.Errorf("invalid connlimit %q", tokens[i])
				}
				// The default mask (32/128) counts per source; an explicit mask
				// of 0 counts globally.
				cl := &ConnLimit{Count: uint(n), PerSource: true}
				if i+2 < len(tokens) && tokens[i+1] == "--connlimit-mask" {
					if tokens[i+2] == "0" {
						cl.PerSource = false
					}
					i += 2
				}
				// iptables-save always appends the counting key (--connlimit-saddr
				// by default, or --connlimit-daddr) after the match; consume it so
				// the trailing flag does not fail the parse and drop the whole rule.
				if i+1 < len(tokens) && (tokens[i+1] == "--connlimit-saddr" || tokens[i+1] == "--connlimit-daddr") {
					i++
				}
				r.ConnLimit = cl
			case "icmp", "icmp6":
				// -m icmp --icmp-type N / -m icmp6 --icmpv6-type N. The type
				// qualifier is optional; a bare match just selects the module.
				v6 := tokens[i] == "icmp6"
				typeFlag := "--icmp-type"
				if v6 {
					typeFlag = "--icmpv6-type"
				}
				if i+2 < len(tokens) && tokens[i+1] == typeFlag {
					i += 2
					// iptables-save spells a type-with-code as `type/code` (e.g.
					// `3/1`); the Rule model carries only the type, so drop a trailing
					// `/code` before resolving rather than failing the whole rule.
					typeTok := tokens[i]
					if slash := strings.IndexByte(typeTok, '/'); slash >= 0 {
						typeTok = typeTok[:slash]
					}
					n, ok := parseICMPTypeFamily(typeTok, v6)
					if !ok {
						return nil, fmt.Errorf("invalid icmp type %q", tokens[i])
					}
					r.ICMPType = Ptr(n)
				}
			case "multiport":
				// -m multiport --dports/--sports 80,443,1000:2000. `--ports`/`--port`
				// means source OR destination port, which the model cannot hold —
				// mapping it onto one side would silently drop the other half on a
				// re-marshal — so such a line stays foreign.
				if i+2 >= len(tokens) {
					return nil, fmt.Errorf("invalid multiport match")
				}
				switch tokens[i+1] {
				case "--dports", "--dport", "--sports", "--sport":
				default:
					return nil, fmt.Errorf("unsupported multiport option: %s", tokens[i+1])
				}
				src := strings.HasPrefix(tokens[i+1], "--s")
				i += 2
				specs, perr := iptParsePorts(tokens[i])
				if perr != nil {
					return nil, perr
				}
				if src {
					if len(specs) == 1 && specs[0].Start == specs[0].End {
						r.SourcePort = specs[0].Start
					} else {
						r.SourcePorts = specs
					}
				} else {
					if len(specs) == 1 && specs[0].Start == specs[0].End {
						r.Port = specs[0].Start
					} else {
						r.Ports = specs
					}
				}
			case "tcp":
				// Reject an unknown protocol token.
				if r.Proto == UDP {
					return nil, fmt.Errorf("specifying TCP options for UDP")
				}

				// Verify options are set.
				i++
				if i >= len(tokens) {
					return nil, fmt.Errorf("invalid match parameter")
				}

				// Parse options.
			tcpTokenLoop:
				for ; i < len(tokens); i++ {
					switch tokens[i] {
					case "!", "--syn", "--tcp-option":
						return nil, fmt.Errorf("invalid match parameter")
					case "--source-port", "--sport":
						i++
						if i >= len(tokens) {
							return nil, fmt.Errorf("invalid match parameter")
						}

						// Parse port (iptables-save renders a contiguous range as lo:hi).
						pr, err := ParsePortRange(tokens[i])
						if err != nil {
							return nil, fmt.Errorf("the port argument %s is invalid", tokens[i])
						}
						if pr.Start == pr.End {
							r.SourcePort = pr.Start
						} else {
							r.SourcePorts = []PortRange{pr}
						}
					case "--destination-port", "--dport":
						i++
						if i >= len(tokens) {
							return nil, fmt.Errorf("invalid match parameter")
						}

						// Parse port (iptables-save renders a contiguous range as lo:hi).
						pr, err := ParsePortRange(tokens[i])
						if err != nil {
							return nil, fmt.Errorf("the port argument %s is invalid", tokens[i])
						}
						if pr.Start == pr.End {
							r.Port = pr.Start
						} else {
							r.Ports = []PortRange{pr}
						}
					default:
						i--
						break tcpTokenLoop
					}
				}
			case "udp", "sctp":
				// SCTP carries ports like UDP and iptables-save spells its port
				// match module `-m sctp`, so it shares this branch.
				// Reject an unknown protocol token.
				if r.Proto == TCP {
					return nil, fmt.Errorf("specifying UDP options for TCP")
				}

				// Verify options are set.
				i++
				if i >= len(tokens) {
					return nil, fmt.Errorf("invalid match parameter")
				}

				// Parse options.
			udpTokenLoop:
				for ; i < len(tokens); i++ {
					switch tokens[i] {
					case "!":
						// A negated match cannot be represented.
						return nil, fmt.Errorf("invalid match parameter")
					case "--source-port", "--sport":
						i++
						if i >= len(tokens) {
							return nil, fmt.Errorf("invalid match parameter")
						}

						// Parse port (iptables-save renders a contiguous range as lo:hi).
						pr, err := ParsePortRange(tokens[i])
						if err != nil {
							return nil, fmt.Errorf("the port argument %s is invalid", tokens[i])
						}
						if pr.Start == pr.End {
							r.SourcePort = pr.Start
						} else {
							r.SourcePorts = []PortRange{pr}
						}
					case "--destination-port", "--dport":
						i++
						if i >= len(tokens) {
							return nil, fmt.Errorf("invalid match parameter")
						}

						// Parse port (iptables-save renders a contiguous range as lo:hi).
						pr, err := ParsePortRange(tokens[i])
						if err != nil {
							return nil, fmt.Errorf("the port argument %s is invalid", tokens[i])
						}
						if pr.Start == pr.End {
							r.Port = pr.Start
						} else {
							r.Ports = []PortRange{pr}
						}
					default:
						i--
						break udpTokenLoop
					}
				}
			default:
				return nil, fmt.Errorf("unsupported match option: %s", tokens[i])
			}
		default:
			return nil, fmt.Errorf("unsupported option: %s", tokens[i])
		}

		// The token consumed any pending negation; clear it for the next one.
		not = false
	}

	// If no action provided, error — unless this is a LOG-only line (the log
	// half of a logged rule), which carries the Log flag but no terminal action.
	if r.Action == ActionInvalid && !r.Log {
		return nil, fmt.Errorf("no valid action was provided")
	}
	return
}

// parseLiveRules decodes counter-annotated `iptables-save -c` output into the
// rules the kernel's filter chains hold. iptables writes a rule as the same
// rulespec it stores, so there is no product framing to undo here — the rulespec
// parser takes each row as it stands, and rejects the chains this backend does
// not report. A LOG line and its action line still pair up into the one logged
// rule the save file reports (see decodeLiveRows).
func (f *IPTables) parseLiveRules(out []string, fam Family) []*Rule {
	return decodeLiveRows(out, func(row liveRow) (*Rule, bool) {
		r, err := unmarshalIPTablesRule(row.line, fam)
		if err != nil {
			return nil, false
		}
		return r, true
	})
}

// mergeLiveCounters copies the kernel's packet/byte counters onto the
// file-parsed rules. The save files carry no counts, so a file edit not yet
// activated by Reload leaves that rule's counters zero.
func (f *IPTables) mergeLiveCounters(ctx context.Context, rules []*Rule, fam Family) {
	// Each save file holds one family, so its rules are the ones that family's
	// live ruleset can account for.
	targets := countableRules(rules, fam)
	if len(targets) == 0 {
		return
	}
	applyLiveCounters(targets, f.parseLiveRules(liveSaveLines(ctx, fam), fam))
}

// parseNATTarget parses an iptables NAT target ("addr", "addr:port" or
// "[v6]:port") into its address and port.
func (f *IPTables) parseNATTarget(tok string) (addr string, port uint16) {
	if strings.HasPrefix(tok, "[") {
		if end := strings.Index(tok, "]"); end >= 0 {
			addr = tok[1:end]
			rest := tok[end+1:]
			if strings.HasPrefix(rest, ":") {
				if p, err := strconv.ParseUint(rest[1:], 10, 16); err == nil {
					port = uint16(p)
				}
			}
			return addr, port
		}
	}
	if strings.Count(tok, ":") == 1 {
		host, ps, _ := strings.Cut(tok, ":")
		if p, err := strconv.ParseUint(ps, 10, 16); err == nil {
			return host, uint16(p)
		}
	}
	return tok, 0
}

// UnmarshalNATRule decodes one iptables-save nat line (-A PREROUTING / -A
// POSTROUTING ...) into a NATRule. A line the model cannot hold faithfully — a
// negated interface/protocol/port match, an unknown protocol, an unsupported
// jump, or another chain — is rejected so the raw line stays foreign and is
// preserved verbatim; an OUTPUT-chain DNAT, for example, has no distinct model
// here and would otherwise be relocated to PREROUTING on Restore.
func (f *IPTables) UnmarshalNATRule(spec string, family Family) (*NATRule, error) {
	tokens, err := shlex.Split(spec, true)
	if err != nil {
		return nil, err
	}

	// An iptables-save line may carry a leading [pkts:bytes] counter prefix
	// (iptables-save -c). NATRule has no counter fields, so just strip it before
	// parsing — mirroring the filter parser so a counter-annotated save file's
	// NAT rules are not silently dropped.
	if len(tokens) > 0 && strings.HasPrefix(tokens[0], "[") && strings.HasSuffix(tokens[0], "]") {
		tokens = tokens[1:]
	}
	if len(tokens) < 2 {
		return nil, fmt.Errorf("unexpected token length")
	}

	r := &NATRule{Family: family}
	switch tokens[1] {
	case "PREROUTING", "POSTROUTING":
	default:
		// The NATRule model derives its chain from Kind (DNAT/Redirect => PREROUTING,
		// SNAT/Masquerade => POSTROUTING) and has no direction field, so an OUTPUT-chain
		// nat rule (locally-generated DNAT) cannot be represented distinctly — surfacing
		// it would make MarshalNATRule relocate it to PREROUTING on Restore. Treat the
		// OUTPUT chain (and any other) as foreign: skip it on read so it is left in place
		// verbatim rather than moved (see managedNATChain).
		return nil, fmt.Errorf("not a managed nat chain: %s", tokens[1])
	}

	i := 2
	switch tokens[0] {
	case "-A", "--append":
	case "-I", "--insert":
		if i < len(tokens) {
			if _, err := strconv.Atoi(tokens[i]); err == nil {
				i++
			}
		}
	default:
		return nil, fmt.Errorf("unsupported command provided")
	}

	not := false
	for ; i < len(tokens); i++ {
		switch tokens[i] {
		case "!":
			not = true
			continue
		case "-s", "--source":
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("invalid source parameter")
			}
			if not {
				r.Source = "!" + tokens[i]
			} else {
				r.Source = tokens[i]
			}
		case "-d", "--destination":
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("invalid destination parameter")
			}
			if not {
				r.Destination = "!" + tokens[i]
			} else {
				r.Destination = tokens[i]
			}
		case "-i", "--in-interface", "-o", "--out-interface":
			// Interface, protocol and port carry no negated form in the model, so
			// a `!` here must reject the line — reading `! -o docker0` as a plain
			// interface match would invert the rule's meaning (Docker's stock
			// masquerade rule is exactly this shape).
			if not {
				return nil, fmt.Errorf("negated interface match is not modeled")
			}
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("invalid interface parameter")
			}
			r.Interface = tokens[i]
		case "-p", "--protocol":
			if not {
				return nil, fmt.Errorf("negated protocol match is not modeled")
			}
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("invalid protocol parameter")
			}
			proto := GetProtocol(tokens[i])
			if proto == ProtocolAny {
				// An unknown protocol token must not silently widen to a
				// match-every-protocol rule a Restore would re-marshal without -p.
				return nil, fmt.Errorf("unsupported protocol: %s", tokens[i])
			}
			r.Proto = proto
		case "--dport", "--destination-port":
			if not {
				return nil, fmt.Errorf("negated port match is not modeled")
			}
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("invalid dport parameter")
			}
			pr, perr := ParsePortRange(tokens[i])
			if perr != nil {
				return nil, perr
			}
			if pr.Start == pr.End {
				r.Port = pr.Start
			} else {
				r.Ports = []PortRange{pr}
			}
		case "-m", "--match":
			if not {
				return nil, fmt.Errorf("negated match is not modeled")
			}
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("invalid match parameter")
			}
			switch tokens[i] {
			case "set":
				// -m set [!] --match-set <name> src|dst names an ipset in place of an
				// address (see the filter parser).
				i++
				setNot := false
				if i < len(tokens) && tokens[i] == "!" {
					setNot = true
					i++
				}
				if i+2 >= len(tokens) || tokens[i] != "--match-set" {
					return nil, fmt.Errorf("unsupported set match")
				}
				name := tokens[i+1]
				dir := tokens[i+2]
				i += 2
				if setNot {
					name = "!" + name
				}
				switch dir {
				case "src":
					r.Source = name
				case "dst":
					r.Destination = name
				default:
					return nil, fmt.Errorf("unsupported set match direction: %s", dir)
				}
			case "comment":
				if i+2 >= len(tokens) || tokens[i+1] != "--comment" {
					return nil, fmt.Errorf("invalid match parameter")
				}
				i += 2
				// A NAT rule carries no user comment, only the prefix tag; its
				// presence marks the rule as one this library tagged.
				if _, hasPrefix := prefixedComment(f.rulePrefix, tokens[i]); hasPrefix {
					r.HasPrefix = true
				}
			case "tcp", "udp", "sctp":
				if i+2 < len(tokens) && (tokens[i+1] == "--dport" || tokens[i+1] == "--destination-port") {
					i += 2
					pr, perr := ParsePortRange(tokens[i])
					if perr != nil {
						return nil, perr
					}
					if pr.Start == pr.End {
						r.Port = pr.Start
					} else {
						r.Ports = []PortRange{pr}
					}
				}
			case "multiport":
				if i+2 >= len(tokens) {
					return nil, fmt.Errorf("invalid multiport match")
				}
				switch tokens[i+1] {
				case "--dports", "--dport":
				default:
					// `--ports`/`--port` means source OR destination port; mapping it
					// onto the destination fields would silently drop the source half
					// on a re-marshal, so the line stays foreign.
					return nil, fmt.Errorf("unsupported multiport option: %s", tokens[i+1])
				}
				i += 2
				specs, perr := iptParsePorts(tokens[i])
				if perr != nil {
					return nil, perr
				}
				if len(specs) == 1 && specs[0].Start == specs[0].End {
					r.Port = specs[0].Start
				} else {
					r.Ports = specs
				}
			default:
				return nil, fmt.Errorf("unsupported match option: %s", tokens[i])
			}
		case "-j", "--jump":
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("invalid jump parameter")
			}
			switch tokens[i] {
			case "DNAT":
				r.Kind = DNAT
				if i+2 < len(tokens) && tokens[i+1] == "--to-destination" {
					i += 2
					r.ToAddress, r.ToPort = f.parseNATTarget(tokens[i])
				}
			case "REDIRECT":
				r.Kind = Redirect
				if i+2 < len(tokens) && tokens[i+1] == "--to-ports" {
					i += 2
					p, perr := strconv.ParseUint(tokens[i], 10, 16)
					if perr != nil {
						return nil, fmt.Errorf("invalid redirect port %q", tokens[i])
					}
					r.ToPort = uint16(p)
				}
			case "SNAT":
				r.Kind = SNAT
				if i+2 < len(tokens) && tokens[i+1] == "--to-source" {
					i += 2
					r.ToAddress, r.ToPort = f.parseNATTarget(tokens[i])
				}
			case "MASQUERADE":
				r.Kind = Masquerade
			default:
				return nil, fmt.Errorf("unsupported nat target: %s", tokens[i])
			}
		default:
			return nil, fmt.Errorf("unsupported option: %s", tokens[i])
		}
		not = false
	}

	if r.Kind == NATInvalid {
		return nil, fmt.Errorf("no nat action was provided")
	}
	if r.Family == FamilyAny {
		r.Family = r.impliedFamily()
	}
	return r, nil
}

// UnmarshalRule decodes an iptables rulespec into a firewall rule.
func (f *IPTables) UnmarshalRule(ruleSpec string, family Family) (*Rule, error) {
	r, err := unmarshalIPTablesRule(ruleSpec, family)
	if err != nil {
		return nil, err
	}
	// The shared parser is prefix-agnostic; strip this backend's configured
	// prefix so only the user-facing comment surfaces, and record whether the
	// prefix was present so callers can tell our rules from foreign ones. The
	// comment is not part of rule identity, so this does not affect dedup or
	// removal comparisons. An empty prefix gives us no namespace, so no rule
	// reports HasPrefix.
	text, hasPrefix := prefixedComment(f.rulePrefix, r.Comment)
	r.Comment = text
	r.HasPrefix = hasPrefix
	return r, nil
}

// iptSameMatch reports whether two rules have identical match fields ignoring
// their action and logging flags. It is used to pair a LOG line with the action
// line that follows it.
func iptSameMatch(a, b *Rule) bool {
	ac, bc := *a, *b
	ac.Log, bc.Log = false, false
	ac.LogPrefix, bc.LogPrefix = "", ""
	ac.Action, bc.Action = Accept, Accept
	return ac.EqualBase(&bc, true)
}

// logPartner reports whether cur and next are the two physical lines that
// iptables needs to express one logical "log and act" rule. The library models
// logging as a flag on a rule that also has a terminal action (e.g. drop and
// log inbound TCP :22), but iptables cannot: its LOG target is non-terminal —
// the packet keeps traversing the chain after being logged — so the rule must
// be written as two lines with identical match fields, a LOG line followed by
// the action line:
//
//	iptables -A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -j LOG --log-prefix "fw: "
//	iptables -A INPUT -s 10.0.0.0/8 -p tcp --dport 22 -j DROP
//
// cur is the standalone LOG line (Log set, no terminal action) and next is its
// action partner: same match fields ignoring the log flags and action, which
// iptSameMatch verifies. When it matches, callers fold the pair back into the
// single logged rule GetRules reports (see mergeLogPair). next may be nil when
// cur is the last rule in the sequence, in which case the LOG line is an orphan
// and this returns false. Callers must also confirm the two lines are physically
// adjacent (no line between them): a LOG and an action separated by an unmodeled
// foreign line are not one rule, and pairing them would synthesize a logical
// rule no removal path could locate. It is the shared predicate behind
// coalesceLoggedRules (native iptables-save reads) and hookScript.scanGroups
// (CSF/APF hook reads), so the pairing behaves identically in both.
func logPartner(cur, next *Rule) bool {
	return cur != nil && cur.Action == ActionInvalid && cur.Log &&
		next != nil && next.Action != ActionInvalid && iptSameMatch(cur, next)
}

// mergeLogPair folds a standalone LOG line's prefix into its action partner,
// producing the single logical rule GetRules reports for a logged rule. The
// action line supplies the terminal action and match fields; only Log and
// LogPrefix are carried over from the LOG line. Pass a pair logPartner accepted.
func mergeLogPair(logLine, action *Rule) *Rule {
	merged := *action
	merged.Log = true
	merged.LogPrefix = logLine.LogPrefix
	return &merged
}

// ruleLineBody strips an optional leading [pkts:bytes] counter token from a
// trimmed iptables-save line and returns the remaining rule body. iptables-save
// -c annotates each rule with counters; the library never emits them, but the
// file-rewrite paths must still recognise a counter-prefixed line as a rule when
// operating on a pre-existing save file (matching the read parser, which strips
// the same prefix). A line without a counter is returned unchanged.
func (f *IPTables) ruleLineBody(line string) string {
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "[") {
		if i := strings.IndexByte(line, ']'); i >= 0 {
			return strings.TrimSpace(line[i+1:])
		}
	}
	return line
}

// --- save-file scanning ------------------------------------------------------

// iptGroup is one logical span of an iptables-save file: a rule line together
// with the rule it encodes — a LOG line and the action line under it count as
// one group — or any other line on its own. It is the iptables counterpart of
// the hook's hookGroup, and every read and rewrite path streams the file through
// it, so table scoping, LOG-pair coalescing and the per-chain numbering GetRules
// reports are each defined in exactly one place.
type iptGroup struct {
	// raw preserves the original lines verbatim, so a rewrite copies user
	// formatting through and a removal drops a logged rule's two lines together.
	raw []string
	// table is the table the group's lines sit in ("filter", "nat", ...), or ""
	// outside any table. A table header belongs to the table it opens and a
	// COMMIT to the table it closes.
	table string
	// chain is the chain a rule line targets, "" for every other line.
	chain string
	// rule is the filter rule the group encodes, nil when it encodes none: a
	// line outside *filter, one the model cannot hold, one a container runtime
	// owns, an orphan LOG line, or a line that is not a rule at all.
	rule *Rule
	// nat is the nat rule the group encodes, on the same terms as rule.
	nat *NATRule
	// number is the 1-based position within its chain that rule or nat occupies,
	// mirroring the Number GetRules and GetNATRules report, or 0 when the group
	// begins no logical rule.
	number int
	// commit marks the group as its table's COMMIT line.
	commit bool
}

// chainOf returns the chain named by an iptables-save rule body such as
// "-A FORWARD -j ACCEPT" (the token after the -A/-I/-R command), or "" when the
// body has no chain token. It lets the file-rewrite paths tell an INPUT/OUTPUT
// rule the library manages from a rule in a chain it does not model.
func (f *IPTables) chainOf(body string) string {
	fields := strings.Fields(body)
	if len(fields) >= 2 {
		return fields[1]
	}
	return ""
}

// ruleLineChain returns the chain an iptables-save rule line targets, or "" when
// the line is not a rule line. It gates chainOf on the commands iptables-save
// emits (-A) and those a hand-edited file may carry (-I, -R), so a chain
// declaration such as ":INPUT ACCEPT [0:0]" is not read as a rule in a chain
// named ACCEPT. Every ignorable line — blank, comment, table header, chain
// declaration, COMMIT — fails the same test, which is why the scanner needs no
// separate ignorable-line check.
func (f *IPTables) ruleLineChain(body string) string {
	switch {
	case strings.HasPrefix(body, "-A "), strings.HasPrefix(body, "-I "), strings.HasPrefix(body, "-R "):
		return f.chainOf(body)
	}
	return ""
}

// scanSaveGroups streams an iptables-save file to fn as logical groups in file
// order, emitting every line exactly once so a caller can rewrite the file in a
// single pass. A rule line is parsed only in the table that models it — *filter
// into a Rule, *nat into a NATRule — so an INPUT rule sitting in *nat or *mangle
// is never mistaken for a filter rule.
//
// A LOG line pairs with the action line PHYSICALLY under it and nothing else:
// iptables writes a logged rule as two lines, and a pair separated by any other
// line (a comment, a rule the model cannot hold, a rule in another chain) is not
// one rule. Pairing across such a line would report through GetRules a logged
// rule that no removal could ever locate, so the scan treats adjacency as the
// whole test — the same rule hookScript.scanGroups applies in the hook. An
// orphan LOG line is invisible to GetRules and so begins no logical rule; its
// group still streams through with rule left nil.
//
// A nil fd scans as an empty file. An error from fn stops the scan.
func (f *IPTables) scanSaveGroups(fd *os.File, family Family, fn func(g iptGroup) error) error {
	if fd == nil {
		return nil
	}
	table := ""
	// counts holds each chain's logical-rule count so far, keyed by table and
	// chain because the same built-in chain name exists in several tables.
	counts := map[string]int{}
	next := func(t, chain string) int {
		k := t + " " + chain
		counts[k]++
		return counts[k]
	}
	// held buffers a parsed LOG line until the following line decides whether it
	// is that line's action partner; emitHeld flushes it as the orphan it turned
	// out to be, with its rule cleared.
	var held *iptGroup
	emitHeld := func() error {
		if held == nil {
			return nil
		}
		g := *held
		held = nil
		g.rule = nil
		return fn(g)
	}

	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)

		// A table header opens its table and a COMMIT closes it. Both end any
		// pending LOG pairing, since a partner must sit on the very next line.
		if strings.HasPrefix(line, "*") || line == "COMMIT" {
			if err := emitHeld(); err != nil {
				return err
			}
			g := iptGroup{raw: []string{raw}, table: table}
			if line == "COMMIT" {
				g.commit = true
				table = ""
			} else {
				table = strings.TrimPrefix(line, "*")
				g.table = table
			}
			if err := fn(g); err != nil {
				return err
			}
			continue
		}

		g := iptGroup{raw: []string{raw}, table: table, chain: f.ruleLineChain(f.ruleLineBody(line))}

		switch {
		case g.chain == "":
			// Not a rule line; it passes through and breaks any pending pairing.
		case table == "filter":
			rule, err := f.UnmarshalRule(line, family)
			// A line the model cannot hold, and one a container runtime owns, are
			// both invisible to GetRules: each keeps its physical slot but begins no
			// logical rule, so it takes no Number and no LOG line pairs across it.
			if err != nil || rule.isContainerRuntime() {
				break
			}
			// Fold a held LOG line together with the action line directly under it
			// into the one logged rule they encode, numbered at the LOG line.
			if held != nil && logPartner(held.rule, rule) {
				pair := *held
				held = nil
				pair.raw = append(pair.raw, raw)
				pair.rule = mergeLogPair(pair.rule, rule)
				pair.number = next(pair.table, pair.chain)
				if err := fn(pair); err != nil {
					return err
				}
				continue
			}
			// Not a partner, so any held LOG line is an orphan; flush it before
			// this line.
			if err := emitHeld(); err != nil {
				return err
			}
			// Buffer a bare LOG line (Log set, no terminal action) against the next
			// line; every other rule is complete on its own.
			if rule.Action == ActionInvalid && rule.Log {
				g.rule = rule
				held = &g
				continue
			}
			g.rule = rule
			g.number = next(table, g.chain)
		case table == "nat":
			nr, err := f.UnmarshalNATRule(line, family)
			// As in *filter, a line the model cannot hold and a container runtime's
			// own translation are both invisible to GetNATRules and take no Number.
			if err != nil || nr.isContainerRuntime() {
				break
			}
			g.nat = nr
			g.number = next(table, g.chain)
		}

		if err := emitHeld(); err != nil {
			return err
		}
		if err := fn(g); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	return emitHeld()
}

// scanSaveFile opens path and streams it through scanSaveGroups, for the read
// paths that have no rewrite to stage. A save file this host manages is expected
// to exist, so an open error is reported rather than scanned as empty.
func (f *IPTables) scanSaveFile(path string, family Family, fn func(g iptGroup) error) error {
	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = fd.Close() }()
	return f.scanSaveGroups(fd, family, fn)
}

// parseFilterFile reads a family's iptables-save file and returns its filter
// rules as logical rules, coalescing each LOG line with the action line that
// follows it. Lines the model cannot hold — nat rules, custom chains, unmodeled
// foreign matches — are skipped by the scan (see scanSaveGroups).
func (f *IPTables) parseFilterFile(path string, family Family) ([]*Rule, error) {
	// The scan already scopes to the table that models each rule and drops the
	// lines GetRules cannot report, so every filter group carrying a rule is one
	// to return. GetRules assigns Number once both save files are read; the other
	// callers use the result only for dedup and never read Number.
	var out []*Rule
	err := f.scanSaveFile(path, family, func(g iptGroup) error {
		if g.table == "filter" && g.rule != nil {
			out = append(out, g.rule)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetRules returns the existing filter rules from the zone.
func (f *IPTables) GetRules(ctx context.Context, zoneName string) (rules []*Rule, err error) {
	// Each save-file line is its own rule: iptables pins one family (by which file
	// holds it), one transport and one direction (by chain) per line, so nothing here
	// spans two of anything and nothing is collapsed.
	v4, err := f.parseFilterFile(f.IP4Path, IPv4)
	if err != nil {
		return nil, fmt.Errorf("failed to read iptables file for IPv4: %s", err)
	}
	// An IPv4-only host has no v6 file to read; it reports IPv4 rows alone.
	var v6 []*Rule
	if f.managesIPv6() {
		if v6, err = f.parseFilterFile(f.IP6Path, IPv6); err != nil {
			return nil, fmt.Errorf("failed to read iptables file for IPv6: %s", err)
		}
	}

	// Number each family's chains independently: the two families are separate
	// rulesets in separate save files, so an IPv6 rule's InsertRule/MoveRule position
	// counts only the ip6tables chain it lives in. Numbering the concatenation instead
	// would offset every IPv6 rule by the IPv4 chain's length.
	numberByDirection(v4)
	numberByDirection(v6)

	// The save files carry no packet/byte counters — the kernel does — so merge
	// them from the live ruleset (RuleCounters).
	f.mergeLiveCounters(ctx, v4, IPv4)
	f.mergeLiveCounters(ctx, v6, IPv6)

	rules = append(rules, v4...)
	rules = append(rules, v6...)
	return
}

// checkFamilyManaged rejects a write pinned to a family this host does not
// manage. Only IPv6 can be unmanaged, and only on an IPv4-only host; the error
// wraps ErrUnsupported so a caller can tell "this host cannot express it" from a
// malformed rule. A FamilyAny write is not rejected: it narrows to the IPv4 file,
// matching how the other backends behave when their IPv6 handling is off.
func (f *IPTables) checkFamilyManaged(fam Family) error {
	if fam == IPv6 && !f.managesIPv6() {
		return fmt.Errorf("iptables does not manage IPv6 on this host, so it cannot manage IPv6 rules: %w", ErrUnsupported)
	}
	return nil
}

// editRuleFiles applies one logical-rule edit to each family save file the
// rule touches. The rule is fanned out once into its concrete cells — the
// DirAny direction split times the TCPUDP protocol split, each cell one
// save-file logical rule — and op rewrites each file's parsed groups covering
// every cell in a single pass. Each changed file is staged first and committed
// only once every file has staged, so a rule spanning families, directions or
// protocols is never left half-applied by a failure part-way through.
func (f *IPTables) editRuleFiles(r *Rule, op func(groups []iptGroup, cells []*Rule) ([]iptGroup, bool, error)) error {
	// Fan the merged axes out into concrete cells. Only the direction decides
	// which chain a cell's lines land in; a TCPUDP split lands a tcp and a udp
	// line at the same spot, and the family split selects whole files below.
	var cells []*Rule
	for _, sub := range expandDirections(r) {
		cells = append(cells, expandProtocols(sub)...)
	}

	// Resolve the family files, letting an ICMP/ICMPv6 protocol pin the family:
	// `-p icmp` belongs only in the IPv4 file and `-p icmpv6` only in the IPv6
	// file. An IPv4-only host contributes no v6 path, so a FamilyAny rule
	// narrows to the IPv4 file and a concrete-IPv6 rule resolves to no file at
	// all — the write entry points reject that shape up front through
	// checkFamilyManaged, leaving removals here as no-ops.
	family := r.impliedFamily()
	var paths []string
	if family == IPv4 || family == FamilyAny {
		paths = append(paths, f.IP4Path)
	}
	if (family == IPv6 || family == FamilyAny) && f.managesIPv6() {
		paths = append(paths, f.IP6Path)
	}

	// Rewrite and stage every file first, committing nothing until all have
	// staged; a failure part-way discards the staged temp files.
	var staged []*atomicFile
	abort := func() {
		for _, s := range staged {
			s.Abort()
		}
	}
	for _, path := range paths {
		var groups []iptGroup
		if err := f.scanSaveFile(path, FamilyAny, func(g iptGroup) error {
			groups = append(groups, g)
			return nil
		}); err != nil {
			abort()
			return err
		}
		out, changed, err := op(groups, cells)
		if err != nil {
			abort()
			return err
		}
		// An unchanged file needs no rewrite.
		if !changed {
			continue
		}
		af, err := newAtomicFile(path, 0644)
		if err != nil {
			abort()
			return err
		}
		for _, g := range out {
			for _, l := range g.raw {
				_, _ = fmt.Fprintln(af, l)
			}
		}
		staged = append(staged, af)
	}

	// Commit each staged file into place, preserving its mode and ownership.
	for _, s := range staged {
		if err := s.Commit(); err != nil {
			return fmt.Errorf("failed to move new firewall rules into place: %s", err)
		}
	}
	return nil
}

// addrArgs encodes a source or destination match. dir is "src" or "dst". An
// IP/CIDR uses `-s`/`-d`; a non-address token names an ipset, matched with
// `-m set --match-set <name> <dir>`. A leading "!" negation is emitted before the
// match in both cases.
func (f *IPTables) addrArgs(addr, dir string) []string {
	neg, bare := splitAddrNeg(addr)
	if isSetRef(addr) {
		// The set match negates internally: `-m set ! --match-set name dir`.
		out := []string{"-m", "set"}
		if neg {
			out = append(out, "!")
		}
		return append(out, "--match-set", bare, dir)
	}
	// An address negates with a leading `!`: `! -s addr`.
	var out []string
	if neg {
		out = append(out, "!")
	}
	flag := "-s"
	if dir == "dst" {
		flag = "-d"
	}
	return append(out, flag, bare)
}

// iptMultiportValue renders port specs for `-m multiport --dports`, using a
// colon for ranges (e.g. "80,443,1000:2000"). The specs are canonicalized
// (sorted, with contiguous/overlapping ranges merged) so that two rules the model
// considers Equal — port-set order and coalescing are not part of rule identity —
// always render to the same string. Backends that match on the exact marshalled
// line (the CSF/APF hook script) rely on this to stay idempotent.
func iptMultiportValue(specs []PortRange) string {
	specs = coalescePortRanges(specs)
	parts := make([]string, len(specs))
	for i, pr := range specs {
		if pr.Start == pr.End {
			parts[i] = strconv.FormatUint(uint64(pr.Start), 10)
		} else {
			parts[i] = fmt.Sprintf("%d:%d", pr.Start, pr.End)
		}
	}
	return strings.Join(parts, ",")
}

// quoteCommentToken double-quotes v for a comment/log-prefix token in an
// iptables-save-format rule line, escaping only backslash and double-quote so it
// round-trips through the shlex.Split reader (strconv.Quote is unusable: its
// \t/\n/\uXXXX escapes are not un-escaped by shlex). A literal newline or
// carriage return is rejected outright, since it would split the one-line rule.
func (f *IPTables) quoteCommentToken(v string) (string, error) {
	if strings.ContainsAny(v, "\n\r") {
		return "", fmt.Errorf("a comment cannot contain a newline")
	}
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range v {
		if r == '\\' || r == '"' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	b.WriteByte('"')
	return b.String(), nil
}

// stateValue renders a conntrack state set as an upper-case comma list (e.g.
// "NEW,ESTABLISHED").
func (f *IPTables) stateValue(s ConnState) string {
	names := s.Strings()
	for i, n := range names {
		names[i] = strings.ToUpper(n)
	}
	return strings.Join(names, ",")
}

// validateRule reports whether iptables can express the filter rule, applying
// the universal Rule.validate and then the iptables-specific shape constraints,
// so marshalMatches encodes a rule already known to be expressible.
func (f *IPTables) validateRule(r *Rule) error {
	if err := r.validate(); err != nil {
		return err
	}
	// A TCPUDP rule has no single-line iptables form; it must be fanned out into a
	// tcp row and a udp row before reaching this row-level marshaller. Reaching here
	// with TCPUDP means that fan-out was skipped.
	if err := r.CheckExpandedProtocol(); err != nil {
		return err
	}
	return nil
}

// marshalMatches builds the iptables-save match tokens for a rule (everything
// up to but not including the `-j <target>`), including any rate/connection
// limit and the identifying comment. MarshalRule and the LOG-line encoder share
// it so a logged rule's two lines carry identical match tokens. It is a pure
// encoder: callers run validateRule on the fanned-out cell first.
func (f *IPTables) marshalMatches(r *Rule) ([]string, error) {
	// Start with the APPEND command and the chain (INPUT, OUTPUT or FORWARD).
	parts := []string{}
	switch r.Direction {
	case DirOutput:
		parts = append(parts, "-A", "OUTPUT")
	case DirForward:
		parts = append(parts, "-A", "FORWARD")
	default:
		parts = append(parts, "-A", "INPUT")
	}

	// Add source and destination. A non-address token names an ipset, matched with
	// `-m set --match-set` rather than `-s`/`-d`.
	if r.Source != "" {
		parts = append(parts, f.addrArgs(r.Source, "src")...)
	}
	if r.Destination != "" {
		parts = append(parts, f.addrArgs(r.Destination, "dst")...)
	}

	// Interface match. `-i` is only valid on INPUT and `-o` only on OUTPUT; the
	// FORWARD chain sees both an ingress and an egress interface, so it accepts
	// either. validateRule has already rejected a wrong-side pairing.
	if r.InInterface != "" {
		parts = append(parts, "-i", r.InInterface)
	}
	if r.OutInterface != "" {
		parts = append(parts, "-o", r.OutInterface)
	}

	// Append protocol.
	if r.Proto != ProtocolAny {
		parts = append(parts, "-p", r.Proto.String())
	}

	// An ICMP type match uses the icmp/icmp6 match module.
	if r.Proto.IsICMP() && r.ICMPType != nil {
		if r.Proto == ICMPv6 {
			parts = append(parts, "-m", "icmp6", "--icmpv6-type", strconv.Itoa(int(*r.ICMPType)))
		} else {
			parts = append(parts, "-m", "icmp", "--icmp-type", strconv.Itoa(int(*r.ICMPType)))
		}
	}

	srcSpecs := r.SourcePortSpecs()
	dstSpecs := r.PortSpecs()

	// If source port(s) defined, add them. A concrete protocol is guaranteed above.
	if len(srcSpecs) == 1 && srcSpecs[0].Start == srcSpecs[0].End {
		parts = append(parts, "-m", r.Proto.String(), "--sport", strconv.FormatUint(uint64(srcSpecs[0].Start), 10))
	} else if len(srcSpecs) > 0 {
		parts = append(parts, "-m", "multiport", "--sports", iptMultiportValue(srcSpecs))
	}

	// If destination port(s) defined, add them.
	if len(dstSpecs) == 1 && dstSpecs[0].Start == dstSpecs[0].End {
		parts = append(parts, "-m", r.Proto.String(), "--dport", strconv.FormatUint(uint64(dstSpecs[0].Start), 10))
	} else if len(dstSpecs) > 0 {
		parts = append(parts, "-m", "multiport", "--dports", iptMultiportValue(dstSpecs))
	}

	// Connection-tracking state match.
	if r.State != 0 {
		parts = append(parts, "-m", "conntrack", "--ctstate", f.stateValue(r.State))
	}

	// Rate limit: `-m limit` matches only while under the configured rate.
	if r.RateLimit != nil {
		parts = append(parts, "-m", "limit", "--limit", r.RateLimit.String())
		if r.RateLimit.Burst > 0 {
			parts = append(parts, "--limit-burst", strconv.FormatUint(uint64(r.RateLimit.Burst), 10))
		}
	}

	// Connection limit: `-m connlimit` matches while the tracked count is over
	// the limit. The default mask counts per source; a mask of 0 counts globally.
	if r.ConnLimit != nil {
		parts = append(parts, "-m", "connlimit", "--connlimit-above", strconv.FormatUint(uint64(r.ConnLimit.Count), 10))
		if !r.ConnLimit.PerSource {
			parts = append(parts, "--connlimit-mask", "0")
		}
	}

	// Attach a comment. A user-supplied Comment is carried alongside the
	// configured prefix (prefix + " " + comment) so rules this library creates
	// stay identifiable; with no user comment the prefix alone tags the rule.
	// The comment is not part of the rule identity, so it is ignored when
	// comparing rules.
	comment := combineComment(f.rulePrefix, r.Comment)
	if comment != "" {
		quoted, err := f.quoteCommentToken(comment)
		if err != nil {
			return nil, err
		}
		parts = append(parts, "-m", "comment", "--comment", quoted)
	}

	return parts, nil
}

// MarshalRule encodes a rule as a single iptables-save rulespec ending in its
// action target.
func (f *IPTables) MarshalRule(r *Rule) (string, error) {
	parts, err := f.marshalMatches(r)
	if err != nil {
		return "", err
	}
	parts = append(parts, "-j", strings.ToUpper(r.Action.String()))
	return strings.Join(parts, " "), nil
}

// marshalLogLine encodes the LOG half of a logged rule: the same matches ending
// in a non-terminal LOG target carrying the optional prefix.
func (f *IPTables) marshalLogLine(r *Rule) (string, error) {
	parts, err := f.marshalMatches(r)
	if err != nil {
		return "", err
	}
	parts = append(parts, "-j", "LOG")
	if r.LogPrefix != "" {
		quoted, err := f.quoteCommentToken(r.LogPrefix)
		if err != nil {
			return "", err
		}
		parts = append(parts, "--log-prefix", quoted)
	}
	return strings.Join(parts, " "), nil
}

// marshalRuleLines returns the save-file lines representing r: a LOG line
// followed by the action line when r.Log is set (iptables cannot both log and
// take a terminal action in one rule), otherwise just the action line.
func (f *IPTables) marshalRuleLines(r *Rule) ([]string, error) {
	action, err := f.MarshalRule(r)
	if err != nil {
		return nil, err
	}
	if !r.Log {
		return []string{action}, nil
	}
	logLine, err := f.marshalLogLine(r)
	if err != nil {
		return nil, err
	}
	return []string{logLine, action}, nil
}

// insertRuleGroups returns groups with each cell's line(s) spliced in before
// the first *filter group at reports true for, falling back to the table's
// COMMIT so a placement past a chain's end appends. A cell an equal logical
// rule already covers is left alone rather than duplicated (LOG+action lines
// scan as one group, so a logged rule compares as one unit), which also fills
// in a subset left by an earlier partial edit instead of re-adding whole. It
// is the shared body of AddRule and InsertRule; each passes its own placement
// predicate.
func (f *IPTables) insertRuleGroups(groups []iptGroup, cells []*Rule, at func(g iptGroup, cell *Rule) bool) ([]iptGroup, bool, error) {
	// Validate and encode every cell's line(s) up front: a logged cell is a LOG
	// line plus an action line, and a rejection or marshalling error must change
	// nothing. The check runs per cell rather than on the caller's rule because
	// editRuleFiles has already fanned the merged axes out — a TCPUDP rule is
	// legitimate on the way in and only its concrete halves are expressible.
	lines := make([][]string, len(cells))
	for i, cell := range cells {
		if err := f.validateRule(cell); err != nil {
			return nil, false, err
		}
		ls, err := f.marshalRuleLines(cell)
		if err != nil {
			return nil, false, err
		}
		lines[i] = ls
	}

	// Note the cells the file already holds. With the groups in hand this is a
	// pass over parsed slices, not a second read of the file.
	placed := make([]bool, len(cells))
	for _, g := range groups {
		if g.table != "filter" || g.rule == nil {
			continue
		}
		for i, cell := range cells {
			if !placed[i] && g.rule.EqualBase(cell, true) {
				placed[i] = true
			}
		}
	}

	// Splice each missing cell in ahead of the first group its predicate (or
	// the filter COMMIT fallback) selects.
	out := make([]iptGroup, 0, len(groups)+len(cells))
	changed := false
	for _, g := range groups {
		if g.table == "filter" {
			for i, cell := range cells {
				if !placed[i] && (at(g, cell) || g.commit) {
					out = append(out, iptGroup{raw: lines[i]})
					placed[i] = true
					changed = true
				}
			}
		}
		out = append(out, g)
	}

	// A cell that found no placement point means the file carries no *filter
	// table to hold it.
	for i := range cells {
		if !placed[i] {
			return nil, false, fmt.Errorf("failed to write the new rule to the iptables-save file")
		}
	}
	return out, changed, nil
}

// AddRule adds a rule to the zone. A family-agnostic set-referencing rule is
// pinned to its set's family first, so its line lands only in the save file the
// single-family ipset can match.
func (f *IPTables) AddRule(ctx context.Context, zoneName string, r *Rule) error {
	r, err := resolveSetRefRule(r, f.setRefFamily)
	if err != nil {
		return err
	}
	if err := f.checkFamilyManaged(r.impliedFamily()); err != nil {
		return err
	}
	// Insert before the first rule line of any chain — physically ahead of every
	// rule line in the table, unmodeled lines included — or before the filter
	// table's COMMIT when it holds none yet, so the rule lands at the top of its
	// chain.
	return f.editRuleFiles(r, func(groups []iptGroup, cells []*Rule) ([]iptGroup, bool, error) {
		return f.insertRuleGroups(groups, cells, func(g iptGroup, _ *Rule) bool {
			return g.chain != ""
		})
	})
}

// iptChainForDirection returns the filter chain name (INPUT, OUTPUT or FORWARD)
// a rule of the given direction lives in.
func iptChainForDirection(d Direction) string {
	switch d {
	case DirOutput:
		return "OUTPUT"
	case DirForward:
		return "FORWARD"
	}
	return "INPUT"
}

// InsertRule inserts rule before the given 1-based position in the iptables save
// file. A non-positive position is treated as 1; a position larger than the
// current rule count appends the rule. A family-agnostic set-referencing rule is
// pinned to its set's family first, as in AddRule.
func (f *IPTables) InsertRule(ctx context.Context, zoneName string, position int, r *Rule) error {
	r, err := resolveSetRefRule(r, f.setRefFamily)
	if err != nil {
		return err
	}
	if err := f.checkFamilyManaged(r.impliedFamily()); err != nil {
		return err
	}
	if position <= 0 {
		position = 1
	}
	// Match each cell's target chain by an exact chain-name compare, not a
	// prefix: a foreign chain whose name merely starts with INPUT/OUTPUT (e.g. a
	// firewalld "INPUT_direct" chain) must not be counted, or the 1-based
	// position would diverge from the per-direction numbering GetRules reports.
	// The scan numbered each group as GetRules does — a LOG+action pair is one
	// logical rule holding both its lines, an unmodeled or orphan line is none —
	// so the insert lands at the position GetRules reports and never splits a
	// logged rule's two lines.
	return f.editRuleFiles(r, func(groups []iptGroup, cells []*Rule) ([]iptGroup, bool, error) {
		return f.insertRuleGroups(groups, cells, func(g iptGroup, cell *Rule) bool {
			return g.chain == iptChainForDirection(cell.Direction) && g.number == position
		})
	})
}

// moveCellGroups returns groups with the first group matching cell lifted and
// re-inserted at the 1-based position within its chain, reporting false when no
// group matches. The lifted group holds every line the rule occupies, so a
// logged rule's LOG and action lines move together and a standalone LOG line is
// never dragged along with an unrelated rule.
func (f *IPTables) moveCellGroups(groups []iptGroup, cell *Rule, position int) ([]iptGroup, bool, error) {
	// Lift the first matching rule.
	moved := -1
	for i, g := range groups {
		if g.table == "filter" && g.rule != nil && g.rule.EqualBase(cell, true) {
			moved = i
			break
		}
	}
	if moved < 0 {
		return groups, false, nil
	}
	lifted := groups[moved]
	// The three-index slice forces a copy rather than shifting groups in place.
	rest := append(groups[:moved:moved], groups[moved+1:]...)

	// Re-insert at the requested 1-based position, renumbering the target chain
	// over the post-removal groups: lifting the rule shifted every rule below it
	// up by one, so the numbers the scan stored cannot be reused. Exact
	// chain-name compare, as in InsertRule. A position past the chain's last
	// rule falls through to the table's COMMIT, which appends after that last
	// rule, so no clamp is needed (insertRuleGroups relies on the same fallback).
	expectedChain := iptChainForDirection(cell.Direction)
	out := make([]iptGroup, 0, len(rest)+1)
	inserted := false
	pos := 0
	for _, g := range rest {
		if !inserted && g.table == "filter" {
			if g.chain == expectedChain && g.rule != nil {
				pos++
				if pos == position {
					out = append(out, lifted)
					inserted = true
				}
			}
			if !inserted && g.commit {
				out = append(out, lifted)
				inserted = true
			}
		}
		out = append(out, g)
	}

	if !inserted {
		return nil, false, fmt.Errorf("failed to move the rule in the iptables-save file")
	}
	return out, true, nil
}

// MoveRule moves an existing rule to the given 1-based position within its chain.
func (f *IPTables) MoveRule(ctx context.Context, zoneName string, r *Rule, position int) error {
	if err := f.checkFamilyManaged(r.impliedFamily()); err != nil {
		return err
	}
	if position <= 0 {
		position = 1
	}
	// A merged rule moves cell by cell: each concrete half is lifted and
	// re-inserted at the position within its own chain. A cell the file does not
	// hold is skipped rather than failing the others.
	return f.editRuleFiles(r, func(groups []iptGroup, cells []*Rule) ([]iptGroup, bool, error) {
		changed := false
		for _, cell := range cells {
			out, moved, err := f.moveCellGroups(groups, cell, position)
			if err != nil {
				return nil, false, err
			}
			if moved {
				groups = out
				changed = true
			}
		}
		return groups, changed, nil
	})
}

// removeRuleGroups returns groups with every *filter group matching one of the
// rule's cells dropped, reporting whether any matched. The scan handed back
// whole logical rules, so a logged rule's LOG and action lines are dropped
// together while a standalone LOG line is left where it is, and the
// *nat/*mangle scoping that keeps a foreign nat rule from being removed as if
// it were a filter rule is the scanner's. Every group a cell matches goes in
// the one pass, so a chain holding the same rule twice comes back clean.
func (f *IPTables) removeRuleGroups(groups []iptGroup, cells []*Rule) ([]iptGroup, bool, error) {
	out := make([]iptGroup, 0, len(groups))
	changed := false
	for _, g := range groups {
		matched := false
		if g.table == "filter" && g.rule != nil {
			for _, cell := range cells {
				if g.rule.EqualBase(cell, true) {
					matched = true
					break
				}
			}
		}
		if matched {
			changed = true
			continue
		}
		out = append(out, g)
	}
	return out, changed, nil
}

// RemoveRule removes a rule from the zone. A family-agnostic set-referencing
// rule is deliberately not pinned here: leaving it FamilyAny sweeps both family
// files, which also clears a stray wrong-family line and still works after the
// referenced set is gone.
func (f *IPTables) RemoveRule(ctx context.Context, zoneName string, r *Rule) error {
	return f.editRuleFiles(r, f.removeRuleGroups)
}

// fileFamily returns the IP family of one of this backend's save files.
func (f *IPTables) fileFamily(path string) Family {
	if f.managesIPv6() && path == f.IP6Path {
		return IPv6
	}
	return IPv4
}

// natRulesInFile parses the nat-table rules from a save file. The scan drops the
// lines GetNATRules cannot report — a line the model cannot hold, and a
// container runtime's own translation such as Docker's per-published-port
// hairpin masquerade — so every nat group carrying a rule is one to return.
// GetNATRules assigns Number per family; the other callers use the result only
// for dedup and never read Number.
func (f *IPTables) natRulesInFile(path string) ([]*NATRule, error) {
	var rules []*NATRule
	err := f.scanSaveFile(path, f.fileFamily(path), func(g iptGroup) error {
		if g.table == "nat" && g.nat != nil {
			rules = append(rules, g.nat)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return rules, nil
}

// GetNATRules returns the existing NAT rules from the zone.
func (f *IPTables) GetNATRules(ctx context.Context, zoneName string) (rules []*NATRule, err error) {
	// Each save-file line is its own NAT rule, pinned to the family of the file it
	// lives in. Number each family's nat chains independently, as GetRules does for
	// the filter chains, so a rule's Number matches the InsertNATRule/MoveNATRule
	// position within the chain it actually lives in.
	v4, err := f.natRulesInFile(f.IP4Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read iptables file for IPv4: %s", err)
	}
	// An IPv4-only host has no v6 file to read.
	var v6 []*NATRule
	if f.managesIPv6() {
		if v6, err = f.natRulesInFile(f.IP6Path); err != nil {
			return nil, fmt.Errorf("failed to read iptables file for IPv6: %s", err)
		}
	}
	numberNATByChain(v4)
	numberNATByChain(v6)
	rules = append(rules, v4...)
	rules = append(rules, v6...)
	return rules, nil
}

// natChain returns the nat-table chain a NAT rule belongs in.
func (f *IPTables) natChain(r *NATRule) string {
	if r.Kind.isSource() {
		return "POSTROUTING"
	}
	return "PREROUTING"
}

// natTarget renders an iptables NAT translation target "addr" or "addr:port",
// bracketing an IPv6 address when a port is present.
func natTarget(fam Family, addr string, port uint16) string {
	if port == 0 {
		return addr
	}
	if fam == IPv6 || familyOfAddr(addr) == IPv6 {
		return fmt.Sprintf("[%s]:%d", addr, port)
	}
	return fmt.Sprintf("%s:%d", addr, port)
}

// MarshalNATRule encodes a NAT rule as an iptables-save rulespec for the nat
// table (e.g. `-A PREROUTING -p tcp --dport 80 -j DNAT --to-destination ...`).
// It is a pure encoder: callers run NATRule.validate first. iptables' nat targets
// cover every modeled shape, so it takes no rejections of its own.
func (f *IPTables) MarshalNATRule(r *NATRule) (string, error) {
	fam := r.impliedFamily()
	parts := []string{"-A", f.natChain(r)}

	if r.Source != "" {
		parts = append(parts, f.addrArgs(r.Source, "src")...)
	}
	if r.Destination != "" {
		parts = append(parts, f.addrArgs(r.Destination, "dst")...)
	}

	// Interface, bound to the translation direction.
	if r.Interface != "" {
		if r.Kind.isSource() {
			parts = append(parts, "-o", r.Interface)
		} else {
			parts = append(parts, "-i", r.Interface)
		}
	}

	if r.Proto != ProtocolAny {
		parts = append(parts, "-p", r.Proto.String())
	}

	specs := r.PortSpecs()
	if len(specs) == 1 && specs[0].Start == specs[0].End {
		parts = append(parts, "-m", r.Proto.String(), "--dport", strconv.FormatUint(uint64(specs[0].Start), 10))
	} else if len(specs) > 0 {
		parts = append(parts, "-m", "multiport", "--dports", iptMultiportValue(specs))
	}

	if f.rulePrefix != "" {
		quoted, err := f.quoteCommentToken(f.rulePrefix)
		if err != nil {
			return "", err
		}
		parts = append(parts, "-m", "comment", "--comment", quoted)
	}

	switch r.Kind {
	case DNAT:
		parts = append(parts, "-j", "DNAT", "--to-destination", natTarget(fam, r.ToAddress, r.ToPort))
	case Redirect:
		parts = append(parts, "-j", "REDIRECT", "--to-ports", strconv.FormatUint(uint64(r.ToPort), 10))
	case SNAT:
		parts = append(parts, "-j", "SNAT", "--to-source", natTarget(fam, r.ToAddress, r.ToPort))
	case Masquerade:
		parts = append(parts, "-j", "MASQUERADE")
	}

	return strings.Join(parts, " "), nil
}

// editNATFile inserts or removes a NAT rule line within a save file's nat table
// in a single streamed pass, creating the table section when adding to a file
// that lacks one. An add is a no-op when the table already holds an equivalent
// rule; a removal drops every matching line, not just the first, so a chain
// holding duplicate equivalent lines comes clean in one call — mirroring
// removeRuleGroups. A container runtime's translation is invisible to the
// scan, so it is never a removal target, as on the filter side.
func (f *IPTables) editNATFile(path string, r *NATRule, line string, add bool) error {
	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = fd.Close() }()

	af, err := newAtomicFile(path, 0644)
	if err != nil {
		return err
	}
	defer af.Abort()

	changed, duplicate, sawNAT := false, false, false
	err = f.scanSaveGroups(fd, f.fileFamily(path), func(g iptGroup) error {
		if g.table == "nat" {
			if g.commit {
				sawNAT = true
			}
			switch {
			case !add:
				if g.nat != nil && g.nat.EqualBase(r) {
					changed = true
					return nil
				}
			case g.nat != nil && g.nat.EqualBase(r):
				duplicate = true
			case g.commit && !changed && !duplicate:
				// Insert before the table's COMMIT.
				_, _ = fmt.Fprintln(af, line)
				changed = true
			}
		}
		for _, l := range g.raw {
			_, _ = fmt.Fprintln(af, l)
		}
		return nil
	})
	// A read error means the staged file is truncated; discard it.
	if err != nil {
		return err
	}

	if add {
		if duplicate {
			return nil
		}
		// The file carries no usable nat table; append a fresh one holding the rule.
		if !sawNAT {
			for _, l := range defaultNATSection[:len(defaultNATSection)-1] {
				_, _ = fmt.Fprintln(af, l)
			}
			_, _ = fmt.Fprintln(af, line)
			_, _ = fmt.Fprintln(af, "COMMIT")
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return af.Commit()
}

// natPaths returns the save files a NAT rule applies to, per its family.
func (f *IPTables) natPaths(r *NATRule) []string {
	// As in editRuleFiles, an IPv4-only host contributes no v6 path.
	fam := r.impliedFamily()
	var paths []string
	if fam == IPv4 || fam == FamilyAny {
		paths = append(paths, f.IP4Path)
	}
	if (fam == IPv6 || fam == FamilyAny) && f.managesIPv6() {
		paths = append(paths, f.IP6Path)
	}
	return paths
}

// defaultNATSection is the nat table scaffold written when a save file has none.
var defaultNATSection = []string{
	"*nat",
	":PREROUTING ACCEPT [0:0]",
	":INPUT ACCEPT [0:0]",
	":OUTPUT ACCEPT [0:0]",
	":POSTROUTING ACCEPT [0:0]",
	"COMMIT",
}

// AddNATRule adds a NAT rule to the zone. A family-agnostic set-referencing
// rule is pinned to its set's family first, as with AddRule.
func (f *IPTables) AddNATRule(ctx context.Context, zoneName string, r *NATRule) error {
	if err := r.validate(); err != nil {
		return err
	}
	r, err := resolveSetRefNAT(r, f.setRefFamily)
	if err != nil {
		return err
	}
	if err := f.checkFamilyManaged(r.impliedFamily()); err != nil {
		return err
	}
	line, err := f.MarshalNATRule(r)
	if err != nil {
		return err
	}
	for _, path := range f.natPaths(r) {
		if err := f.editNATFile(path, r, line, true); err != nil {
			return err
		}
	}
	return nil
}

// insertNATFile inserts a NAT rule line at the given 1-based position within its
// nat chain, creating the table section when the file lacks one. Position counts
// only lines in the rule's own chain (PREROUTING or POSTROUTING); a non-positive
// position is treated as 1 and a position past the chain's end appends after the
// chain's last rule.
func (f *IPTables) insertNATFile(path string, r *NATRule, line string, position int) error {
	if position <= 0 {
		position = 1
	}
	// Exact chain-name compare so a foreign chain whose name starts with the
	// target chain (e.g. "PREROUTING_direct") is not counted (see
	// InsertRule). The scan numbers each group as GetNATRules does, so
	// a line the model cannot hold takes no position with it.
	chainName := f.natChain(r)

	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = fd.Close() }()

	af, err := newAtomicFile(path, 0644)
	if err != nil {
		return err
	}
	defer af.Abort()

	written, duplicate, sawNAT, seenChain := false, false, false, false
	writeRule := func() {
		_, _ = fmt.Fprintln(af, line)
		written = true
	}
	err = f.scanSaveGroups(fd, f.fileFamily(path), func(g iptGroup) error {
		if g.table == "nat" {
			if g.commit {
				sawNAT = true
			}
			if g.nat != nil && g.nat.EqualBase(r) {
				duplicate = true
			}
			if !written && !duplicate {
				switch {
				case g.chain == chainName && g.number == position:
					writeRule()
				case seenChain && g.chain != "" && g.chain != chainName:
					// The position ran past the chain's last rule: append directly
					// after it rather than at the table's COMMIT, so the chain's lines
					// stay together instead of landing behind another chain's.
					writeRule()
				case g.commit:
					// A chain with no rules of its own still lands inside the table.
					writeRule()
				}
			}
			if g.chain == chainName {
				seenChain = true
			}
		}
		for _, l := range g.raw {
			_, _ = fmt.Fprintln(af, l)
		}
		return nil
	})
	// A read error means the staged file is truncated; discard it.
	if err != nil {
		return err
	}
	// Skip when an equivalent rule already exists.
	if duplicate {
		return nil
	}
	// The file carries no usable nat table; append a fresh one holding the rule.
	// A table header with no COMMIT under it still lets the position and
	// chain-run branches above place the rule, so append only when nothing was
	// written — otherwise the rule would land twice.
	if !sawNAT && !written {
		for _, l := range defaultNATSection[:len(defaultNATSection)-1] {
			_, _ = fmt.Fprintln(af, l)
		}
		_, _ = fmt.Fprintln(af, line)
		_, _ = fmt.Fprintln(af, "COMMIT")
		return af.Commit()
	}
	if !written {
		return nil
	}
	return af.Commit()
}

// InsertNATRule inserts a NAT rule at the given 1-based position within its nat
// chain. A non-positive position is treated as 1; a position larger than the
// chain's current rule count appends the rule.
func (f *IPTables) InsertNATRule(ctx context.Context, zoneName string, position int, r *NATRule) error {
	if err := r.validate(); err != nil {
		return err
	}
	if err := f.checkFamilyManaged(r.impliedFamily()); err != nil {
		return err
	}
	line, err := f.MarshalNATRule(r)
	if err != nil {
		return err
	}
	for _, path := range f.natPaths(r) {
		if err := f.insertNATFile(path, r, line, position); err != nil {
			return err
		}
	}
	return nil
}

// moveNATFile relocates the first NAT rule equal to r within its chain to the
// given 1-based position, mirroring moveCellGroups for the nat table. The
// matched line is lifted and re-placed verbatim so its comment prefix and
// formatting survive; only its position in the chain changes. A non-positive
// position is treated as 1; a position past the chain's end appends. It is a
// no-op (nil) when the rule is not present or the file has no nat table.
func (f *IPTables) moveNATFile(path string, r *NATRule, position int) error {
	if position <= 0 {
		position = 1
	}
	// Exact chain-name compare so a foreign chain whose name starts with the
	// target chain is not counted.
	chainName := f.natChain(r)

	// As on the filter side, a move is the one nat edit that cannot stream: the
	// rule's new slot may sit ahead of the one it was lifted from. Holding the
	// scanned groups keeps the file read and parsed exactly once.
	var groups []iptGroup
	if err := f.scanSaveFile(path, f.fileFamily(path), func(g iptGroup) error {
		groups = append(groups, g)
		return nil
	}); err != nil {
		return err
	}

	// Lift the first matching rule verbatim, so its comment prefix and formatting
	// survive; only its position in the chain changes.
	moved := -1
	for i, g := range groups {
		if g.table == "nat" && g.nat != nil && g.nat.EqualBase(r) {
			moved = i
			break
		}
	}
	if moved < 0 {
		return nil
	}
	lifted := groups[moved]
	// The three-index slice forces a copy rather than shifting groups in place.
	groups = append(groups[:moved:moved], groups[moved+1:]...)

	af, err := newAtomicFile(path, 0644)
	if err != nil {
		return err
	}
	defer af.Abort()

	// Re-insert at the requested position within the rule's chain, renumbering
	// over the post-removal groups. A position past the chain's last rule appends
	// after it, and a chain with no surviving rules falls back to the table's
	// COMMIT, mirroring insertNATFile.
	written, seenChain := false, false
	pos := 0
	writeLifted := func() {
		for _, l := range lifted.raw {
			_, _ = fmt.Fprintln(af, l)
		}
		written = true
	}
	for _, g := range groups {
		if g.table == "nat" && !written {
			if g.chain == chainName && g.nat != nil {
				pos++
			}
			switch {
			case g.chain == chainName && g.nat != nil && pos == position:
				writeLifted()
			case seenChain && g.chain != "" && g.chain != chainName:
				writeLifted()
			case g.commit:
				writeLifted()
			}
			if g.chain == chainName {
				seenChain = true
			}
		}
		for _, l := range g.raw {
			_, _ = fmt.Fprintln(af, l)
		}
	}
	if !written {
		return nil
	}
	return af.Commit()
}

// MoveNATRule moves an existing NAT rule to the given 1-based position within
// its nat chain. A non-positive position is treated as 1; a position larger than
// the chain's current rule count moves the rule to the end.
func (f *IPTables) MoveNATRule(ctx context.Context, zoneName string, r *NATRule, position int) error {
	if err := f.checkFamilyManaged(r.impliedFamily()); err != nil {
		return err
	}
	for _, path := range f.natPaths(r) {
		if err := f.moveNATFile(path, r, position); err != nil {
			return err
		}
	}
	return nil
}

// RemoveNATRule removes a NAT rule from the zone.
func (f *IPTables) RemoveNATRule(ctx context.Context, zoneName string, r *NATRule) error {
	for _, path := range f.natPaths(r) {
		if err := f.editNATFile(path, r, "", false); err != nil {
			return err
		}
	}
	return nil
}

// parsePolicyLine decodes a `:CHAIN POLICY [counters]` chain declaration.
func (f *IPTables) parsePolicyLine(line string) (chain string, action Action, ok bool) {
	t := strings.TrimSpace(line)
	if !strings.HasPrefix(t, ":") {
		return "", 0, false
	}
	fields := strings.Fields(t)
	if len(fields) < 2 {
		return "", 0, false
	}
	switch fields[1] {
	case "ACCEPT":
		action = Accept
	case "DROP":
		action = Drop
	default:
		return "", 0, false
	}
	return strings.TrimPrefix(fields[0], ":"), action, true
}

// policyFromFile reads the INPUT/OUTPUT/FORWARD chain policies from an
// iptables-save file. A direction whose chain line is absent is reported as
// ActionInvalid.
func (f *IPTables) policyFromFile(path string) (*DefaultPolicy, error) {
	p := &DefaultPolicy{}
	// Only the *filter table carries the input/output/forward policy. The other
	// tables (*nat, *mangle, *raw, ...) declare their own :INPUT/:OUTPUT built-in
	// chains — *nat's is always ACCEPT (iptables rejects any other policy there),
	// while *mangle/*raw can carry any policy but are not filtering tables — and
	// iptables-save emits them after *filter, so scanning table-agnostically would
	// let one of those chains shadow a hardened filter policy (e.g. report
	// Input=Accept when filter INPUT is DROP). The scan supplies the table scope.
	err := f.scanSaveFile(path, FamilyAny, func(g iptGroup) error {
		if g.table != "filter" {
			return nil
		}
		chain, action, ok := f.parsePolicyLine(g.raw[0])
		if !ok {
			return nil
		}
		switch chain {
		case "INPUT":
			p.Input = action
		case "OUTPUT":
			p.Output = action
		case "FORWARD":
			p.Forward = action
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// GetDefaultPolicy returns the default action applied to packets that match no rule.
func (f *IPTables) GetDefaultPolicy(ctx context.Context, zoneName string) (*DefaultPolicy, error) {
	v4, err := f.policyFromFile(f.IP4Path)
	if err != nil {
		return nil, err
	}
	// An IPv4-only host has only the one policy to report, so there is nothing to
	// reconcile against.
	if !f.managesIPv6() {
		return v4, nil
	}
	v6, err := f.policyFromFile(f.IP6Path)
	if err != nil {
		return nil, err
	}
	// SetDefaultPolicy writes both families identically, so on a host this library
	// manages they always agree. A divergence means the IPv4 and IPv6 chain
	// policies were set out of band and there is no single policy to report.
	if *v4 != *v6 {
		return nil, fmt.Errorf("iptables default policy differs between IPv4 (%+v) and IPv6 (%+v)", *v4, *v6)
	}
	return v4, nil
}

// savePaths returns the save files this host manages, IPv4 first. It is the
// whole-file counterpart to editRuleFiles' per-rule family fan-out, for the
// operations that touch every managed file regardless of any one rule's family.
func (f *IPTables) savePaths() []string {
	if !f.managesIPv6() {
		return []string{f.IP4Path}
	}
	return []string{f.IP4Path, f.IP6Path}
}

// setPolicyFile rewrites the chain declaration lines in an iptables-save
// file for the directions named in policy, preserving the counter slots.
func (f *IPTables) setPolicyFile(path string, policy *DefaultPolicy) error {
	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = fd.Close() }()

	af, err := newAtomicFile(path, 0644)
	if err != nil {
		return err
	}
	defer af.Abort()

	// Only rewrite policy lines inside the *filter table; the other tables
	// (nat/mangle/raw/...) declare their own built-in chains — nat's must stay
	// ACCEPT (iptables rejects any other policy there), and mangle/raw are not
	// filtering tables regardless — so leave them all untouched.
	err = f.scanSaveGroups(fd, FamilyAny, func(g iptGroup) error {
		raw := g.raw[0]
		if g.table == "filter" {
			if chain, _, ok := f.parsePolicyLine(raw); ok {
				var action Action
				switch chain {
				case "INPUT":
					action = policy.Input
				case "OUTPUT":
					action = policy.Output
				case "FORWARD":
					action = policy.Forward
				}
				// A direction the caller left unset keeps the file's own policy.
				if action != ActionInvalid {
					fields := strings.Fields(raw)
					counters := "[0:0]"
					if len(fields) >= 3 {
						counters = fields[2]
					}
					raw = fmt.Sprintf("%s %s %s", fields[0], strings.ToUpper(action.String()), counters)
				}
			}
		}
		_, _ = fmt.Fprintln(af, raw)
		for _, l := range g.raw[1:] {
			_, _ = fmt.Fprintln(af, l)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return af.Commit()
}

// SetDefaultPolicy sets the default action for the directions named in policy.
func (f *IPTables) SetDefaultPolicy(ctx context.Context, zoneName string, policy *DefaultPolicy) error {
	if policy == nil {
		return fmt.Errorf("policy cannot be nil")
	}
	for _, action := range []Action{policy.Input, policy.Output, policy.Forward} {
		if action == Reject {
			return fmt.Errorf("iptables chain policy may only be accept or drop")
		}
	}
	for _, path := range f.savePaths() {
		if err := f.setPolicyFile(path, policy); err != nil {
			return err
		}
	}
	return nil
}

// --- address sets (ipset) ---------------------------------------------------
//
// Address sets follow the same staged model as this backend's rules: a mutation
// edits the ipset staging file and nothing reaches the kernel until Reload,
// which loads the file before restarting the rules services so a `-m set` rule
// resolves. Reading and writing the file rather than the live kernel is what
// keeps a set another tool created to be temporary — a fail2ban ban, a hand-made
// test set — out of the boot configuration, and it lets a rule removal and the
// removal of the set it referenced land in one Reload instead of failing on
// "in use by a kernel component".
//
// A host with no persistence mechanism (IPSetPath empty) has no staging file to
// edit, so sets there are created live immediately and warned about; see
// setPersistedStaging.
//
// Everything that touches the kernel goes through the netlink primitives in
// ipset_linux.go. The one exception is applyStagedSets, which shells out to
// `ipset restore`: that tool owns the save format, parses the entries and picks
// each type's revision, and reproducing all three over netlink to load a file we
// wrote in its own format would be work for its own sake.

// ipsetParseType reads the family and type out of an ipset `create` line's
// trailing options.
func (f *IPTables) ipsetParseType(fields []string) (Family, SetType) {
	family := IPv4
	t := SetHashIP
	for i := 2; i < len(fields); i++ {
		switch fields[i] {
		case "hash:net":
			t = SetHashNet
		case "hash:ip":
			t = SetHashIP
		case "family":
			if i+1 < len(fields) && fields[i+1] == "inet6" {
				family = IPv6
			}
		}
	}
	return family, t
}

// ipsetSaveScanner decodes ipset save-format lines into address sets in
// create-line order. The staging file is streamed through it straight off disk,
// so a large blocklist is never held in memory twice — once as raw lines and
// again as parsed entries.
//
// The decode is single-pass: `ipset save` emits each set's create line ahead of
// its members, and `ipset restore` rejects any other order, so an add line whose
// set has not been seen names no set this file declares and is dropped.
type ipsetSaveScanner struct {
	sets  map[string]*AddressSet
	order []string
}

// line folds one ipset save-format line into the sets decoded so far.
func (s *ipsetSaveScanner) line(f *IPTables, line string) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return
	}
	switch fields[0] {
	case "create":
		if s.sets == nil {
			s.sets = map[string]*AddressSet{}
		}
		if _, dup := s.sets[fields[1]]; dup {
			return
		}
		family, t := f.ipsetParseType(fields)
		s.sets[fields[1]] = &AddressSet{Name: fields[1], Family: family, Type: t}
		s.order = append(s.order, fields[1])
	case "add":
		// An add line may carry entry options (`timeout 600`, `comment "x"`);
		// the entry itself is still the third field.
		if set, ok := s.sets[fields[1]]; ok {
			set.Entries = append(set.Entries, fields[2])
		}
	}
}

// result returns the decoded sets in create-line order.
func (s *ipsetSaveScanner) result() []*AddressSet {
	out := make([]*AddressSet, 0, len(s.order))
	for _, n := range s.order {
		out = append(out, s.sets[n])
	}
	return out
}

// scanIPSetSave streams an ipset save-format file off disk into address sets. A
// file that does not exist decodes as no sets: nothing has been staged yet.
func (f *IPTables) scanIPSetSave(path string) ([]*AddressSet, error) {
	fd, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = fd.Close() }()
	var s ipsetSaveScanner
	scanner := bufio.NewScanner(fd)
	for scanner.Scan() {
		s.line(f, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return s.result(), nil
}

// stagedSets reads the sets staged in the layout's ipset file, the authority for
// what this backend manages. Callers that can act on a damaged file take the
// error; setRefFamily and other best-effort readers use persistedIPSetSets.
func (f *IPTables) stagedSets() ([]*AddressSet, error) {
	if f.IPSetPath == "" {
		return nil, nil
	}
	return f.scanIPSetSave(f.IPSetPath)
}

// persistedIPSetSets reads the staged sets for family resolution. An
// unconfigured layout or an unreadable file means no sets — resolution falls
// through to the live kernel rather than failing the write.
func (f *IPTables) persistedIPSetSets() []*AddressSet {
	sets, err := f.stagedSets()
	if err != nil {
		return nil
	}
	return sets
}

// setRefFamily resolves the single family of the ipset(s) a rule references
// through the shared ipset resolver: the live kernel first, then the layout's
// ipset persistence file for a set declared only in boot config. A set neither
// knows is an error: writing the rule anyway would put a line no restore can
// load into a save file. A caller that knows better sets the rule's Family,
// which bypasses resolution entirely.
func (f *IPTables) setRefFamily(source, destination string) (Family, error) {
	return ipsetRefFamily(source, destination, func() ([]*AddressSet, error) {
		return f.persistedIPSetSets(), nil
	})
}

// setPersistedStaging reports whether this host has an ipset staging file to manage
// sets through. When it does not, the address-set methods fall back to acting on
// the live kernel directly.
func (f *IPTables) setPersistedStaging() bool {
	return f.IPSetPath != ""
}

// GetAddressSets returns the address sets managed by this backend: the staged
// sets, or the live kernel's on a host with no staging file.
func (f *IPTables) GetAddressSets(ctx context.Context) ([]*AddressSet, error) {
	if f.setPersistedStaging() {
		return f.stagedSets()
	}
	return ipsetLiveSets()
}

// GetAddressSet returns a single address set by name, or an error if it does not exist.
func (f *IPTables) GetAddressSet(ctx context.Context, name string) (*AddressSet, error) {
	sets, err := f.GetAddressSets(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range sets {
		if s.Name == name {
			return s, nil
		}
	}
	return nil, fmt.Errorf("address set %q not found", name)
}

// ipsetTypeSpec renders the ipset type keyword and family option for a set.
func (f *IPTables) ipsetTypeSpec(family Family, t SetType) string {
	spec := t.String()
	fam := "inet"
	if family == IPv6 {
		fam = "inet6"
	}
	return spec + " family " + fam
}

// marshalIPSetSave renders sets in ipset save format, the format the staging
// file keeps so the distro's own restore unit and `ipset save` tooling read it
// unchanged.
func (f *IPTables) marshalIPSetSave(sets []*AddressSet) []byte {
	var b strings.Builder
	for _, s := range sets {
		b.WriteString("create " + s.Name + " " + f.ipsetTypeSpec(s.Family, s.Type) + "\n")
		for _, e := range s.Entries {
			b.WriteString("add " + s.Name + " " + e + "\n")
		}
	}
	return []byte(b.String())
}

// writeStagedSets replaces the staging file with sets and makes sure the restore
// unit is enabled, so a reboot loads them before the rules service loads the
// rules that reference them.
func (f *IPTables) writeStagedSets(ctx context.Context, sets []*AddressSet) error {
	if f.IPSetService != "" {
		if err := enableService(ctx, f.IPSetService); err != nil {
			return err
		}
	}
	return writeConfigFile(f.IPSetPath, f.marshalIPSetSave(sets), 0600)
}

// setFamily resolves a set's stored family: a set is family-typed, and
// FamilyAny is recorded as IPv4 so the staged file always names a concrete one.
func (f *IPTables) setFamily(set *AddressSet) Family {
	if set.Family == FamilyAny {
		return IPv4
	}
	return set.Family
}

// editStagedSets reads the staged sets, hands them to edit, and writes the
// result back when edit reports a change.
func (f *IPTables) editStagedSets(ctx context.Context, edit func(sets []*AddressSet) ([]*AddressSet, bool, error)) error {
	sets, err := f.stagedSets()
	if err != nil {
		return err
	}
	out, changed, err := edit(sets)
	if err != nil {
		return err
	}
	if !changed {
		return nil
	}
	return f.writeStagedSets(ctx, out)
}

// dropPendingRemoval cancels a staged removal for name, for a set added back
// before the Reload that would have destroyed it.
func (f *IPTables) dropPendingRemoval(name string) {
	for i, n := range f.pendingSetRemovals {
		if n == name {
			f.pendingSetRemovals = append(f.pendingSetRemovals[:i], f.pendingSetRemovals[i+1:]...)
			return
		}
	}
}

// liveAddAddressSet creates a set directly in the kernel, the fallback on a host
// with no staging file to write.
func (f *IPTables) liveAddAddressSet(ctx context.Context, set *AddressSet) error {
	if err := ipsetCreate(set.Name, f.setFamily(set), set.Type); err != nil {
		return err
	}
	for _, entry := range set.Entries {
		if err := ipsetAddEntry(set.Name, entry); err != nil {
			return err
		}
	}
	return nil
}

// AddAddressSet stages an address set; it is created in the kernel by Reload.
// Adding a set that already exists by name merges its entries, matching what a
// re-create with -exist does live; re-declaring one with a different family or
// type is a conflict and is reported rather than silently rewriting the set.
func (f *IPTables) AddAddressSet(ctx context.Context, set *AddressSet) error {
	if set == nil || set.Name == "" {
		return fmt.Errorf("an address set requires a name")
	}
	if !f.setPersistedStaging() {
		log.Printf("firewall: address sets are live-only; no ipset persistence mechanism found, they will not survive a reboot")
		return f.liveAddAddressSet(ctx, set)
	}
	err := f.editStagedSets(ctx, func(sets []*AddressSet) ([]*AddressSet, bool, error) {
		family := f.setFamily(set)
		for _, s := range sets {
			if s.Name != set.Name {
				continue
			}
			if s.Family != family || s.Type != set.Type {
				return nil, false, fmt.Errorf("address set %q is already staged as %s %s, not %s %s",
					set.Name, s.Family, s.Type, family, set.Type)
			}
			// Merge the requested entries into the existing set.
			changed := false
			for _, e := range set.Entries {
				if !slices.Contains(s.Entries, e) {
					s.Entries = append(s.Entries, e)
					changed = true
				}
			}
			return sets, changed, nil
		}
		add := &AddressSet{Name: set.Name, Family: family, Type: set.Type}
		add.Entries = append(add.Entries, set.Entries...)
		return append(sets, add), true, nil
	})
	if err != nil {
		return err
	}
	f.dropPendingRemoval(set.Name)
	return nil
}

// RemoveAddressSet removes an address set by name. The set is dropped from the
// staging file now and destroyed in the kernel by Reload, once the rules that
// referenced it are gone. Removing a set that is not staged is a no-op.
func (f *IPTables) RemoveAddressSet(ctx context.Context, name string) error {
	if !f.setPersistedStaging() {
		return f.liveRemoveAddressSet(ctx, name)
	}
	removed := false
	err := f.editStagedSets(ctx, func(sets []*AddressSet) ([]*AddressSet, bool, error) {
		out := make([]*AddressSet, 0, len(sets))
		for _, s := range sets {
			if s.Name == name {
				removed = true
				continue
			}
			out = append(out, s)
		}
		return out, removed, nil
	})
	if err != nil {
		return err
	}
	// Queue the kernel-side destroy for Reload. A set that was never staged has
	// nothing to destroy, so an already-gone set stays a clean no-op.
	if removed && !slices.Contains(f.pendingSetRemovals, name) {
		f.pendingSetRemovals = append(f.pendingSetRemovals, name)
	}
	return nil
}

// liveRemoveAddressSet destroys a set directly in the kernel, the fallback on a
// host with no staging file, and the path Reload takes for a staged removal.
func (f *IPTables) liveRemoveAddressSet(ctx context.Context, name string) error {
	// Empty the set before destroying it. A missing set is a no-op in both steps;
	// any other failure — notably the kernel refusing to destroy a set a loaded
	// rule still matches on — is real and must be surfaced rather than reported as
	// success while the set remains.
	if err := ipsetFlush(name); err != nil {
		return err
	}
	return ipsetDestroy(name)
}

// AddAddressSetEntry adds an entry to the named set.
func (f *IPTables) AddAddressSetEntry(ctx context.Context, name, entry string) error {
	if !f.setPersistedStaging() {
		return ipsetAddEntry(name, entry)
	}
	return f.editStagedSets(ctx, func(sets []*AddressSet) ([]*AddressSet, bool, error) {
		for _, s := range sets {
			if s.Name != name {
				continue
			}
			if slices.Contains(s.Entries, entry) {
				return sets, false, nil
			}
			s.Entries = append(s.Entries, entry)
			return sets, true, nil
		}
		// Mirrors what `ipset add` reports against a set the kernel does not hold.
		return nil, false, fmt.Errorf("address set %q does not exist", name)
	})
}

// RemoveAddressSetEntry removes an entry from the named set. A missing entry, or
// a missing set, is a no-op.
func (f *IPTables) RemoveAddressSetEntry(ctx context.Context, name, entry string) error {
	if !f.setPersistedStaging() {
		return ipsetDelEntry(name, entry)
	}
	return f.editStagedSets(ctx, func(sets []*AddressSet) ([]*AddressSet, bool, error) {
		for _, s := range sets {
			if s.Name != name {
				continue
			}
			if i := slices.Index(s.Entries, entry); i >= 0 {
				s.Entries = append(s.Entries[:i], s.Entries[i+1:]...)
				return sets, true, nil
			}
		}
		return sets, false, nil
	})
}

// applyStagedSets loads the staging file into the kernel. Each declared set is
// created if missing, then flushed and refilled so it ends up matching the file
// exactly; a set the file does not declare is left alone, since the kernel also
// holds sets other tools own and reconcile (kube-proxy, Calico, fail2ban).
func (f *IPTables) applyStagedSets(ctx context.Context) error {
	if !f.setPersistedStaging() {
		return nil
	}
	sets, err := f.stagedSets()
	if err != nil {
		return err
	}
	if len(sets) == 0 {
		return nil
	}
	var script strings.Builder
	for _, s := range sets {
		script.WriteString("create " + s.Name + " " + f.ipsetTypeSpec(s.Family, s.Type) + " -exist\n")
		script.WriteString("flush " + s.Name + "\n")
		for _, e := range s.Entries {
			script.WriteString("add " + s.Name + " " + e + "\n")
		}
	}
	_, err = runCommandStdin(ctx, script.String(), "ipset", "restore")
	return err
}

// applyPendingSetRemovals destroys the sets removed from the staging file this
// session. It runs after the rules services restart, so the rules that
// referenced them are already gone and the destroy is not refused as in-use. A
// set that will not destroy stays queued for the next Reload.
func (f *IPTables) applyPendingSetRemovals(ctx context.Context) error {
	if len(f.pendingSetRemovals) == 0 {
		return nil
	}
	var failed []string
	var firstErr error
	for _, name := range f.pendingSetRemovals {
		if err := f.liveRemoveAddressSet(ctx, name); err != nil {
			failed = append(failed, name)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	f.pendingSetRemovals = failed
	return firstErr
}

// Backup captures the current filter and NAT rules managed by this backend.
func (f *IPTables) Backup(ctx context.Context, zoneName string) (*Backup, error) {
	rules, err := f.GetRules(ctx, zoneName)
	if err != nil {
		return nil, err
	}
	natRules, err := f.GetNATRules(ctx, zoneName)
	if err != nil {
		return nil, err
	}
	// Backup captures the INPUT/OUTPUT/FORWARD filter rules, the nat rules, the
	// filter chain default policies and the managed ipsets; Restore replaces exactly
	// those on replay, leaving user-defined chains and other tables (which Backup
	// does not capture) intact.
	backup := &Backup{Rules: rules, NATRules: natRules}
	if err := captureBackupState(ctx, f, zoneName, backup); err != nil {
		return nil, err
	}
	return backup, nil
}

// modeledFilterChain reports whether a *filter chain name is one the library
// models as a Rule direction (INPUT, OUTPUT or FORWARD). The file-rewrite paths
// use it to tell a managed rule from a rule in a chain the library does not model
// (a user-defined chain), which must be preserved verbatim.
func (f *IPTables) modeledFilterChain(ch string) bool {
	switch ch {
	case "INPUT", "OUTPUT", "FORWARD":
		return true
	}
	return false
}

// rewriteFilterRules atomically rewrites path so that the *filter table's rule
// (-A) lines are exactly ruleLines, leaving the chain-policy lines, any *nat
// table and all other content untouched. A file with no *filter table gains one.
//
// A modeled-chain (INPUT/OUTPUT/FORWARD) line is dropped only when the scan
// resolved it to a rule, because only then can the desired set reproduce it.
// Every line the scan leaves unresolved is kept verbatim, on the same principle
// the library already applies to a user-defined chain — a rule it does not model
// must not be deleted just because it is invisible. Three kinds qualify:
//   - A line the rule parser rejects outright — a foreign rule using a match this
//     library does not model (e.g. -m recent, -m owner, --tcp-flags).
//   - A line a container runtime owns, which GetRules never reports and whose
//     deletion would sever live container networking.
//   - A standalone LOG rule — a non-terminal `-j LOG` line with no action partner
//     immediately after it. GetRules coalesces a LOG line with its following
//     action line into one logged rule and drops an unpaired one, so it too is
//     unmodeled. A LOG line that DID pair is part of its group's resolved rule
//     and is dropped with it.
func (f *IPTables) rewriteFilterRules(path string, ruleLines []string) error {
	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = fd.Close() }()

	af, err := newAtomicFile(path, 0644)
	if err != nil {
		return err
	}
	defer af.Abort()

	inserted := false
	err = f.scanSaveGroups(fd, FamilyAny, func(g iptGroup) error {
		if g.table == "filter" {
			switch {
			case g.commit:
				if !inserted {
					for _, l := range ruleLines {
						_, _ = fmt.Fprintln(af, l)
					}
					inserted = true
				}
			// The library models the INPUT, OUTPUT and FORWARD chains, so the
			// desired set can only ever contain those. Drop an existing modeled rule
			// (counter-annotated or not) — the desired set replaces it — but keep a
			// rule in any other chain verbatim, since parseFilterFile never captures
			// those chains and dropping them would silently delete rules the library
			// does not manage.
			case g.chain != "" && f.modeledFilterChain(g.chain) && g.rule != nil:
				return nil
			}
		}
		for _, l := range g.raw {
			_, _ = fmt.Fprintln(af, l)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !inserted {
		for _, l := range []string{"*filter", ":INPUT ACCEPT [0:0]", ":OUTPUT ACCEPT [0:0]", ":FORWARD ACCEPT [0:0]"} {
			_, _ = fmt.Fprintln(af, l)
		}
		for _, l := range ruleLines {
			_, _ = fmt.Fprintln(af, l)
		}
		_, _ = fmt.Fprintln(af, "COMMIT")
	}
	return af.Commit()
}

// managedNATChain reports whether a nat-table chain is one this backend reads
// and writes (PREROUTING/POSTROUTING). rewriteNATRules replaces the rules in these
// chains and preserves every other nat chain verbatim — including OUTPUT, whose
// locally-generated DNAT the NATRule model cannot represent distinctly (see
// UnmarshalNATRule), so it is left untouched rather than relocated to PREROUTING.
func (f *IPTables) managedNATChain(chain string) bool {
	switch chain {
	case "PREROUTING", "POSTROUTING":
		return true
	}
	return false
}

// rewriteNATRules atomically rewrites path so that the *nat table's rule lines in
// the managed chains are exactly natLines, leaving the chain-policy lines, any
// user-defined nat chain, unmodeled managed-chain lines, the *filter table and
// all other content untouched. A file with no *nat table gains one. It is the
// nat counterpart of rewriteFilterRules, and preserves an unresolved
// managed-chain line on the same grounds: an unsupported jump (-j DOCKER, -j
// RETURN), an unmodeled or negated match, a source-port match, or a container
// runtime's own translation is invisible to GetNATRules, so it never appears in
// the desired set and dropping it would sever — for example — Docker's port
// publishing on a Backup/Restore round trip.
func (f *IPTables) rewriteNATRules(path string, natLines []string) error {
	fd, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = fd.Close() }()

	af, err := newAtomicFile(path, 0644)
	if err != nil {
		return err
	}
	defer af.Abort()

	inserted := false
	err = f.scanSaveGroups(fd, FamilyAny, func(g iptGroup) error {
		if g.table == "nat" {
			switch {
			case g.commit:
				if !inserted {
					for _, l := range natLines {
						_, _ = fmt.Fprintln(af, l)
					}
					inserted = true
				}
			case g.chain != "" && f.managedNATChain(g.chain) && g.nat != nil:
				return nil
			}
		}
		for _, l := range g.raw {
			_, _ = fmt.Fprintln(af, l)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if !inserted {
		for _, l := range defaultNATSection[:len(defaultNATSection)-1] {
			_, _ = fmt.Fprintln(af, l)
		}
		for _, l := range natLines {
			_, _ = fmt.Fprintln(af, l)
		}
		_, _ = fmt.Fprintln(af, "COMMIT")
	}
	return af.Commit()
}

// Restore replaces the managed INPUT/OUTPUT/FORWARD filter rules and the nat rules
// with the contents of a Backup, splicing them into each family's existing save
// file, and re-asserts the captured filter chain policies and ipsets. User-defined
// chains and the *mangle/*raw tables — none of which Backup captures — are left
// untouched.
func (f *IPTables) Restore(ctx context.Context, zoneName string, backup *Backup) error {
	if backup == nil {
		return fmt.Errorf("backup cannot be nil")
	}

	// Stage the ipsets first so a set-referencing rule (@set) resolves against a
	// declared set while the save files below are rewritten, and so the caller's
	// Reload loads the sets ahead of the rules. AddAddressSet merges into an
	// already-staged set, making a restore over existing state idempotent.
	if err := restoreBackupSets(ctx, f, backup, false); err != nil {
		return err
	}

	// Group rules by family.
	groupRules := func() map[Family][]*Rule {
		m := map[Family][]*Rule{}
		for _, r := range backup.Rules {
			fam := r.impliedFamily()
			if fam == FamilyAny {
				m[IPv4] = append(m[IPv4], r)
				m[IPv6] = append(m[IPv6], r)
			} else {
				m[fam] = append(m[fam], r)
			}
		}
		return m
	}

	groupNAT := func() map[Family][]*NATRule {
		m := map[Family][]*NATRule{}
		for _, r := range backup.NATRules {
			fam := r.impliedFamily()
			if fam == FamilyAny {
				m[IPv4] = append(m[IPv4], r)
				m[IPv6] = append(m[IPv6], r)
			} else {
				m[fam] = append(m[fam], r)
			}
		}
		return m
	}

	// A backup taken on a dual-stack host and replayed onto an IPv4-only one has
	// no v6 file to splice its IPv6 rows into. Report what is being dropped rather
	// than failing the whole restore: the IPv4 half is still worth applying, and
	// the host genuinely cannot hold the rest.
	if !f.managesIPv6() {
		// Count only rows pinned to IPv6: a family-agnostic row is not dropped,
		// it narrows to the IPv4 file like every other FamilyAny write.
		dropped := 0
		for _, r := range backup.Rules {
			if r.impliedFamily() == IPv6 {
				dropped++
			}
		}
		for _, r := range backup.NATRules {
			if r.impliedFamily() == IPv6 {
				dropped++
			}
		}
		if dropped > 0 {
			log.Printf("firewall: iptables restore skipped %d IPv6 rule(s); this host does not manage IPv6", dropped)
		}
	}

	for _, path := range f.savePaths() {
		fam := f.fileFamily(path)

		// Marshal only the rule (-A) lines; rewriteFilterRules/rewriteNATRules splice
		// them into the existing save file, replacing the managed chains' rules while
		// preserving chain-policy lines, user-defined chains, and the *mangle/*raw
		// tables that Backup never captures. A from-scratch scaffold would silently
		// reset a DROP policy to ACCEPT and delete every unmanaged rule.
		var ruleLines []string
		for _, r := range groupRules()[fam] {
			c := *r
			if c.Family == FamilyAny {
				c.Family = fam
			}
			// A TCPUDP rule has no single-line iptables form; fan it out into a tcp
			// row and a udp row before marshalling.
			for _, sub := range expandProtocols(&c) {
				rl, err := f.marshalRuleLines(sub)
				if err != nil {
					return err
				}
				ruleLines = append(ruleLines, rl...)
			}
		}

		var natLines []string
		for _, r := range groupNAT()[fam] {
			c := *r
			if c.Family == FamilyAny {
				c.Family = fam
			}
			if err := c.validate(); err != nil {
				return err
			}
			rl, err := f.MarshalNATRule(&c)
			if err != nil {
				return err
			}
			natLines = append(natLines, rl)
		}

		if err := f.rewriteFilterRules(path, ruleLines); err != nil {
			return err
		}
		if err := f.rewriteNATRules(path, natLines); err != nil {
			return err
		}
	}

	// Re-assert the captured filter chain policies last, so a restore onto a host
	// whose default policy differs (e.g. a fresh ACCEPT host) reproduces the backed-
	// up policy rather than silently inheriting the current one.
	return applyBackupPolicy(ctx, f, zoneName, backup)
}

// Reload activates the staged state: the address sets first, so a rule matching
// on one resolves when the save files load, then the restore service(s) for the
// rules, then the kernel-side destroy of any set removed this session, which has
// to wait until the rules that referenced it are gone.
//
// The sets are loaded here directly rather than by restarting IPSetService,
// whose stop hook varies by packaging — some flush, some save the live state
// back over the file — and would put this backend's staged file at the mercy of
// it. The service still matters for boot, which is why writeStagedSets enables it.
func (f *IPTables) Reload(ctx context.Context) error {
	if err := f.applyStagedSets(ctx); err != nil {
		return err
	}

	if err := restartService(ctx, f.IP4Service); err != nil {
		return err
	}

	// Nothing more to restart when the host has no v6 service, or when the Debian
	// layout's single service (netfilter-persistent) already restored both
	// families above.
	if f.IP6Service != "" && f.IP6Service != f.IP4Service {
		if err := restartService(ctx, f.IP6Service); err != nil {
			return err
		}
	}

	return f.applyPendingSetRemovals(ctx)
}

// Close releases manager resources.
func (f *IPTables) Close(ctx context.Context) error {
	return nil
}

// coalesceLoggedRules merges each LOG-only rule that is immediately followed by
// a matching action rule into a single logical rule with Log set. An orphan LOG
// rule (no matching action after it) is dropped.
func coalesceLoggedRules(rules []*Rule) []*Rule {
	out := make([]*Rule, 0, len(rules))
	for i := 0; i < len(rules); i++ {
		cur := rules[i]
		if cur.Action == ActionInvalid && cur.Log {
			// A LOG-only line: fold it into the next line if that line is its
			// action partner, else drop this orphan LOG line.
			var next *Rule
			if i+1 < len(rules) {
				next = rules[i+1]
			}
			if logPartner(cur, next) {
				out = append(out, mergeLogPair(cur, next))
				i++
			}
			continue
		}
		out = append(out, cur)
	}
	return out
}
