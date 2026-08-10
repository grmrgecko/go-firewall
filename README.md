# go-firewall

[![Go Reference](https://pkg.go.dev/badge/github.com/grmrgecko/go-firewall.svg)](https://pkg.go.dev/github.com/grmrgecko/go-firewall)

A Go module that presents a single, uniform interface over the many
firewall managers found across operating systems. You describe rules with one
platform‑agnostic `Rule` struct and the module translates them to whatever
backend is actually running on the host.

Reference documentation: <https://pkg.go.dev/github.com/grmrgecko/go-firewall>

```go
import "github.com/grmrgecko/go-firewall"
```

## Supported backends

| Platform | Backends                                                        |
| -------- | --------------------------------------------------------------- |
| Linux    | firewalld → ufw → CSF → APF → iptables → nftables               |
| macOS    | pf (Packet Filter)                                              |
| FreeBSD  | pf (Packet Filter)                                              |
| Windows  | Windows Filtering Platform (WFP)                                |

## Usage

```go
package main

import (
	"context"
	"log"

	"github.com/grmrgecko/go-firewall"
)

func main() {
	ctx := context.Background()

	// Detect and connect to the host's firewall. The rule prefix tags/namespaces
	// rules this module creates.
	mgr, err := firewall.NewManager(ctx, "myapp")
	if err != nil {
		log.Fatal(err)
	}
	defer mgr.Close(ctx)

	// Resolve the zone for an interface (empty for backends without zones).
	zone, err := mgr.GetZone(ctx, "eth0")
	if err != nil {
		log.Fatal(err)
	}

	// Allow inbound TCP 443 from a subnet, logged and rate-limited.
	rule := &firewall.Rule{
		Family:    firewall.IPv4,
		Source:    "192.168.0.0/24",
		Port:      443,
		Proto:     firewall.TCP,
		Action:    firewall.Accept,
		Log:       true,
		LogPrefix: "https",
		RateLimit: &firewall.RateLimit{Rate: 20, Unit: firewall.PerSecond, Burst: 10},
	}

	if err := mgr.AddRule(ctx, zone, rule); err != nil {
		log.Fatal(err)
	}

	// Forward inbound TCP 8080 to an internal host (a NAT rule).
	nat := &firewall.NATRule{
		Kind:      firewall.DNAT,
		Family:    firewall.IPv4,
		Proto:     firewall.TCP,
		Port:      8080,
		ToAddress: "10.0.0.5",
		ToPort:    80,
	}
	if err := mgr.AddNATRule(ctx, zone, nat); err != nil {
		log.Fatal(err)
	}

	// Some backends stage changes; Reload activates them (a no-op where
	// changes apply immediately).
	if err := mgr.Reload(ctx); err != nil {
		log.Fatal(err)
	}
}
```

## CLI

`cmd/go-firewall` is a unified firewall management CLI and implementation demo
for the library. It auto-detects the host's active backend and exposes the same
surface across all of them. Build it from the repo root:

```sh
make cli                  # builds ./build/go-firewall
make install              # installs into $GOBIN
```

Managing rules needs appropriate privileges (root/Administrator), and the CLI
never modifies the host unless you run a mutating subcommand.

```sh
go-firewall status                                    # backend + capabilities
go-firewall rule list                                 # all filter rules (PREFIX column flags ours)
go-firewall rule add --proto tcp --port 443 --source 192.168.0.0/24 --log
go-firewall rule add --proto tcp --ports 80,443,1000-2000 --comment "web"
go-firewall rule remove --proto tcp --port 443
go-firewall rule insert 1 --proto tcp --port 22       # 1-based position
go-firewall nat add --kind dnat --proto tcp --port 8080 --to-address 10.0.0.5 --to-port 80
go-firewall nat insert 1 --kind dnat --proto tcp --port 8080 --to-address 10.0.0.5 --to-port 80
go-firewall nat add --kind masquerade
go-firewall policy get
go-firewall policy set --input drop --forward drop
go-firewall set create blocklist --family ipv4 --type hash:net
go-firewall set add-entry blocklist 203.0.113.0/24
go-firewall set show blocklist                        # metadata + every entry
go-firewall backup -o snapshot.json                   # portable JSON snapshot (rules, NAT, policy, sets)
go-firewall restore -f snapshot.json                  # replay the snapshot
go-firewall zone eth0
go-firewall reload
go-firewall install-completions                       # bash/zsh/fish completion
```

Global flags: `--prefix` (rule namespace; default `go_firewall`), `--no-reload`
(skip the automatic reload after a mutation), `-j/--json` (machine-readable
output — list, status, and a `{"status":...}` object on mutations), `--version`.
A rule's flags are identical across `add`,
`remove`, `insert` and `move`, so the flag set that creates a rule is also its
match key for removal. Run `go-firewall <command> --help` for the full flag
reference.

## The `Rule` type

| Field          | Meaning                                                                          |
| -------------- | -------------------------------------------------------------------------------- |
| `Direction`    | `DirInput` (default), `DirOutput`, `DirForward`, or `DirAny` — the input, output, forward (routing) chain, or both input and output. See `Capabilities().Forward` and the multi-state note below. |
| `Priority`     | Rule priority, where the backend supports it (e.g. firewalld rich rules).        |
| `Family`       | `FamilyAny`, `IPv4`, or `IPv6`.                                                   |
| `Source`       | Source address/CIDR. Prefix with `!` to negate, where supported.                 |
| `Destination`  | Destination address/CIDR. Prefix with `!` to negate, where supported.            |
| `Port`         | Single destination port. A non-zero port requires a port-carrying proto (`TCP`, `UDP`, `TCPUDP`, `SCTP`). |
| `Ports`        | Destination port list/ranges (`[]PortRange`). Overrides `Port` when non-empty.   |
| `Proto`        | `ProtocolAny`, `TCP`, `UDP`, `TCPUDP`, `ICMP`, `ICMPv6`, `SCTP`, `GRE`, `ESP`, or `AH`. `TCPUDP` matches both transports; `ProtocolAny` matches *every* IP protocol and cannot carry a port. |
| `ICMPType`     | Optional single ICMP type for an `ICMP`/`ICMPv6` rule (`*uint8`, nil = any type). |
| `State`        | Connection-tracking states to match, OR-combined (e.g. `StateEstablished\|StateRelated`). |
| `InInterface`  | Inbound interface to match. Empty means any interface. A forward rule may match this alongside `OutInterface`. |
| `OutInterface` | Outbound interface to match. Empty means any interface. A forward rule may match this alongside `InInterface`. |
| `Action`       | `Accept`, `Reject`, or `Drop`.                                                    |
| `Log`          | Log each matched packet before applying `Action`.                                |
| `LogPrefix`    | Optional label on the log line (not all backends carry a prefix; pf ignores it). |
| `RateLimit`    | `*RateLimit` (`Rate`/`Unit`/`Burst`) — cap the packet rate the rule matches. `nil` = unlimited. |
| `ConnLimit`    | `*ConnLimit` (`Count`/`PerSource`) — cap concurrent connections. `nil` = unlimited. |
| `Packets`      | Per-rule packet counter, populated by `GetRules` on backends that read them (nftables, iptables, pf). Zero elsewhere and ignored when adding a rule. |
| `Bytes`        | Per-rule byte counter, populated alongside `Packets`. Not part of rule identity. |
| `Comment`      | Optional human-readable label carried where the backend can store one. Informational: not part of rule identity, ignored where unsupported. See `Capabilities().Comments`. |
| `HasPrefix`    | Informational flag reporting whether the rule carries the configured prefix. |

`Capabilities().Output` reports whether a backend distinguishes input from output
(firewalld, for example, does not), and `Capabilities().Forward` reports whether it
can express a forward-chain (routing) rule. A `DirForward` rule on a backend without
forward support is rejected with `ErrUnsupportedForward`.

### Multi-state rules and coverage

Three values each describe a rule spanning both values of one axis:

- `FamilyAny` — both IPv4 and IPv6.
- `TCPUDP` — both TCP and UDP; it carries a port just as `TCP` or `UDP` does. It is
  **not** `ProtocolAny`, which matches *every* IP protocol (ICMP, GRE, ESP, …).
- `DirAny` — both the input and output directions (never forward). A `DirAny` rule
  is authored in the inbound frame, and its outbound half is the **role swap**:
  `Source`↔`Destination`, source↔destination ports, and
  `InInterface`↔`OutInterface`. So `DirAny` with `Source: X` matches inbound traffic
  *from* `X` and outbound traffic *to* `X`.

Whether such a rule becomes **one** object in the firewall or **several** depends
entirely on the backend's own model:

- **On add**, the rule is split only on the axes the backend cannot express.
  nftables stores a `FamilyAny` + `TCPUDP` rule as a single row; iptables must write
  a line per family, per transport and per chain, so a rule spanning all three axes
  becomes eight lines.
- **On read**, `GetRules` reports the firewall's actual rows. It reports a
  multi-state value only for an entry that genuinely carries both values and never
  fabricates one by pairing up separately-stored rows, so that same rule reads back
  as one rule from nftables and as eight from iptables.
- **On remove**, a target clears every row it covers. Where a stored row covers
  *more* than the target, the backend deletes it and re-adds the remainder in its
  place so the untargeted coverage survives; where its model cannot express the
  remainder, it returns `ErrUnsupported` rather than over-removing.
- Where an axis does not exist at all — `Capabilities().Output` is false, as on
  firewalld — a `DirAny` rule degrades to its input half (`DirInput`, same fields)
  rather than being rejected.

Because the read-back shape is backend-specific, a caller cannot check for a rule
with `==`. `Covers` and `CoveredBy` express the relation directly, and are the
supported way to test a multi-state rule against what the firewall actually holds:

```go
// Does this one rule contain that one?
want := &fw.Rule{Family: fw.FamilyAny, Proto: fw.TCPUDP, Direction: fw.DirAny, Port: 53, Action: fw.Accept}
want.Covers(&fw.Rule{Family: fw.IPv4, Proto: fw.UDP, Direction: fw.DirInput, Port: 53, Action: fw.Accept}) // true

// Is this rule fully present across a set — even if no single rule contains it?
existing, _ := mgr.GetRules(ctx, "")
if !want.CoveredBy(existing) {
    _ = mgr.AddRule(ctx, "", want)
}
```

`Covers` is asymmetric: a `TCPUDP` rule covers its TCP half, never the reverse.
`CoveredBy` is its set-valued inverse — it expands the receiver across all three
axes and requires every resulting cell to be covered by *some* rule in the set. That
is what makes it work against a fan-out backend, where no single stored row covers
the rule but the rows together do, and why a rule spanning both transports is not
reported present when only its TCP half is. `NATRule.Covers` and `NATRule.CoveredBy`
mirror them over family, the only axis a NAT rule spans. `Sync` compares this way,
which is why it stays a no-op against its own output whichever representation the
backend chose.

## NAT (port forwarding and masquerade)

NAT rules are managed separately from filter rules through
`AddNATRule`/`RemoveNATRule`/`GetNATRules`, using the `NATRule` type.

| Field       | Meaning                                                                          |
| ----------- | -------------------------------------------------------------------------------- |
| `Kind`      | `DNAT`, `Redirect`, `SNAT`, or `Masquerade`.                                     |
| `Family`    | `FamilyAny`, `IPv4`, or `IPv6`.                                                   |
| `Proto`     | Protocol to match (`TCP`, `UDP`, etc.).                                          |
| `Port`      | Matched destination port (`Ports` for a list/range). Requires a tcp/udp protocol. |
| `ToAddress` | Rewrite target address: new destination for `DNAT`, new source for `SNAT`.        |
| `ToPort`    | Rewrite target port (`DNAT`/`Redirect`). Unused for `SNAT`/`Masquerade`.          |
| `Interface` | Inbound interface for `DNAT`/`Redirect`; outbound for `SNAT`/`Masquerade`.       |
| `HasPrefix` | Informational flag, same semantics as `Rule.HasPrefix`.                          |

`DNAT` forwards inbound traffic to `ToAddress:ToPort`. `Redirect` sends matching
traffic to a local `ToPort`. `SNAT` rewrites the source to a fixed address, and
`Masquerade` uses the outgoing interface address. Backends that cannot express
NAT return `ErrUnsupportedNAT`.

## Capabilities

`mgr.Capabilities()` returns a `Capabilities` struct advertising which features
the active backend can express, so a caller can branch before trial-and-error:

```go
caps := mgr.Capabilities()
if !caps.NAT {
    log.Println("this backend cannot do NAT")
}
if caps.RuleCounters {
    // rules read back will carry Packets/Bytes
}
```

Every boolean corresponds to a `Rule`/`NATRule` field or an interface method. A
false field means the corresponding operation returns an unsupported error,
except `RuleCounters` and `Comments`, where it means `GetRules` reports the value
empty. Features every backend supports are not advertised as booleans. The matrix
below documents each backend's coverage, booleans and unconditional features
alike.

| Feature          | firewalld | ufw | CSF | APF | iptables | nftables | pf                   | WFP                      |
| ---------------- | --------- | --- | --- | --- | -------- | -------- | -------------------- | ------------------------ |
| Forward rules    | no        | yes | yes | yes | yes      | yes      | no                   | no                       |
| IPv6             | yes       | yes | yes | yes | yes      | yes      | yes                  | yes                      |
| ICMP             | yes       | yes | yes | yes | yes      | yes      | yes                  | yes                      |
| ICMP type        | yes       | yes | yes | yes | yes      | yes      | yes                  | yes                      |
| SCTP/GRE/ESP/AH  | yes       | yes | yes | yes | yes      | yes      | yes                  | partial (no SCTP port)   |
| Comment          | no        | yes | yes | yes | yes      | yes      | yes                  | yes                      |
| Port range       | yes       | yes | yes | yes | yes      | yes      | yes                  | yes                      |
| Port list        | no        | yes | yes | yes | yes      | yes      | yes                  | yes                      |
| Source port      | partial (not with a destination port) | yes | yes | yes | yes | yes | yes | yes          |
| Connection state | no        | yes | yes | yes | yes      | yes      | no                   | no                       |
| Interface match  | no        | yes | yes | yes | yes      | yes      | yes                  | no                       |
| Logging          | yes       | yes | yes | yes | yes      | yes      | partial (no prefix)  | no                       |
| Rate limit       | yes       | yes | yes | yes | yes      | yes      | partial (per-source) | no                       |
| Connection limit | no        | yes | yes | yes | yes      | yes      | partial (per-source) | no                       |
| NAT              | partial (forward-port and masquerade only) | yes | yes | yes | yes | yes | partial (no redirect) | no |

A `yes` means the feature is fully expressible, whatever route the backend takes
to get there: firewalld reaches several through a rich rule, ufw through its
route ruleset, and CSF and APF write the shapes their own config files cannot
hold through their managed pre-hook. A `partial` cell means the backend can only
express the narrowed form named beside it. Two of the `no` cells have a
backend-specific reason: firewalld binds interfaces to zones rather than matching
them per rule, and pf keeps state on a pass rule automatically but exposes no
equivalent of the connection-state match this model carries.

`Capabilities().DenyActionFromConfig` (true for CSF and APF) flags a backend whose
native deny store carries no per-entry action: the tool applies the action its own
config names (`csf.conf` `DROP`, `conf.apf` `ALL_STOP`), so a deny added with the
config's action is stored natively, one with a differing action is expressed
through the backend's pre-hook, and `RemoveRule` clears a native deny entry
whatever action the removal target names.

The `IPv6` row above is the one capability resolved per host rather than per
backend, and it covers every IPv6 rule shape, ICMPv6 included. CSF and APF report
it false when their own config disables IPv6 (`csf.conf` `IPV6`, `conf.apf`
`USE_IPV6`), since neither tool then keeps an IPv6 ruleset in sync. iptables
reports it false on a host whose packaging ships no ip6tables save file — a
system built without IPv6, or one that never installed the ip6tables package —
and manages IPv4 alone: reads report IPv4 rows only, a `FamilyAny` write narrows
to the IPv4 file, a concrete-IPv6 write returns `ErrUnsupported`, and a removal
is a no-op (there is nothing IPv6 to remove).

## Default policy

`GetDefaultPolicy`/`SetDefaultPolicy` read and set the default action applied to
packets that match no rule. A `DefaultPolicy` carries an `Action` per direction
(`Input`, `Output`, `Forward`); a direction left as `ActionInvalid` is not
exposed (on `Get`) or left unchanged (on `Set`). On a backend that supports it,
the policy is captured in a `Backup` and re-asserted by `Restore`, so a snapshot
of a default-drop host reproduces that policy on replay rather than inheriting the
restore host's.

| Backend      | Directions supported            |
| ------------ | ------------------------------- |
| iptables     | input, output, forward          |
| ufw          | input, output, forward          |
| nftables     | input, output, forward          |
| firewalld    | input (the zone target)         |
| others       | unsupported (`ErrUnsupportedPolicy`) |

## Address sets (ipset / nftset / pf tables)

Address sets are named collections of addresses (`AddressSet`) that rules can
match against, managed separately from filter and NAT rules. A `Backup` captures
the managed sets (with their entries) and `Restore` recreates them before the
rules, so a set-referencing rule (`@set`) resolves when a snapshot is replayed on
a host that does not yet have the set. They map onto the backend's native
construct:

| Backend   | Construct                          |
| --------- | ---------------------------------- |
| iptables  | ipset (`hash:ip`, `hash:net`)      |
| ufw       | ipset (via the host iptables)      |
| nftables  | a set in the private `inet` table  |
| firewalld | a firewalld ipset (D-Bus)          |
| pf        | a pf table                         |
| CSF/APF   | ipset commands in the managed pre-hook |
| WFP       | unsupported (`ErrUnsupportedSet`)  |

```go
set := &firewall.AddressSet{Name: "blocklist", Family: firewall.IPv4, Type: firewall.SetHashNet}
_ = mgr.AddAddressSet(ctx, set)
_ = mgr.AddAddressSetEntry(ctx, "blocklist", "203.0.113.0/24")
sets, _ := mgr.GetAddressSets(ctx)
```

## Testing

The Makefile drives every test path; run these from the repo root.

```sh
make test-general              # unit/parser tests — fast, no root, no VM
make test-integration-linux    # Linux backends end-to-end in a throwaway QEMU VM
make test-integration-freebsd  # pf end-to-end in a throwaway FreeBSD VM
make test-integration-windows  # Windows Firewall end-to-end in a throwaway Windows VM
make test-integration          # all three integration suites
make test                      # test-general plus every integration suite
make lint                      # golangci-lint across every target GOOS
```

`make test-general` is the plain `go test ./...` suite — rule encoding/decoding,
capability and helper logic. It never touches a live firewall and needs no root,
so it is the one to run while iterating.

The `test-integration*` targets boot disposable QEMU VMs and run the
capability-driven suite against the real backends inside them, so nothing on the
host is modified. Backend detection and rule application need the corresponding
firewall installed and running, which is what the VMs provide. Limit the Linux
run to particular backends with `BACKENDS`:

```sh
BACKENDS="nft firewalld ufw iptables apf csf" make test-integration-linux
```

They require `qemu-system-x86_64`, KVM (`/dev/kvm`), `genisoimage`, and
`python3` for the FreeBSD image. VM artifacts are cached under `./.cache`;
`make clean` removes that cache and the compiled test binaries.

macOS cannot be automated in a VM, so run its pf backend manually on a Mac:

```sh
sudo go test -tags integration -run TestIntegration
```
