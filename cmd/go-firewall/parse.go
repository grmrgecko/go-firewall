package main

import (
	"fmt"
	"strconv"
	"strings"

	fw "github.com/grmrgecko/go-firewall"
)

// This file holds a small parser the firewall library keeps private
// (parseRateToken) but that the CLI needs to turn flag strings into library
// types. It intentionally mirrors the library's own logic so a CLI-authored rule
// is accepted identically to one the library writes. ICMP-type resolution is
// delegated to the library's exported fw.ParseICMPType so the CLI cannot drift
// from the backends' own name tables.

// parseRateToken parses a "<rate>/<unit>" token (e.g. "10/minute") into its
// numeric rate and unit. It is the flag-facing counterpart of RateLimit.String.
func parseRateToken(tok string) (uint, fw.RateUnit, error) {
	num, unitStr, ok := strings.Cut(strings.TrimSpace(tok), "/")
	if !ok {
		return 0, 0, fmt.Errorf("invalid rate %q (want <rate>/<unit>, e.g. 10/minute)", tok)
	}
	n, err := strconv.ParseUint(strings.TrimSpace(num), 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid rate %q: %w", tok, err)
	}
	unit, err := fw.ParseRateUnit(unitStr)
	if err != nil {
		return 0, 0, err
	}
	return uint(n), unit, nil
}

// parseProto resolves a --proto flag to a library Protocol, erroring on an
// unrecognized token instead of silently widening to "any". The library's
// GetProtocol returns ProtocolAny for both an empty value (the legitimate
// "match any protocol" default) and an unknown one, so a typo like "tpc" would
// otherwise pass through as an any-protocol rule — broader than the user asked
// for. An empty value, or the explicit spelling "any", is accepted as ProtocolAny.
func parseProto(tok string) (fw.Protocol, error) {
	p := fw.GetProtocol(tok)
	if p == fw.ProtocolAny && strings.TrimSpace(tok) != "" && !strings.EqualFold(strings.TrimSpace(tok), "any") {
		return 0, fmt.Errorf("unknown protocol %q", tok)
	}
	return p, nil
}
