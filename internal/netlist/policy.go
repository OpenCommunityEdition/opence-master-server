package netlist

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// The master admin's settings (the admin pages' Netlist), by their keys in
// the database: one entry a line, '#' a comment.
const (
	// autonomous systems added to the sources' ("AS13335")
	PolicyExtraASNs = "extra_asns"
	// autonomous systems whose ranges are taken out
	PolicyAllowASNs = "allow_asns"
	// ranges taken out (CIDRs, addresses, "first-last")
	PolicyAllow = "allow"
	// ranges added
	PolicyBlock = "block"
)

// PolicyKeys are the settings, in the page's order.
var PolicyKeys = []string{PolicyExtraASNs, PolicyAllowASNs, PolicyBlock, PolicyAllow}

// DefaultPolicy is the settings before the admin sets them: Cloudflare,
// whose WARP VPN's exits are not published apart from the rest of its
// network (X4BNet's lists leave it out).
var DefaultPolicy = map[string]string{
	PolicyExtraASNs: "AS13335 # Cloudflare: its WARP VPN's exits are not published apart",
}

// Policy is the master admin's settings, read.
type Policy struct {
	ExtraASNs, AllowASNs []uint32
	Allow, Block         []Range
}

// MaximumPolicyEntries is the most entries a setting takes.
const MaximumPolicyEntries = 10000

// entries calls entry with each entry of a setting's text: separated by
// lines, commas or spaces, '#' starting a comment to the line's end.
func entries(text string, entry func(line int, token string) error) error {
	var errs []error
	n := 0
	for i, line := range strings.Split(text, "\n") {
		if j := strings.IndexByte(line, '#'); j >= 0 {
			line = line[:j]
		}
		for _, token := range strings.FieldsFunc(line, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t' || r == '\r'
		}) {
			if n++; n > MaximumPolicyEntries {
				return fmt.Errorf("%d entries at most", MaximumPolicyEntries)
			}
			if err := entry(i+1, token); err != nil {
				errs = append(errs, err)
				if len(errs) >= 5 {
					return errors.Join(errs...)
				}
			}
		}
	}
	return errors.Join(errs...)
}

func parseASNs(text string) ([]uint32, error) {
	seen := map[uint32]bool{}
	var out []uint32
	err := entries(text, func(line int, token string) error {
		n, ok := ParseASN(token)
		if !ok {
			return fmt.Errorf("line %d: %q is not an autonomous system (AS13335, or 13335)", line, token)
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, err
}

func parseRanges(text string) ([]Range, error) {
	var out []Range
	err := entries(text, func(line int, token string) error {
		r, ok, err := ParseRangeText(token)
		if err != nil {
			return fmt.Errorf("line %d: %w (a CIDR, an address, or first-last)", line, err)
		}
		if !ok {
			return fmt.Errorf("line %d: %q is IPv6: the netlist is IPv4 only", line, token)
		}
		out = append(out, r)
		return nil
	})
	return Merge(out), err
}

// ParsePolicy reads the settings' texts (a missing one is its default),
// naming the setting and the line of each mistake.
func ParsePolicy(texts map[string]string) (Policy, error) {
	text := func(key string) string {
		if v, ok := texts[key]; ok {
			return v
		}
		return DefaultPolicy[key]
	}
	var p Policy
	var errs []error
	var err error
	if p.ExtraASNs, err = parseASNs(text(PolicyExtraASNs)); err != nil {
		errs = append(errs, fmt.Errorf("blocked autonomous systems: %w", err))
	}
	if p.AllowASNs, err = parseASNs(text(PolicyAllowASNs)); err != nil {
		errs = append(errs, fmt.Errorf("allowed autonomous systems: %w", err))
	}
	if p.Block, err = parseRanges(text(PolicyBlock)); err != nil {
		errs = append(errs, fmt.Errorf("blocked ranges: %w", err))
	}
	if p.Allow, err = parseRanges(text(PolicyAllow)); err != nil {
		errs = append(errs, fmt.Errorf("allowed ranges: %w", err))
	}
	return p, errors.Join(errs...)
}
