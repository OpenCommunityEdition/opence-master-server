// Package netlist builds and serves the netlist: the IPv4 ranges of VPN
// providers, Tor exits and datacenters, from public sources and the master
// admin's own, merged into one list the master signs. Dedicated servers
// fetch it (GET /v1/netlist) and check joining players' addresses against
// it on their own. docs/master_protocol.md in the game's repository, "The
// netlist", is the format.
package netlist

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

// Magic starts a netlist's body.
const Magic = "OPCENET1"

// Format is the body's format.
const Format = 1

// HeaderSize is the body's size before its ranges.
const HeaderSize = 32

// MaximumRanges is the most ranges a reader takes.
const MaximumRanges = 1 << 20

// Range is the first and the last IPv4 address of a range, as numbers.
type Range struct {
	First, Last uint32
}

// Size is how many addresses the range holds.
func (r Range) Size() uint64 { return uint64(r.Last) - uint64(r.First) + 1 }

// String writes the range as "first-last" (one address alone for a range of
// one).
func (r Range) String() string {
	if r.First == r.Last {
		return Address(r.First).String()
	}
	return Address(r.First).String() + "-" + Address(r.Last).String()
}

// Address is a number's IPv4 address.
func Address(n uint32) netip.Addr {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	return netip.AddrFrom4(b)
}

// Number is an IPv4 address's number (false for another address).
func Number(a netip.Addr) (uint32, bool) {
	a = a.Unmap()
	if !a.Is4() {
		return 0, false
	}
	b := a.As4()
	return binary.BigEndian.Uint32(b[:]), true
}

// PrefixRange is a prefix's range (false for an IPv6 prefix).
func PrefixRange(p netip.Prefix) (Range, bool) {
	p = p.Masked()
	first, ok := Number(p.Addr())
	if !ok || p.Bits() < 0 {
		return Range{}, false
	}
	size := uint64(1) << (32 - p.Bits())
	return Range{First: first, Last: uint32(uint64(first) + size - 1)}, true
}

// Merge sorts ranges and joins those that overlap or touch, so that the last
// of one is at least 2 below the first of the next (the format's rule).
func Merge(ranges []Range) []Range {
	if len(ranges) == 0 {
		return nil
	}
	sorted := append([]Range(nil), ranges...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].First != sorted[j].First {
			return sorted[i].First < sorted[j].First
		}
		return sorted[i].Last < sorted[j].Last
	})
	out := sorted[:0:0]
	current := sorted[0]
	for _, r := range sorted[1:] {
		if r.First > current.Last && r.First-current.Last >= 2 {
			out = append(out, current)
			current = r
			continue
		}
		if r.Last > current.Last {
			current.Last = r.Last
		}
	}
	return append(out, current)
}

// Subtract takes the addresses of remove out of ranges; both are merged
// first.
func Subtract(ranges, remove []Range) []Range {
	ranges, remove = Merge(ranges), Merge(remove)
	var out []Range
	j := 0
	for _, r := range ranges {
		first := uint64(r.First)
		last := uint64(r.Last)
		for j < len(remove) && uint64(remove[j].Last) < first {
			j++
		}
		k := j
		for k < len(remove) && uint64(remove[k].First) <= last && first <= last {
			cut := remove[k]
			if uint64(cut.First) > first {
				out = append(out, Range{First: uint32(first), Last: cut.First - 1})
			}
			first = uint64(cut.Last) + 1
			k++
		}
		if first <= last {
			out = append(out, Range{First: uint32(first), Last: uint32(last)})
		}
	}
	return out
}

// Count is how many addresses the ranges hold (merged ranges: each once).
func Count(ranges []Range) uint64 {
	var n uint64
	for _, r := range ranges {
		n += r.Size()
	}
	return n
}

// Contains tells whether merged, sorted ranges hold an address.
func Contains(ranges []Range, n uint32) bool {
	i := sort.Search(len(ranges), func(i int) bool { return ranges[i].Last >= n })
	return i < len(ranges) && ranges[i].First <= n
}

// Equal tells whether two lists of ranges are the same.
func Equal(a, b []Range) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Encode writes a netlist's body: the magic, the format, 3 reserved bytes,
// the generated time, the serial, the count, then each range's first and
// last address, all in network byte order. The ranges are merged ones.
func Encode(ranges []Range, generated, serial uint64) []byte {
	body := make([]byte, HeaderSize+8*len(ranges))
	copy(body, Magic)
	body[8] = Format
	binary.BigEndian.PutUint64(body[12:], generated)
	binary.BigEndian.PutUint64(body[20:], serial)
	binary.BigEndian.PutUint32(body[28:], uint32(len(ranges)))
	for i, r := range ranges {
		binary.BigEndian.PutUint32(body[HeaderSize+8*i:], r.First)
		binary.BigEndian.PutUint32(body[HeaderSize+8*i+4:], r.Last)
	}
	return body
}

// List is a netlist read from a body.
type List struct {
	Generated, Serial uint64
	Ranges            []Range
}

// Decode reads a body as a server does, refusing one of the wrong size,
// without the magic and format 1, with a reserved byte set, of more than
// MaximumRanges ranges, or with ranges out of order, overlapping, touching
// or backwards.
func Decode(body []byte) (*List, error) {
	if len(body) < HeaderSize {
		return nil, errors.New("shorter than the header")
	}
	if string(body[:8]) != Magic {
		return nil, errors.New("not " + Magic)
	}
	if body[8] != Format {
		return nil, fmt.Errorf("format %d, not %d", body[8], Format)
	}
	if body[9] != 0 || body[10] != 0 || body[11] != 0 {
		return nil, errors.New("a reserved byte is set")
	}
	count := binary.BigEndian.Uint32(body[28:])
	if count > MaximumRanges {
		return nil, fmt.Errorf("%d ranges, more than %d", count, MaximumRanges)
	}
	if uint64(len(body)) != HeaderSize+8*uint64(count) {
		return nil, fmt.Errorf("%d bytes, not %d for %d ranges", len(body), HeaderSize+8*uint64(count), count)
	}
	l := &List{Generated: binary.BigEndian.Uint64(body[12:]), Serial: binary.BigEndian.Uint64(body[20:]),
		Ranges: make([]Range, count)}
	for i := range l.Ranges {
		r := Range{First: binary.BigEndian.Uint32(body[HeaderSize+8*i:]),
			Last: binary.BigEndian.Uint32(body[HeaderSize+8*i+4:])}
		if r.First > r.Last {
			return nil, fmt.Errorf("range %d: its first address is after its last", i)
		}
		if i > 0 {
			previous := l.Ranges[i-1]
			if r.First <= previous.Last {
				return nil, fmt.Errorf("range %d: out of order or overlapping", i)
			}
			if r.First-previous.Last < 2 {
				return nil, fmt.Errorf("range %d: touches the one before", i)
			}
		}
		l.Ranges[i] = r
	}
	return l, nil
}
