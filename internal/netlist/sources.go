package netlist

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// The kinds of sources.
const (
	// autonomous systems, "AS<n>" a line (X4BNet's input/*/ASN.txt)
	KindASN = "asn"
	// iptoasn.com's ip2asn-v4.tsv.gz: the ranges of every autonomous system
	KindIPToASN = "iptoasn"
	// a CIDR or an address a line (X4BNet's output/*/ipv4.txt)
	KindList = "list"
	// an address a line (the Tor Project's exits)
	KindTor = "tor"
)

// lines calls line with each line of a reader, without its comment ('#'
// and after) and spaces; blank lines are skipped.
func lines(r io.Reader, line func(text string) error) error {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		text := scanner.Text()
		if i := strings.IndexByte(text, '#'); i >= 0 {
			text = text[:i]
		}
		text = strings.TrimSpace(text)
		if text == "" {
			continue
		}
		if err := line(text); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// ParseASN reads "AS<n>" or "<n>".
func ParseASN(text string) (uint32, bool) {
	text = strings.TrimSpace(text)
	if len(text) > 2 && strings.EqualFold(text[:2], "AS") {
		text = text[2:]
	}
	n, err := strconv.ParseUint(text, 10, 32)
	if err != nil || n == 0 {
		return 0, false
	}
	return uint32(n), true
}

// ParseASNList reads a list of autonomous systems: the "AS<n>" token that
// starts each line ("AS9009 # M247, GB (NordVPN)"); comments, blank lines
// and other lines are skipped.
func ParseASNList(r io.Reader) ([]uint32, error) {
	seen := map[uint32]bool{}
	var out []uint32
	err := lines(r, func(text string) error {
		first := strings.Fields(text)[0]
		if n, ok := ParseASN(first); ok && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
		return nil
	})
	if err == nil && len(out) == 0 {
		err = errors.New("no autonomous system in it")
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, err
}

// ParseRangeText reads a CIDR ("1.2.3.0/24"), an address ("1.2.3.4") or a
// range ("1.2.3.4-1.2.3.9") of IPv4; ok is false for IPv6, and err set for
// what is none of these.
func ParseRangeText(text string) (r Range, ok bool, err error) {
	text = strings.TrimSpace(text)
	switch {
	case strings.Contains(text, "/"):
		p, err := netip.ParsePrefix(text)
		if err != nil {
			return r, false, fmt.Errorf("%q is not a CIDR", text)
		}
		r, ok = PrefixRange(p)
		return r, ok, nil
	case strings.Contains(text, "-"):
		a, b, _ := strings.Cut(text, "-")
		first, err1 := netip.ParseAddr(strings.TrimSpace(a))
		last, err2 := netip.ParseAddr(strings.TrimSpace(b))
		if err1 != nil || err2 != nil {
			return r, false, fmt.Errorf("%q is not a range of two addresses", text)
		}
		f, ok1 := Number(first)
		l, ok2 := Number(last)
		if ok1 != ok2 {
			return r, false, fmt.Errorf("%q mixes IPv4 and IPv6", text)
		}
		if !ok1 {
			return r, false, nil
		}
		if f > l {
			return r, false, fmt.Errorf("%q: its first address is after its last", text)
		}
		return Range{First: f, Last: l}, true, nil
	}
	a, err := netip.ParseAddr(text)
	if err != nil {
		return r, false, fmt.Errorf("%q is not an address", text)
	}
	n, ok := Number(a)
	return Range{First: n, Last: n}, ok, nil
}

// ParseRangeList reads a list of CIDRs and addresses, one a line (IPv6 ones
// skipped), merged. A line that is none of these fails the whole list, so
// that a page of something else (an error page) is not taken as a list.
func ParseRangeList(r io.Reader) ([]Range, error) {
	var out []Range
	err := lines(r, func(text string) error {
		got, ok, err := ParseRangeText(strings.Fields(text)[0])
		if err != nil {
			return err
		}
		if ok {
			out = append(out, got)
		}
		return nil
	})
	if err == nil && len(out) == 0 {
		err = errors.New("no IPv4 address in it")
	}
	return Merge(out), err
}

// Row is a range of one autonomous system.
type Row struct {
	First, Last, ASN uint32
}

// Table is iptoasn's table: every routed IPv4 range and its autonomous
// system, sorted, with the systems' names.
type Table struct {
	Rows  []Row
	Names map[uint32]string
}

// MaximumName is the longest autonomous system's name kept.
const MaximumName = 64

// ParseIPToASN reads iptoasn.com's ip2asn-v4.tsv.gz as it streams in:
// "first\tlast\tasn\tcountry\tdescription" a line, the addresses dotted.
// Ranges of no system (0, "Not routed") are left out. maximum caps the
// uncompressed bytes read.
func ParseIPToASN(compressed io.Reader, maximum int64) (*Table, error) {
	reader, err := gzip.NewReader(compressed)
	if err != nil {
		return nil, fmt.Errorf("not gzip: %w", err)
	}
	defer reader.Close()
	limited := &io.LimitedReader{R: reader, N: maximum + 1}
	t := &Table{Names: map[uint32]string{}}
	scanner := bufio.NewScanner(limited)
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	bad := 0
	for scanner.Scan() {
		fields := strings.SplitN(scanner.Text(), "\t", 5)
		if len(fields) < 3 {
			bad++
			continue
		}
		first, err1 := netip.ParseAddr(fields[0])
		last, err2 := netip.ParseAddr(fields[1])
		asn, err3 := strconv.ParseUint(fields[2], 10, 32)
		f, ok1 := Number(first)
		l, ok2 := Number(last)
		if err1 != nil || err2 != nil || err3 != nil || !ok1 || !ok2 || f > l {
			bad++
			continue
		}
		if asn == 0 {
			continue
		}
		t.Rows = append(t.Rows, Row{First: f, Last: l, ASN: uint32(asn)})
		if _, ok := t.Names[uint32(asn)]; !ok && len(fields) == 5 {
			t.Names[uint32(asn)] = cleanName(fields[4])
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if limited.N <= 0 {
		return nil, fmt.Errorf("more than %d bytes uncompressed", maximum)
	}
	if len(t.Rows) == 0 {
		return nil, errors.New("no IPv4 range in it")
	}
	if bad > len(t.Rows)/100 {
		return nil, fmt.Errorf("%d lines do not read as ranges", bad)
	}
	sort.Slice(t.Rows, func(i, j int) bool { return t.Rows[i].First < t.Rows[j].First })
	return t, nil
}

func cleanName(text string) string {
	b := []byte(strings.TrimSpace(text))
	for i, c := range b {
		if c < 0x20 || c > 0x7e {
			b[i] = '?'
		}
	}
	if len(b) > MaximumName {
		b = b[:MaximumName]
	}
	return string(b)
}

// Ranges are the ranges of a set of autonomous systems.
func (t *Table) Ranges(systems map[uint32]bool) []Range {
	var out []Range
	if t == nil {
		return nil
	}
	for _, row := range t.Rows {
		if systems[row.ASN] {
			out = append(out, Range{First: row.First, Last: row.Last})
		}
	}
	return Merge(out)
}

// Lookup is the autonomous system of an address (0 for none).
func (t *Table) Lookup(n uint32) uint32 {
	if t == nil {
		return 0
	}
	i := sort.Search(len(t.Rows), func(i int) bool { return t.Rows[i].Last >= n })
	if i < len(t.Rows) && t.Rows[i].First <= n {
		return t.Rows[i].ASN
	}
	return 0
}

// tableMagic starts a table's copy (the source's last good one, in the
// database).
const tableMagic = "OPCEASN1"

// MarshalBinary writes the table compactly, gzipped: the rows (first, last,
// system), then the names.
func (t *Table) MarshalBinary() ([]byte, error) {
	var buffer bytes.Buffer
	w := gzip.NewWriter(&buffer)
	var b [12]byte
	_, _ = w.Write([]byte(tableMagic))
	binary.BigEndian.PutUint32(b[:4], uint32(len(t.Rows)))
	_, _ = w.Write(b[:4])
	for _, row := range t.Rows {
		binary.BigEndian.PutUint32(b[0:], row.First)
		binary.BigEndian.PutUint32(b[4:], row.Last)
		binary.BigEndian.PutUint32(b[8:], row.ASN)
		_, _ = w.Write(b[:12])
	}
	asns := make([]uint32, 0, len(t.Names))
	for asn := range t.Names {
		asns = append(asns, asn)
	}
	sort.Slice(asns, func(i, j int) bool { return asns[i] < asns[j] })
	binary.BigEndian.PutUint32(b[:4], uint32(len(asns)))
	_, _ = w.Write(b[:4])
	for _, asn := range asns {
		name := t.Names[asn]
		binary.BigEndian.PutUint32(b[:4], asn)
		b[4] = byte(len(name))
		_, _ = w.Write(b[:5])
		_, _ = w.Write([]byte(name))
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// UnmarshalBinary reads what MarshalBinary wrote.
func (t *Table) UnmarshalBinary(data []byte) error {
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	r := bufio.NewReader(reader)
	var b [12]byte
	if _, err := io.ReadFull(r, b[:8]); err != nil || string(b[:8]) != tableMagic {
		return errors.New("not a table's copy")
	}
	if _, err := io.ReadFull(r, b[:4]); err != nil {
		return err
	}
	count := binary.BigEndian.Uint32(b[:4])
	if count > 1<<24 {
		return errors.New("a table's copy of too many rows")
	}
	t.Rows = make([]Row, count)
	for i := range t.Rows {
		if _, err := io.ReadFull(r, b[:12]); err != nil {
			return err
		}
		t.Rows[i] = Row{First: binary.BigEndian.Uint32(b[0:]), Last: binary.BigEndian.Uint32(b[4:]),
			ASN: binary.BigEndian.Uint32(b[8:])}
	}
	if _, err := io.ReadFull(r, b[:4]); err != nil {
		return err
	}
	names := binary.BigEndian.Uint32(b[:4])
	if names > 1<<24 {
		return errors.New("a table's copy of too many names")
	}
	t.Names = make(map[uint32]string, names)
	for range names {
		if _, err := io.ReadFull(r, b[:5]); err != nil {
			return err
		}
		name := make([]byte, b[4])
		if _, err := io.ReadFull(r, name); err != nil {
			return err
		}
		t.Names[binary.BigEndian.Uint32(b[:4])] = string(name)
	}
	return nil
}

// encodeRanges writes ranges as pairs of numbers (a list's last good copy).
func encodeRanges(ranges []Range) []byte {
	out := make([]byte, 8*len(ranges))
	for i, r := range ranges {
		binary.BigEndian.PutUint32(out[8*i:], r.First)
		binary.BigEndian.PutUint32(out[8*i+4:], r.Last)
	}
	return out
}

func decodeRanges(data []byte) ([]Range, error) {
	if len(data)%8 != 0 {
		return nil, errors.New("not a list's copy")
	}
	out := make([]Range, len(data)/8)
	for i := range out {
		out[i] = Range{First: binary.BigEndian.Uint32(data[8*i:]), Last: binary.BigEndian.Uint32(data[8*i+4:])}
	}
	return out, nil
}

// encodeASNs writes autonomous systems as numbers (a list's last good copy).
func encodeASNs(asns []uint32) []byte {
	out := make([]byte, 4*len(asns))
	for i, n := range asns {
		binary.BigEndian.PutUint32(out[4*i:], n)
	}
	return out
}

func decodeASNs(data []byte) ([]uint32, error) {
	if len(data)%4 != 0 {
		return nil, errors.New("not a list's copy")
	}
	out := make([]uint32, len(data)/4)
	for i := range out {
		out[i] = binary.BigEndian.Uint32(data[4*i:])
	}
	return out, nil
}
