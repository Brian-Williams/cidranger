package cidranger

import (
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"reflect"
	"sort"
	"testing"
)

func TestPCTrieRanger(t *testing.T) {
	type metadata struct {
		Name  string
		Score int
	}

	ranger := NewPCTrieRanger[metadata]()
	entries := []Entry[metadata]{
		{netip.MustParsePrefix("0.0.0.0/0"), metadata{"all-v4", 1}},
		{netip.MustParsePrefix("192.0.2.0/24"), metadata{"test-v4", 2}},
		{netip.MustParsePrefix("192.0.2.128/25"), metadata{"specific-v4", 3}},
		{netip.MustParsePrefix("2001:db8::/32"), metadata{"test-v6", 4}},
		{netip.MustParsePrefix("2001:db8:1::/48"), metadata{"specific-v6", 5}},
	}
	for _, entry := range entries {
		if err := ranger.Insert(entry.Prefix, entry.Value); err != nil {
			t.Fatalf("Insert(%s): %v", entry.Prefix, err)
		}
	}

	if got, want := ranger.Len(), len(entries); got != want {
		t.Fatalf("Len() = %d, want %d", got, want)
	}

	tests := []struct {
		addr string
		want []string
	}{
		{"192.0.2.1", []string{"all-v4", "test-v4"}},
		{"192.0.2.200", []string{"all-v4", "test-v4", "specific-v4"}},
		{"198.51.100.1", []string{"all-v4"}},
		{"2001:db8:1::1", []string{"test-v6", "specific-v6"}},
		{"2001:db9::1", nil},
	}
	for _, test := range tests {
		t.Run(test.addr, func(t *testing.T) {
			addr := netip.MustParseAddr(test.addr)
			gotContains, err := ranger.Contains(addr)
			if err != nil {
				t.Fatal(err)
			}
			if gotContains != (len(test.want) > 0) {
				t.Fatalf("Contains() = %t, want %t", gotContains, len(test.want) > 0)
			}

			got, err := ranger.ContainingNetworks(addr)
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, entry := range got {
				names = append(names, entry.Value.Name)
			}
			if !reflect.DeepEqual(names, test.want) {
				t.Fatalf("ContainingNetworks() = %v, want %v", names, test.want)
			}
		})
	}
}

func TestInsertMasksPrefixAndReplacesValue(t *testing.T) {
	ranger := NewPCTrieRanger[string]()
	nonCanonical := netip.PrefixFrom(netip.MustParseAddr("192.0.2.129"), 24)
	if err := ranger.Insert(nonCanonical, "old"); err != nil {
		t.Fatal(err)
	}
	if err := ranger.Insert(netip.MustParsePrefix("192.0.2.0/24"), "new"); err != nil {
		t.Fatal(err)
	}

	if got := ranger.Len(); got != 1 {
		t.Fatalf("Len() = %d, want 1", got)
	}
	got, err := ranger.ContainingNetworks(netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	want := []Entry[string]{{netip.MustParsePrefix("192.0.2.0/24"), "new"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ContainingNetworks() = %#v, want %#v", got, want)
	}
}

func TestIPv4MappedIPv6RemainsIPv6(t *testing.T) {
	ranger := NewPCTrieRanger[string]()
	mappedPrefix := netip.MustParsePrefix("::ffff:192.0.2.0/120")
	if err := ranger.Insert(mappedPrefix, "mapped"); err != nil {
		t.Fatal(err)
	}

	entry, found, err := ranger.Lookup(netip.MustParseAddr("::ffff:192.0.2.1"))
	if err != nil || !found || entry.Prefix != mappedPrefix {
		t.Fatalf("mapped IPv6 Lookup() = %#v, %t, %v", entry, found, err)
	}
	if found, err := ranger.Contains(netip.MustParseAddr("192.0.2.1")); err != nil || found {
		t.Fatalf("IPv4 Contains() = %t, %v; mapped IPv6 must remain a separate family", found, err)
	}
}

func TestLookupReturnsMostSpecificEntry(t *testing.T) {
	ranger := NewPCTrieRanger[string]()
	for prefix, value := range map[string]string{
		"10.0.0.0/8":        "v4 /8",
		"10.1.0.0/16":       "v4 /16",
		"10.1.2.0/24":       "v4 /24",
		"2001:db8::/32":     "v6 /32",
		"2001:db8:1::/48":   "v6 /48",
		"2001:db8:1:2::/64": "v6 /64",
	} {
		if err := ranger.Insert(netip.MustParsePrefix(prefix), value); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		addr       string
		wantPrefix string
		wantValue  string
		wantFound  bool
	}{
		{"10.1.2.3", "10.1.2.0/24", "v4 /24", true},
		{"10.1.3.4", "10.1.0.0/16", "v4 /16", true},
		{"10.2.3.4", "10.0.0.0/8", "v4 /8", true},
		{"11.0.0.1", "", "", false},
		{"2001:db8:1:2::1", "2001:db8:1:2::/64", "v6 /64", true},
		{"2001:db8:2::1", "2001:db8::/32", "v6 /32", true},
		{"2001:db9::1", "", "", false},
	}
	for _, test := range tests {
		t.Run(test.addr, func(t *testing.T) {
			entry, found, err := ranger.Lookup(netip.MustParseAddr(test.addr))
			if err != nil {
				t.Fatal(err)
			}
			if found != test.wantFound {
				t.Fatalf("Lookup() found = %t, want %t", found, test.wantFound)
			}
			if !found {
				return
			}
			if entry.Prefix.String() != test.wantPrefix || entry.Value != test.wantValue {
				t.Fatalf("Lookup() = %#v, want prefix %s value %q", entry, test.wantPrefix, test.wantValue)
			}
		})
	}
}

func TestRemoveAndCompression(t *testing.T) {
	ranger := NewPCTrieRanger[int]()
	prefixes := []string{
		"10.0.0.0/8",
		"10.1.0.0/16",
		"10.1.1.0/24",
		"10.2.0.0/16",
		"2001:db8::/32",
	}
	for i, raw := range prefixes {
		if err := ranger.Insert(netip.MustParsePrefix(raw), i); err != nil {
			t.Fatal(err)
		}
	}

	removed, found, err := ranger.Remove(netip.MustParsePrefix("10.1.0.0/16"))
	if err != nil {
		t.Fatal(err)
	}
	if !found || removed.Value != 1 || removed.Prefix.String() != "10.1.0.0/16" {
		t.Fatalf("Remove() = %#v, %t; want removed value 1", removed, found)
	}

	entries, err := ranger.ContainingNetworks(netip.MustParseAddr("10.1.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := entryPrefixes(entries), []string{"10.0.0.0/8", "10.1.1.0/24"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("ContainingNetworks() = %v, want %v", got, want)
	}

	if _, found, err := ranger.Remove(netip.MustParsePrefix("10.1.0.0/16")); err != nil || found {
		t.Fatalf("second Remove() found=%t err=%v, want false, nil", found, err)
	}
	if got := ranger.Len(); got != len(prefixes)-1 {
		t.Fatalf("Len() = %d, want %d", got, len(prefixes)-1)
	}
}

func TestCoveredNetworks(t *testing.T) {
	ranger := NewPCTrieRanger[struct{}]()
	for _, raw := range []string{
		"10.0.0.0/8",
		"10.1.0.0/16",
		"10.1.1.0/24",
		"10.2.0.0/16",
		"11.0.0.0/8",
		"2001:db8::/32",
		"2001:db8:1::/48",
	} {
		if err := ranger.Insert(netip.MustParsePrefix(raw), struct{}{}); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		prefix string
		want   []string
	}{
		{"10.1.0.0/16", []string{"10.1.0.0/16", "10.1.1.0/24"}},
		{"10.0.0.0/9", []string{"10.1.0.0/16", "10.1.1.0/24", "10.2.0.0/16"}},
		{"0.0.0.0/0", []string{"10.0.0.0/8", "10.1.0.0/16", "10.1.1.0/24", "10.2.0.0/16", "11.0.0.0/8"}},
		{"2001:db8::/32", []string{"2001:db8::/32", "2001:db8:1::/48"}},
		{"192.0.2.0/24", nil},
	}
	for _, test := range tests {
		t.Run(test.prefix, func(t *testing.T) {
			got, err := ranger.CoveredNetworks(netip.MustParsePrefix(test.prefix))
			if err != nil {
				t.Fatal(err)
			}
			gotPrefixes := entryPrefixes(got)
			sort.Strings(gotPrefixes)
			sort.Strings(test.want)
			if !reflect.DeepEqual(gotPrefixes, test.want) {
				t.Fatalf("CoveredNetworks() = %v, want %v", gotPrefixes, test.want)
			}
		})
	}
}

func TestInvalidInput(t *testing.T) {
	ranger := NewPCTrieRanger[struct{}]()

	if err := ranger.Insert(netip.Prefix{}, struct{}{}); !errors.Is(err, ErrInvalidNetworkInput) {
		t.Fatalf("Insert() error = %v, want %v", err, ErrInvalidNetworkInput)
	}
	if _, _, err := ranger.Remove(netip.Prefix{}); !errors.Is(err, ErrInvalidNetworkInput) {
		t.Fatalf("Remove() error = %v, want %v", err, ErrInvalidNetworkInput)
	}
	if _, err := ranger.CoveredNetworks(netip.Prefix{}); !errors.Is(err, ErrInvalidNetworkInput) {
		t.Fatalf("CoveredNetworks() error = %v, want %v", err, ErrInvalidNetworkInput)
	}
	if _, err := ranger.Contains(netip.Addr{}); !errors.Is(err, ErrInvalidNetworkNumberInput) {
		t.Fatalf("Contains() error = %v, want %v", err, ErrInvalidNetworkNumberInput)
	}
	if _, _, err := ranger.Lookup(netip.Addr{}); !errors.Is(err, ErrInvalidNetworkNumberInput) {
		t.Fatalf("Lookup() error = %v, want %v", err, ErrInvalidNetworkNumberInput)
	}
	if _, err := ranger.ContainingNetworks(netip.MustParseAddr("fe80::1%eth0")); !errors.Is(err, ErrInvalidNetworkNumberInput) {
		t.Fatalf("ContainingNetworks() error = %v, want %v", err, ErrInvalidNetworkNumberInput)
	}
}

func TestAddressFamilyRootsAllocatedLazily(t *testing.T) {
	ranger := NewPCTrieRanger[struct{}]()
	if ranger.ipv4 != nil || ranger.ipv6 != nil {
		t.Fatal("NewPCTrieRanger allocated roots before the first insertion")
	}

	ipv4Prefix := netip.MustParsePrefix("192.0.2.0/24")
	if err := ranger.Insert(ipv4Prefix, struct{}{}); err != nil {
		t.Fatal(err)
	}
	if ranger.ipv4 == nil || ranger.ipv6 != nil {
		t.Fatalf("IPv4 insert roots = (%p, %p), want (non-nil, nil)", ranger.ipv4, ranger.ipv6)
	}

	// A lookup in an unused family must not allocate that family's root.
	if found, err := ranger.Contains(netip.MustParseAddr("2001:db8::1")); err != nil || found {
		t.Fatalf("IPv6 Contains() = %t, %v; want false, nil", found, err)
	}
	if ranger.ipv6 != nil {
		t.Fatal("IPv6 lookup allocated an empty root")
	}

	if _, found, err := ranger.Remove(ipv4Prefix); err != nil || !found {
		t.Fatalf("Remove() found=%t err=%v, want true, nil", found, err)
	}
	if ranger.ipv4 != nil {
		t.Fatal("removing the last IPv4 prefix retained an empty root")
	}
}

func TestLookupDoesNotAllocate(t *testing.T) {
	ranger := NewPCTrieRanger[int]()
	for i, prefix := range []string{
		"10.0.0.0/8",
		"10.1.0.0/16",
		"10.1.2.0/24",
		"10.1.2.3/32",
	} {
		if err := ranger.Insert(netip.MustParsePrefix(prefix), i); err != nil {
			t.Fatal(err)
		}
	}
	addr := netip.MustParseAddr("10.1.2.3")

	allocations := testing.AllocsPerRun(1_000, func() {
		benchmarkEntry, benchmarkFound, benchmarkErr = ranger.Lookup(addr)
	})
	if allocations != 0 {
		t.Fatalf("Lookup() allocations = %f, want 0", allocations)
	}
}

func TestZeroValueRanger(t *testing.T) {
	var ranger Ranger[string]
	prefix := netip.MustParsePrefix("198.51.100.0/24")
	addr := netip.MustParseAddr("198.51.100.1")

	contains, err := ranger.Contains(addr)
	if err != nil || contains {
		t.Fatalf("zero-value Contains() = %t, %v; want false, nil", contains, err)
	}
	if err := ranger.Insert(prefix, "TEST-NET-2"); err != nil {
		t.Fatal(err)
	}
	contains, err = ranger.Contains(addr)
	if err != nil || !contains {
		t.Fatalf("Contains() after Insert = %t, %v; want true, nil", contains, err)
	}
}

func TestRandomizedAgainstBruteForce(t *testing.T) {
	random := rand.New(rand.NewSource(1))
	ranger := NewPCTrieRanger[int]()
	entries := make(map[netip.Prefix]int)

	for i := 0; i < 2_000; i++ {
		prefix := randomPrefix(random, i%2 == 0)
		entries[prefix] = i
		if err := ranger.Insert(prefix, i); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := ranger.Len(), len(entries); got != want {
		t.Fatalf("Len() = %d, want %d", got, want)
	}

	for i := 0; i < 20_000; i++ {
		addr := randomAddr(random, i%2 == 0)
		var want []netip.Prefix
		for prefix := range entries {
			if prefix.Contains(addr) {
				want = append(want, prefix)
			}
		}
		sortPrefixes(want)

		got, err := ranger.ContainingNetworks(addr)
		if err != nil {
			t.Fatal(err)
		}
		var gotPrefixes []netip.Prefix
		for i := range got {
			gotPrefixes = append(gotPrefixes, got[i].Prefix)
		}
		if !reflect.DeepEqual(gotPrefixes, want) {
			t.Fatalf("ContainingNetworks(%s) = %v, want %v", addr, gotPrefixes, want)
		}

		contains, err := ranger.Contains(addr)
		if err != nil {
			t.Fatal(err)
		}
		if contains != (len(want) > 0) {
			t.Fatalf("Contains(%s) = %t, want %t", addr, contains, len(want) > 0)
		}

		entry, found, err := ranger.Lookup(addr)
		if err != nil {
			t.Fatal(err)
		}
		if found != (len(want) > 0) {
			t.Fatalf("Lookup(%s) found = %t, want %t", addr, found, len(want) > 0)
		}
		if found {
			wantPrefix := want[len(want)-1]
			if entry.Prefix != wantPrefix || entry.Value != entries[wantPrefix] {
				t.Fatalf(
					"Lookup(%s) = %#v, want prefix %s value %d",
					addr,
					entry,
					wantPrefix,
					entries[wantPrefix],
				)
			}
		}
	}

	// CoveredNetworks takes a different traversal path: it may descend to a
	// query prefix and then enumerate an entire subtree. Compare both halves of
	// that operation against netip's containment semantics.
	for i := 0; i < 1_000; i++ {
		query := randomPrefix(random, i%2 == 0)
		var want []netip.Prefix
		for prefix := range entries {
			if query.Bits() <= prefix.Bits() && query.Contains(prefix.Addr()) {
				want = append(want, prefix)
			}
		}
		sortPrefixes(want)

		got, err := ranger.CoveredNetworks(query)
		if err != nil {
			t.Fatal(err)
		}
		var gotPrefixes []netip.Prefix
		for i := range got {
			gotPrefixes = append(gotPrefixes, got[i].Prefix)
		}
		sortPrefixes(gotPrefixes)
		if !reflect.DeepEqual(gotPrefixes, want) {
			t.Fatalf("CoveredNetworks(%s) = %v, want %v", query, gotPrefixes, want)
		}
	}
}

func TestRandomizedRemovalAgainstBruteForce(t *testing.T) {
	random := rand.New(rand.NewSource(2))
	ranger := NewPCTrieRanger[int]()
	entries := make(map[netip.Prefix]int)
	for i := 0; i < 1_000; i++ {
		prefix := randomPrefix(random, i%2 == 0)
		entries[prefix] = i
		if err := ranger.Insert(prefix, i); err != nil {
			t.Fatal(err)
		}
	}

	prefixes := make([]netip.Prefix, 0, len(entries))
	for prefix := range entries {
		prefixes = append(prefixes, prefix)
	}
	random.Shuffle(len(prefixes), func(i, j int) {
		prefixes[i], prefixes[j] = prefixes[j], prefixes[i]
	})

	for i, prefix := range prefixes {
		wantValue := entries[prefix]
		removed, found, err := ranger.Remove(prefix)
		if err != nil || !found {
			t.Fatalf("Remove(%s) found=%t err=%v", prefix, found, err)
		}
		if removed.Prefix != prefix || removed.Value != wantValue {
			t.Fatalf("Remove(%s) = %#v, want value %d", prefix, removed, wantValue)
		}
		delete(entries, prefix)
		if ranger.Len() != len(entries) {
			t.Fatalf("Len() = %d after %d removals, want %d", ranger.Len(), i+1, len(entries))
		}

		// Sample the compressed trie throughout teardown, including after
		// structural branch nodes have been bypassed.
		if i%10 == 0 {
			addr := randomAddr(random, i%2 == 0)
			var want []netip.Prefix
			for remaining := range entries {
				if remaining.Contains(addr) {
					want = append(want, remaining)
				}
			}
			sortPrefixes(want)
			got, err := ranger.ContainingNetworks(addr)
			if err != nil {
				t.Fatal(err)
			}
			var gotPrefixes []netip.Prefix
			for i := range got {
				gotPrefixes = append(gotPrefixes, got[i].Prefix)
			}
			if !reflect.DeepEqual(gotPrefixes, want) {
				t.Fatalf("ContainingNetworks(%s) = %v, want %v", addr, gotPrefixes, want)
			}
		}
	}
	if ranger.ipv4 != nil || ranger.ipv6 != nil {
		t.Fatalf("removing all prefixes retained roots (%p, %p)", ranger.ipv4, ranger.ipv6)
	}
}

func BenchmarkPCTrieContainsIPv4(b *testing.B) {
	benchmarkContains(b, netip.MustParseAddr("52.95.110.1"), 24)
}

func BenchmarkPCTrieContainsIPv6(b *testing.B) {
	benchmarkContains(b, netip.MustParseAddr("2001:db8:1234::1"), 64)
}

func BenchmarkPCTrieLookupIPv4(b *testing.B) {
	benchmarkLookup(b, netip.MustParseAddr("52.95.110.1"), 24)
}

func BenchmarkPCTrieLookupIPv6(b *testing.B) {
	benchmarkLookup(b, netip.MustParseAddr("2001:db8:1234::1"), 64)
}

func BenchmarkPCTrieContainingNetworksIPv4(b *testing.B) {
	benchmarkContainingNetworks(b, netip.MustParseAddr("52.95.110.1"), 24)
}

func BenchmarkPCTrieContainingNetworksIPv6(b *testing.B) {
	benchmarkContainingNetworks(b, netip.MustParseAddr("2001:db8:1234::1"), 64)
}

var (
	benchmarkEntry   Entry[int]
	benchmarkEntries []Entry[int]
	benchmarkFound   bool
	benchmarkErr     error
)

func benchmarkContains(b *testing.B, addr netip.Addr, prefixBits int) {
	ranger := populatedBenchmarkRanger(b, addr, prefixBits)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkFound, benchmarkErr = ranger.Contains(addr)
	}
}

func benchmarkLookup(b *testing.B, addr netip.Addr, prefixBits int) {
	ranger := populatedBenchmarkRanger(b, addr, prefixBits)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkEntry, benchmarkFound, benchmarkErr = ranger.Lookup(addr)
	}
}

func benchmarkContainingNetworks(b *testing.B, addr netip.Addr, prefixBits int) {
	ranger := populatedBenchmarkRanger(b, addr, prefixBits)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkEntries, benchmarkErr = ranger.ContainingNetworks(addr)
	}
}

func populatedBenchmarkRanger(tb testing.TB, addr netip.Addr, prefixBits int) *Ranger[int] {
	tb.Helper()
	ranger := NewPCTrieRanger[int]()
	random := rand.New(rand.NewSource(1))
	for i := 0; i < 10_000; i++ {
		generatedAddr := randomAddr(random, addr.Is4())
		prefix := netip.PrefixFrom(generatedAddr, prefixBits).Masked()
		if err := ranger.Insert(prefix, i); err != nil {
			tb.Fatal(err)
		}
	}
	target := netip.PrefixFrom(addr, addr.BitLen()).Masked()
	if err := ranger.Insert(target, 10_000); err != nil {
		tb.Fatal(err)
	}
	return ranger
}

func entryPrefixes[T any](entries []Entry[T]) []string {
	var prefixes []string
	for _, entry := range entries {
		prefixes = append(prefixes, entry.Prefix.String())
	}
	return prefixes
}

func randomPrefix(random *rand.Rand, ipv4 bool) netip.Prefix {
	addr := randomAddr(random, ipv4)
	bits := 128
	if ipv4 {
		bits = 32
	}
	return netip.PrefixFrom(addr, random.Intn(bits+1)).Masked()
}

func randomAddr(random *rand.Rand, ipv4 bool) netip.Addr {
	if ipv4 {
		return netip.AddrFrom4([4]byte{
			byte(random.Uint32()),
			byte(random.Uint32()),
			byte(random.Uint32()),
			byte(random.Uint32()),
		})
	}
	var bytes [16]byte
	for i := range bytes {
		bytes[i] = byte(random.Uint32())
	}
	return netip.AddrFrom16(bytes)
}

func sortPrefixes(prefixes []netip.Prefix) {
	sort.Slice(prefixes, func(i, j int) bool {
		if prefixes[i].Bits() != prefixes[j].Bits() {
			return prefixes[i].Bits() < prefixes[j].Bits()
		}
		return prefixes[i].Addr().Less(prefixes[j].Addr())
	})
}

func ExampleNewPCTrieRanger() {
	ranger := NewPCTrieRanger[string]()
	_ = ranger.Insert(netip.MustParsePrefix("192.0.2.0/24"), "TEST-NET-1")

	entry, found, _ := ranger.Lookup(netip.MustParseAddr("192.0.2.10"))
	fmt.Println(found, entry.Value)
	// Output: true TEST-NET-1
}
