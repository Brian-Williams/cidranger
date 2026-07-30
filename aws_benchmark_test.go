package cidranger

import (
	"encoding/json"
	"net/netip"
	"os"
	"testing"
)

type awsRangesBenchmarkData struct {
	Prefixes []struct {
		Prefix string `json:"ip_prefix"`
	} `json:"prefixes"`
	IPv6Prefixes []struct {
		Prefix string `json:"ipv6_prefix"`
	} `json:"ipv6_prefixes"`
}

func BenchmarkAWSContainsHitIPv4(b *testing.B) {
	benchmarkAWSContains(b, netip.MustParseAddr("52.95.110.1"))
}

func BenchmarkAWSContainsHitIPv6(b *testing.B) {
	benchmarkAWSContains(b, netip.MustParseAddr("2620:107:300f::36b7:ff81"))
}

func BenchmarkAWSContainsMissIPv4(b *testing.B) {
	benchmarkAWSContains(b, netip.MustParseAddr("123.123.123.123"))
}

func BenchmarkAWSContainsMissIPv6(b *testing.B) {
	benchmarkAWSContains(b, netip.MustParseAddr("2620::ffff"))
}

func BenchmarkAWSLookupHitIPv4(b *testing.B) {
	benchmarkAWSLookup(b, netip.MustParseAddr("52.95.110.1"))
}

func BenchmarkAWSLookupHitIPv6(b *testing.B) {
	benchmarkAWSLookup(b, netip.MustParseAddr("2620:107:300f::36b7:ff81"))
}

func BenchmarkAWSContainingNetworksHitIPv4(b *testing.B) {
	benchmarkAWSContainingNetworks(b, netip.MustParseAddr("52.95.110.1"))
}

func BenchmarkAWSContainingNetworksHitIPv6(b *testing.B) {
	benchmarkAWSContainingNetworks(b, netip.MustParseAddr("2620:107:300f::36b7:ff81"))
}

func benchmarkAWSContains(b *testing.B, addr netip.Addr) {
	// Membership-only users should choose struct{} so nodes carry no payload.
	ranger := newAWSBenchmarkRanger(b, func(int) struct{} { return struct{}{} })
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkFound, benchmarkErr = ranger.Contains(addr)
	}
}

func benchmarkAWSLookup(b *testing.B, addr netip.Addr) {
	ranger := newAWSBenchmarkRanger(b, func(index int) int { return index })
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkEntry, benchmarkFound, benchmarkErr = ranger.Lookup(addr)
	}
}

func benchmarkAWSContainingNetworks(b *testing.B, addr netip.Addr) {
	ranger := newAWSBenchmarkRanger(b, func(index int) int { return index })
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkEntries, benchmarkErr = ranger.ContainingNetworks(addr)
	}
}

func newAWSBenchmarkRanger[T any](tb testing.TB, value func(int) T) *Ranger[T] {
	tb.Helper()
	data, err := os.ReadFile("testdata/aws_ip_ranges.json")
	if err != nil {
		tb.Fatal(err)
	}
	var ranges awsRangesBenchmarkData
	if err := json.Unmarshal(data, &ranges); err != nil {
		tb.Fatal(err)
	}

	ranger := NewPCTrieRanger[T]()
	index := 0
	for _, item := range ranges.Prefixes {
		if err := ranger.Insert(netip.MustParsePrefix(item.Prefix), value(index)); err != nil {
			tb.Fatal(err)
		}
		index++
	}
	for _, item := range ranges.IPv6Prefixes {
		if err := ranger.Insert(netip.MustParsePrefix(item.Prefix), value(index)); err != nil {
			tb.Fatal(err)
		}
		index++
	}
	return ranger
}
