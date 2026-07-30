package cidranger

import (
	"net/netip"
	"strings"
	"testing"
)

func TestTriePathCompression(t *testing.T) {
	ranger := NewPCTrieRanger[string]()
	for _, raw := range []string{
		"192.0.2.1/32",
		"192.0.2.2/32",
		"192.0.2.128/25",
	} {
		if err := ranger.Insert(netip.MustParsePrefix(raw), raw); err != nil {
			t.Fatal(err)
		}
	}

	got := ranger.String()
	for _, want := range []string{
		"192.0.2.0/24 (target_pos:7:has_entry:false)",
		"192.0.2.0/30 (target_pos:1:has_entry:false)",
		"192.0.2.1/32 (target_pos:-1:has_entry:true)",
		"192.0.2.2/32 (target_pos:-1:has_entry:true)",
		"192.0.2.128/25 (target_pos:6:has_entry:true)",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("String() missing %q:\n%s", want, got)
		}
	}
}

func TestBitAt(t *testing.T) {
	tests := []struct {
		addr     string
		position int
		want     uint8
	}{
		{"128.0.0.0", 0, 1},
		{"64.0.0.0", 0, 0},
		{"64.0.0.0", 1, 1},
		{"2001:db8::", 0, 0},
		{"8000::", 0, 1},
		{"::1", 127, 1},
	}
	for _, test := range tests {
		if got := packAddress(netip.MustParseAddr(test.addr)).bitAt(test.position); got != test.want {
			t.Errorf("bitAt(%s, %d) = %d, want %d", test.addr, test.position, got, test.want)
		}
	}
}

func TestCommonPrefixBits(t *testing.T) {
	tests := []struct {
		left, right string
		limit       int
		want        int
	}{
		{"192.0.2.1", "192.0.2.2", 32, 30},
		{"0.0.0.0", "255.0.0.0", 32, 0},
		{"192.0.2.1", "192.0.2.2", 24, 24},
		{"2001:db8::1", "2001:db8::2", 128, 126},
	}
	for _, test := range tests {
		got := packPrefix(netip.PrefixFrom(
			netip.MustParseAddr(test.left),
			netip.MustParseAddr(test.left).BitLen(),
		)).commonBits(
			packPrefix(netip.PrefixFrom(
				netip.MustParseAddr(test.right),
				netip.MustParseAddr(test.right).BitLen(),
			)),
			test.limit,
		)
		if got != test.want {
			t.Errorf("commonPrefixBits(%s, %s, %d) = %d, want %d", test.left, test.right, test.limit, got, test.want)
		}
	}
}

func TestPackedPrefixRoundTrip(t *testing.T) {
	for _, raw := range []string{
		"0.0.0.0/0",
		"128.0.0.0/1",
		"192.0.2.0/24",
		"192.0.2.254/31",
		"192.0.2.255/32",
		"::/0",
		"8000::/1",
		"2001:db8::/63",
		"2001:db8::/64",
		"2001:db8::/65",
		"2001:db8::/127",
		"2001:db8::1/128",
		"::ffff:192.0.2.0/120",
	} {
		prefix := netip.MustParsePrefix(raw)
		if got := packPrefix(prefix).netipPrefix(); got != prefix {
			t.Errorf("packPrefix(%s).netipPrefix() = %s", prefix, got)
		}
	}
}

func TestPackedPrefixWithBits(t *testing.T) {
	for _, rawAddr := range []string{
		"255.255.255.255",
		"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
	} {
		addr := netip.MustParseAddr(rawAddr)
		for prefixBits := 0; prefixBits <= addr.BitLen(); prefixBits++ {
			full := packPrefix(netip.PrefixFrom(addr, addr.BitLen()))
			got := full.withBits(prefixBits).netipPrefix()
			want := netip.PrefixFrom(addr, prefixBits).Masked()
			if got != want {
				t.Fatalf("%s.withBits(%d) = %s, want %s", rawAddr, prefixBits, got, want)
			}
		}
	}
}

func TestPackedPrefixContainsBoundaries(t *testing.T) {
	tests := []struct {
		prefix string
		addr   string
		want   bool
	}{
		{"0.0.0.0/0", "255.255.255.255", true},
		{"192.0.2.0/31", "192.0.2.1", true},
		{"192.0.2.0/31", "192.0.2.2", false},
		{"192.0.2.1/32", "192.0.2.1", true},
		{"192.0.2.1/32", "192.0.2.0", false},
		{"::/0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"2001:db8::/63", "2001:db8:0:1:ffff::1", true},
		{"2001:db8::/64", "2001:db8:0:1::", false},
		{"2001:db8::/65", "2001:db8::7fff:ffff:ffff:ffff", true},
		{"2001:db8::/65", "2001:db8::8000:0:0:0", false},
		{"2001:db8::/127", "2001:db8::1", true},
		{"2001:db8::1/128", "2001:db8::2", false},
	}
	for _, test := range tests {
		prefix := packPrefix(netip.MustParsePrefix(test.prefix))
		addr := packAddress(netip.MustParseAddr(test.addr))
		if got := prefix.contains(addr); got != test.want {
			t.Errorf("%s contains %s = %t, want %t", test.prefix, test.addr, got, test.want)
		}
	}
}
