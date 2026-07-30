// Example custom values stored in a generic cidranger v2 trie.
package main

import (
	"fmt"
	"net/netip"
	"os"

	"github.com/yl2chen/cidranger/v2"
)

type asnMetadata struct {
	ASN string
}

func main() {
	ranger := cidranger.NewPCTrieRanger[asnMetadata]()

	for prefix, asn := range map[string]string{
		"192.168.1.0/24": "0001",
		"128.168.1.0/24": "0002",
	} {
		if err := ranger.Insert(netip.MustParsePrefix(prefix), asnMetadata{ASN: asn}); err != nil {
			fmt.Println("Insert:", err)
			os.Exit(1)
		}
	}

	addr := netip.MustParseAddr("128.168.1.7")
	contains, err := ranger.Contains(addr)
	if err != nil {
		fmt.Println("Contains:", err)
		os.Exit(1)
	}
	fmt.Println("Contains:", contains)

	addr = netip.MustParseAddr("192.168.1.42")
	entries, err := ranger.ContainingNetworks(addr)
	if err != nil {
		fmt.Println("ContainingNetworks:", err)
		os.Exit(1)
	}

	fmt.Printf("Entries for %s:\n", addr)
	for _, entry := range entries {
		fmt.Println("\t", entry.Prefix, entry.Value.ASN)
	}
}
