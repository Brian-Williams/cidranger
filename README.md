# cidranger v2

Fast IPv4 and IPv6 prefix containment lookups using a generic,
path-compressed trie.

Version 2 uses [`net/netip`](https://pkg.go.dev/net/netip) throughout. Addresses
are `netip.Addr`, networks are `netip.Prefix`, and associated values are stored
as their concrete generic type instead of as interface values.

## Install

```shell
go get github.com/Brian-Williams/cidranger/v2
```

## Prefix membership

Use `struct{}` when prefixes do not need associated data:

```go
package main

import (
	"fmt"
	"net/netip"

	"github.com/Brian-Williams/cidranger/v2"
)

func main() {
	ranger := cidranger.NewPCTrieRanger[struct{}]()
	_ = ranger.Insert(netip.MustParsePrefix("192.0.2.0/24"), struct{}{})

	contains, _ := ranger.Contains(netip.MustParseAddr("192.0.2.10"))
	fmt.Println(contains) // true
}
```

## Associated values

Any value type can be stored without implementing an interface:

```go
type Metadata struct {
	ASN  uint32
	Name string
}

ranger := cidranger.NewPCTrieRanger[Metadata]()
prefix := netip.MustParsePrefix("2001:db8::/32")

err := ranger.Insert(prefix, Metadata{ASN: 64496, Name: "example"})
entry, found, err := ranger.Lookup(netip.MustParseAddr("2001:db8::1"))

if found {
	fmt.Println(entry.Prefix)
	fmt.Println(entry.Value.ASN)
}
```

## API

```go
func NewPCTrieRanger[T any]() *Ranger[T]

func (r *Ranger[T]) Insert(netip.Prefix, T) error
func (r *Ranger[T]) Remove(netip.Prefix) (Entry[T], bool, error)
func (r *Ranger[T]) Contains(netip.Addr) (bool, error)
func (r *Ranger[T]) Lookup(netip.Addr) (Entry[T], bool, error)
func (r *Ranger[T]) ContainingNetworks(netip.Addr) ([]Entry[T], error)
func (r *Ranger[T]) CoveredNetworks(netip.Prefix) ([]Entry[T], error)
func (r *Ranger[T]) Len() int
```

`Lookup` returns the most-specific matching entry without allocating a result
slice. `ContainingNetworks` returns all entries from the shortest matching
prefix to the longest. `CoveredNetworks` returns entries fully contained by the
supplied prefix.

The ranger is not safe for concurrent mutation. Concurrent reads are safe when
no goroutine is mutating it.

## Migrating from v1

| v1 | v2 |
| --- | --- |
| `net.IP` | `netip.Addr` |
| `net.IPNet` | `netip.Prefix` |
| `RangerEntry` interface | generic value `T` |
| `Ranger` interface | concrete `*Ranger[T]` |
| `NewPCTrieRanger()` | `NewPCTrieRanger[T]()` |
| `Insert(entry)` | `Insert(prefix, value)` |
| `Remove(network)` | `Remove(prefix)` |

If a caller starts with a textual address or prefix, prefer `netip.ParseAddr`
and `netip.ParsePrefix`. During a staged migration, `netip.AddrFromSlice` can
bridge a legacy `net.IP`; call `Unmap` on the result because `net.ParseIP`
commonly represents IPv4 as an IPv4-mapped IPv6 address.

## Design notes

- Each trie node embeds two child pointers rather than allocating a child
  slice.
- `netip.Addr` and `netip.Prefix` provide the public API; each operation packs
  them once into fixed-width integer words for trie traversal.
- Values are stored directly as `T`; no interface boxing or type assertions are
  required.
- IPv4 comparisons use a single `uint32`; IPv6 comparisons use two `uint64`
  words. XOR plus leading-zero counts replace repeated per-node address
  conversion and byte scanning.
- `Lookup` performs longest-prefix matching in one traversal and does not
  allocate.
- IPv4 and IPv6 have independent, lazily allocated roots in one ranger. A
  single-family ranger does not pay for an unused root.

## Benchmarking

The lookup benchmarks build a 10,000-prefix trie before measuring the hot path:

```shell
go test -run '^$' -bench 'BenchmarkPCTrie(Contains|Lookup|ContainingNetworks)' -benchmem .
```

`Contains` and `Lookup` are expected to report zero allocations.
`ContainingNetworks` returns a caller-owned slice and therefore allocates when
it finds entries.

The AWS-range benchmarks use the repository's historical comparison dataset:

```shell
go test -run '^$' -bench '^BenchmarkAWS' -benchmem .
```
