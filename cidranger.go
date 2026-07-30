// Package cidranger provides a generic, path-compressed prefix trie for fast
// IPv4 and IPv6 containment lookups.
//
// Addresses and prefixes use net/netip's compact, immutable value types. A
// ranger is parameterized by the value associated with each prefix:
//
//	ranger := cidranger.NewPCTrieRanger[string]()
//	prefix := netip.MustParsePrefix("192.0.2.0/24")
//	_ = ranger.Insert(prefix, "documentation network")
//
//	ok, _ := ranger.Contains(netip.MustParseAddr("192.0.2.1"))
package cidranger

import (
	"errors"
	"net/netip"
)

var (
	// ErrInvalidNetworkInput is returned when a prefix is invalid or contains a
	// scoped address. IP prefixes cannot contain zones.
	ErrInvalidNetworkInput = errors.New("cidranger: invalid prefix")

	// ErrInvalidNetworkNumberInput is returned when an address is invalid or
	// contains a zone.
	ErrInvalidNetworkNumberInput = errors.New("cidranger: invalid address")
)

var (
	// AllIPv4 contains every IPv4 address.
	AllIPv4 = netip.MustParsePrefix("0.0.0.0/0")

	// AllIPv6 contains every IPv6 address.
	AllIPv6 = netip.MustParsePrefix("::/0")
)

// Keep constructor roots independent of the exported variables, which callers
// can reassign.
var (
	allIPv4 = netip.MustParsePrefix("0.0.0.0/0")
	allIPv6 = netip.MustParsePrefix("::/0")
)

// Entry is a prefix and its associated value.
type Entry[T any] struct {
	Prefix netip.Prefix
	Value  T
}

// Ranger is a path-compressed prefix trie containing both IPv4 and IPv6
// prefixes. T is stored directly, without interface boxing.
//
// A Ranger is not safe for concurrent mutation. Multiple goroutines may perform
// lookups concurrently when no goroutine is mutating the ranger.
type Ranger[T any] struct {
	ipv4 *trieNode[T]
	ipv6 *trieNode[T]
	size int
}

// NewPCTrieRanger creates an empty ranger. Use struct{} as T when only
// membership is needed:
//
//	ranger := cidranger.NewPCTrieRanger[struct{}]()
//
// Address-family roots are allocated on first insertion. This keeps empty and
// single-family rangers small, which is useful when an application maintains
// separate IPv4 and IPv6 rangers.
func NewPCTrieRanger[T any]() *Ranger[T] {
	return &Ranger[T]{}
}

// Insert associates value with prefix. An existing value for the same prefix
// is replaced without changing Len.
func (r *Ranger[T]) Insert(prefix netip.Prefix, value T) error {
	prefix, err := validPrefix(prefix)
	if err != nil {
		return err
	}
	packed := packPrefix(prefix)

	// Allocate only the address family being populated. Lookups intentionally
	// treat a nil family root as an empty trie.
	root := r.ensureRoot(packed.is4)
	var inserted bool
	root, inserted = insertNode(root, packed, value)
	r.setRoot(packed.is4, root)
	if inserted {
		r.size++
	}
	return nil
}

// Remove deletes prefix. The removed entry and true are returned when prefix
// existed. A missing prefix returns the zero Entry, false, and a nil error.
func (r *Ranger[T]) Remove(prefix netip.Prefix) (Entry[T], bool, error) {
	prefix, err := validPrefix(prefix)
	if err != nil {
		return Entry[T]{}, false, err
	}
	packed := packPrefix(prefix)

	root := r.root(packed.is4)
	root, entry, found := removeNode(root, packed, true)
	r.setRoot(packed.is4, root)
	if found {
		r.size--
	}
	return entry, found, nil
}

// Contains reports whether addr is contained by at least one stored prefix.
func (r *Ranger[T]) Contains(addr netip.Addr) (bool, error) {
	if err := validateAddr(addr); err != nil {
		return false, err
	}
	packed := packAddress(addr)

	// Keep this separate from Lookup: membership can return at the first stored
	// parent prefix, while longest-prefix lookup must walk to the deepest match.
	for node := r.root(packed.is4); node != nil && node.prefix.contains(packed); {
		if node.hasValue {
			return true, nil
		}
		if int(node.prefix.bits) >= packed.bitLen() {
			break
		}
		node = node.children[packed.bitAt(int(node.prefix.bits))]
	}
	return false, nil
}

// Lookup returns the most-specific entry containing addr. A miss returns the
// zero Entry, false, and a nil error.
//
// Unlike ContainingNetworks, Lookup does not allocate a result slice. It is the
// preferred value lookup for routing tables and metadata enrichment paths.
func (r *Ranger[T]) Lookup(addr netip.Addr) (Entry[T], bool, error) {
	if err := validateAddr(addr); err != nil {
		return Entry[T]{}, false, err
	}
	packed := packAddress(addr)

	// Nodes are visited from shorter to longer prefixes. Retaining the latest
	// value therefore implements longest-prefix match without a second walk.
	var match *trieNode[T]
	for node := r.root(packed.is4); node != nil && node.prefix.contains(packed); {
		if node.hasValue {
			match = node
		}
		if int(node.prefix.bits) >= packed.bitLen() {
			break
		}
		node = node.children[packed.bitAt(int(node.prefix.bits))]
	}
	if match == nil {
		return Entry[T]{}, false, nil
	}
	return Entry[T]{Prefix: match.prefix.netipPrefix(), Value: match.value}, true, nil
}

// ContainingNetworks returns entries whose prefixes contain addr, ordered from
// the shortest prefix to the longest.
func (r *Ranger[T]) ContainingNetworks(addr netip.Addr) ([]Entry[T], error) {
	if err := validateAddr(addr); err != nil {
		return nil, err
	}
	packed := packAddress(addr)

	var entries []Entry[T]
	for node := r.root(packed.is4); node != nil && node.prefix.contains(packed); {
		if node.hasValue {
			entries = append(entries, Entry[T]{
				Prefix: node.prefix.netipPrefix(),
				Value:  node.value,
			})
		}
		if int(node.prefix.bits) >= packed.bitLen() {
			break
		}
		node = node.children[packed.bitAt(int(node.prefix.bits))]
	}
	return entries, nil
}

// CoveredNetworks returns entries completely covered by prefix. Parent entries
// are returned before their children.
func (r *Ranger[T]) CoveredNetworks(prefix netip.Prefix) ([]Entry[T], error) {
	prefix, err := validPrefix(prefix)
	if err != nil {
		return nil, err
	}
	packed := packPrefix(prefix)

	var entries []Entry[T]
	coveredEntries(r.root(packed.is4), packed, &entries)
	return entries, nil
}

// Len returns the number of stored prefixes.
func (r *Ranger[T]) Len() int {
	return r.size
}

func validPrefix(prefix netip.Prefix) (netip.Prefix, error) {
	if !prefix.IsValid() || prefix.Addr().Zone() != "" {
		return netip.Prefix{}, ErrInvalidNetworkInput
	}
	// Canonical prefixes are required for equality and Patricia-trie branching.
	// Mask here so callers may safely provide PrefixFrom(hostAddress, bits).
	return prefix.Masked(), nil
}

func validateAddr(addr netip.Addr) error {
	if !addr.IsValid() || addr.Zone() != "" {
		return ErrInvalidNetworkNumberInput
	}
	return nil
}

func (r *Ranger[T]) root(is4 bool) *trieNode[T] {
	if is4 {
		return r.ipv4
	}
	return r.ipv6
}

func (r *Ranger[T]) setRoot(is4 bool, root *trieNode[T]) {
	if is4 {
		r.ipv4 = root
		return
	}
	r.ipv6 = root
}

func (r *Ranger[T]) ensureRoot(is4 bool) *trieNode[T] {
	if root := r.root(is4); root != nil {
		return root
	}
	if is4 {
		r.ipv4 = newRoot[T](true)
		return r.ipv4
	}
	r.ipv6 = newRoot[T](false)
	return r.ipv6
}
