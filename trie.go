package cidranger

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"net/netip"
	"strings"
)

// packedAddress is the lookup form used inside the trie. Conversion happens
// once at the public API boundary, so an IPv4 traversal works on one uint32
// value instead of repeatedly unpacking netip.Addr at every node.
type packedAddress struct {
	high uint64
	low  uint64
	is4  bool
}

// packedPrefix keeps the hot node representation fixed-size and pointer-free.
// IPv4 uses the low 32 bits of low; IPv6 uses high and low together.
type packedPrefix struct {
	high uint64
	low  uint64
	bits uint8
	is4  bool
}

// trieNode embeds its two child slots to avoid a separate slice allocation per
// node. hasValue is separate from value so every T, including its zero value,
// can be stored.
type trieNode[T any] struct {
	prefix   packedPrefix
	children [2]*trieNode[T]
	value    T
	hasValue bool
}

func newRoot[T any](is4 bool) *trieNode[T] {
	return &trieNode[T]{prefix: packedPrefix{is4: is4}}
}

func newValueNode[T any](prefix packedPrefix, value T) *trieNode[T] {
	return &trieNode[T]{
		prefix:   prefix,
		value:    value,
		hasValue: true,
	}
}

func insertNode[T any](node *trieNode[T], prefix packedPrefix, value T) (*trieNode[T], bool) {
	if node.prefix == prefix {
		inserted := !node.hasValue
		node.value = value
		node.hasValue = true
		return node, inserted
	}

	childIndex := prefix.bitAt(int(node.prefix.bits))
	child := node.children[childIndex]
	if child == nil {
		node.children[childIndex] = newValueNode(prefix, value)
		return node, true
	}

	common := child.prefix.commonBits(prefix, min(int(child.prefix.bits), int(prefix.bits)))
	// These three cases are the core of the path-compressed trie:
	//   1. descend when the existing child contains the new prefix;
	//   2. insert the new prefix above a more-specific existing child; or
	//   3. create a value-less branch at the prefixes' divergence point.
	switch {
	case common == int(child.prefix.bits):
		child, inserted := insertNode(child, prefix, value)
		node.children[childIndex] = child
		return node, inserted

	case common == int(prefix.bits):
		parent := newValueNode(prefix, value)
		parent.children[child.prefix.bitAt(int(prefix.bits))] = child
		node.children[childIndex] = parent
		return node, true

	default:
		branchPrefix := prefix.withBits(common)
		branch := &trieNode[T]{prefix: branchPrefix}
		branch.children[child.prefix.bitAt(common)] = child
		branch.children[prefix.bitAt(common)] = newValueNode(prefix, value)
		node.children[childIndex] = branch
		return node, true
	}
}

func removeNode[T any](
	node *trieNode[T],
	prefix packedPrefix,
	isRoot bool,
) (*trieNode[T], Entry[T], bool) {
	if node == nil || !node.prefix.containsPrefix(prefix) {
		return node, Entry[T]{}, false
	}

	var entry Entry[T]
	var found bool
	if node.prefix == prefix {
		if !node.hasValue {
			return node, Entry[T]{}, false
		}
		entry = Entry[T]{Prefix: node.prefix.netipPrefix(), Value: node.value}
		var zero T
		node.value = zero
		node.hasValue = false
		found = true
	} else {
		childIndex := prefix.bitAt(int(node.prefix.bits))
		node.children[childIndex], entry, found = removeNode(
			node.children[childIndex],
			prefix,
			false,
		)
		if !found {
			return node, Entry[T]{}, false
		}
	}

	if isRoot {
		// A non-empty family retains its /0 root because insertion assumes the
		// starting node covers every address in that family. Release an empty
		// root so a ranger returns to its allocation-lazy state.
		if !node.hasValue && node.children[0] == nil && node.children[1] == nil {
			return nil, entry, true
		}
		return node, entry, true
	}
	if node.hasValue {
		return node, entry, true
	}
	// Removing a value may leave a structural node with one child. Bypass that
	// node to preserve path compression.
	switch {
	case node.children[0] == nil:
		return node.children[1], entry, true
	case node.children[1] == nil:
		return node.children[0], entry, true
	default:
		return node, entry, true
	}
}

func coveredEntries[T any](node *trieNode[T], prefix packedPrefix, entries *[]Entry[T]) {
	if node == nil {
		return
	}

	if prefix.containsPrefix(node.prefix) {
		appendSubtree(node, entries)
		return
	}
	if !node.prefix.containsPrefix(prefix) {
		return
	}
	coveredEntries(node.children[prefix.bitAt(int(node.prefix.bits))], prefix, entries)
}

func appendSubtree[T any](node *trieNode[T], entries *[]Entry[T]) {
	if node == nil {
		return
	}
	if node.hasValue {
		*entries = append(*entries, Entry[T]{
			Prefix: node.prefix.netipPrefix(),
			Value:  node.value,
		})
	}
	appendSubtree(node.children[0], entries)
	appendSubtree(node.children[1], entries)
}

func packAddress(addr netip.Addr) packedAddress {
	if addr.Is4() {
		octets := addr.As4()
		return packedAddress{low: uint64(binary.BigEndian.Uint32(octets[:])), is4: true}
	}
	octets := addr.As16()
	return packedAddress{
		high: binary.BigEndian.Uint64(octets[:8]),
		low:  binary.BigEndian.Uint64(octets[8:]),
	}
}

func packPrefix(prefix netip.Prefix) packedPrefix {
	addr := packAddress(prefix.Addr())
	return packedPrefix{
		high: addr.high,
		low:  addr.low,
		bits: uint8(prefix.Bits()),
		is4:  addr.is4,
	}
}

func (a packedAddress) bitLen() int {
	if a.is4 {
		return 32
	}
	return 128
}

// bitAt counts from the most-significant bit: position zero is the first bit.
func (a packedAddress) bitAt(position int) uint8 {
	if a.is4 {
		return uint8((uint32(a.low) >> (31 - uint(position))) & 1)
	}
	if position < 64 {
		return uint8((a.high >> (63 - uint(position))) & 1)
	}
	return uint8((a.low >> (127 - uint(position))) & 1)
}

func (p packedPrefix) bitAt(position int) uint8 {
	return packedAddress{high: p.high, low: p.low, is4: p.is4}.bitAt(position)
}

func (p packedPrefix) contains(addr packedAddress) bool {
	if p.is4 != addr.is4 {
		return false
	}
	if p.is4 {
		return bits.LeadingZeros32(uint32(p.low)^uint32(addr.low)) >= int(p.bits)
	}
	if p.bits <= 64 {
		return bits.LeadingZeros64(p.high^addr.high) >= int(p.bits)
	}
	return p.high == addr.high &&
		64+bits.LeadingZeros64(p.low^addr.low) >= int(p.bits)
}

func (p packedPrefix) containsPrefix(other packedPrefix) bool {
	return p.is4 == other.is4 &&
		p.bits <= other.bits &&
		p.contains(packedAddress{high: other.high, low: other.low, is4: other.is4})
}

func (p packedPrefix) commonBits(other packedPrefix, limit int) int {
	var common int
	if p.is4 {
		common = bits.LeadingZeros32(uint32(p.low) ^ uint32(other.low))
	} else if xor := p.high ^ other.high; xor != 0 {
		common = bits.LeadingZeros64(xor)
	} else {
		common = 64 + bits.LeadingZeros64(p.low^other.low)
	}
	return min(common, limit)
}

func (p packedPrefix) withBits(prefixBits int) packedPrefix {
	p.bits = uint8(prefixBits)
	if p.is4 {
		if prefixBits == 0 {
			p.low = 0
		} else if prefixBits < 32 {
			p.low &= uint64(^uint32(0) << (32 - uint(prefixBits)))
		}
		return p
	}

	switch {
	case prefixBits == 0:
		p.high, p.low = 0, 0
	case prefixBits < 64:
		p.high &= ^uint64(0) << (64 - uint(prefixBits))
		p.low = 0
	case prefixBits == 64:
		p.low = 0
	case prefixBits < 128:
		p.low &= ^uint64(0) << (128 - uint(prefixBits))
	}
	return p
}

func (p packedPrefix) netipPrefix() netip.Prefix {
	if p.is4 {
		var octets [4]byte
		binary.BigEndian.PutUint32(octets[:], uint32(p.low))
		return netip.PrefixFrom(netip.AddrFrom4(octets), int(p.bits))
	}
	var octets [16]byte
	binary.BigEndian.PutUint64(octets[:8], p.high)
	binary.BigEndian.PutUint64(octets[8:], p.low)
	return netip.PrefixFrom(netip.AddrFrom16(octets), int(p.bits))
}

// String returns a compact representation of the two tries for debugging.
func (r *Ranger[T]) String() string {
	var ipv4, ipv6 string
	if r.ipv4 != nil {
		ipv4 = r.ipv4.string(0)
	} else {
		ipv4 = allIPv4.String() + " (target_pos:31:has_entry:false)"
	}
	if r.ipv6 != nil {
		ipv6 = r.ipv6.string(0)
	} else {
		ipv6 = allIPv6.String() + " (target_pos:127:has_entry:false)"
	}
	return ipv4 + "\n" + ipv6
}

func (n *trieNode[T]) string(level int) string {
	var children strings.Builder
	padding := strings.Repeat("| ", level+1)
	for bit, child := range n.children {
		if child == nil {
			continue
		}
		fmt.Fprintf(&children, "\n%s%d--> %s", padding, bit, child.string(level+1))
	}
	return fmt.Sprintf(
		"%s (target_pos:%d:has_entry:%t)%s",
		n.prefix.netipPrefix(),
		n.prefix.bitLen()-int(n.prefix.bits)-1,
		n.hasValue,
		children.String(),
	)
}

func (p packedPrefix) bitLen() int {
	if p.is4 {
		return 32
	}
	return 128
}
