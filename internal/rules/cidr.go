package rules

import (
	"net/netip"
)

// cidrNode is a binary radix trie node over address bits. Child[0] follows
// a 0 bit, child[1] follows a 1 bit. A non-nil terminal prefix marks the
// end of one or more CIDR ranges (longest-prefix match wins).
type cidrNode struct {
	child    [2]*cidrNode
	terminal bool
}

// CIDRSet matches IP addresses against a set of CIDR ranges with
// longest-prefix-match semantics. IPv4 and IPv6 live in separate tries;
// the IPv6 side is wired up but empty until IPv6 support is enabled.
type CIDRSet struct {
	v4root *cidrNode
	v6root *cidrNode
	count  int
}

func NewCIDRSet() *CIDRSet {
	return &CIDRSet{v4root: &cidrNode{}, v6root: &cidrNode{}}
}

// Insert adds a CIDR range.
func (s *CIDRSet) Insert(p netip.Prefix) error {
	p = p.Masked()
	if p.Addr().Is4() || p.Addr().Is4In6() {
		a := p.Addr().As4()
		insertBits(s.v4root, a[:], int(p.Bits()))
	} else {
		a := p.Addr().As16()
		insertBits(s.v6root, a[:], int(p.Bits()))
	}
	s.count++
	return nil
}

func insertBits(root *cidrNode, addr []byte, bits int) {
	n := root
	for i := 0; i < bits; i++ {
		bit := (addr[i/8] >> (7 - uint(i)%8)) & 1
		if n.child[bit] == nil {
			n.child[bit] = &cidrNode{}
		}
		n = n.child[bit]
	}
	n.terminal = true
}

// Contains reports whether ip falls inside any inserted range.
func (s *CIDRSet) Contains(ip netip.Addr) bool {
	if ip.Is4() || ip.Is4In6() {
		a := ip.Unmap().As4()
		return containsBits(s.v4root, a[:])
	}
	a := ip.As16()
	return containsBits(s.v6root, a[:])
}

func containsBits(root *cidrNode, addr []byte) bool {
	n := root
	best := root.terminal
	total := len(addr) * 8
	for i := 0; i < total; i++ {
		if n == nil {
			break
		}
		bit := (addr[i/8] >> (7 - uint(i)%8)) & 1
		n = n.child[bit]
		if n != nil && n.terminal {
			best = true
		}
	}
	return best
}

// Len reports how many prefixes were inserted.
func (s *CIDRSet) Len() int { return s.count }

// MergeV4 inserts all prefixes of the given set into s's v4 trie. Both sets
// must have been built from the same family split (see PrivateSets for the
// pattern); IPv6 entries are inserted into s's v6 trie as well.
func (s *CIDRSet) MergeV4(other *CIDRSet) {
	mergeTrie(s.v4root, other.v4root, 32)
	mergeTrie(s.v6root, other.v6root, 128)
	s.count += other.count
}

func mergeTrie(dst, src *cidrNode, depth int) {
	if src == nil || depth < 0 {
		return
	}
	if src.terminal {
		dst.terminal = true
	}
	for b := 0; b < 2; b++ {
		if src.child[b] != nil {
			if dst.child[b] == nil {
				dst.child[b] = &cidrNode{}
			}
			mergeTrie(dst.child[b], src.child[b], depth-1)
		}
	}
}
