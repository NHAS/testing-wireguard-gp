/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"container/list"
	"encoding/binary"
	"errors"
	"math/bits"
	"net"
	"net/netip"
	"sync"
	"time"
	"unsafe"
)

type DecisionType uint16

const (
	ANY    = uint16(0)
	MFA    = 0
	PUBLIC = 1 << DecisionType(iota)
	DENY

	RANGE
	SINGLE
)

const (
	MAX_POLICIES = 128

	ICMP = 1  // Internet Control Message
	TCP  = 6  // Transmission Control
	UDP  = 17 // User Datagram
)

type Decision struct {
	PolicyType uint16
	Proto      uint16
	LowerPort  uint16
	UpperPort  uint16
}

func (p *Decision) Is(pt DecisionType) bool {
	if p.PolicyType == 0 && pt == 0 {
		return true
	}

	return p.PolicyType&uint16(pt) != 0
}

type Policy struct {
	selector    string
	trieEntries list.List
	collect     bool
	decisions   []Decision

	prefix netip.Prefix
}

type parentIndirection struct {
	parentBit     **trieEntry
	parentBitType uint8
}

type trieEntry struct {
	policy         *Policy
	child          [2]*trieEntry
	parent         parentIndirection
	cidr           uint8
	bitAtByte      uint8
	bitAtShift     uint8
	bits           []byte
	linkedPolicies []*list.Element
}

func commonBits(ip1, ip2 []byte) uint8 {
	size := len(ip1)
	if size == net.IPv4len {
		a := binary.BigEndian.Uint32(ip1)
		b := binary.BigEndian.Uint32(ip2)
		x := a ^ b
		return uint8(bits.LeadingZeros32(x))
	} else if size == net.IPv6len {
		a := binary.BigEndian.Uint64(ip1)
		b := binary.BigEndian.Uint64(ip2)
		x := a ^ b
		if x != 0 {
			return uint8(bits.LeadingZeros64(x))
		}
		a = binary.BigEndian.Uint64(ip1[8:])
		b = binary.BigEndian.Uint64(ip2[8:])
		x = a ^ b
		return 64 + uint8(bits.LeadingZeros64(x))
	} else {
		panic("Wrong size bit string")
	}
}

func (node *trieEntry) addToPolicyEntries() {
	node.linkedPolicies = append(node.linkedPolicies, node.policy.trieEntries.PushBack(node))
}

func (node *trieEntry) removeFromPolicyEntries() {
	if node.linkedPolicies != nil {
		for i := range node.linkedPolicies {
			node.policy.trieEntries.Remove(node.linkedPolicies[i])
		}

		node.linkedPolicies = nil
	}
}

func (node *trieEntry) choose(ip []byte) byte {
	return (ip[node.bitAtByte] >> node.bitAtShift) & 1
}

func (node *trieEntry) maskSelf() {
	mask := net.CIDRMask(int(node.cidr), len(node.bits)*8)
	for i := 0; i < len(mask); i++ {
		node.bits[i] &= mask[i]
	}
}

func (node *trieEntry) zeroizePointers() {
	// Make the garbage collector's life slightly easier
	node.policy = nil
	node.child[0] = nil
	node.child[1] = nil
	node.parent.parentBit = nil
}

func (node *trieEntry) nodePlacement(ip []byte, cidr uint8) (parent *trieEntry, exact bool) {
	for node != nil && node.cidr <= cidr && commonBits(node.bits, ip) >= node.cidr {
		parent = node
		if parent.cidr == cidr {
			exact = true
			return
		}
		bit := node.choose(ip)
		node = node.child[bit]
	}
	return
}

func (trie parentIndirection) insert(ip []byte, cidr uint8, policy *Policy) {
	if *trie.parentBit == nil {
		node := &trieEntry{
			policy:     policy,
			parent:     trie,
			bits:       ip,
			cidr:       cidr,
			bitAtByte:  cidr / 8,
			bitAtShift: 7 - (cidr % 8),
		}
		node.maskSelf()
		node.addToPolicyEntries()
		*trie.parentBit = node
		return
	}
	node, exact := (*trie.parentBit).nodePlacement(ip, cidr)
	if exact {
		node.removeFromPolicyEntries()
		node.policy = policy
		node.addToPolicyEntries()
		return
	}

	newNode := &trieEntry{
		policy:     policy,
		bits:       ip,
		cidr:       cidr,
		bitAtByte:  cidr / 8,
		bitAtShift: 7 - (cidr % 8),
	}
	newNode.maskSelf()
	newNode.addToPolicyEntries()

	var down *trieEntry
	if node == nil {
		down = *trie.parentBit
	} else {
		bit := node.choose(ip)
		down = node.child[bit]
		if down == nil {
			newNode.parent = parentIndirection{&node.child[bit], bit}
			node.child[bit] = newNode
			return
		}
	}
	common := commonBits(down.bits, ip)
	if common < cidr {
		cidr = common
	}
	parent := node

	if newNode.cidr == cidr {
		bit := newNode.choose(down.bits)
		down.parent = parentIndirection{&newNode.child[bit], bit}
		newNode.child[bit] = down
		if parent == nil {
			newNode.parent = trie
			*trie.parentBit = newNode
		} else {
			bit := parent.choose(newNode.bits)
			newNode.parent = parentIndirection{&parent.child[bit], bit}
			parent.child[bit] = newNode
		}
		return
	}

	node = &trieEntry{
		bits:       append([]byte{}, newNode.bits...),
		cidr:       cidr,
		bitAtByte:  cidr / 8,
		bitAtShift: 7 - (cidr % 8),
	}
	node.maskSelf()

	bit := node.choose(down.bits)
	down.parent = parentIndirection{&node.child[bit], bit}
	node.child[bit] = down
	bit = node.choose(newNode.bits)
	newNode.parent = parentIndirection{&node.child[bit], bit}
	node.child[bit] = newNode
	if parent == nil {
		node.parent = trie
		*trie.parentBit = node
	} else {
		bit := parent.choose(node.bits)
		node.parent = parentIndirection{&parent.child[bit], bit}
		parent.child[bit] = node
	}
}

func (node *trieEntry) lookup(ip []byte) *Policy {
	var found *Policy
	size := uint8(len(ip))
	for node != nil && commonBits(node.bits, ip) >= node.cidr {
		if node.policy != nil {
			found = node.policy
		}
		if node.bitAtByte == size {
			break
		}
		bit := node.choose(ip)
		node = node.child[bit]
	}
	return found
}

type Policies struct {
	sync.RWMutex

	authorized time.Time

	IPv4 *trieEntry
	IPv6 *trieEntry
}

var (
	globalRemovalLock sync.RWMutex
)

func RemovePolicy(policy *Policy) {
	globalRemovalLock.Lock()
	defer globalRemovalLock.Unlock()

	var next *list.Element
	for elem := policy.trieEntries.Front(); elem != nil; elem = next {
		next = elem.Next()
		node := elem.Value.(*trieEntry)

		node.removeFromPolicyEntries()
		node.policy = nil

		if node.child[0] != nil && node.child[1] != nil {
			continue
		}
		bit := 0
		if node.child[0] == nil {
			bit = 1
		}
		child := node.child[bit]
		if child != nil {
			child.parent = node.parent
		}
		*node.parent.parentBit = child
		if node.child[0] != nil || node.child[1] != nil || node.parent.parentBitType > 1 {
			node.zeroizePointers()
			continue
		}
		parent := (*trieEntry)(unsafe.Pointer(uintptr(unsafe.Pointer(node.parent.parentBit)) - unsafe.Offsetof(node.child) - unsafe.Sizeof(node.child[0])*uintptr(node.parent.parentBitType)))
		if parent.policy != nil {
			node.zeroizePointers()
			continue
		}
		child = parent.child[node.parent.parentBitType^1]
		if child != nil {
			child.parent = parent.parent
		}
		*parent.parent.parentBit = child
		node.zeroizePointers()
		parent.zeroizePointers()
	}
}

func (table *Policies) Insert(prefix netip.Prefix, policy *Policy) {
	table.Lock()
	defer table.Unlock()

	globalRemovalLock.Lock()
	defer globalRemovalLock.Unlock()

	if prefix.Addr().Is6() {
		ip := prefix.Addr().As16()
		parentIndirection{&table.IPv6, 2}.insert(ip[:], uint8(prefix.Bits()), policy)
	} else if prefix.Addr().Is4() {
		ip := prefix.Addr().As4()
		parentIndirection{&table.IPv4, 2}.insert(ip[:], uint8(prefix.Bits()), policy)
	} else {
		panic(errors.New("inserting unknown address type"))
	}
}

func (table *Policies) Lookup(ip []byte) *Policy {
	table.RLock()
	defer table.RUnlock()

	globalRemovalLock.Lock()
	defer globalRemovalLock.Unlock()

	return table.tableLookup(ip)
}

func (table *Policies) tableLookup(ip []byte) *Policy {

	switch len(ip) {
	case net.IPv6len:
		return table.IPv6.lookup(ip)
	case net.IPv4len:
		return table.IPv4.lookup(ip)
	default:
		panic(errors.New("looking up unknown address type"))
	}
}

func (table *Policies) Evaluate(ip []byte, proto, port uint16) bool {
	table.RLock()
	defer table.RUnlock()

	globalRemovalLock.Lock()
	defer globalRemovalLock.Unlock()

	policy := table.tableLookup(ip)
	if policy == nil {
		return false
	}

	authorized := !table.authorized.Equal(time.Time{})
	action := false
	for _, decision := range policy.decisions {

		//      ANY = 0
		//      If we match the protocol,
		//      If type is SINGLE and the port is either any, or equal
		//      OR
		//      If type is RANGE and the port is within bounds

		if decision.Proto == ANY || decision.Proto == proto &&
			((decision.Is(SINGLE) && (decision.LowerPort == ANY || decision.LowerPort == port)) ||
				(decision.Is(RANGE) && (decision.LowerPort <= port && decision.UpperPort >= port))) {

			if decision.Is(DENY) {
				return false
			}

			if decision.Is(MFA) && authorized {
				action = true
			}

			if decision.Is(PUBLIC) {
				action = true
			}
		}

	}

	return action
}

func (table *Policies) Authorize() {
	table.RLock()
	defer table.RUnlock()

	table.authorized = time.Now()
}

func (table *Policies) Deauthorize() {
	table.RLock()
	defer table.RUnlock()

	table.authorized = time.Time{}
}

func (table *Policies) IsAuthed() bool {
	table.RLock()
	defer table.RUnlock()

	return !table.authorized.Equal(time.Time{})
}
