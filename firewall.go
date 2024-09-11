/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2023 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/gaissmai/bart"
)

type Acl struct {
	Mfa   []string `json:",omitempty"`
	Allow []string `json:",omitempty"`
	Deny  []string `json:",omitempty"`
}

type Firewall struct {
	sync.RWMutex

	inactivityTimeout time.Duration

	// Username to policy
	userPolicies map[string]*Policies
	userLock     map[string]bool

	addressToDevice   map[netip.Addr]*Device
	addressToPolicies map[netip.Addr]*Policies

	deviceToUser  map[netip.Addr]string
	userToDevices map[string]map[*Device]bool
}

func (f *Firewall) SetInactivityTimeout(inactivityTimeoutMinutes int) error {
	f.Lock()
	defer f.Unlock()

	f.inactivityTimeout = time.Duration(inactivityTimeoutMinutes) * time.Minute

	return nil
}

func (f *Firewall) RefreshUserAcls(username string) error {
	f.Lock()
	defer f.Unlock()

	// Do acls stuff here

	return nil
}

func (f *Firewall) Evaluate(src, dst netip.AddrPort, proto uint16) bool {
	// As we are evaluating for a single packet, we can take a snapshot of this current moment
	// Yes I know there is a pointer that may be modified, but its largely fine
	f.RLock()
	targetAddr := dst
	deviceAddr := src
	policies, ok := f.addressToPolicies[src.Addr()]
	if !ok || policies == nil {
		policies, ok = f.addressToPolicies[dst.Addr()]
		if !ok || policies == nil {
			f.RUnlock()
			return false
		}

		deviceAddr = dst
		targetAddr = src
	}

	policy := policies.tableLookup(targetAddr.Addr())
	if policy == nil {
		f.RUnlock()
		return false
	}

	authorized := f.isAuthed(deviceAddr.Addr())

	// It doesnt matter if this gets race conditioned
	device := f.addressToDevice[deviceAddr.Addr()]
	if device != nil && time.Since(device.lastPacketTime) < f.inactivityTimeout {
		device.lastPacketTime = time.Now()
	} else {
		authorized = false
	}

	f.RUnlock()

	action := false
	for _, decision := range policy.decisions {

		//      ANY = 0
		//      If we match the protocol,
		//      If type is SINGLE and the port is either any, or equal
		//      OR
		//      If type is RANGE and the port is within bounds

		if decision.Proto == ANY || decision.Proto == proto &&
			((decision.Is(SINGLE) && (decision.LowerPort == ANY || decision.LowerPort == targetAddr.Port())) ||
				(decision.Is(RANGE) && (decision.LowerPort <= targetAddr.Port() && decision.UpperPort >= targetAddr.Port()))) {

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

func (f *Firewall) SetAuthorized(address netip.Addr, until time.Time, node uint64) error {
	f.Lock()
	defer f.Unlock()

	device, ok := f.addressToDevice[address]
	if !ok {
		return fmt.Errorf("device %q was not found", address)
	}

	device.sessionExpiry = until
	device.lastPacketTime = time.Now()
	device.associatedNode = node

	return nil
}

func (f *Firewall) Deauthenticate(address netip.Addr) error {
	f.Lock()
	defer f.Unlock()

	return f._deauthenticate(address)
}

func (f *Firewall) _deauthenticate(address netip.Addr) error {
	device, ok := f.addressToDevice[address]
	if !ok {
		return fmt.Errorf("device %q was not found", address)
	}

	device.sessionExpiry = time.Time{}
	device.lastPacketTime = time.Time{}

	return nil
}

func (f *Firewall) DeauthenticateAllDevices(username string) error {
	f.Lock()
	defer f.Unlock()

	for device := range f.userToDevices[username] {
		err := f._deauthenticate(device.address)
		if err != nil {
			return fmt.Errorf("failed to deauthenticate all devices: %s", err)
		}
	}

	return nil
}

func (f *Firewall) AddUser(username string, acls Acl) error {
	f.Lock()
	defer f.Unlock()

	if _, ok := f.userLock[username]; ok {
		return errors.New("user already exists")
	}

	// New users are obviously unlocked
	f.userLock[username] = false
	f.userPolicies[username] = new(Policies)

	// todo acls -> keys & rules

	f.userToDevices[username] = make(map[*Device]bool)

	return nil
}

func (f *Firewall) RefreshConfiguration() []error {
	f.Lock()
	defer f.Unlock()

	return nil
}

func (f *Firewall) RemoveUser(username string) error {
	f.Lock()
	defer f.Unlock()

	delete(f.userLock, username)
	delete(f.userPolicies, username)

	for d := range f.userToDevices[username] {
		delete(f.addressToPolicies, d.address)
		delete(f.addressToDevice, d.address)
		delete(f.deviceToUser, d.address)
	}
	delete(f.userToDevices, username)

	return nil
}

func (f *Firewall) GetAllAuthorised() ([]string, error) {
	f.RLock()
	defer f.RUnlock()

	result := []string{}
	for addr, device := range f.addressToDevice {
		if f.isAuthed(addr) {
			result = append(result, device.address.String())
		}
	}

	return result, nil
}

// IsAuthed returns true if the device is authorised
func (f *Firewall) IsAuthed(address string) bool {
	f.RLock()
	defer f.RUnlock()

	addr, err := netip.ParseAddr(address)
	if err != nil {
		return false
	}

	return f.isAuthed(addr)
}

func (f *Firewall) isAuthed(addr netip.Addr) bool {
	ok := f.userLock[addr.String()]
	if !ok {
		return false
	}

	device, ok := f.addressToDevice[addr]
	if !ok {
		return false
	}

	// If the device has been inactive
	if device.lastPacketTime.Add(f.inactivityTimeout).Before(time.Now()) {
		return false
	}

	return device.isAuthed()
}

func (f *Firewall) SetLockAccount(username string, locked bool) error {
	f.Lock()
	defer f.Unlock()

	_, ok := f.userLock[username]
	if !ok {
		return fmt.Errorf("user %q not found", username)
	}

	f.userLock[username] = locked
	if locked {
		for device := range f.userToDevices[username] {
			device.sessionExpiry = time.Time{}
		}
	}
	return nil

}

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

type Device struct {
	sync.RWMutex

	address netip.Addr

	lastPacketTime time.Time
	sessionExpiry  time.Time
	//username       string

	associatedNode uint64
}

func (d *Device) isAuthed() bool {
	t := time.Now()
	return !d.sessionExpiry.Equal(time.Time{}) &&
		t.Before(d.sessionExpiry)

}

type Policy struct {
	decisions []Decision
}

type Policies struct {
	sync.RWMutex

	policies *bart.Table[*Policy]
}

func (table *Policies) Insert(prefix netip.Prefix, policy *Policy) {
	table.Lock()
	defer table.Unlock()

	table.policies.Insert(prefix, policy)
}

func (table *Policies) Lookup(ip netip.Addr) *Policy {
	table.RLock()
	defer table.RUnlock()

	return table.tableLookup(ip)
}

func (table *Policies) LookupBytes(ip []byte) *Policy {
	table.RLock()
	defer table.RUnlock()

	var n netip.Addr
	switch len(ip) {
	case net.IPv4len:
		n = netip.AddrFrom4([net.IPv4len]byte(ip))
	case net.IPv6len:
		n = netip.AddrFrom16([net.IPv6len]byte(ip))

	default:
		panic(errors.New("looking up unknown address length/type"))
	}

	return table.tableLookup(n)
}

func (table *Policies) tableLookup(ip netip.Addr) *Policy {

	if ip.Is4() {
		policy, _ := table.policies.Get(netip.PrefixFrom(ip, net.IPv4len))
		return policy

	} else if ip.Is6() {
		policy, _ := table.policies.Get(netip.PrefixFrom(ip, net.IPv6len))
		return policy
	}

	panic(errors.New("looking up unknown address type"))

}
