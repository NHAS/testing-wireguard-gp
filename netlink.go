package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"unsafe"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

type IfInfomsg struct {
	Family uint8
	_      uint8
	Type   uint16
	Index  int32
	Flags  uint32
	Change uint32
}

func (msg *IfInfomsg) Serialize() []byte {
	return (*(*[unix.SizeofIfInfomsg]byte)(unsafe.Pointer(msg)))[:]
}

type IfAddrmsg struct {
	Family    uint8
	Prefixlen uint8
	Flags     uint8
	Scope     uint8
	Index     uint32
}

func (msg *IfAddrmsg) Serialize() []byte {
	return (*(*[unix.SizeofIfAddrmsg]byte)(unsafe.Pointer(msg)))[:]
}

func setUp(c *netlink.Conn, interfaceName string) error {

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("wireguard network iface %s does not exist: %s", interfaceName, err)
	}

	log.Println("index: ", iface)

	req := netlink.Message{
		Header: netlink.Header{
			Type:  unix.RTM_NEWLINK,
			Flags: netlink.Request | netlink.Acknowledge,
		},
	}

	msg := &IfInfomsg{
		Family: unix.AF_UNSPEC,
		Change: unix.IFF_UP,
		Flags:  unix.IFF_UP,
	}

	msg.Index = int32(iface.Index)

	req.Data = msg.Serialize()

	resp, err := c.Execute(req)
	if err != nil {
		return fmt.Errorf("failed to execute message: %v", err)
	}

	switch resp[0].Header.Type {
	case netlink.Error:
		errCode := binary.LittleEndian.Uint32(resp[0].Data)
		if errCode != 0 {
			return errors.New("got netlink error: " + fmt.Sprintf("%d", errCode))
		}

	}

	return nil
}

func setIp(c *netlink.Conn, interfaceName string, address net.IPNet) error {

	if address.IP.To4() != nil {
		address.IP = address.IP.To4()[:4]
	} else {
		address.IP = address.IP.To16()
	}

	req := netlink.Message{
		Header: netlink.Header{
			Type:  unix.RTM_NEWADDR,
			Flags: netlink.Request | netlink.Acknowledge,
		},
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("wireguard network iface %s does not exist: %s", interfaceName, err)
	}

	addrMsg := IfAddrmsg{
		Family: unix.AF_INET,
		Index:  uint32(iface.Index),
	}

	if len(address.IP) == 4 {
		addrMsg.Family = unix.AF_INET
	}

	preflen, _ := address.Mask.Size()
	addrMsg.Prefixlen = uint8(preflen)

	req.Data = addrMsg.Serialize()

	ne := netlink.NewAttributeEncoder()

	ne.Bytes(unix.IFA_LOCAL, address.IP)

	msg, err := ne.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode af: %v", err)
	}

	req.Data = append(req.Data, msg...)

	resp, err := c.Execute(req)
	if err != nil {
		return fmt.Errorf("failed to execute message: %v", err)
	}

	switch resp[0].Header.Type {
	case netlink.Error:
		errCode := binary.LittleEndian.Uint32(resp[0].Data)
		if errCode != 0 {
			return errors.New("got netlink error: " + fmt.Sprintf("%d", errCode))
		}
	}

	return nil
}
