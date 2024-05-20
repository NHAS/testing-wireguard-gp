package main

import (
	"log"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
	"tailscale.com/net/packet"
)

var parsedPacketPool = sync.Pool{New: func() any { return new(packet.Parsed) }}

type Wrapper struct {
	tun.Device

	eventsUpDown chan tun.Event
	// eventsOther yields non-up-and-down tun.Events that arrive on a Wrapper's events channel.
	eventsOther chan tun.Event

	// closed signals poll (by closing) when the device is closed.
	closed chan struct{}

	closeOnce sync.Once
}

func NewWrap(tdev tun.Device) *Wrapper {
	w := &Wrapper{
		Device: tdev,
		closed: make(chan struct{}),

		eventsUpDown: make(chan tun.Event),
		eventsOther:  make(chan tun.Event),
	}

	go w.pumpEvents()

	return w
}

// EventsUpDown returns a TUN event channel that contains all Up and Down events.
func (t *Wrapper) EventsUpDown() chan tun.Event {
	return t.eventsUpDown
}

// Events returns a TUN event channel that contains all non-Up, non-Down events.
// It is named Events because it is the set of events that we want to expose to wireguard-go,
// and Events is the name specified by the wireguard-go tun.Device interface.
func (t *Wrapper) Events() <-chan tun.Event {
	return t.eventsOther
}

func (t *Wrapper) pumpEvents() {
	defer close(t.eventsUpDown)
	defer close(t.eventsOther)
	src := t.Device.Events()
	for {
		// Retrieve an event from the TUN device.
		var event tun.Event
		var ok bool
		select {
		case <-t.closed:
			return
		case event, ok = <-src:
			if !ok {
				return
			}
		}

		// Pass along event to the correct recipient.
		// Though event is a bitmask, in practice there is only ever one bit set at a time.
		dst := t.eventsOther
		if event&(tun.EventUp|tun.EventDown) != 0 {
			dst = t.eventsUpDown
		}
		select {
		case <-t.closed:
			return
		case dst <- event:
		}
	}
}

func (t *Wrapper) Close() error {
	var err error
	t.closeOnce.Do(func() {
		err = t.Device.Close()
	})
	return err
}

func (t *Wrapper) Read(buffs [][]byte, sizes []int, offset int) (int, error) {

	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)

	n, err := t.Device.Read(buffs, sizes, offset)
	if err != nil {
		return n, err
	}

	for i := 0; i < n; i++ {
		p.Decode(buffs[i][offset : offset+sizes[i]])
		log.Println(p.String())
	}

	log.Println("read from tun")
	return n, err
}

func (t *Wrapper) Write(buffs [][]byte, offset int) (int, error) {
	log.Println("writing to tun")

	p := parsedPacketPool.Get().(*packet.Parsed)
	defer parsedPacketPool.Put(p)

	for _, buff := range buffs {
		p.Decode(buff[offset:])
		log.Println("write pkt: ", p.String())
	}

	return t.Device.Write(buffs, offset)
}
