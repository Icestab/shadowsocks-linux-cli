// Package tun owns the TUN device and the gvisor userspace TCP/IP stack
// that terminates application flows arriving on it.
package tun

import (
	"fmt"

	"golang.zx2c4.com/wireguard/tun"
)

// Device wraps the kernel TUN interface.
type Device struct {
	dev        tun.Device
	Name       string
	MTU        int
	tunAddress string // configured CIDR, e.g. 198.18.0.1/15
}

// Create opens (or creates) the named TUN device with the given MTU.
func Create(name string, mtu int) (*Device, error) {
	dev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create tun %q (mtu %d): %w", name, mtu, err)
	}
	return &Device{dev: dev, Name: name, MTU: mtu}, nil
}

// Close destroys the device handle.
func (d *Device) Close() error {
	if d.dev != nil {
		return d.dev.Close()
	}
	return nil
}
