package wireguard

/* SPDX-License-Identifier: MIT
 *
 * Original code: Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 MagnaX Software. All Rights Reserved.
 */

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/crypto/curve25519"
)

const KeyLength = 32

type Endpoint struct {
	Host string
	Port uint16
}

type (
	Key           [KeyLength]byte
	HandshakeTime time.Duration
	Bytes         uint64
)

type Config struct {
	Name      string
	Interface Interface
	Peers     []Peer
}

type Interface struct {
	PrivateKey Key
	Addresses  []netip.Prefix
	ListenPort uint16
	MTU        uint16
	DNS        []netip.Addr
	DNSSearch  []string
	PreUp      string
	PostUp     string
	PreDown    string
	PostDown   string
	TableOff   bool
}

type Peer struct {
	Name     string
	Disabled bool

	PublicKey           Key
	PresharedKey        Key
	AllowedIPs          []netip.Prefix
	Endpoint            Endpoint
	PersistentKeepalive uint16
}

func (c *Config) IntersectsWith(other *Config) bool {
	allRoutes := make(map[netip.Prefix]bool, len(c.Interface.Addresses)*2+len(c.Peers)*3)
	for _, a := range c.Interface.Addresses {
		allRoutes[netip.PrefixFrom(a.Addr(), a.Addr().BitLen())] = true
		allRoutes[a.Masked()] = true
	}
	for i := range c.Peers {
		for _, a := range c.Peers[i].AllowedIPs {
			allRoutes[a.Masked()] = true
		}
	}
	for _, a := range other.Interface.Addresses {
		if allRoutes[netip.PrefixFrom(a.Addr(), a.Addr().BitLen())] {
			return true
		}
		if allRoutes[a.Masked()] {
			return true
		}
	}
	for i := range other.Peers {
		for _, a := range other.Peers[i].AllowedIPs {
			if allRoutes[a.Masked()] {
				return true
			}
		}
	}
	return false
}

func (e *Endpoint) String() string {
	if strings.IndexByte(e.Host, ':') != -1 {
		return fmt.Sprintf("[%s]:%d", e.Host, e.Port)
	}
	return fmt.Sprintf("%s:%d", e.Host, e.Port)
}

func (e *Endpoint) IsEmpty() bool {
	return len(e.Host) == 0
}

func (k Key) String() string {
	return base64.StdEncoding.EncodeToString(k[:])
}

func (k Key) IsZero() bool {
	var zeros Key
	return subtle.ConstantTimeCompare(zeros[:], k[:]) == 1
}

func (k Key) Public() *Key {
	var p [KeyLength]byte
	curve25519.ScalarBaseMult(&p, (*[KeyLength]byte)(&k))
	return (*Key)(&p)
}

func NewPresharedKey() (*Key, error) {
	var k [KeyLength]byte
	_, err := rand.Read(k[:])
	if err != nil {
		return nil, err
	}
	return (*Key)(&k), nil
}

func NewPrivateKey() (*Key, error) {
	k, err := NewPresharedKey()
	if err != nil {
		return nil, err
	}
	k[0] &= 248
	k[31] = (k[31] & 127) | 64
	return k, nil
}

func NewPrivateKeyFromString(b64 string) (*Key, error) {
	return ParseKeyBase64(b64)
}

func (c *Config) DeduplicateNetworkEntries() {
	m := make(map[string]bool, len(c.Interface.Addresses))
	i := 0
	for _, addr := range c.Interface.Addresses {
		s := addr.String()
		if m[s] {
			continue
		}
		m[s] = true
		c.Interface.Addresses[i] = addr
		i++
	}
	c.Interface.Addresses = c.Interface.Addresses[:i]

	m = make(map[string]bool, len(c.Interface.DNS))
	i = 0
	for _, addr := range c.Interface.DNS {
		s := addr.String()
		if m[s] {
			continue
		}
		m[s] = true
		c.Interface.DNS[i] = addr
		i++
	}
	c.Interface.DNS = c.Interface.DNS[:i]

	for _, peer := range c.Peers {
		m = make(map[string]bool, len(peer.AllowedIPs))
		i = 0
		for _, addr := range peer.AllowedIPs {
			s := addr.String()
			if m[s] {
				continue
			}
			m[s] = true
			peer.AllowedIPs[i] = addr
			i++
		}
		peer.AllowedIPs = peer.AllowedIPs[:i]
	}
}

func (c *Config) Redact() {
	c.Interface.PrivateKey = Key{}
	for i := range c.Peers {
		c.Peers[i].PublicKey = Key{}
		c.Peers[i].PresharedKey = Key{}
	}
}
