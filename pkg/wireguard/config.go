package wireguard

//go:generate go tool msgp
//msgp:shim netip.Prefix as:string using:(netip.Prefix).String/netip.ParsePrefix witherr:true
//msgp:shim netip.Addr as:string using:(netip.Addr).String/netip.ParseAddr witherr:true

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

	"golang.org/x/crypto/curve25519"
)

const KeyLength = 32

type Endpoint struct {
	Host string `msg:"host"`
	Port uint16 `msg:"port"`
}

type (
	Key [KeyLength]byte
)

type Config struct {
	Name      string    `msg:"name"`
	Interface Interface `msg:"interface"`
	Peers     []Peer    `msg:"peers"`
}

type Interface struct {
	PrivateKey Key            `msg:"key"`
	Addresses  []netip.Prefix `msg:"addresses"`
	ListenPort uint16         `msg:"listen_port"`
	MTU        uint16         `msg:"mtu"`
	DNS        []netip.Addr   `msg:"dns,omitempty"`
	DNSSearch  []string       `msg:"dns_search,omitempty"`
	PreUp      string         `msg:"pre_up,omitempty"`
	PostUp     string         `msg:"post_up,omitempty"`
	PreDown    string         `msg:"pre_down,omitempty"`
	PostDown   string         `msg:"post_down,omitempty"`
	Table      string         `msg:"table,omitempty"`
}

type Peer struct {
	Name     string `msg:"name"`
	Disabled bool   `msg:"disabled"`

	PublicKey           Key            `msg:"key"`
	PresharedKey        Key            `msg:"psk,omitzero"`
	AllowedIPs          []netip.Prefix `msg:"ips"`
	Endpoint            Endpoint       `msg:"endpoint,omitempty"`
	PersistentKeepalive uint16         `msg:"keepalive,omitempty"`
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
