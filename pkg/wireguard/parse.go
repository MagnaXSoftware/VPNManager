package wireguard

/* SPDX-License-Identifier: MIT
 *
 * Original code: Copyright (C) 2019-2022 WireGuard LLC. All Rights Reserved.
 * Copyright (C) 2026 MagnaX Software. All Rights Reserved.
 */

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

type ParseError struct {
	Why      string
	Offender string
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("%s: %q", e.Why, e.Offender)
}

func parseIPCidr(s string) (netip.Prefix, error) {
	ipcidr, err := netip.ParsePrefix(s)
	if err == nil {
		return ipcidr, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, &ParseError{"Invalid IP address: ", s}
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func parseEndpoint(s string) (*Endpoint, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return nil, &ParseError{"Missing port from endpoint", s}
	}
	host, portStr := s[:i], s[i+1:]
	if len(host) < 1 {
		return nil, &ParseError{"Invalid endpoint host", host}
	}
	port, err := parsePort(portStr)
	if err != nil {
		return nil, err
	}
	hostColon := strings.IndexByte(host, ':')
	if host[0] == '[' || host[len(host)-1] == ']' || hostColon > 0 {
		err := &ParseError{"Brackets must contain an IPv6 address", host}
		if len(host) > 3 && host[0] == '[' && host[len(host)-1] == ']' && hostColon > 0 {
			end := len(host) - 1
			if i := strings.LastIndexByte(host, '%'); i > 1 {
				end = i
			}
			maybeV6, err2 := netip.ParseAddr(host[1:end])
			if err2 != nil || !maybeV6.Is6() {
				return nil, err
			}
		} else {
			return nil, err
		}
		host = host[1 : len(host)-1]
	}
	return &Endpoint{host, port}, nil
}

func parseMTU(s string) (uint16, error) {
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 576 || m > 65535 {
		return 0, &ParseError{"Invalid MTU", s}
	}
	return uint16(m), nil
}

func parsePort(s string) (uint16, error) {
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 0 || m > 65535 {
		return 0, &ParseError{"Invalid port", s}
	}
	return uint16(m), nil
}

func parsePersistentKeepalive(s string) (uint16, error) {
	if s == "off" {
		return 0, nil
	}
	m, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	if m < 0 || m > 65535 {
		return 0, &ParseError{"Invalid persistent keepalive", s}
	}
	return uint16(m), nil
}

func parseTableOff(s string) (bool, error) {
	if s == "off" {
		return true, nil
	} else if s == "auto" || s == "main" {
		return false, nil
	}
	_, err := strconv.ParseUint(s, 10, 32)
	return false, err
}

func ParseKeyBase64(s string) (*Key, error) {
	k, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, &ParseError{fmt.Sprintf("Invalid key: %v", err), s}
	}
	if len(k) != KeyLength {
		return nil, &ParseError{"Keys must decode to exactly 32 bytes", s}
	}
	var key Key
	copy(key[:], k)
	return &key, nil
}

func splitList(s string) ([]string, error) {
	var out []string
	for split := range strings.SplitSeq(s, ",") {
		trim := strings.TrimSpace(split)
		if len(trim) == 0 {
			return nil, &ParseError{"Two commas in a row", s}
		}
		out = append(out, trim)
	}
	return out, nil
}

type parserState int

const (
	notInSection parserState = iota
	inInterface
	inPeer
)

func (c *Config) maybeAddPeer(p *Peer) {
	if p != nil {
		c.Peers = append(c.Peers, *p)
	}
}

var (
	spacesRE               = regexp.MustCompile(`\s+`)
	beginRegex             = regexp.MustCompile(`^## begin ([a-zA-Z0-9.@_-]+) ###\s*$`)
	beginWithDisabledRegex = regexp.MustCompile(`^(\[disabled] #)?## begin ([a-zA-Z0-9.@_-]+) ###\s*$`)
	endRegex               = regexp.MustCompile(`^## end ([a-zA-Z0-9.@_-]+) ###\s*$`)
)

func parsePeer(scanner *bufio.Scanner) (*Peer, error) {
	peer := Peer{}
	disabled := false
	seenPeer := false
	// invariants: line will never be empty on first go
	for {
		line := scanner.Text()
		if disabled {
			_, line, _ = strings.Cut(line, "[disabled] ")
		}
		line, lineAfter, _ := strings.Cut(line, "#")
		if line == "" && strings.HasPrefix(lineAfter, "[disabled]") {
			// this can only hit on the first go, as the [disabled] prefix gets removed on subsequent runs
			disabled = true
			peer.Disabled = true
			// reparse the first line while removing the disabled prefix
			continue
		}
		line = strings.TrimSpace(line)
		lineLower := strings.ToLower(line)

		if matches := beginRegex.FindStringSubmatch(lineAfter); matches != nil && matches[1] != "" {
			if peer.Name != "" {
				return nil, &ParseError{"Duplicate begin line", lineAfter}
			}
			peer.Name = matches[1]
		} else if lineLower == "[interface]" {
			break
		} else if lineLower == "[peer]" {
			if seenPeer {
				break
			}
			seenPeer = true
		} else if endRegex.MatchString(lineAfter) {
			// exit but don't move the scanner up
			break
		} else if len(line) == 0 {
			// continue
		} else {
			equals := strings.IndexByte(line, '=')
			if equals < 0 {
				return nil, &ParseError{"Server key is missing an equals separator", line}
			}
			key, val := strings.TrimSpace(lineLower[:equals]), strings.TrimSpace(line[equals+1:])
			if len(val) == 0 {
				return nil, &ParseError{"Key must have a value", line}
			}

			switch key {
			case "publickey":
				k, err := ParseKeyBase64(val)
				if err != nil {
					return nil, err
				}
				peer.PublicKey = *k
			case "presharedkey":
				k, err := ParseKeyBase64(val)
				if err != nil {
					return nil, err
				}
				peer.PresharedKey = *k
			case "allowedips":
				addresses, err := splitList(val)
				if err != nil {
					return nil, err
				}
				for _, address := range addresses {
					a, err := parseIPCidr(address)
					if err != nil {
						return nil, err
					}
					peer.AllowedIPs = append(peer.AllowedIPs, a)
				}
			case "persistentkeepalive":
				p, err := parsePersistentKeepalive(val)
				if err != nil {
					return nil, err
				}
				peer.PersistentKeepalive = p
			case "endpoint":
				e, err := parseEndpoint(val)
				if err != nil {
					return nil, err
				}
				peer.Endpoint = *e
			default:
				return nil, &ParseError{"Invalid key for [Peer] section", key}
			}
		}

		if !scanner.Scan() {
			break
		}
	}

	return &peer, nil
}

func ParseConfig(input io.Reader, name string) (*Config, error) {
	conf := &Config{Name: name}
	err := conf.UnmarshalReader(input)
	if err != nil {
		return nil, err
	}
	return conf, err
}

func (c *Config) UnmarshalText(text []byte) error {
	return c.UnmarshalReader(bytes.NewBuffer(text))
}

func (c *Config) UnmarshalReader(input io.Reader) error {
	var peer *Peer
	state := notInSection
	scanner := bufio.NewScanner(input)
	sawPrivateKey := false

	for scanner.Scan() {
		line := scanner.Text()
		line, lineAfter, _ := strings.Cut(line, "#")
		line = strings.TrimSpace(line)
		lineLower := strings.ToLower(line)

		if lineLower == "[interface]" {
			// in case there was a peer before the interface section
			c.maybeAddPeer(peer)
			state = inInterface
			continue
		}
		if lineLower == "[peer]" || beginWithDisabledRegex.MatchString(lineAfter) {
			peer, err := parsePeer(scanner)
			if err != nil {
				return err
			}
			c.maybeAddPeer(peer)
			state = inPeer
			continue
		}

		if len(line) == 0 {
			continue
		}

		if state == notInSection {
			// at this point, if we haven't seen a section, it's a malformed file
			return &ParseError{"line must occur in a section", line}
		}
		equals := strings.IndexByte(line, '=')
		if equals < 0 {
			return &ParseError{"Server key is missing an equals separator", line}
		}
		key, val := strings.TrimSpace(lineLower[:equals]), strings.TrimSpace(line[equals+1:])
		if len(val) == 0 {
			return &ParseError{"Key must have a value", line}
		}

		if state == inInterface {
			switch key {
			case "privatekey":
				k, err := ParseKeyBase64(val)
				if err != nil {
					return err
				}
				c.Interface.PrivateKey = *k
				sawPrivateKey = true
			case "listenport":
				p, err := parsePort(val)
				if err != nil {
					return err
				}
				c.Interface.ListenPort = p
			case "mtu":
				m, err := parseMTU(val)
				if err != nil {
					return err
				}
				c.Interface.MTU = m
			case "address":
				addresses, err := splitList(val)
				if err != nil {
					return err
				}
				for _, address := range addresses {
					a, err := parseIPCidr(address)
					if err != nil {
						return err
					}
					c.Interface.Addresses = append(c.Interface.Addresses, a)
				}
			case "dns":
				addresses, err := splitList(val)
				if err != nil {
					return err
				}
				for _, address := range addresses {
					a, err := netip.ParseAddr(address)
					if err != nil {
						c.Interface.DNSSearch = append(c.Interface.DNSSearch, address)
					} else {
						c.Interface.DNS = append(c.Interface.DNS, a)
					}
				}
			case "preup":
				c.Interface.PreUp = val
			case "postup":
				c.Interface.PostUp = val
			case "predown":
				c.Interface.PreDown = val
			case "postdown":
				c.Interface.PostDown = val
			case "table":
				tableOff, err := parseTableOff(val)
				if err != nil {
					return err
				}
				c.Interface.TableOff = tableOff
			default:
				return &ParseError{"Invalid key for [Interface] section", key}
			}
		}
	}
	c.maybeAddPeer(peer)

	if !sawPrivateKey {
		return &ParseError{"An interface must have a private key", "[none specified]"}
	}
	for _, p := range c.Peers {
		if p.PublicKey.IsZero() {
			return &ParseError{"All peers must have public keys", "[none specified]"}
		}
	}

	return nil
}
