package pivpn

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"magnax.ca/VPNManager/pkg/wireguard"
)

type (
	ClientList     []Client
	ClientInfoList []ClientInfo
)

// Client is a special type of wireguard.Config.
//
// Client has exactly 1 peer, which is the vpn server.
// Each Client and vpn server pair share 1 unique pre-shared key.
type Client struct {
	wireguard.Config

	Disabled     bool
	CreationDate time.Time
}

var (
	invalidDNSChars = regexp.MustCompile(`[^a-zA-Z0-9-]+`)
)

func (c *Client) DNSName() string {
	return invalidDNSChars.ReplaceAllLiteralString(c.Name, "-")
}

func (c *Client) ToPeer() wireguard.Peer {
	return wireguard.Peer{
		Name:         c.Name,
		PublicKey:    *c.Interface.PrivateKey.Public(),
		PresharedKey: c.Peers[0].PresharedKey,
		AllowedIPs:   []netip.Prefix{netip.PrefixFrom(c.Interface.Addresses[0].Addr(), 32)},
	}
}

func (c *ClientList) ToClientInfoList() ClientInfoList {
	l := make(ClientInfoList, len(*c))
	for i, client := range *c {
		l[i] = ClientInfo{
			Name:         client.Name,
			PublicKey:    *client.Interface.PrivateKey.Public(),
			CreationDate: client.CreationDate,
			IPAddr:       client.Interface.Addresses[0].Addr(),
		}
	}

	return l
}

type ClientInfo struct {
	Name         string
	PublicKey    wireguard.Key
	CreationDate time.Time
	IPAddr       netip.Addr
}

func int2ip(nn uint32) netip.Addr {
	var bytes [4]byte
	binary.BigEndian.PutUint32(bytes[:], nn)
	return netip.AddrFrom4(bytes)
}

func ip2int(ip netip.Addr) uint32 {
	bytes := ip.As4()
	return binary.BigEndian.Uint32(bytes[:])
}

var (
	spacesRE = regexp.MustCompile(`\s+`)
)

func ParseClientList(input io.Reader) (ClientInfoList, error) {
	clients := make([]ClientInfo, 0)
	scanner := bufio.NewScanner(input)

	for scanner.Scan() {
		line := scanner.Text()
		chunks := spacesRE.Split(line, -1)
		if len(chunks) != 4 {
			slog.Error("Invalid line in clients.txt", "line", line)
			return nil, &wireguard.ParseError{Why: fmt.Sprintf("expected 4 chunks in line, got %d", len(chunks)), Offender: line}
		}
		pubKey, err := wireguard.ParseKeyBase64(chunks[1])
		if err != nil {
			slog.Error("Invalid public key in line", "line", line, "key", chunks[1])
			return nil, err
		}
		creationDate, err := strconv.ParseInt(chunks[2], 10, 64)
		if err != nil {
			slog.Error("Invalid time in line", "line", line, "timestamp", chunks[2])
			return nil, err
		}
		ip, err := strconv.ParseUint(chunks[3], 10, 32)
		if err != nil {
			slog.Error("Invalid decimal IP address in line", "line", line, "ip", chunks[3])
			return nil, err
		}
		clients = append(clients, ClientInfo{
			chunks[0],
			*pubKey,
			time.Unix(creationDate, 0),
			int2ip(uint32(ip)),
		})
	}

	return clients, nil
}

func (c ClientInfoList) AsMap() map[string]ClientInfo {
	m := make(map[string]ClientInfo, len(c))
	for _, info := range c {
		if _, ok := m[info.Name]; ok {
			panic("duplicate name in client list")
		}
		m[info.Name] = info
	}
	return m
}

func (c ClientInfoList) Export() string {
	var builder strings.Builder

	for _, client := range c {
		builder.WriteString(fmt.Sprintf("%-15s %44s %10d %10d\n", client.Name, client.PublicKey.String(), client.CreationDate.Unix(), ip2int(client.IPAddr)))
	}

	return builder.String()
}
