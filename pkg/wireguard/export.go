package wireguard

import (
	"fmt"
	"strings"
)

func (p *Peer) Export() string {
	var builder strings.Builder

	insertDisabledPrefix := func() func() {
		if p.Disabled {
			return func() {
				builder.WriteString("#[disabled] ")
			}
		}
		return func() {}
	}()

	if p.Name != "" {
		insertDisabledPrefix()
		_, _ = fmt.Fprintf(&builder, "### begin %s ###\n", p.Name)
	}

	insertDisabledPrefix()
	builder.WriteString("[Peer]\n")

	insertDisabledPrefix()
	_, _ = fmt.Fprintf(&builder, "PublicKey = %s\n", p.PublicKey.String())

	if !p.PresharedKey.IsZero() {
		insertDisabledPrefix()
		_, _ = fmt.Fprintf(&builder, "PresharedKey = %s\n", p.PresharedKey.String())
	}

	if len(p.AllowedIPs) > 0 {
		addrStrings := make([]string, len(p.AllowedIPs))
		for i, address := range p.AllowedIPs {
			addrStrings[i] = address.String()
		}
		insertDisabledPrefix()
		_, _ = fmt.Fprintf(&builder, "AllowedIPs = %s\n", strings.Join(addrStrings[:], ", "))
	}

	if !p.Endpoint.IsEmpty() {
		insertDisabledPrefix()
		_, _ = fmt.Fprintf(&builder, "Endpoint = %s\n", p.Endpoint.String())
	}

	if p.PersistentKeepalive > 0 {
		insertDisabledPrefix()
		_, _ = fmt.Fprintf(&builder, "PersistentKeepalive = %d\n", p.PersistentKeepalive)
	}

	if p.Name != "" {
		insertDisabledPrefix()
		_, _ = fmt.Fprintf(&builder, "### end %s ###", p.Name)
	}
	return builder.String()
}

func (p *Peer) MarshalText() ([]byte, error) {
	return []byte(p.Export()), nil
}

func (c *Config) Export() string {
	var builder strings.Builder

	builder.WriteString("[Interface]\n")

	_, _ = fmt.Fprintf(&builder, "PrivateKey = %s\n", c.Interface.PrivateKey.String())

	if c.Interface.ListenPort > 0 {
		_, _ = fmt.Fprintf(&builder, "ListenPort = %d\n", c.Interface.ListenPort)
	}

	if len(c.Interface.Addresses) > 0 {
		addrStrings := make([]string, len(c.Interface.Addresses))
		for i, address := range c.Interface.Addresses {
			addrStrings[i] = address.String()
		}
		_, _ = fmt.Fprintf(&builder, "Address = %s\n", strings.Join(addrStrings[:], ", "))
	}

	if len(c.Interface.DNS)+len(c.Interface.DNSSearch) > 0 {
		addrStrings := make([]string, 0, len(c.Interface.DNS)+len(c.Interface.DNSSearch))
		for _, address := range c.Interface.DNS {
			addrStrings = append(addrStrings, address.String())
		}
		addrStrings = append(addrStrings, c.Interface.DNSSearch...)
		_, _ = fmt.Fprintf(&builder, "DNS = %s\n", strings.Join(addrStrings[:], ", "))
	}

	if c.Interface.MTU > 0 {
		_, _ = fmt.Fprintf(&builder, "MTU = %d\n", c.Interface.MTU)
	}

	if len(c.Interface.PreUp) > 0 {
		_, _ = fmt.Fprintf(&builder, "PreUp = %s\n", c.Interface.PreUp)
	}
	if len(c.Interface.PostUp) > 0 {
		_, _ = fmt.Fprintf(&builder, "PostUp = %s\n", c.Interface.PostUp)
	}
	if len(c.Interface.PreDown) > 0 {
		_, _ = fmt.Fprintf(&builder, "PreDown = %s\n", c.Interface.PreDown)
	}
	if len(c.Interface.PostDown) > 0 {
		_, _ = fmt.Fprintf(&builder, "PostDown = %s\n", c.Interface.PostDown)
	}
	if c.Interface.Table != "" {
		_, _ = fmt.Fprintf(&builder, "Table = %s\n", c.Interface.Table)
	}

	builder.WriteString("\n")

	for _, peer := range c.Peers {
		builder.WriteString(peer.Export())
		builder.WriteString("\n")
	}

	return builder.String()
}

func (c *Config) MarshalText() ([]byte, error) {
	return []byte(c.Export()), nil
}
