package pivpn

import (
	"fmt"
	"io"
	"net/netip"
	"path/filepath"
	"strconv"

	"github.com/joho/godotenv"
	"magnax.ca/VPNManager/pkg/wireguard"
)

type Config struct {
	DNS            []netip.Addr
	Endpoint       wireguard.Endpoint
	UserConfigPath string

	all map[string]string
}

func LoadConfig(r io.Reader) (*Config, error) {
	conf := Config{}

	envs, err := godotenv.Parse(r)
	if err != nil {
		return nil, err
	}

	conf.DNS = make([]netip.Addr, 1, 2)
	if dns, ok := envs["pivpnDNS1"]; ok {
		addr, err := netip.ParseAddr(dns)
		if err != nil {
			return nil, err
		}
		conf.DNS[0] = addr
	}
	if dns, ok := envs["pivpnDNS2"]; ok && dns != "" {
		addr, err := netip.ParseAddr(dns)
		if err != nil {
			return nil, err
		}
		conf.DNS = append(conf.DNS, addr)
	}

	if host, ok := envs["pivpnHOST"]; ok {
		conf.Endpoint.Host = host
	} else {
		return nil, fmt.Errorf("pivpnHOST was not present in the pivpn setup vars")
	}
	if portString, ok := envs["pivpnPORT"]; ok {
		port, err := strconv.ParseUint(portString, 10, 16)
		if err != nil {
			return nil, err
		}
		conf.Endpoint.Port = uint16(port)
	}

	if installHome, ok := envs["install_home"]; ok {
		conf.UserConfigPath = filepath.Join(installHome, "configs")
	} else {
		return nil, fmt.Errorf("install_home was not present in the pivpn setup vars")
	}

	conf.all = envs

	return &conf, nil
}

func (c *Config) Get(name string) (string, bool) {
	val, ok := c.all[name]
	return val, ok
}
