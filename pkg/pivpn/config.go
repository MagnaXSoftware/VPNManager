package pivpn

import (
	"fmt"
	"io"
	"iter"
	"net/netip"
	"os/user"
	"path/filepath"
	"strconv"

	"github.com/joho/godotenv"

	"magnax.ca/VPNManager/pkg/wireguard"
)

type Config struct {
	DNS            []netip.Addr
	Endpoint       wireguard.Endpoint
	UserConfigPath string
	Username       string
	UserId         int
	GroupId        int

	all map[string]string
}

type MissingSetupVar struct {
	Var string
}

func (m *MissingSetupVar) Error() string {
	return fmt.Sprintf("`%s` was not present in the pivpn setup vars", m.Var)
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
		return nil, &MissingSetupVar{"pivpnHOST"}
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
		return nil, &MissingSetupVar{"install_home"}
	}

	if installUser, ok := envs["install_user"]; ok {
		conf.Username = installUser
		userObj, err := user.Lookup(installUser)
		if err != nil {
			return nil, err
		}
		uid, err := strconv.ParseInt(userObj.Uid, 10, 0)
		if err != nil {
			return nil, err
		}
		conf.UserId = int(uid)
		gid, err := strconv.ParseInt(userObj.Gid, 10, 0)
		if err != nil {
			return nil, err
		}
		conf.GroupId = int(gid)
	} else {
		return nil, &MissingSetupVar{"install_user"}
	}

	conf.all = envs

	return &conf, nil
}

func (c *Config) Get(name string) (string, bool) {
	val, ok := c.all[name]
	return val, ok
}

func (c *Config) All() iter.Seq2[string, string] {
	return func(yield func(string, string) bool) {
		for k, v := range c.all {
			if !yield(k, v) {
				return
			}
		}
	}
}
