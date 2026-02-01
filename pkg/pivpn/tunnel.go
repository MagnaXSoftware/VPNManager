package pivpn

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"magnax.ca/VPNManager/pkg/wireguard"
)

const (
	pivpnConfigFile     = "/etc/pivpn/wireguard/setupVars.conf"
	pivpnPiholeHostFile = "/etc/pivpn/hosts.wireguard"
	defaultConfigsDir   = "/etc/wireguard/configs"
	defaultTunnelDir    = "/etc/wireguard/"
)

var (
	ClientNotFoundErr   = errors.New("client not found")
	ClientNameExistsErr = errors.New("client with this name already exists")
)

type Vpn struct {
	tunnelFilePath string
	configsDir     string
	keysDir        string

	lock sync.Mutex

	Conf Config

	Server  wireguard.Config
	Clients ClientList
}

func LoadVpn() (*Vpn, error) {
	return LoadVpnWithLocations("wg0", pivpnConfigFile, defaultTunnelDir, defaultConfigsDir, defaultKeysFilepath)
}

func LoadVpnWithLocations(name, pivpnSetupVars, tunnelDir, configsDir, KeysDir string) (*Vpn, error) {
	vpn := Vpn{
		tunnelFilePath: filepath.Join(tunnelDir, name+".conf"),
		configsDir:     configsDir,
		keysDir:        KeysDir,
	}

	setupVarsFile, err := os.Open(pivpnSetupVars)
	if err != nil {
		return nil, err
	}
	defer func() { _ = setupVarsFile.Close() }()
	pivpnConf, err := LoadConfig(setupVarsFile)
	if err != nil {
		return nil, err
	}
	vpn.Conf = *pivpnConf

	tunnelConfFile, err := os.DirFS(tunnelDir).Open(name + ".conf")
	if err != nil {
		return nil, err
	}
	defer func() { _ = tunnelConfFile.Close() }()
	tunnelConf, err := wireguard.ParseConfig(tunnelConfFile, name)
	if err != nil {
		return nil, err
	}

	clientsFile, err := os.DirFS(configsDir).Open("clients.txt")
	if err != nil {
		return nil, err
	}
	defer func(file fs.File) { _ = file.Close() }(clientsFile)
	clients, err := ParseClientList(clientsFile)
	if err != nil {
		return nil, err
	}
	clientMap := clients.AsMap()

	vpn.Clients = make(ClientList, len(tunnelConf.Peers))

	for i, peer := range tunnelConf.Peers {
		c, err := func() (c *wireguard.Config, err error) {
			file, err := os.Open(filepath.Join(configsDir, peer.Name+".conf"))
			if err != nil {
				return
			}
			defer func(file fs.File) { err = file.Close() }(file)

			c, err = wireguard.ParseConfig(file, peer.Name)

			return
		}()
		if err != nil {
			return nil, err
		}

		client, ok := clientMap[peer.Name]
		if !ok {
			return nil, fmt.Errorf("client %s not found in clients.txt", peer.Name)
		}

		vpn.Clients[i] = Client{*c, peer.Disabled, client.CreationDate}
	}

	vpn.Server = *tunnelConf

	return &vpn, nil
}

func (t *Vpn) Name() string {
	return t.Server.Name
}

func (t *Vpn) SyncTunnel() error {
	err := os.WriteFile(t.tunnelFilePath, []byte(t.Server.Export()), 0640)
	if err != nil {
		return err
	}
	// todo reload config in wg
	return nil
}

func (t *Vpn) SyncClients() error {
	return os.WriteFile(filepath.Join(t.configsDir, "clients.txt"), []byte(t.Clients.ToClientInfoList().Export()), 0644)
}

func (t *Vpn) SyncPihole() error {
	if _, err := os.Stat(pivpnPiholeHostFile); os.IsNotExist(err) {
		return nil
	}
	var builder strings.Builder

	builder.WriteString(fmt.Sprintf("%s %s.pivpn\n", t.Server.Interface.Addresses[0].Addr().String(), "server"))
	for _, client := range t.Clients {
		builder.WriteString(fmt.Sprintf("%s %s.pivpn\n", client.Interface.Addresses[0].Addr().String(), client.DNSName()))
	}

	err := os.WriteFile(pivpnPiholeHostFile, []byte(builder.String()), 0644)
	if err != nil {
		return err
	}
	// todo reload pihole
	return nil
}

func (t *Vpn) DisableClient(name string) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	err := t.Server.DisablePeer(name)
	if err != nil {
		return err
	}

	for i, clients := range t.Clients {
		if clients.Name == name {
			t.Clients[i].Disabled = true
		}
	}

	return t.SyncTunnel()
}

func (t *Vpn) EnableClient(name string) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	err := t.Server.EnablePeer(name)
	if err != nil {
		return err
	}

	for i, clients := range t.Clients {
		if clients.Name == name {
			t.Clients[i].Disabled = false
		}
	}

	return t.SyncTunnel()
}

func (t *Vpn) RemoveClient(name string) error {
	t.lock.Lock()
	defer t.lock.Unlock()

	// remove peer from tunnel
	err := t.Server.RemovePeer(name)
	if err != nil {
		return err
	}

	// update running config
	err = t.SyncTunnel()
	if err != nil {
		return err
	}

	// remove client from client list if present
	for i, c := range t.Clients {
		if c.Name == name {
			t.Clients = append(t.Clients[:i], t.Clients[i+1:]...)
			break
		}
	}

	err = t.SyncClients()
	if err != nil {
		return err
	}

	err = os.Remove(filepath.Join(t.configsDir, name+".conf"))
	if err != nil && !os.IsNotExist(err) {
		return IoError{err, name + ".conf"}
	}

	err = os.Remove(filepath.Join(t.Conf.UserConfigPath, name+".conf"))
	if err != nil && !os.IsNotExist(err) {
		return IoError{err, name + ".conf"}
	}

	for _, f := range []string{name + "_priv", name + "_psk", name + "_pub"} {
		err = os.Remove(filepath.Join(t.keysDir, f))
		if err != nil && !os.IsNotExist(err) {
			return IoError{err, f}
		}
	}

	err = t.SyncPihole()
	if err != nil {
		return err
	}

	return nil
}

var (
	clientNameRE         = regexp.MustCompile(`^[a-zA-Z0-9.@_-]{1,15}$`)
	clientNameNonDigitRE = regexp.MustCompile(`^[a-zA-Z0-9.@_-]*[^0-9][a-zA-Z0-9.@_-]*$`)

	ipv4All = netip.MustParsePrefix("0.0.0.0/0")
	ipv6All = netip.MustParsePrefix("::0/0")
)

func (t *Vpn) AddClient(name string) error {
	// enforce peer name restrictions on addition, accept anything for all other options
	if !clientNameRE.MatchString(name) {
		return fmt.Errorf("invalid client name %q: name must only contains alphanumerical, period, @, underscore, and hyphen; and be between 1 and 15 characters", name)
	}
	if !clientNameNonDigitRE.MatchString(name) {
		return fmt.Errorf("invalid client name %q: client name must contain at least one digit", name)
	}
	if name == "server" {
		return fmt.Errorf("invalid client name %q: client name must not match %q", name, "server")
	}
	t.lock.Lock()
	defer t.lock.Unlock()

	for _, c := range t.Clients {
		if c.Name == name {
			return ClientNameExistsErr
		}
	}

	// create keys
	keys := NewKeys(name)

	// find next usable IP
	netblock := t.Server.Interface.Addresses[0]

	ips := make(map[netip.Addr]bool, len(t.Clients))
	for _, client := range t.Clients {
		ips[client.Interface.Addresses[0].Addr()] = true
	}
	// get first address after the server's IP
	ip := netblock.Addr().Next()
	for {
		// if IP is in map (aka is used by a client, increment and continue)
		if _, ok := ips[ip]; ok {
			ip = ip.Next()
			continue
		}
		if !netblock.Contains(ip) {
			return errors.New("unable to add client: tunnel as no usable IP addresses left")
		}
		break
	}

	// create client
	client := Client{
		wireguard.Config{
			Name: name,
			Interface: wireguard.Interface{
				PrivateKey: keys.PrivateKey,
				Addresses:  []netip.Prefix{netip.PrefixFrom(ip, netblock.Bits())},
				DNS:        t.Conf.DNS[:],
			},
			Peers: []wireguard.Peer{
				{
					PublicKey:    *t.Server.Interface.PrivateKey.Public(),
					PresharedKey: keys.PresharedKey,
					AllowedIPs: []netip.Prefix{
						ipv4All,
						ipv6All,
					},
					Endpoint:            t.Conf.Endpoint,
					PersistentKeepalive: 25,
				},
			},
		},
		false,
		time.Now(),
	}

	// save client
	err := os.WriteFile(filepath.Join(t.configsDir, name+".conf"), []byte(client.Export()), 0640)
	if err != nil {
		return err
	}

	saveKey := func(keyB64, filename string) error {
		err := os.WriteFile(filename, []byte(keyB64), 0640)
		if err != nil {
			return IoError{err, filename}
		}
		err = os.Chown(filename, 0, 0)
		if err != nil {
			return IoError{err, filename}
		}
		return nil
	}
	if err = saveKey(keys.PrivateKey.String(), filepath.Join(t.keysDir, name+"_priv")); err != nil {
		return err
	}
	if err = saveKey(keys.PrivateKey.Public().String(), filepath.Join(t.keysDir, name+"_pub")); err != nil {
		return err
	}
	if err = saveKey(keys.PresharedKey.String(), filepath.Join(t.keysDir, name+"_psk")); err != nil {
		return err
	}

	t.Clients = append(t.Clients, client)

	err = t.SyncClients()
	if err != nil {
		return err
	}

	// add client to tunnel
	clientPeer := client.ToPeer()
	clientPeer.PresharedKey = keys.PresharedKey
	t.Server.Peers = append(t.Server.Peers, clientPeer)

	// save tunnel
	err = t.SyncTunnel()
	if err != nil {
		return err
	}

	err = t.SyncPihole()
	if err != nil {
		return err
	}

	err = os.WriteFile(filepath.Join(t.Conf.UserConfigPath, name+".conf"), []byte(client.Export()), 0640)
	if err != nil {
		return err
	}

	return nil
}
