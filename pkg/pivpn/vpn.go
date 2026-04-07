package pivpn

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"magnax.ca/VPNManager/pkg/wireguard"
)

const (
	DefaultConfigFilePath     = "/etc/pivpn/wireguard/setupVars.conf"
	DefaultPiholeHostFilePath = "/etc/pivpn/hosts.wireguard"

	DefaultTunnelName   = "wg0"
	DefaultConfigsDir   = "/etc/wireguard/configs"
	DefaultTunnelDir    = "/etc/wireguard/"
	DefaultKeysFilePath = "/etc/wireguard/keys"
)

var (
	ErrClientNotFound = errors.New("client not found")
	ErrClientExists   = errors.New("client with this name already exists")
)

type Vpn struct {
	tunnelFilePath string
	configsDir     string
	keysDir        string
	ReloadCmds     struct {
		Pihole []string
		Wg     []string
	}

	lock sync.Mutex

	Conf Config

	Server  wireguard.Config
	Clients ClientList
}

func LoadVpn() (*Vpn, error) {
	return LoadVpnWithLocations(DefaultTunnelName, DefaultConfigFilePath, DefaultTunnelDir, DefaultConfigsDir, DefaultKeysFilePath)
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

func (v *Vpn) SetReloadCmds(pihole, wg []string) {
	v.ReloadCmds.Pihole = pihole
	v.ReloadCmds.Wg = wg
}

func (v *Vpn) Name() string {
	return v.Server.Name
}

func (v *Vpn) SyncTunnel() error {
	err := os.WriteFile(v.tunnelFilePath, []byte(v.Server.Export()), 0640)
	if err != nil {
		return err
	}

	err = exec.Command(v.ReloadCmds.Wg[0], v.ReloadCmds.Wg[1:]...).Run()
	if err != nil {
		return err
	}
	return nil
}

func (v *Vpn) SyncClients() error {
	// todo rewrite the clients .conf files
	return os.WriteFile(filepath.Join(v.configsDir, "clients.txt"), []byte(v.Clients.ToClientInfoList().Export()), 0644)
}

func (v *Vpn) SyncPihole() error {
	if _, err := os.Stat(DefaultPiholeHostFilePath); os.IsNotExist(err) {
		return nil
	}
	var builder strings.Builder

	_, _ = fmt.Fprintf(&builder, "%s %s.pivpn\n", v.Server.Interface.Addresses[0].Addr().String(), "pivpn")
	for _, client := range v.Clients {
		_, _ = fmt.Fprintf(&builder, "%s %s.pivpn\n", client.Interface.Addresses[0].Addr().String(), client.DNSName())
	}

	err := os.WriteFile(DefaultPiholeHostFilePath, []byte(builder.String()), 0644)
	if err != nil {
		return err
	}

	err = exec.Command(v.ReloadCmds.Pihole[0], v.ReloadCmds.Pihole[1:]...).Run()
	if err != nil {
		return err
	}
	return nil
}

func (v *Vpn) DisableClient(name string) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	err := v.Server.DisablePeer(name)
	if err != nil {
		return err
	}

	for i, clients := range v.Clients {
		if clients.Name == name {
			v.Clients[i].Disabled = true
		}
	}

	return v.SyncTunnel()
}

func (v *Vpn) EnableClient(name string) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	err := v.Server.EnablePeer(name)
	if err != nil {
		return err
	}

	for i, clients := range v.Clients {
		if clients.Name == name {
			v.Clients[i].Disabled = false
		}
	}

	return v.SyncTunnel()
}

func (v *Vpn) RemoveClient(name string) error {
	v.lock.Lock()
	defer v.lock.Unlock()

	// remove peer from tunnel
	err := v.Server.RemovePeer(name)
	if err != nil {
		return err
	}

	// update running config
	err = v.SyncTunnel()
	if err != nil {
		return err
	}

	// remove client from client list if present
	for i, c := range v.Clients {
		if c.Name == name {
			v.Clients = append(v.Clients[:i], v.Clients[i+1:]...)
			break
		}
	}

	err = v.SyncClients()
	if err != nil {
		return err
	}

	err = os.Remove(filepath.Join(v.configsDir, name+".conf"))
	if err != nil && !os.IsNotExist(err) {
		return IoError{err, name + ".conf"}
	}

	err = os.Remove(filepath.Join(v.Conf.UserConfigPath, name+".conf"))
	if err != nil && !os.IsNotExist(err) {
		return IoError{err, name + ".conf"}
	}

	for _, f := range []string{name + "_priv", name + "_psk", name + "_pub"} {
		err = os.Remove(filepath.Join(v.keysDir, f))
		if err != nil && !os.IsNotExist(err) {
			return IoError{err, f}
		}
	}

	err = v.SyncPihole()
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

func (v *Vpn) AddClient(name string) error {
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
	v.lock.Lock()
	defer v.lock.Unlock()

	for _, c := range v.Clients {
		if c.Name == name {
			return ErrClientExists
		}
	}

	// create keys
	keys := NewKeys(name)

	// find next usable IP
	netblock := v.Server.Interface.Addresses[0]

	ips := make(map[netip.Addr]bool, len(v.Clients))
	for _, client := range v.Clients {
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
				DNS:        v.Conf.DNS[:],
			},
			Peers: []wireguard.Peer{
				{
					PublicKey:    *v.Server.Interface.PrivateKey.Public(),
					PresharedKey: keys.PresharedKey,
					AllowedIPs: []netip.Prefix{
						ipv4All,
						ipv6All,
					},
					Endpoint:            v.Conf.Endpoint,
					PersistentKeepalive: 25,
				},
			},
		},
		false,
		time.Now(),
	}

	// save client
	err := os.WriteFile(filepath.Join(v.configsDir, name+".conf"), []byte(client.Export()), 0640)
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
	if err = saveKey(keys.PrivateKey.String(), filepath.Join(v.keysDir, name+"_priv")); err != nil {
		return err
	}
	if err = saveKey(keys.PrivateKey.Public().String(), filepath.Join(v.keysDir, name+"_pub")); err != nil {
		return err
	}
	if err = saveKey(keys.PresharedKey.String(), filepath.Join(v.keysDir, name+"_psk")); err != nil {
		return err
	}

	v.Clients = append(v.Clients, client)

	err = v.SyncClients()
	if err != nil {
		return err
	}

	// add client to tunnel
	clientPeer := client.ToPeer()
	clientPeer.PresharedKey = keys.PresharedKey
	v.Server.Peers = append(v.Server.Peers, clientPeer)

	// save tunnel
	err = v.SyncTunnel()
	if err != nil {
		return err
	}

	err = v.SyncPihole()
	if err != nil {
		return err
	}

	err = ensureDir(v.Conf.UserConfigPath, v.Conf.UserId, v.Conf.GroupId)
	if err != nil {
		return err
	}
	err = os.WriteFile(filepath.Join(v.Conf.UserConfigPath, name+".conf"), []byte(client.Export()), 0640)
	if err != nil {
		return err
	}

	return nil
}

func ensureDir(path string, uid, gid int) error {
	dir, err := os.Stat(path)
	if err == nil {
		if dir.IsDir() {
			return nil
		}
		return &os.PathError{Op: "mkdir", Path: path, Err: syscall.ENOTDIR}
	}

	err = os.MkdirAll(path, 0775)
	if err != nil {
		return err
	}
	err = os.Chown(path, uid, gid)
	if err != nil {
		return err
	}

	return nil
}
