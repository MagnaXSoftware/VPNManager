package pivpn

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"magnax.ca/VPNManager/pkg/wireguard"
)

var (
	defaultKeysFilepath = "/etc/wireguard/keys"
)

type IoError struct {
	Err  error
	File string
}

func (k IoError) Error() string {
	return fmt.Sprintf("error with file %q: %v", k.File, k.Err)
}

type Keys struct {
	Name string

	PrivateKey   wireguard.Key
	PresharedKey wireguard.Key
}

func NewKeys(name string) *Keys {
	priv, err := wireguard.NewPrivateKey()
	if err != nil {
		panic(err)
	}
	psk, err := wireguard.NewPresharedKey()
	if err != nil {
		panic(err)
	}
	return &Keys{
		name,
		*priv,
		*psk,
	}
}

func NewKeysFromClient(client *Client) *Keys {
	keys := Keys{
		client.Name,
		client.Interface.PrivateKey,
		client.Peers[0].PresharedKey,
	}

	return &keys
}

func ReadKeys(name string) (*Keys, error) {
	return ReadKeysFromFS(name, os.DirFS(defaultKeysFilepath))
}

func ReadKeysFromFS(name string, fsys fs.FS) (*Keys, error) {
	privB64, err := fs.ReadFile(fsys, name+"_priv")
	if err != nil {
		return nil, IoError{err, name + "_priv"}
	}
	priv, err := wireguard.NewPrivateKeyFromString(string(privB64))
	if err != nil {
		return nil, IoError{err, name + "_priv"}
	}
	pskB64, err := fs.ReadFile(fsys, name+"_psk")
	if err != nil {
		return nil, IoError{err, name + "_psk"}
	}
	psk, err := wireguard.NewPrivateKeyFromString(string(pskB64))
	if err != nil {
		return nil, IoError{err, name + "_psk"}
	}

	return &Keys{
		name,
		*priv,
		*psk,
	}, nil
}

func (k *Keys) PublicKey() *wireguard.Key {
	return k.PrivateKey.Public()
}

func (k *Keys) WriteOut() error {
	return k.WriteOutDir(defaultKeysFilepath)
}

func writeOutAndChown(filepath string, data string) error {
	// there is a race condition in here
	err := os.WriteFile(filepath, []byte(data), 0644)
	if err != nil {
		return err
	}
	err = os.Chown(filepath, 0, 0)
	return err
}

func (k *Keys) WriteOutDir(dir string) error {
	filebase := filepath.Join(dir, k.Name)
	err := writeOutAndChown(filebase+"_priv", k.PrivateKey.String())
	if err == nil {
		return nil
	}
	err = writeOutAndChown(filebase+"_psk", k.PresharedKey.String())
	if err == nil {
		return nil
	}
	err = writeOutAndChown(filebase+"_pub", k.PublicKey().String())
	return err
}
