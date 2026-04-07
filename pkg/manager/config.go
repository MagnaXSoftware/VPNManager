package manager

import (
	"errors"
	"os"
	"time"

	"magnax.ca/VPNManager/pkg/pivpn"

	"github.com/hashicorp/hcl/v2/hclsimple"
)

type Config struct {
	Name string `hcl:"name,optional"`

	OrchestratorAddr string `hcl:"orchestrator_addr"`
	UseTLS           bool   `hcl:"use_tls,optional"`
	PSK              string `hcl:"psk,optional"`

	PiVPNConfig *PiVPNConfig `hcl:"pivpn,block"`

	Timeouts *Timeouts `hcl:"timeouts,block"`
}

type PiVPNConfig struct {
	ConfigFilePath string `hcl:"config_file,optional"`

	Name             string `hcl:"name,optional"`
	TunnelDirectory  string `hcl:"tunnel_dir,optional"`
	ConfigsDirectory string `hcl:"configs_dir,optional"`
	KeysDirectory    string `hcl:"keys_dir,optional"`

	ReloadPiholeCmd []string `hcl:"reload_cmd_pihole,optional"`
	ReloadWgCmd []string `hcl:"reload_cmd_wg,optional"`
}

type Timeouts struct {
	MinRetryIntervalMS int64 `hcl:"min_retry,optional"`
	MaxRetryIntervalMS int64 `hcl:"max_retry,optional"`
}

func DefaultConfig() (*Config, error) {
	config := Config{
		PiVPNConfig: &PiVPNConfig{
			ConfigFilePath:   pivpn.DefaultConfigFilePath,
			Name:             pivpn.DefaultTunnelName,
			TunnelDirectory:  pivpn.DefaultTunnelDir,
			ConfigsDirectory: pivpn.DefaultConfigsDir,
			KeysDirectory:    pivpn.DefaultKeysFilePath,
			ReloadPiholeCmd:  []string{"/usr/local/bin/pihole", "reloadlists"},
			ReloadWgCmd:      []string{"systemctl", "reload", "wg-quick@wg0"},
		},
		Timeouts: &Timeouts{
			MinRetryIntervalMS: 100,
			MaxRetryIntervalMS: int64(10 * time.Minute / time.Millisecond),
		},
	}
	name, err := os.Hostname()
	if err == nil {
		config.Name = name
	}

	return &config, err
}

func ParseConfig(src []byte) (*Config, error) {
	config, _ := DefaultConfig()

	err := hclsimple.Decode("manager.hcl", src, nil, config)
	if err != nil {
		return nil, err
	}

	err = config.Validate()
	if err != nil {
		return nil, err
	}

	return config, nil
}

func (c *Config) Validate() error {
	if c.Name == "" {
		return errors.New("name is required and couldn't be set from the hostname")
	}

	if c.OrchestratorAddr == "" {
		return errors.New("orchestrator_addr cannot be empty")
	}

	return nil
}

func (t *Timeouts) MinRetry() time.Duration {
	return time.Duration(t.MinRetryIntervalMS) * time.Millisecond
}

func (t *Timeouts) MaxRetry() time.Duration {
	return time.Duration(t.MaxRetryIntervalMS) * time.Millisecond
}
