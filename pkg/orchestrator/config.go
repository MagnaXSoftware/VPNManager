package orchestrator

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2/hclsimple"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type Config struct {
	Address string `hcl:"address,optional"`
	PSK     string `hcl:"psk,optional"`

	UseTLS         bool     `hcl:"use_tls,optional"`
	CertFile       string   `hcl:"cert,optional"`
	KeyFile        string   `hcl:"key,optional"`
	TrustedProxies []string `hcl:"trusted_proxies,optional"`

	// RawPollInterval is the time between polls of each manager's vpn configuration
	// expressed in seconds. Use [Config.PollInterval] to get it in [time.Duration].
	RawPollInterval int64 `hcl:"poll_interval,optional"`

	OAuth *OIDCConfig `hcl:"auth,block"`
}

func ParseConfig(src []byte) (*Config, error) {
	config := Config{
		RawPollInterval: 60,
	}

	err := hclsimple.Decode("orchestrator.hcl", src, nil, &config)
	if err != nil {
		return nil, err
	}

	if config.Address == "" {
		if config.UseTLS {
			config.Address = ":https"
		} else {
			config.Address = ":http"
		}
	}

	err = config.Validate()
	if err != nil {
		return nil, err
	}

	return &config, nil
}

func (c *Config) Validate() error {
	if c.UseTLS && (c.CertFile == "" || c.KeyFile == "") {
		return errors.New("`cert` and `key` are required if `use_tls` is true")
	}

	if err := c.OAuth.Validate(); err != nil {
		return err
	}

	return nil
}

func (c *Config) PollInterval() time.Duration {
	return time.Duration(c.RawPollInterval) * time.Second
}

type OIDCConfig struct {
	RealmUrl       string `hcl:"oidc_url"`
	ClientID       string `hcl:"client_id"`
	ClientSecret   string `hcl:"client_secret"`
	RawCallbackUrl string `hcl:"callback_url"`
}

func (c *OIDCConfig) Validate() error {
	if c == nil {
		return nil
	}

	if c.RealmUrl == "" {
		return errors.New("`oidc_url` is required")
	}
	if strings.HasSuffix(c.RealmUrl, oidc.DiscoveryEndpoint) {
		return fmt.Errorf("`oidc_url` should not include %q", oidc.DiscoveryEndpoint)
	}
	if _, err := url.Parse(c.RealmUrl); err != nil {
		return err
	}

	if c.ClientID == "" {
		return errors.New("`client_id` is required")
	}
	if c.ClientSecret == "" {
		return errors.New("`client_secret` is required")
	}

	if c.RawCallbackUrl == "" {
		return errors.New("`callback_url` is required")
	}
	if u, err := url.Parse(c.RawCallbackUrl); err != nil {
		return err
	} else if u.Scheme == "" {
		return errors.New("`callback_url` requires a scheme (http or https)")
	} else if u.Host == "" {
		return errors.New("`callback_url` requires a host")
	}

	return nil
}
