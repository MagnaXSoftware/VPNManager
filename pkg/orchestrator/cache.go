package orchestrator

import (
	"errors"
	"iter"
	"sync"

	"magnax.ca/VPNManager/pkg/api"
)

type Cache struct {
	vpns    map[string]api.Tunnel
	vpnLock sync.RWMutex

	channels     map[string]chan ActionRequest
	channelsLock sync.RWMutex
}

func NewCache() *Cache {
	vpns := make(map[string]api.Tunnel)
	channels := make(map[string]chan ActionRequest)
	return &Cache{
		vpns:     vpns,
		channels: channels,
	}
}

type ActionRequest struct {
	Request  api.Request
	Response chan<- api.Response
}

func (c *Cache) Register(name string) (<-chan ActionRequest, error) {
	c.channelsLock.Lock()
	defer c.channelsLock.Unlock()

	if _, ok := c.channels[name]; ok {
		return nil, errors.New("manager with the same name already exists")
	}

	comm := make(chan ActionRequest)
	c.channels[name] = comm

	return comm, nil
}

func (c *Cache) Get(name string) (chan<- ActionRequest, bool) {
	c.channelsLock.RLock()
	defer c.channelsLock.RUnlock()

	comm, ok := c.channels[name]
	return comm, ok
}

func (c *Cache) Unregister(name string) {
	c.channelsLock.Lock()
	defer c.channelsLock.Unlock()

	if comm, ok := c.channels[name]; ok {
		// might be unnecessary?
		close(comm)
	}
	delete(c.channels, name)

	c.vpnLock.Lock()
	defer c.vpnLock.Unlock()

	delete(c.vpns, name)
}

func (c *Cache) Managers() []string {
	c.vpnLock.RLock()
	defer c.vpnLock.RUnlock()
	managers := make([]string, 0, len(c.vpns))
	for name := range c.vpns {
		managers = append(managers, name)
	}
	return managers
}

func (c *Cache) Tunnels() iter.Seq2[string, *api.Tunnel] {
	return func(yield func(string, *api.Tunnel) bool) {
		c.vpnLock.RLock()
		defer c.vpnLock.RUnlock()
		for name, vpn := range c.vpns {
			if !yield(name, &vpn) {
				return
			}
		}
	}
}

func (c *Cache) GetTunnel(name string) *api.Tunnel {
	c.vpnLock.RLock()
	defer c.vpnLock.RUnlock()

	if t, ok := c.vpns[name]; ok {
		return &t
	}
	return nil
}

func (c *Cache) InsertTunnel(name string, tunnel *api.Tunnel) {
	c.vpnLock.Lock()
	defer c.vpnLock.Unlock()

	c.vpns[name] = *tunnel
}
