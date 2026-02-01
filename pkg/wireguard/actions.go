package wireguard

import (
	"errors"
	"fmt"
)

var (
	PeerNotFound = errors.New("peer not found")
)

func (c *Config) DisablePeer(name string) error {
	idx := -1
	for i, peer := range c.Peers {
		if peer.Name == name {
			idx = i
		}
	}
	if idx < 0 {
		return PeerNotFound
	}

	c.Peers[idx].Disabled = true
	return nil
}

func (c *Config) EnablePeer(name string) error {
	idx := -1
	for i, peer := range c.Peers {
		if peer.Name == name {
			idx = i
		}
	}
	if idx < 0 {
		return PeerNotFound
	}

	c.Peers[idx].Disabled = false
	return nil
}

func (c *Config) RemovePeer(name string) error {
	idx := -1
	for i, peer := range c.Peers {
		if peer.Name == name {
			idx = i
		}
	}
	if idx < 0 {
		return PeerNotFound
	}

	c.Peers = append(c.Peers[:idx], c.Peers[idx+1:]...)
	return nil
}

func (c *Config) AddPeer(peer Peer) error {
	if peer.Name == "" {
		return errors.New("peer must have a name")
	}
	for _, p := range c.Peers {
		if p.Name == peer.Name {
			return fmt.Errorf("peer %q is already registered", peer.Name)
		}
	}

	c.Peers = append(c.Peers, peer)
	return nil
}
