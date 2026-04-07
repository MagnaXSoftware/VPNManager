package api

//go:generate go tool msgp

import (
	"github.com/tinylib/msgp/msgp"

	"magnax.ca/VPNManager/pkg/pivpn"
	"magnax.ca/VPNManager/pkg/wireguard"
)

type Tunnel struct {
	Endpoint wireguard.Endpoint `msg:"endpoint"`
	Server   wireguard.Config   `msg:"server"`
	Clients  pivpn.ClientList   `msg:"clients"`
}

type RequestType int

const (
	UpdateRequest RequestType = iota
	CreatePeerRequest
	DeletePeerRequest
	EnablePeerRequest
	DisablePeerRequest
)

type Request struct {
	Type RequestType `msg:"type"`
	ID   uint64      `msg:"id,omitempty"`
	Data msgp.Raw    `msg:"data,omitempty"`
}

type CreateRequestData struct {
	Name string `msg:"name"`
}

type DeleteRequestData struct {
	Name string `msg:"name"`
}

type EnableRequestData struct {
	Name string `msg:"name"`
}

type DisableRequestData struct {
	Name string `msg:"name"`
}

type Status int

const (
	StatusErr Status = iota
	StatusOk
	StatusReqErr
)

type Response struct {
	Type   RequestType `msg:"type,omitempty"`
	ID     uint64      `msg:"id,omitempty"`
	Status Status      `msg:"status"`
	Data   msgp.Raw    `msg:"data,omitempty"`
	Err    string      `msg:"err,omitempty"`
}

func TunnelFromVPN(vpn *pivpn.Vpn) *Tunnel {
	return &Tunnel{
		Endpoint: vpn.Conf.Endpoint,
		Server:   vpn.Server,
		Clients:  vpn.Clients,
	}
}
