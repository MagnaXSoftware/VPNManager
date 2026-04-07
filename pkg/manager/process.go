package manager

import (
	"log"

	"magnax.ca/VPNManager/pkg/api"
	"magnax.ca/VPNManager/pkg/pivpn"

	"github.com/tinylib/msgp/msgp"
)

func _runProcessor[T any, PT interface {
	*T
	msgp.Unmarshaler
}](cfg *Config, req *api.Request, f func(*Config, *T) (msgp.Raw, error)) *api.Response {
	resp := &api.Response{
		Type: req.Type,
		ID:   req.ID,
	}
	data := PT(new(T))
	_, err := data.UnmarshalMsg(req.Data)
	if err != nil {
		resp.Status = api.StatusErr
		resp.Err = err.Error()
		return resp
	}

	r, err := f(cfg, data)
	if err != nil {
		resp.Status = api.StatusErr
		resp.Err = err.Error()
	} else {
		resp.Status = api.StatusOk
		if r != nil {
			resp.Data = r
		}
	}

	return resp
}

func processRequest(req *api.Request, cfg *Config) *api.Response {
	switch req.Type {
	case api.UpdateRequest:
		resp := &api.Response{
			Type: req.Type,
			ID:   req.ID,
		}
		data, err := processUpdateRequest(cfg)
		if err != nil {
			resp.Status = api.StatusErr
			resp.Err = err.Error()
		} else {
			resp.Status = api.StatusOk
			resp.Data = data
		}
		return resp
	case api.CreatePeerRequest:
		return _runProcessor(cfg, req, processCreateRequest)
	case api.DeletePeerRequest:
		return _runProcessor(cfg, req, processDeleteRequest)
	case api.EnablePeerRequest:
		return _runProcessor(cfg, req, processEnableRequest)
	case api.DisablePeerRequest:
		return _runProcessor(cfg, req, processDisableRequest)
	}

	return &api.Response{
		Type:   req.Type,
		ID:     req.ID,
		Status: api.StatusErr,
		Err:    "did not process request",
	}
}

func processUpdateRequest(cfg *Config) (msgp.Raw, error) {
	vpn, err := pivpn.LoadVpnWithLocations(
		cfg.PiVPNConfig.Name,
		cfg.PiVPNConfig.ConfigFilePath,
		cfg.PiVPNConfig.TunnelDirectory,
		cfg.PiVPNConfig.ConfigsDirectory,
		cfg.PiVPNConfig.KeysDirectory,
	)
	if err != nil {
		log.Printf("unable to load VPN: %s", err)
		return nil, err
	}

	tunnel := api.TunnelFromVPN(vpn)

	return tunnel.MarshalMsg(nil)
}

func processCreateRequest(cfg *Config, data *api.CreateRequestData) (msgp.Raw, error) {
	vpn, err := pivpn.LoadVpnWithLocations(
		cfg.PiVPNConfig.Name,
		cfg.PiVPNConfig.ConfigFilePath,
		cfg.PiVPNConfig.TunnelDirectory,
		cfg.PiVPNConfig.ConfigsDirectory,
		cfg.PiVPNConfig.KeysDirectory,
	)
	if err != nil {
		log.Printf("unable to load VPN: %s", err)
		return nil, err
	}

	err = vpn.AddClient(data.Name)
	if err != nil {
		return nil, err
	}

	client := vpn.Clients.Client(data.Name)
	return client.MarshalMsg(nil)
}

func processDeleteRequest(cfg *Config, data *api.DeleteRequestData) (msgp.Raw, error) {
	vpn, err := pivpn.LoadVpnWithLocations(
		cfg.PiVPNConfig.Name,
		cfg.PiVPNConfig.ConfigFilePath,
		cfg.PiVPNConfig.TunnelDirectory,
		cfg.PiVPNConfig.ConfigsDirectory,
		cfg.PiVPNConfig.KeysDirectory,
	)
	if err != nil {
		log.Printf("unable to load VPN: %s", err)
		return nil, err
	}

	err = vpn.RemoveClient(data.Name)
	return nil, err
}

func processEnableRequest(cfg *Config, data *api.EnableRequestData) (msgp.Raw, error) {
	vpn, err := pivpn.LoadVpnWithLocations(
		cfg.PiVPNConfig.Name,
		cfg.PiVPNConfig.ConfigFilePath,
		cfg.PiVPNConfig.TunnelDirectory,
		cfg.PiVPNConfig.ConfigsDirectory,
		cfg.PiVPNConfig.KeysDirectory,
	)
	if err != nil {
		log.Printf("unable to load VPN: %s", err)
		return nil, err
	}

	err = vpn.EnableClient(data.Name)
	return nil, err
}

func processDisableRequest(cfg *Config, data *api.DisableRequestData) (msgp.Raw, error) {
	vpn, err := pivpn.LoadVpnWithLocations(
		cfg.PiVPNConfig.Name,
		cfg.PiVPNConfig.ConfigFilePath,
		cfg.PiVPNConfig.TunnelDirectory,
		cfg.PiVPNConfig.ConfigsDirectory,
		cfg.PiVPNConfig.KeysDirectory,
	)
	if err != nil {
		log.Printf("unable to load VPN: %s", err)
		return nil, err
	}

	err = vpn.DisableClient(data.Name)
	return nil, err
}
