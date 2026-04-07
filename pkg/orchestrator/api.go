package orchestrator

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"magnax.ca/VPNManager/pkg/api"

	"github.com/gorilla/websocket"
)

type managerApi struct {
	pollInterval time.Duration
	cache        *Cache
}

func (m *managerApi) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("unable to upgrade", "err", err)
		return
	}
	defer c.Close() //nolint:errcheck

	t, msg, err := c.ReadMessage()
	if err != nil {
		slog.Error("read error", "err", err)
		return
	}
	if t != websocket.TextMessage {
		_ = sendConnectionClose(c, websocket.CloseUnsupportedData)
		slog.Error("expected text message")
		return
	}
	helloMsg := string(msg)
	parts := strings.Split(helloMsg, " ")

	if len(parts) != 3 {
		slog.Error("invalid HELLO msg", "message", helloMsg, "parts", parts)
		return
	} else if parts[0] != "HELLO" {
		slog.Error("invalid HELLO msg", "message", helloMsg, "greeting", parts[0])
		return
	}

	slog.Info("new connection", "name", parts[2])

	ctx := r.Context()

	switch parts[1] {
	case "0":
		resp, err := sendV1Request(c, api.Request{Type: api.UpdateRequest})
		if err != nil {
			slog.Error("status error", "err", err)
			return
		}
		if resp.Status != api.StatusOk {
			slog.Error("status error", "err", resp.Err)
			_ = sendConnectionClose(c, websocket.ClosePolicyViolation)
			return
		}
		processV1Update(m.cache, parts[2], resp.Data)
		m.manageV1Conn(ctx, parts[2], c)
	}
}

func sendConnectionClose(conn *websocket.Conn, code int) error {
	return conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(code, ""))
}

func (m *managerApi) manageV1Conn(ctx context.Context, name string, c *websocket.Conn) {
	// register connection for this manager
	actionReq, err := m.cache.Register(name)
	if err != nil {
		return
	}
	defer m.cache.Unregister(name)

	updateReqTicker := time.NewTicker(m.pollInterval)
	defer updateReqTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			_ = sendConnectionClose(c, websocket.CloseGoingAway)
			return
		case req := <-actionReq:
			resp, err := sendV1Request(c, req.Request)
			if err != nil {
				slog.Error("error sending request", "type", req.Request.Type, "err", err)
				req.Response <- api.Response{
					Status: api.StatusReqErr,
					Err:    err.Error(),
				}
				_ = sendConnectionClose(c, websocket.CloseProtocolError)
				return
			}

			req.Response <- *resp
			continue

		case <-updateReqTicker.C:
			resp, err := sendV1Request(c, api.Request{Type: api.UpdateRequest})
			if err != nil {
				slog.Error("status request error", "err", err)
				_ = sendConnectionClose(c, websocket.CloseProtocolError)
				return
			}
			switch resp.Status {
			case api.StatusOk:
				processV1Update(m.cache, name, resp.Data)
			case api.StatusErr:
				slog.Error("error from manager", "err", resp.Err)
				return
			case api.StatusReqErr:
				panic("sendV1Request should not generate StatusReqErr")
			}

			continue
		}
	}
}

func sendV1Request(c *websocket.Conn, r api.Request) (*api.Response, error) {
	msg, err := r.MarshalMsg(nil)
	if err != nil {
		return nil, err
	}
	err = c.WriteMessage(websocket.BinaryMessage, msg)
	if err != nil {
		return nil, err
	}
	t, msg, err := c.ReadMessage()
	if err != nil {
		return nil, err
	}
	if t != websocket.BinaryMessage {
		_ = sendConnectionClose(c, websocket.CloseUnsupportedData)
		return nil, ErrNotBinary
	}
	resp := &api.Response{}
	_, err = resp.UnmarshalMsg(msg)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func processV1Update(cache *Cache, name string, data []byte) {
	tunnel := &api.Tunnel{}
	_, err := tunnel.UnmarshalMsg(data)
	if err != nil {
		slog.Error("couldn't unmarshal update", "err", err)
		return
	}
	cache.InsertTunnel(name, tunnel)
}
