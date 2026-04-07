package manager

import (
	"context"
	"errors"
	"fmt"
	"log"
	"math"
	"math/rand/v2"
	"net/http"
	"net/url"
	"time"

	"magnax.ca/VPNManager/pkg/api"

	"github.com/gorilla/websocket"
)

const (
	helloV0Format = "HELLO 0 %s"
)

type Client struct {
	cfg *Config
}

func NewClient(cfg *Config) *Client {
	return &Client{
		cfg: cfg,
	}
}

type dialWithBackoff struct {
	RetryMin time.Duration
	RetryMax time.Duration
}

func (d *dialWithBackoff) backOff(i int) time.Duration {
	mult := int64(math.Pow(2, float64(i)) * float64(d.RetryMin))
	mult += rand.N(int64(d.RetryMin)) - (int64(d.RetryMin) / 2)
	sleep := time.Duration(mult)
	if sleep > d.RetryMax {
		sleep = d.RetryMax
	} else if sleep < d.RetryMin {
		sleep = d.RetryMin
	}
	return sleep
}

func (d *dialWithBackoff) Dial(url url.URL, ctx context.Context, psk string) (*websocket.Conn, error) {
	var headers http.Header
	if psk != "" {
		headers = make(http.Header)
		headers.Add("Authorization", fmt.Sprintf("Bearer %s", psk))
	}
	for i := 0; ; i++ {
		conn, resp, err := websocket.DefaultDialer.DialContext(ctx, url.String(), headers)
		if err == nil {
			log.Printf("connected to %s", url.String())
			return conn, nil
		}
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			log.Printf("unauthorized, is the PSK correct?")
		}

		wait := d.backOff(i)
		log.Printf("retrying after %s", wait)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func (c *Client) Connect(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			_ = c.connect(ctx)
		}
	}
}

func (c *Client) connect(ctx context.Context) error {
	u := url.URL{Scheme: "ws", Host: c.cfg.OrchestratorAddr, Path: "/api/comms/manager"}
	if c.cfg.UseTLS {
		u.Scheme = "wss"
	}
	d := &dialWithBackoff{
		c.cfg.Timeouts.MinRetry(),
		c.cfg.Timeouts.MaxRetry(),
	}
	conn, err := d.Dial(u, ctx, c.cfg.PSK)
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck

	err = conn.WriteMessage(websocket.TextMessage, []byte(fmt.Sprintf(helloV0Format, c.cfg.Name))) //nolint:modernize
	if err != nil {
		return err
	}

	done := make(chan struct{})
	go c.manageConnection(ctx, done, conn)

	for {
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			return nil
		}
	}
}

func (c *Client) manageConnection(ctx context.Context, done chan struct{}, conn *websocket.Conn) {
	defer close(done)

	for {
		t, message, err := conn.ReadMessage()
		if err != nil {
			if cErr, ok := errors.AsType[*websocket.CloseError](err); ok {
				switch cErr.Code {
				case websocket.CloseNormalClosure:
					fallthrough
				case websocket.CloseGoingAway:
					log.Println("server going away")
				}
			} else if ctx.Err() == nil {
				log.Printf("received error when receiving message: %s", err)
			}
			return
		}
		if t != websocket.BinaryMessage {
			log.Println("recv: received invalid message (not binary)")
			_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseUnsupportedData, "received invalid message (not binary)"))
			return
		}
		req := &api.Request{}
		_, err = req.UnmarshalMsg(message)
		if err != nil {
			_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseInvalidFramePayloadData, err.Error()))
			return
		}
		resp := processRequest(req, c.cfg)
		respRaw, err := resp.MarshalMsg(nil)
		if err != nil {
			_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseInvalidFramePayloadData, err.Error()))
			return
		}
		_ = conn.WriteMessage(websocket.BinaryMessage, respRaw)
	}
}
