package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"

	"magnax.ca/VPNManager/internal/web"
	"magnax.ca/VPNManager/pkg/api"
	"magnax.ca/VPNManager/pkg/pivpn"
)

var upgrader = websocket.Upgrader{}

var (
	ErrNotBinary = errors.New("expected response type as binary")

	reqId atomic.Uint64
)

func nextReqId() uint64 {
	return reqId.Add(1)
}

type Server struct {
	srv *http.Server

	cfg   *Config
	cache *Cache
	view  web.Engine
}

func NewServer(ctx context.Context, cfg *Config) *Server {
	cache := NewCache()
	mux := http.NewServeMux()
	engine, err := web.NewStdlibEngine()
	if err != nil {
		slog.Error("failed to initialize template engine", "err", err)
		return nil
	}

	httpLogger := slog.Default().WithGroup("http")
	httpLogger.Handler()

	srv := &Server{
		srv: &http.Server{
			Addr:     cfg.Address,
			ErrorLog: slog.NewLogLogger(httpLogger.Handler(), slog.LevelInfo),
		},
		cfg:   cfg,
		cache: cache,
		view:  engine,
	}

	// API
	mux.Handle("/api/comms/manager", BearerAuthMiddleware(cfg.PSK)(&managerApi{cfg.PollInterval(), cache}))

	// Static
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServerFS(web.StaticFS)))

	// Normal routes
	sub := srv.loadRoutes()
	CSRF := http.NewCrossOriginProtection()
	SS := NewSessionStore()

	h := sub
	if cfg.OAuth == nil {
		slog.Warn("no SSO configuration was provided, was it forgotten?")
	} else {
		sso, err := OIDCSSOMiddleware(ctx, cfg.OAuth, srv.serveError)
		if err != nil {
			slog.Error("unable to setup SSO", "err", err)
			return nil
		}
		h = sso(h)
	}
	mux.Handle("/", CSRF.Handler(SS.Middleware(h)))
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		srv.serveError(w, http.StatusNotFound, errors.New("page not found"))
	})

	proxiedMiddleware := ForwardedMiddleware(cfg)
	srv.srv.Handler = RecoverPanicMiddleware(SetSchemeMiddleware(proxiedMiddleware(LoggingMiddleware(mux))))

	return srv
}

func (s *Server) loadRoutes() http.Handler {
	mux := http.NewServeMux()

	mux.Handle("/", http.RedirectHandler("/tunnels", http.StatusSeeOther))
	mux.HandleFunc("GET /tunnels", s.httpGetTunnels)
	mux.HandleFunc("GET /tunnel/{name}", s.httpGetTunnel)
	mux.HandleFunc("GET /tunnel/{name}/{client}", s.httpGetTunnelClient)
	mux.HandleFunc("GET /tunnel/{name}/{client}/qr.png", s.httpGetTunnelClientQR)
	mux.HandleFunc("POST /tunnel/{name}/create", s.httpPOSTTunnelClientCreate)
	mux.HandleFunc("POST /tunnel/{name}/{client}/enable", s.httpPOSTTunnelClientEnable)
	mux.HandleFunc("POST /tunnel/{name}/{client}/disable", s.httpPOSTTunnelClientDisable)
	mux.HandleFunc("POST /tunnel/{name}/{client}/remove", s.httpPOSTTunnelClientRemove)

	return mux
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	var wg sync.WaitGroup

	wg.Go(func() {
		<-ctx.Done()
		_ = s.srv.Shutdown(ctx)
	})

	s.srv.BaseContext = func(_ net.Listener) context.Context {
		return ctx
	}

	slog.Info("starting server", "addr", s.srv.Addr)
	err := s.srv.ListenAndServe()
	wg.Wait()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

var (
	ErrBadTunnelName  = errors.New("bad tunnel name")
	ErrTunnelNotFound = errors.New("tunnel not found")
	ErrBadClientName  = errors.New("bad client name")
	ErrClientNotFound = errors.New("client not found")
)

func (s *Server) loadTunnel(r *http.Request) (string, *api.Tunnel, error) {
	tunnelName := r.PathValue("name")
	if tunnelName == "" {
		return tunnelName, nil, ErrBadTunnelName
	}

	tunnel := s.cache.GetTunnel(tunnelName)
	if tunnel == nil {
		return tunnelName, nil, ErrTunnelNotFound
	}

	return tunnelName, tunnel, nil
}

func (s *Server) loadClient(r *http.Request, t *api.Tunnel) (*pivpn.Client, error) {
	clientName := r.PathValue("client")
	if clientName == "" {
		return nil, ErrBadClientName
	}

	client := t.Clients.Client(clientName)
	if client == nil {
		return nil, ErrClientNotFound
	}

	return client, nil
}

func (s *Server) refreshTunnel(w http.ResponseWriter, comms chan<- ActionRequest, resultChan chan api.Response, tunnelName string) bool {
	comms <- ActionRequest{
		Request: api.Request{
			Type: api.UpdateRequest,
			ID:   nextReqId(),
		},
		Response: resultChan,
	}
	result := <-resultChan
	if result.Status != api.StatusOk {
		s.serveError(w, http.StatusInternalServerError, errors.New(result.Err))
		return true
	}

	newTunnel := &api.Tunnel{}
	_, err := newTunnel.UnmarshalMsg(result.Data)
	if err != nil {
		s.serveError(w, http.StatusInternalServerError, errors.New(result.Err))
		return true
	}

	s.cache.InsertTunnel(tunnelName, newTunnel)
	return false
}

func (s *Server) serveError(w http.ResponseWriter, statusCode int, err error) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	w.WriteHeader(statusCode)
	_ = s.view.Render(w, "error", web.C{
		"Title":   "Error",
		"Message": err.Error(),
	}, context.Background())
}

func (s *Server) httpGetTunnels(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = s.view.Render(
		w,
		"tunnels/list",
		web.C{
			"Title":   "Tunnels",
			"Tunnels": s.cache.Tunnels(),
		},
		r.Context(),
	)
}

func (s *Server) httpGetTunnel(w http.ResponseWriter, r *http.Request) {
	tunnelName, tunnel, err := s.loadTunnel(r)
	if err != nil {
		if errors.Is(err, ErrTunnelNotFound) {
			s.serveError(w, http.StatusNotFound, err)
		} else {
			s.serveError(w, http.StatusBadRequest, err)
		}
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = s.view.Render(
		w,
		"tunnels/show",
		web.C{
			"Title":      fmt.Sprintf("%s - %s", tunnelName, tunnel.Endpoint.String()),
			"TunnelName": tunnelName,
			"Tunnel":     tunnel,
		},
		r.Context(),
	)
}

func (s *Server) httpGetTunnelClient(w http.ResponseWriter, r *http.Request) {
	tunnelName, tunnel, err := s.loadTunnel(r)
	if err != nil {
		if errors.Is(err, ErrTunnelNotFound) {
			s.serveError(w, http.StatusNotFound, err)
		} else {
			s.serveError(w, http.StatusBadRequest, err)
		}
		return
	}

	client, err := s.loadClient(r, tunnel)
	if err != nil {
		if errors.Is(err, ErrClientNotFound) {
			s.serveError(w, http.StatusNotFound, err)
		} else {
			s.serveError(w, http.StatusBadRequest, err)
		}
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = s.view.Render(
		w,
		"tunnels/client",
		web.C{
			"Title":      fmt.Sprintf("%[3]s @ %[1]s - %[2]s", tunnelName, tunnel.Endpoint.String(), client.Name),
			"TunnelName": tunnelName,
			"Tunnel":     tunnel,
			"Client":     client,
		},
		r.Context(),
	)
}

func (s *Server) httpGetTunnelClientQR(w http.ResponseWriter, r *http.Request) {
	_, tunnel, err := s.loadTunnel(r)
	if err != nil {
		if errors.Is(err, ErrTunnelNotFound) {
			s.serveError(w, http.StatusNotFound, err)
		} else {
			s.serveError(w, http.StatusBadRequest, err)
		}
		return
	}

	client, err := s.loadClient(r, tunnel)
	if err != nil {
		if errors.Is(err, ErrClientNotFound) {
			s.serveError(w, http.StatusNotFound, err)
		} else {
			s.serveError(w, http.StatusBadRequest, err)
		}
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.WriteHeader(http.StatusOK)
	_ = client.WriteQrCode(w)
}

func (s *Server) httpPOSTTunnelClientEnable(w http.ResponseWriter, r *http.Request) {
	tunnelName, tunnel, err := s.loadTunnel(r)
	if err != nil {
		if errors.Is(err, ErrTunnelNotFound) {
			s.serveError(w, http.StatusNotFound, err)
		} else {
			s.serveError(w, http.StatusBadRequest, err)
		}
		return
	}

	client, err := s.loadClient(r, tunnel)
	if err != nil {
		if errors.Is(err, ErrClientNotFound) {
			s.serveError(w, http.StatusNotFound, err)
		} else {
			s.serveError(w, http.StatusBadRequest, err)
		}
		return
	}

	comms, ok := s.cache.Get(tunnelName)
	if !ok {
		s.serveError(w, http.StatusServiceUnavailable, fmt.Errorf("no communication channel with %q available", tunnelName))
		return
	}

	resultChan := make(chan api.Response, 1)
	data, err := api.EnableRequestData{Name: client.Name}.MarshalMsg(nil)
	if err != nil {
		s.serveError(w, http.StatusInternalServerError, err)
		return
	}
	comms <- ActionRequest{
		Request: api.Request{
			Type: api.EnablePeerRequest,
			ID:   nextReqId(),
			Data: data,
		},
		Response: resultChan,
	}
	result := <-resultChan
	if result.Status != api.StatusOk {
		s.serveError(w, http.StatusInternalServerError, errors.New(result.Err))
		return
	}

	if s.refreshTunnel(w, comms, resultChan, tunnelName) {
		return
	}

	nextUrl := "/tunnel/" + tunnelName
	if v := r.FormValue("next"); v != "" {
		nextUrl = v
	}

	http.Redirect(w, r, nextUrl, http.StatusFound)
}

func (s *Server) httpPOSTTunnelClientDisable(w http.ResponseWriter, r *http.Request) {
	tunnelName, tunnel, err := s.loadTunnel(r)
	if err != nil {
		if errors.Is(err, ErrTunnelNotFound) {
			s.serveError(w, http.StatusNotFound, err)
		} else {
			s.serveError(w, http.StatusBadRequest, err)
		}
		return
	}

	client, err := s.loadClient(r, tunnel)
	if err != nil {
		if errors.Is(err, ErrClientNotFound) {
			s.serveError(w, http.StatusNotFound, err)
		} else {
			s.serveError(w, http.StatusBadRequest, err)
		}
		return
	}

	comms, ok := s.cache.Get(tunnelName)
	if !ok {
		s.serveError(w, http.StatusServiceUnavailable, fmt.Errorf("no communication channel with %q available", tunnelName))
		return
	}

	resultChan := make(chan api.Response, 1)
	data, err := api.DisableRequestData{Name: client.Name}.MarshalMsg(nil)
	if err != nil {
		s.serveError(w, http.StatusInternalServerError, err)
		return
	}
	comms <- ActionRequest{
		Request: api.Request{
			Type: api.DisablePeerRequest,
			ID:   nextReqId(),
			Data: data,
		},
		Response: resultChan,
	}
	result := <-resultChan
	if result.Status != api.StatusOk {
		s.serveError(w, http.StatusInternalServerError, errors.New(result.Err))
		return
	}

	if s.refreshTunnel(w, comms, resultChan, tunnelName) {
		return
	}

	nextUrl := "/tunnel/" + tunnelName
	if v := r.FormValue("next"); v != "" {
		nextUrl = v
	}

	http.Redirect(w, r, nextUrl, http.StatusFound)
}

func (s *Server) httpPOSTTunnelClientCreate(w http.ResponseWriter, r *http.Request) {
	tunnelName, tunnel, err := s.loadTunnel(r)
	if err != nil {
		if errors.Is(err, ErrTunnelNotFound) {
			s.serveError(w, http.StatusNotFound, err)
		} else {
			s.serveError(w, http.StatusBadRequest, err)
		}
		return
	}

	clientName := r.PostFormValue("name")

	comms, ok := s.cache.Get(tunnelName)
	if !ok {
		s.serveError(w, http.StatusServiceUnavailable, fmt.Errorf("no communication channel with %q available", tunnelName))
		return
	}

	resultChan := make(chan api.Response, 1)
	data, err := api.CreateRequestData{Name: clientName}.MarshalMsg(nil)
	if err != nil {
		s.serveError(w, http.StatusInternalServerError, err)
		return
	}
	comms <- ActionRequest{
		Request: api.Request{
			Type: api.CreatePeerRequest,
			ID:   nextReqId(),
			Data: data,
		},
		Response: resultChan,
	}
	result := <-resultChan
	if result.Status != api.StatusOk {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		_ = s.view.Render(
			w,
			"tunnels/show",
			web.C{
				"Title":      fmt.Sprintf("%s - %s", tunnelName, tunnel.Endpoint.String()),
				"TunnelName": tunnelName,
				"Tunnel":     tunnel,
				"Error":      result.Err,
				"FormValue":  clientName,
			},
			r.Context(),
		)
		return
	}

	if s.refreshTunnel(w, comms, resultChan, tunnelName) {
		return
	}

	http.Redirect(w, r, strings.Join([]string{"/tunnel", tunnelName, clientName}, "/"), http.StatusFound)
}

func (s *Server) httpPOSTTunnelClientRemove(w http.ResponseWriter, r *http.Request) {
	tunnelName, tunnel, err := s.loadTunnel(r)
	if err != nil {
		if errors.Is(err, ErrTunnelNotFound) {
			s.serveError(w, http.StatusNotFound, err)
		} else {
			s.serveError(w, http.StatusBadRequest, err)
		}
		return
	}

	client, err := s.loadClient(r, tunnel)
	if err != nil {
		if errors.Is(err, ErrClientNotFound) {
			s.serveError(w, http.StatusNotFound, err)
		} else {
			s.serveError(w, http.StatusBadRequest, err)
		}
		return
	}

	comms, ok := s.cache.Get(tunnelName)
	if !ok {
		s.serveError(w, http.StatusServiceUnavailable, fmt.Errorf("no communication channel with %q available", tunnelName))
		return
	}

	resultChan := make(chan api.Response, 1)
	data, err := api.DeleteRequestData{Name: client.Name}.MarshalMsg(nil)
	if err != nil {
		s.serveError(w, http.StatusInternalServerError, err)
		return
	}
	comms <- ActionRequest{
		Request: api.Request{
			Type: api.DeletePeerRequest,
			ID:   nextReqId(),
			Data: data,
		},
		Response: resultChan,
	}
	result := <-resultChan
	if result.Status != api.StatusOk {
		s.serveError(w, http.StatusInternalServerError, errors.New(result.Err))
		return
	}

	if s.refreshTunnel(w, comms, resultChan, tunnelName) {
		return
	}

	http.Redirect(w, r, "/tunnel/"+tunnelName, http.StatusFound)
}
