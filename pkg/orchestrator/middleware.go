package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"runtime/debug"
	"slices"
	"strings"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

type CtxKey struct {
	name string
}

var (
	OriginalAddrCtxKey = &CtxKey{"original-addr"}
)

func Must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

type Middleware func(h http.Handler) http.Handler

func RecoverPanicMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				slog.Error("panic", "err", err)
				debug.PrintStack() // from "runtime/debug"

				w.Header().Set("Connection", "close")
				w.Header().Set("Content-Type", "text/html; charset=utf-8")

				w.WriteHeader(http.StatusInternalServerError)
				_, _ = fmt.Fprintf(w, `<!doctype html>
<html lang="en">
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
	<title>Internal Server Error</title>
	<style>
html {
font-family: sans-serif;
line-height: 1.15;
}
body {
margin: 0;
}
.page {
max-width: 1280px;
margin: 0 auto;
}
h1 {
font-size: 2em;
margin: .67em 0;
}
pre {
font-family: monospace,monospace;
font-size: 1em;
}
	</style>
</head>
<body>
	<div class="page">
		<h1>Internal Server Error</h1>
		<pre>%v</pre>
	</div>
</body>
</html>`, err)
			}
		}()
		h.ServeHTTP(w, r)
	})
}

func OIDCSSOMiddleware(ctx context.Context, cfg *OIDCConfig, errorHandler func(http.ResponseWriter, int, error)) (Middleware, error) {
	ssoLogger := slog.Default().WithGroup("oidc")

	oidcRP, err := rp.NewRelyingPartyOIDC(
		ctx,
		cfg.RealmUrl,
		cfg.ClientID,
		cfg.ClientSecret,
		cfg.RawCallbackUrl,
		[]string{"openid", "offline_access"},
		rp.WithLogger(ssoLogger),
		rp.WithSigningAlgsFromDiscovery(),
	)
	if err != nil {
		return nil, err
	}

	// we use Must here because the config parse already checks
	callbackUrl := Must(url.Parse(cfg.RawCallbackUrl))

	return func(h http.Handler) http.Handler {
		processTokens := func(ctx context.Context, session *Session, tokens *oidc.Tokens[*oidc.IDTokenClaims], userinfo *oidc.UserInfo) {
			session.Tokens = tokens
			session.RegenerateId()
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			session := SessionFromContext(ctx)

			session.RefreshTokens(ctx, oidcRP)

			if session.IsAuth() {
				h.ServeHTTP(w, r)
				return
			}

			// todo investigate verifier

			if r.URL.Path == callbackUrl.Path && r.Host == callbackUrl.Host {
				state := r.FormValue("state")
				if errValue := r.FormValue("error"); errValue != "" {
					errorHandler(w, http.StatusInternalServerError, fmt.Errorf("%s: %s", errValue, r.FormValue("error_description")))
					return
				}

				tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](ctx, r.FormValue("code"), oidcRP)
				if err != nil {
					errorHandler(w, http.StatusUnauthorized, err)
					return
				}
				info, err := rp.Userinfo[*oidc.UserInfo](r.Context(), tokens.AccessToken, tokens.TokenType, tokens.IDTokenClaims.GetSubject(), oidcRP)
				if err != nil {
					errorHandler(w, http.StatusUnauthorized, err)
					return
				}

				processTokens(ctx, session, tokens, info)
				UpdateSessionId(w, ctx, session)

				http.Redirect(w, r, state, http.StatusFound)
			}

			http.Redirect(w, r, rp.AuthURL(r.URL.Path, oidcRP), http.StatusFound)
		})
	}, nil
}

func BearerAuthMiddleware(tokens ...string) Middleware {
	return func(h http.Handler) http.Handler {
		if len(tokens) == 0 {
			return h
		}

		unauthHandler := func(w http.ResponseWriter, r *http.Request) {
			slog.Info("unauthorized request")
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized"))
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(strings.TrimSpace(parts[0])) != "bearer" {
				unauthHandler(w, r)
				return
			}

			token := strings.TrimSpace(parts[1])
			if !slices.Contains(tokens, token) {
				unauthHandler(w, r)
				return
			}

			//slog.Debug("request authorized using a Bearer token")

			h.ServeHTTP(w, r)
		})
	}
}

func LoggingMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqAttr := slog.Group("req",
			"method", r.Method,
			"scheme", r.URL.Scheme,
			"host", r.Host,
			"path", r.URL.Path,
		)
		var remoteAttr slog.Attr
		if val, ok := r.Context().Value(OriginalAddrCtxKey).(string); ok {
			remoteAttr = slog.Group("remote",
				"addr", r.RemoteAddr,
				"orig", val,
			)
		} else {
			remoteAttr = slog.Group("remote",
				"addr", r.RemoteAddr,
			)
		}
		slog.Info("received request", reqAttr, remoteAttr)
		h.ServeHTTP(w, r)
	})
}

type PrefixList []netip.Prefix

func (p PrefixList) Contains(ip netip.Addr) bool {
	for _, prefix := range p {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func ForwardedMiddleware(cfg *Config) Middleware {
	var (
		XForwardedFor   = http.CanonicalHeaderKey("X-Forwarded-For")
		XForwardedProto = http.CanonicalHeaderKey("X-Forwarded-Proto")
	)

	return func(h http.Handler) http.Handler {
		if len(cfg.TrustedProxies) == 0 {
			return h
		}

		trustedRanges := make(PrefixList, 0, len(cfg.TrustedProxies))
		for _, proxyStr := range cfg.TrustedProxies {
			if strings.Contains(proxyStr, "/") {
				trustedRanges = append(trustedRanges, netip.MustParsePrefix(proxyStr))
			} else {
				addr := netip.MustParseAddr(proxyStr)
				trustedRanges = append(trustedRanges, netip.PrefixFrom(addr, addr.BitLen()))
			}
		}

		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			remoteIp := netip.MustParseAddrPort(r.RemoteAddr)
			if trustedRanges.Contains(remoteIp.Addr()) {
				// we can trust the headers
				header := r.Header

				if pr := header.Get(XForwardedProto); pr != "" {
					switch pr {
					case "http":
						r.URL.Scheme = "http"
					case "https":
						r.URL.Scheme = "https"
					default:
						slog.Warn("unknown X-Forwarded-Proto value", "value", pr)
					}
				}

				ctx := context.WithValue(r.Context(), OriginalAddrCtxKey, r.RemoteAddr)
				r = r.WithContext(ctx)

				if fr := header.Get(XForwardedFor); fr != "" {
					for _, ip := range slices.Backward(strings.Split(fr, ",")) {
						ip = strings.TrimSpace(ip)

						addr, err := netip.ParseAddr(ip)
						if err != nil {
							slog.Error("unable to parse addr", "addr", ip, "err", err)
							break
						}
						r.RemoteAddr = addr.String()
						if !trustedRanges.Contains(addr) {
							break
						}
					}
				}
			}
			h.ServeHTTP(w, r)
		})
	}
}

func SetSchemeMiddleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		r.URL.Scheme = scheme

		h.ServeHTTP(w, r)
	})
}
