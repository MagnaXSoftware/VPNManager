package orchestrator

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

const (
	sessionCookieName = "orchestrator_session"
)

var (
	SessionStoreCtxKey = &CtxKey{"session-store"}
	SessionCtxKey      = &CtxKey{"session"}
)

type SessionStore struct {
	mu    sync.Mutex
	store []*Session
}

func SessionStoreFromContext(ctx context.Context) *SessionStore {
	if session, ok := ctx.Value(SessionStoreCtxKey).(*SessionStore); ok {
		return session
	}
	panic(errors.New("SessionStore not found in context"))
}

func SessionFromContext(ctx context.Context) *Session {
	if session, ok := ctx.Value(SessionCtxKey).(*Session); ok {
		return session
	}
	panic(errors.New("session not found in context"))
}

func UpdateSessionId(w http.ResponseWriter, ctx context.Context, session *Session) {
	cookies := w.Header().Values("Set-Cookie")

	for i, cookieStr := range cookies {
		cookie, err := http.ParseSetCookie(cookieStr)
		if err != nil {
			return
		}
		if cookie.Name != sessionCookieName {
			continue
		}
		cookie.Value = session.Id
		cookies[i] = cookie.String()
	}
}

func addSessionCookie(w http.ResponseWriter, session *Session) {
	cookie := &http.Cookie{
		Name:     sessionCookieName,
		Value:    session.Id,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(session.Duration),
		MaxAge:   int(session.Duration.Seconds()),
	}

	w.Header().Add("Set-Cookie", cookie.String())
}

func NewSessionStore() *SessionStore {
	return &SessionStore{}
}

func (s *SessionStore) New() *Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.newLocked()
}

func (s *SessionStore) newLocked() *Session {
	for {
		session := &Session{}
		session.RegenerateId()
		session.LastSeen = time.Now()
		session.Duration = 14 * 24 * time.Hour

		for _, knownSessions := range s.store {
			if knownSessions.Id == session.Id {
				continue
			}
		}

		s.store = append(s.store, session)

		return session
	}
}

func (s *SessionStore) Get(id string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.getLocked(id)
}

func (s *SessionStore) GetOrNew(id string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()

	session := s.getLocked(id)
	if session == nil {
		session = s.newLocked()
	}
	return session
}

func (s *SessionStore) getLocked(id string) *Session {
	for i, session := range s.store {
		if session.Id == id {
			if session.LastSeen.Add(session.Duration).After(time.Now()) {
				return session
			}

			s.store = append(s.store[:i], s.store[i+1:]...)
			break
		}
	}

	return nil
}

func (s *SessionStore) Middleware(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), SessionStoreCtxKey, s)

		w.Header().Add("Vary", "Cookie")
		w.Header().Add("Cache-Control", "no-store")

		var session *Session
		for _, cookie := range r.CookiesNamed(sessionCookieName) {
			session = s.Get(cookie.Value)
			if session == nil {
				continue
			}
			session.LastSeen = time.Now()
			break
		}
		if session == nil {
			session = s.New()
		}

		addSessionCookie(w, session)

		r = r.WithContext(context.WithValue(ctx, SessionCtxKey, session))

		h.ServeHTTP(w, r)
	})
}

type Session struct {
	Id       string
	Values   map[string]any
	Duration time.Duration
	LastSeen time.Time
	Tokens   *oidc.Tokens[*oidc.IDTokenClaims]
}

func (s *Session) RegenerateId() {
	s.Id = rand.Text()
}

func (s *Session) IsAuth() bool {
	return s.Tokens != nil && s.Tokens.Valid()
}

func (s *Session) RefreshTokens(ctx context.Context, relParty rp.RelyingParty) {
	if s.Tokens == nil || s.Tokens.Valid() {
		return
	}
	if s.Tokens.RefreshToken == "" {
		return
	}

	newTokens, err := rp.RefreshTokens[*oidc.IDTokenClaims](ctx, relParty, s.Tokens.RefreshToken, "", "")
	if err != nil {
		return
	}

	if newTokens.RefreshToken == "" {
		newTokens.RefreshToken = s.Tokens.RefreshToken
	}
	s.Tokens = newTokens
}
