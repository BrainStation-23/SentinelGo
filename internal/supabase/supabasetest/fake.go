// Package supabasetest provides an in-process fake of the Supabase gateway for
// tests: it records every request and answers with scripted responses, and can
// simulate an expired access token and refresh-token rotation.
package supabasetest

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"sentinelgo/internal/supabase"
)

// AnonKey is the anon key the fake expects in the apikey header.
const AnonKey = "test-anon-key"

// Request is one recorded request.
type Request struct {
	Method   string
	Path     string // raw path, exactly as sent
	RawQuery string
	Header   http.Header
	Body     []byte
}

// Response is a scripted reply.
type Response struct {
	Status int
	Body   string
	Header map[string]string
	Delay  time.Duration // wait before answering (honours client cancellation)
}

// Server is a fake Supabase gateway backed by httptest.
type Server struct {
	*httptest.Server

	mu       sync.Mutex
	routes   map[string][]Response // "METHOD /path" -> responses; the last one repeats
	requests []Request

	accessToken  string
	refreshToken string
	expired      map[string]bool // access tokens that now get rejected
	rotate       bool            // emulate GoTrue refresh-token rotation
	revoked      map[string]bool // refresh tokens already used
	generation   int
}

// New starts a fake gateway that is closed when the test ends. Its initial
// session is access token "access-0" / refresh token "refresh-0".
func New(t testing.TB) *Server {
	t.Helper()
	s := &Server{
		routes:       map[string][]Response{},
		accessToken:  "access-0",
		refreshToken: "refresh-0",
		expired:      map[string]bool{},
		revoked:      map[string]bool{},
	}
	s.Server = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.Close)
	return s
}

// Handle scripts the responses for method + exact path. Each request consumes
// the next response; the last one keeps being returned.
func (s *Server) Handle(method, path string, responses ...Response) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes[method+" "+path] = responses
}

// Requests returns a copy of every request received so far.
func (s *Server) Requests() []Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Request(nil), s.requests...)
}

// AccessToken returns the session's current access token.
func (s *Server) AccessToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.accessToken
}

// RefreshToken returns the session's current refresh token.
func (s *Server) RefreshToken() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refreshToken
}

// ExpireJWT makes the current access token rejected from now on, the way the
// real gateway answers an expired JWT: PostgREST 401 PGRST301, Storage 400
// InvalidJWT.
func (s *Server) ExpireJWT() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expired[s.accessToken] = true
}

// RotateRefresh turns on GoTrue refresh emulation at /auth/v1/token: each
// successful refresh issues a new access/refresh pair and revokes the refresh
// token that was used; reusing a revoked one fails with
// refresh_token_already_used.
func (s *Server) RotateRefresh() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rotate = true
}

// Client returns a supabase.Client pointed at the fake, using token for the
// bearer (nil means the fake's current access token).
func (s *Server) Client(token func() string) *supabase.Client {
	if token == nil {
		token = s.AccessToken
	}
	return supabase.New(s.URL, AnonKey, token, supabase.WithHTTPClient(s.Server.Client()))
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	s.requests = append(s.requests, Request{
		Method:   r.Method,
		Path:     r.URL.EscapedPath(),
		RawQuery: r.URL.RawQuery,
		Header:   r.Header.Clone(),
		Body:     body,
	})

	if s.rotate && r.URL.Path == "/auth/v1/token" {
		resp := s.refreshLocked(body)
		s.mu.Unlock()
		write(w, r, resp)
		return
	}
	if bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "); bearer != "" && s.expired[bearer] {
		s.mu.Unlock()
		write(w, r, expiredResponse(r.URL.Path))
		return
	}

	key := r.Method + " " + r.URL.EscapedPath()
	responses, ok := s.routes[key]
	var resp Response
	switch {
	case !ok || len(responses) == 0:
		resp = Response{Status: http.StatusNotFound, Body: `{"error":"not_found","message":"no fake route for ` + key + `"}`}
	case len(responses) == 1:
		resp = responses[0]
	default:
		resp = responses[0]
		s.routes[key] = responses[1:]
	}
	s.mu.Unlock()
	write(w, r, resp)
}

// refreshLocked emulates a GoTrue refresh. s.mu must be held.
func (s *Server) refreshLocked(body []byte) Response {
	got := extractRefreshToken(body)
	switch {
	case s.revoked[got]:
		return Response{Status: http.StatusBadRequest, Body: `{"code":400,"error_code":"refresh_token_already_used","msg":"Invalid Refresh Token: Already Used"}`}
	case got != s.refreshToken:
		return Response{Status: http.StatusBadRequest, Body: `{"code":400,"error_code":"refresh_token_not_found","msg":"Invalid Refresh Token: Refresh Token Not Found"}`}
	}
	s.revoked[got] = true
	s.generation++
	s.accessToken = fmt.Sprintf("access-%d", s.generation)
	s.refreshToken = fmt.Sprintf("refresh-%d", s.generation)
	return Response{Status: http.StatusOK, Body: fmt.Sprintf(
		`{"access_token":%q,"token_type":"bearer","expires_in":3600,"refresh_token":%q,"user":{"id":"00000000-0000-0000-0000-000000000001"}}`,
		s.accessToken, s.refreshToken)}
}

func extractRefreshToken(body []byte) string {
	const key = `"refresh_token":"`
	i := strings.Index(string(body), key)
	if i < 0 {
		return ""
	}
	rest := string(body[i+len(key):])
	if j := strings.IndexByte(rest, '"'); j >= 0 {
		return rest[:j]
	}
	return ""
}

func expiredResponse(path string) Response {
	if strings.HasPrefix(path, "/storage/") {
		return Response{Status: http.StatusBadRequest, Body: `{"statusCode":"400","error":"InvalidJWT","message":"\"exp\" claim timestamp check failed"}`}
	}
	return Response{Status: http.StatusUnauthorized, Body: `{"code":"PGRST301","details":null,"hint":null,"message":"JWT expired"}`}
}

func write(w http.ResponseWriter, r *http.Request, resp Response) {
	if resp.Delay > 0 {
		select {
		case <-time.After(resp.Delay):
		case <-r.Context().Done():
			return
		}
	}
	for k, v := range resp.Header {
		w.Header().Set(k, v)
	}
	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	status := resp.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, resp.Body)
}
