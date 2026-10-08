package supabase

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestParseAPIError_Shapes(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		wantCode string
		wantMsg  string
	}{
		{"postgrest", 401, `{"code":"PGRST301","details":null,"hint":null,"message":"JWT expired"}`, "PGRST301", "JWT expired"},
		{"storage", 400, `{"statusCode":"400","error":"InvalidJWT","message":"jwt expired"}`, "InvalidJWT", "jwt expired"},
		{"storage not found", 400, `{"statusCode":"404","error":"not_found","message":"Object not found"}`, "not_found", "Object not found"},
		{"gotrue legacy", 400, `{"error":"invalid_grant","error_description":"Invalid Refresh Token"}`, "invalid_grant", "Invalid Refresh Token"},
		{"gotrue current", 403, `{"code":403,"error_code":"bad_jwt","msg":"invalid JWT"}`, "bad_jwt", "invalid JWT"},
		{"postgres", 403, `{"code":"42501","message":"permission denied for table agents"}`, "42501", "permission denied for table agents"},
		{"html", 502, `<html>Bad Gateway</html>`, "", ""},
		{"empty", 500, ``, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := parseAPIError("POST", "/rest/v1/rpc/f", tc.status, []byte(tc.body))
			if e.Status != tc.status || e.Code != tc.wantCode || e.Message != tc.wantMsg {
				t.Errorf("got status=%d code=%q msg=%q, want %d %q %q", e.Status, e.Code, e.Message, tc.status, tc.wantCode, tc.wantMsg)
			}
			if e.Body != tc.body {
				t.Errorf("Body = %q, want %q", e.Body, tc.body)
			}
		})
	}
}

func TestAPIError_ErrorFormat(t *testing.T) {
	e := &APIError{Status: 401, Code: "PGRST301", Message: "JWT expired", Method: "POST", Path: "/rest/v1/rpc/f"}
	if got, want := e.Error(), "POST /rest/v1/rpc/f: status 401: PGRST301 JWT expired"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	bare := &APIError{Status: 502, Body: "<html>Bad Gateway</html>", Method: "GET", Path: "/x"}
	if got, want := bare.Error(), "GET /x: status 502: <html>Bad Gateway</html>"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}

func TestParseAPIError_TruncatesBody(t *testing.T) {
	big := strings.Repeat("x", 3*maxErrorBody)
	if e := parseAPIError("GET", "/x", 500, []byte(big)); len(e.Body) != maxErrorBody {
		t.Errorf("len(Body) = %d, want %d", len(e.Body), maxErrorBody)
	}
}

func TestClassifiers(t *testing.T) {
	apiErr := func(status int, code string) error {
		return fmt.Errorf("wrapped: %w", &APIError{Status: status, Code: code, Method: "POST", Path: "/p"})
	}
	tests := []struct {
		name                        string
		err                         error
		unauthorized, forbidden, nf bool
	}{
		{"401 plain", apiErr(401, ""), true, false, false},
		{"401 PGRST301", apiErr(401, "PGRST301"), true, false, false},
		{"storage 400 InvalidJWT", apiErr(400, "InvalidJWT"), true, false, false},
		{"gotrue 403 bad_jwt", apiErr(403, "bad_jwt"), true, false, false},
		{"403 plain", apiErr(403, ""), false, true, false},
		{"403 42501", apiErr(403, "42501"), false, true, false},
		{"404", apiErr(404, ""), false, false, true},
		{"storage 400 not_found", apiErr(400, "not_found"), false, false, true},
		{"PGRST202", apiErr(404, "PGRST202"), false, false, true},
		{"500", apiErr(500, ""), false, false, false},
		{"plain error mentioning 401", errors.New("status 401 unauthorized"), false, false, false},
		{"nil", nil, false, false, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsUnauthorized(tc.err); got != tc.unauthorized {
				t.Errorf("IsUnauthorized = %v, want %v", got, tc.unauthorized)
			}
			if got := IsForbidden(tc.err); got != tc.forbidden {
				t.Errorf("IsForbidden = %v, want %v", got, tc.forbidden)
			}
			if got := IsNotFound(tc.err); got != tc.nf {
				t.Errorf("IsNotFound = %v, want %v", got, tc.nf)
			}
		})
	}
	if got := StatusCode(apiErr(429, "")); got != 429 {
		t.Errorf("StatusCode = %d, want 429", got)
	}
	if got := StatusCode(errors.New("dial tcp: refused")); got != 0 {
		t.Errorf("StatusCode(network error) = %d, want 0", got)
	}
}

// FuzzParseAPIError feeds arbitrary error bodies (which come from the network)
// through the parser and the error formatter.
//
// To fuzz: go test -run='^$' -fuzz='^FuzzParseAPIError$' -fuzztime=1m ./internal/supabase/
func FuzzParseAPIError(f *testing.F) {
	for _, s := range []string{
		`{"code":"PGRST301","details":null,"hint":null,"message":"JWT expired"}`,
		`{"statusCode":"400","error":"InvalidJWT","message":"jwt expired"}`,
		`{"error":"invalid_grant","error_description":"x"}`,
		`{"code":403,"error_code":"bad_jwt","msg":"invalid JWT"}`,
		`{"code":{"nested":1},"message":["a"],"error":null}`,
		`<html>502</html>`, ``, `null`, `[]`, `"str"`, `{`, "\xff\xfe",
		strings.Repeat(`{"a":`, 1000),
	} {
		f.Add(401, s)
	}

	f.Fuzz(func(t *testing.T, status int, body string) {
		e := parseAPIError("POST", "/rest/v1/rpc/f", status, []byte(body))
		if len(e.Body) > maxErrorBody {
			t.Fatalf("Body length %d exceeds %d", len(e.Body), maxErrorBody)
		}
		msg := e.Error()
		if !strings.HasPrefix(msg, "POST /rest/v1/rpc/f: status ") {
			t.Fatalf("Error() = %q, missing method/path/status prefix", msg)
		}
		if utf8.ValidString(body) && len(body) <= maxErrorBody && !utf8.ValidString(msg) {
			t.Fatalf("Error() produced invalid UTF-8 from valid input: %q", msg)
		}
		_ = IsUnauthorized(e)
		_ = IsForbidden(e)
		_ = IsNotFound(e)
	})
}

func TestParseRetryAfter(t *testing.T) {
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		in   string
		want time.Duration
	}{
		{"", 0},
		{"0", 0},
		{"-5", 0},
		{"30", 30 * time.Second},
		{" 2 ", 2 * time.Second},
		{"99999999999999999", maxRetryAfter},
		{"Thu, 08 Oct 2026 12:00:45 GMT", 45 * time.Second},
		{"Thu, 08 Oct 2026 11:59:00 GMT", 0}, // in the past
		{"Fri, 09 Oct 2026 12:00:00 GMT", maxRetryAfter},
		{"soon", 0},
	}
	for _, tc := range tests {
		if got := parseRetryAfter(tc.in, now); got != tc.want {
			t.Errorf("parseRetryAfter(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
