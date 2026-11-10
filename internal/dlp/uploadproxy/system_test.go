package uploadproxy

import (
	"context"
	"errors"
	"testing"
)

func TestSessionsResult(t *testing.T) {
	cases := []struct {
		reasons []string
		want    error // nil: active
		reason  string
	}{
		{nil, ErrNoSession, "no_graphical_session"},
		{[]string{"existing_proxy", ""}, nil, ""},
		{[]string{"existing_proxy", "unsupported_desktop"}, ErrExistingProxy, "existing_proxy"},
		{[]string{"unsupported_desktop", "no_answer"}, ErrUnsupportedDesktop, "unsupported_desktop"},
		{[]string{"no_answer"}, nil, "error"},
	}
	for _, c := range cases {
		err := sessionsResult(c.reasons)
		switch {
		case c.reason == "" && err != nil:
			t.Errorf("%v: %v", c.reasons, err)
		case c.want != nil && !errors.Is(err, c.want):
			t.Errorf("%v: %v, want %v", c.reasons, err, c.want)
		case c.reason != "" && Reason(err) != c.reason:
			t.Errorf("%v: reason %q, want %q", c.reasons, Reason(err), c.reason)
		}
	}
}

func TestSessionRedirector(t *testing.T) {
	var sent []string
	r := sessionRedirector{set: func(_ context.Context, pacURL string) []string {
		sent = append(sent, pacURL)
		if pacURL == "" {
			return []string{"error"} // a session that couldn't restore
		}
		return []string{""}
	}}
	if err := r.Apply("http://127.0.0.1:3129/proxy.pac"); err != nil {
		t.Fatal(err)
	}
	if err := r.Remove(); err != nil { // per-session failures stay per session
		t.Fatal(err)
	}
	if len(sent) != 2 || sent[1] != "" {
		t.Errorf("sent %q", sent)
	}
	if err := (sessionRedirector{}).Apply("x"); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("without helpers: %v", err)
	}
	if err := (sessionRedirector{}).Remove(); err != nil {
		t.Errorf("remove without helpers: %v", err)
	}
}
