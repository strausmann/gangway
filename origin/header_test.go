package origin_test

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/strausmann/gangway/origin"
)

func mustPrefixes(t *testing.T, ss ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			t.Fatalf("parse prefix %q: %v", s, err)
		}
		out = append(out, p)
	}
	return out
}

func TestClientIP(t *testing.T) {
	trusted := mustPrefixes(t, "172.16.0.0/12")

	tests := []struct {
		name       string
		mode       origin.HeaderMode
		remoteAddr string
		headers    map[string]string
		want       string
		wantErr    bool
	}{
		{
			name:       "no proxy, remote address wins",
			mode:       origin.ModeXForwardedFor,
			remoteAddr: "203.0.113.7:5000",
			want:       "203.0.113.7",
		},
		{
			name:       "forged header from untrusted peer is ignored",
			mode:       origin.ModeXForwardedFor,
			remoteAddr: "203.0.113.7:5000",
			headers:    map[string]string{"X-Forwarded-For": "160.79.104.1"},
			want:       "203.0.113.7",
		},
		{
			name:       "single trusted proxy",
			mode:       origin.ModeXForwardedFor,
			remoteAddr: "172.20.0.5:5000",
			headers:    map[string]string{"X-Forwarded-For": "160.79.104.1"},
			want:       "160.79.104.1",
		},
		{
			name:       "chain: rightmost untrusted entry wins, leftmost is forged",
			mode:       origin.ModeXForwardedFor,
			remoteAddr: "172.20.0.5:5000",
			headers:    map[string]string{"X-Forwarded-For": "1.2.3.4, 5.6.7.8, 172.20.0.9"},
			want:       "5.6.7.8",
		},
		{
			name:       "x-real-ip from trusted peer",
			mode:       origin.ModeXRealIP,
			remoteAddr: "172.20.0.5:5000",
			headers:    map[string]string{"X-Real-IP": "160.79.104.1"},
			want:       "160.79.104.1",
		},
		{
			name:       "x-real-ip from untrusted peer is ignored",
			mode:       origin.ModeXRealIP,
			remoteAddr: "203.0.113.7:5000",
			headers:    map[string]string{"X-Real-IP": "160.79.104.1"},
			want:       "203.0.113.7",
		},
		{
			name:       "cloudflare header is not read in x-forwarded-for mode",
			mode:       origin.ModeXForwardedFor,
			remoteAddr: "172.20.0.5:5000",
			headers:    map[string]string{"CF-Connecting-IP": "160.79.104.1"},
			want:       "172.20.0.5",
		},
		{
			name:       "malformed header falls back to the peer",
			mode:       origin.ModeXForwardedFor,
			remoteAddr: "172.20.0.5:5000",
			headers:    map[string]string{"X-Forwarded-For": "not-an-address"},
			want:       "172.20.0.5",
		},
		{
			name:       "cf-connecting-ip from trusted proxy",
			mode:       origin.ModeCFConnectingIP,
			remoteAddr: "172.20.0.5:5000",
			headers:    map[string]string{"CF-Connecting-IP": "160.79.104.1"},
			want:       "160.79.104.1",
		},
		{
			name:       "malformed x-real-ip falls back to the peer",
			mode:       origin.ModeXRealIP,
			remoteAddr: "172.20.0.5:5000",
			headers:    map[string]string{"X-Real-IP": "not-an-address"},
			want:       "172.20.0.5",
		},
		{
			name:       "chain: all entries trusted falls back to the peer",
			mode:       origin.ModeXForwardedFor,
			remoteAddr: "172.20.0.5:5000",
			headers:    map[string]string{"X-Forwarded-For": "172.16.0.1, 172.20.0.9"},
			want:       "172.20.0.5",
		},
		{
			name:       "unknown header mode returns an error",
			mode:       origin.HeaderMode("bogus"),
			remoteAddr: "172.20.0.5:5000",
			wantErr:    true,
		},
		{
			name:       "unparsable peer address returns an error",
			mode:       origin.ModeXForwardedFor,
			remoteAddr: "not-an-address",
			wantErr:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/", nil)
			r.RemoteAddr = tc.remoteAddr
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}

			got, err := origin.ClientIP(r, tc.mode, trusted)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want error, got none")
				}
				return
			}
			if err != nil {
				t.Fatalf("ClientIP: %v", err)
			}
			if got.String() != tc.want {
				t.Errorf("ClientIP = %s, want %s", got, tc.want)
			}
		})
	}
}
