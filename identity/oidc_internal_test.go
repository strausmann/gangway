package identity

import (
	"testing"
	"time"
)

// TestResolveRefreshInterval exercises resolveRefreshInterval directly so
// the default (15 minutes) is verifiable without ever waiting fifteen
// minutes for it to take effect in a running refreshKeys loop, and so a
// future change to the "zero means unset" / "negative means disabled"
// mapping shows up here instead of only in end-to-end tests that happen to
// configure the interval explicitly (as every existing test in
// oidc_test.go does — none of them exercise the default at all).
func TestResolveRefreshInterval(t *testing.T) {
	tests := []struct {
		name  string
		input time.Duration
		want  time.Duration
	}{
		{
			name:  "unset (zero) resolves to the default",
			input: 0,
			want:  defaultKeyRefreshInterval,
		},
		{
			name:  "negative disables refreshing and is passed through unchanged",
			input: -1 * time.Second,
			want:  -1 * time.Second,
		},
		{
			name:  "a configured positive value is taken as given",
			input: 42 * time.Second,
			want:  42 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveRefreshInterval(tt.input); got != tt.want {
				t.Errorf("resolveRefreshInterval(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
