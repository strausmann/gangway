// Package origin restricts which callers may reach the server at all,
// before any request body is read.
package origin

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// HeaderMode selects the single forwarding header that is trusted.
// Exactly one is evaluated: trying several in turn lets a caller pick
// whichever one the server happens to prefer.
type HeaderMode string

const (
	// ModeXForwardedFor reads the X-Forwarded-For chain from the right.
	// Correct with one or more proxies.
	ModeXForwardedFor HeaderMode = "x-forwarded-for"
	// ModeXRealIP reads X-Real-IP. Unambiguous with exactly one proxy;
	// misleading behind a chain, because each proxy overwrites it with
	// what it saw.
	ModeXRealIP HeaderMode = "x-real-ip"
	// ModeCFConnectingIP reads CF-Connecting-IP. Only when Cloudflare is
	// the outermost proxy.
	ModeCFConnectingIP HeaderMode = "cf-connecting-ip"
)

// ClientIP determines the originating address of r.
//
// The peer address always decides whether any header is believed at all:
// unless the connection comes from a trusted prefix, headers are ignored
// entirely.
func ClientIP(r *http.Request, mode HeaderMode, trusted []netip.Prefix) (netip.Addr, error) {
	peer, err := peerAddr(r)
	if err != nil {
		return netip.Addr{}, err
	}
	if !inAny(peer, trusted) {
		return peer, nil
	}

	switch mode {
	case ModeXRealIP:
		return single(r.Header.Get("X-Real-IP"), peer), nil
	case ModeCFConnectingIP:
		return single(r.Header.Get("CF-Connecting-IP"), peer), nil
	case ModeXForwardedFor:
		return rightmostUntrusted(r.Header.Get("X-Forwarded-For"), peer, trusted), nil
	default:
		return netip.Addr{}, fmt.Errorf("gangway: unknown header mode %q", mode)
	}
}

func peerAddr(r *http.Request) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr // some transports carry no port
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("gangway: unparsable peer %q: %w", r.RemoteAddr, err)
	}
	return addr.Unmap(), nil
}

// single reads a header carrying exactly one address, falling back to the
// peer when it is absent or malformed.
func single(value string, fallback netip.Addr) netip.Addr {
	addr, err := netip.ParseAddr(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return addr.Unmap()
}

// rightmostUntrusted walks the chain from right to left, skipping entries
// from trusted prefixes. The first entry that is not trusted is the
// origin. Everything further left was appended by a proxy we do not know
// and is therefore unproven.
func rightmostUntrusted(value string, fallback netip.Addr, trusted []netip.Prefix) netip.Addr {
	parts := strings.Split(value, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		addr, err := netip.ParseAddr(strings.TrimSpace(parts[i]))
		if err != nil {
			continue
		}
		addr = addr.Unmap()
		if !inAny(addr, trusted) {
			return addr
		}
	}
	return fallback
}

func inAny(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
