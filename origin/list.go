package origin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

// List decides whether an address is allowed to reach the server.
type List interface {
	Contains(netip.Addr) bool
}

type staticList struct{ prefixes []netip.Prefix }

// Static returns a fixed list. Use it for providers that publish a stable
// range and promise not to change it without notice, and for a caller's
// own infrastructure.
func Static(prefixes []netip.Prefix) List { return &staticList{prefixes: prefixes} }

func (l *staticList) Contains(addr netip.Addr) bool { return inAny(addr, l.prefixes) }

type combined struct{ lists []List }

// Combine allows an address that any of the given lists allows.
func Combine(lists ...List) List { return &combined{lists: lists} }

func (c *combined) Contains(addr netip.Addr) bool {
	for _, l := range c.lists {
		if l.Contains(addr) {
			return true
		}
	}
	return false
}

// RemoteListConfig configures a list that refreshes itself from a URL —
// for providers, such as OpenAI's connector range, that publish a list
// which changes and must be re-fetched periodically.
type RemoteListConfig struct {
	// URL is fetched on start and then every Interval.
	URL string
	// Interval between refreshes. Zero or negative falls back to one
	// hour; any positive value, however small, is otherwise accepted as
	// given. This package deliberately does not impose a minimum: a
	// caller who constructs RemoteListConfig directly is assumed to know
	// what they are asking for. A value that is too small will hammer
	// the provider with requests. Callers who derive Interval from an
	// environment variable should not rely on this package for
	// protection against a misconfigured, too-small value — that floor
	// is enforced where the environment is parsed, not here.
	Interval time.Duration
	// Parse turns the response body into prefixes.
	Parse func([]byte) ([]netip.Prefix, error)
	// Client is optional; a client with a timeout is used when nil.
	Client *http.Client
}

type remoteList struct {
	cfg RemoteListConfig

	mu       sync.RWMutex
	prefixes []netip.Prefix

	// afterRefresh, when set, is invoked synchronously at the end of
	// every refresh — initial and background, successful or not — after
	// any state change from that refresh has already been applied. It
	// exists solely so tests can wait deterministically for a specific
	// background refresh to have fully completed, instead of inferring
	// completion from an observable side effect such as the request
	// having reached the server (which races the mutex-protected state
	// update: the request can be observed as received before the state
	// it caused, or failed to cause, is actually committed). Nil outside
	// of tests; production callers never set it.
	afterRefresh func(err error)
}

// NewRemoteList fetches the list once and then keeps it fresh in the
// background for as long as ctx is not cancelled.
//
// If the first fetch fails, it returns an error: a server that never
// learned its allowlist must not start, or it would run without any
// filter at all. If a later refresh fails — or succeeds but yields no
// usable prefixes — the last good state is kept: a brief outage or a
// malformed response at the provider must not lock the server's own
// callers out.
func NewRemoteList(ctx context.Context, cfg RemoteListConfig) (List, error) {
	if cfg.Parse == nil {
		return nil, fmt.Errorf("gangway: RemoteListConfig.Parse is required")
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Hour
	}

	l := &remoteList{cfg: cfg}
	if err := l.refresh(ctx); err != nil {
		return nil, fmt.Errorf("gangway: initial fetch of %s: %w", cfg.URL, err)
	}

	go l.loop(ctx)
	return l, nil
}

func (l *remoteList) loop(ctx context.Context) {
	t := time.NewTicker(l.cfg.Interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			// Deliberately ignored: keeping the last good state is the
			// correct behaviour on failure.
			_ = l.refresh(ctx)
		}
	}
}

func (l *remoteList) refresh(ctx context.Context) (err error) {
	if l.afterRefresh != nil {
		defer func() { l.afterRefresh(err) }()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, l.cfg.URL, nil)
	if err != nil {
		return err
	}
	resp, err := l.cfg.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("gangway: fetch %s: status %d", l.cfg.URL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	prefixes, err := l.cfg.Parse(body)
	if err != nil {
		return err
	}
	if len(prefixes) == 0 {
		// A parse that silently yields nothing must not replace a good
		// list with an empty one — that would either allow no one, if
		// this is the first fetch, or (worse) it would look like a no-op
		// and be missed. Treat it the same as a failed fetch.
		return fmt.Errorf("gangway: fetch %s: parsed list is empty", l.cfg.URL)
	}

	l.mu.Lock()
	l.prefixes = prefixes
	l.mu.Unlock()
	return nil
}

func (l *remoteList) Contains(addr netip.Addr) bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return inAny(addr, l.prefixes)
}

// ParseOpenAIPrefixes reads OpenAI's published connector IP-range format —
// an object with a "prefixes" array. Entries without an ipv4Prefix, and
// entries whose ipv4Prefix fails to parse, are skipped: OpenAI's outbound
// ranges are IPv4-only, and a single malformed entry must not invalidate
// the rest of the list.
func ParseOpenAIPrefixes(b []byte) ([]netip.Prefix, error) {
	var doc struct {
		Prefixes []struct {
			IPv4Prefix string `json:"ipv4Prefix"`
		} `json:"prefixes"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("gangway: parse prefix list: %w", err)
	}

	out := make([]netip.Prefix, 0, len(doc.Prefixes))
	for _, e := range doc.Prefixes {
		if e.IPv4Prefix == "" {
			continue
		}
		p, err := netip.ParsePrefix(e.IPv4Prefix)
		if err != nil {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}
