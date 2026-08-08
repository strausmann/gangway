---
icon: lucide/settings
---

# Configuration

`serve.LoadConfig()` reads every one of the settings below from the
environment — never from a file — so that credentials never end up sitting
on disk next to the binary. It fails to start rather than come up with a
gap: a missing public base URL or allowlist is an error, not a silent
default.

One setting on this page is the exception to "everything comes from the
environment": the OIDC key-refresh interval, covered under
[Identity](#identity), is reachable only by calling `identity.NewOIDC`
directly with your own `identity.OIDCConfig` — bypassing `serve.LoadConfig`
and `serve.New` — not through any `GANGWAY_*` variable.

Error messages name the offending variable but never its value. Several of
these variables are not meant to be echoed back — allowlist prefixes, writer
claim values — and startup failures end up in logs.

## Required

| Variable | Purpose | Example |
|---|---|---|
| `GANGWAY_PUBLIC_BASE_URL` | The server's own externally reachable base URL. Sent back in the `WWW-Authenticate` challenge so a connector knows where to discover OAuth metadata. Never derived from request headers — that would let a caller redirect the sign-in flow to a server of its own choosing. | `https://mcp.example.com` |

## Required for the default OIDC verifier — not by [`WithVerifier`](#replacing-the-verifier-entirely-withverifier)

| Variable | Purpose | Example |
|---|---|---|
| `GANGWAY_ISSUER_URL` | The OpenID Connect issuer, without the `/.well-known/...` suffix. `serve.New` fetches its discovery document at startup and refuses to start if it cannot be reached. | `https://login.microsoftonline.com/<tenant-id>/v2.0` |
| `GANGWAY_AUDIENCE` | The value the token's `aud` claim must contain. | `api://your-app-id` |

Both are read by `serve.LoadConfig`, but not required by it — the
requirement lives in `serve.New`'s default branch instead (see
`identity.NewOIDC`), because that is the only place that actually reads
them. A caller who calls `serve.New` without `WithVerifier` and leaves
either empty still fails to start, exactly as before — just from `New`,
not from `LoadConfig`. A caller who uses `WithVerifier` is not forced to
set either.

## The allowlist: one of these two, at least

| Variable | Purpose | Example |
|---|---|---|
| `GANGWAY_ALLOWED_PREFIXES` | Comma-separated CIDR prefixes. Fixed and read once at startup — use it for a provider's stable range or your own infrastructure. | `203.0.113.0/24,2001:db8::/32` |
| `GANGWAY_REMOTE_LIST_URL` | A URL fetched at startup and re-fetched on `GANGWAY_REMOTE_LIST_INTERVAL`, for a provider whose published range changes — the shipped parser reads the format OpenAI publishes for its connector IPs. A failed initial fetch stops the server from starting; a later failed refresh keeps the last good list rather than locking out every caller over a transient outage. | `https://example.com/published-ips.json` |

At least one of the two is required. Both may be set — the effective
allowlist is their union. Refusing to start with neither configured is
deliberate: without a filter, every caller would be let in.

If `GANGWAY_REMOTE_LIST_URL` itself carries a credential — a signed URL,
a token in the query string — a failed fetch will not echo it back:
every error message this fetch can produce names only the scheme and
host, never the path or query.

`GANGWAY_REMOTE_LIST_INTERVAL` (optional, default `1h`, minimum `1m`) sets
the refresh interval for the remote list. The one-minute floor exists
because this value comes from the environment — unchecked input — and an
accidentally tiny interval would hammer whoever publishes the list.

## Client address and trusted proxies

These two matter together, and choosing the wrong header is the single
easiest way to defeat the allowlist above without anything failing loudly.
Read [Behind a proxy](behind-a-proxy.md) before setting either of them in
front of a real proxy.

| Variable | Purpose | Default |
|---|---|---|
| `GANGWAY_CLIENT_IP_HEADER` | Which single forwarding header is trusted: `x-forwarded-for`, `x-real-ip`, or `cf-connecting-ip`. Exactly one is evaluated — trying several in turn would let a caller pick whichever one the server happens to prefer. | `x-forwarded-for` |
| `GANGWAY_TRUSTED_PROXIES` | Comma-separated CIDR prefixes of the proxies whose forwarding header is believed. Leave empty when nothing sits in front of Gangway — then only the TCP peer address counts, and the header (whatever it says) is ignored entirely. | empty |

## Identity

| Variable | Purpose | Default |
|---|---|---|
| `GANGWAY_SUBJECT_CLAIM` | The claim used as the caller's stable identifier. `sub` works for most providers; Entra ID pseudonymizes it per application, so `oid` is the tenant-stable choice there — see [Microsoft Entra ID](providers/entra.md). | `sub` |

### Key rotation

`identity.NewOIDC` — what `serve.New` calls internally to build the
verifier — refetches the issuer's discovery document and signing keys on a
background timer, defaulting to **every 15 minutes**, and swaps in a
verifier built from whatever it just fetched, dropping any key the
previous verifier trusted that is no longer being published.

This is the practical answer to a stolen signing key: rotating the key at
the identity provider does not immediately invalidate tokens signed with
the old one everywhere — it invalidates them here only once the next
background refresh has run. Between the rotation and that refresh, a
token forged with the compromised key would still verify. With the
default interval, that window is at most 15 minutes; it does not shrink
by rotating faster at the provider, only by refreshing faster here.

There is currently **no `GANGWAY_*` variable** for this interval. It is
set through `identity.OIDCConfig.KeyRefreshInterval`, a field on the
`identity` package's own config type — reachable only by calling
`identity.NewOIDC` yourself instead of going through `serve.LoadConfig`
and `serve.New`. If you need a shorter window than 15 minutes, that is
the path; there is no `Option` on `serve.Server` for it today.

### Replacing the verifier entirely: WithVerifier

Everything above this point assumes callers present an OIDC bearer token,
verified against `GANGWAY_ISSUER_URL`'s discovery document. `WithVerifier`
replaces that assumption outright, for a caller that is not recognised by
OIDC at all — a static token, an opaque token looked up in your own
database, a second identity provider Gangway has no built-in support for.
Anything that implements `identity.Verifier` works:

```go
type Verifier interface {
	Verify(ctx context.Context, rawToken string) (*Identity, error)
}
```

```go
gw, err := serve.New(ctx, cfg, serve.WithVerifier(myVerifier))
```

Once this option is used, `serve.New` never calls `identity.NewOIDC` and
never touches `GANGWAY_ISSUER_URL`, `GANGWAY_AUDIENCE`, or
`GANGWAY_SUBJECT_CLAIM` — none of the three need to be set. Everything
*downstream* of authentication is unaffected: the identity your verifier
returns is exactly what `serve.IdentityFrom(ctx)` hands to tool handlers
and what the `GANGWAY_WRITERS_*` grid (or a replaced `access.Decider`)
checks — so a hand-rolled verifier still needs to populate
`Identity.Claims` with whatever your writer-claim check expects to find
there, the same as an OIDC token's claims would.

Omitting `WithVerifier` keeps the default OIDC verifier exactly as
before — adding this option changes nothing for a server that never
calls it. Calling it with `nil` is a different, always-mistaken thing:
`serve.New` refuses it at construction time with an error naming
`WithVerifier`, rather than silently treating a nil verifier as "no
option was given" and falling back to OIDC, or, worse, ending up with a
server that answers requests while never checking anyone. That refusal
also catches a *typed* nil — a nil pointer, map, or similar value that
happens to implement `identity.Verifier` — not just the bare `nil`
literal, since Go considers those `!= nil` at the interface level even
though calling `Verify` on one would panic.

!!! danger "Gangway trusts your Verifier completely"

    This is the most security-sensitive extension point in the package —
    using it redefines what "authenticated" means for this server.
    Gangway does not, and cannot, second-guess what `Verify` returns:
    every `*identity.Identity` it hands back is treated as genuine by
    everything downstream — `serve.IdentityFrom`, the tool-authorization
    middleware, the `GANGWAY_WRITERS_*` grid. A `Verify` that accepts more
    than it should, or that mishandles its own rejection path and returns
    an `Identity` instead of an error, grants exactly that access, with
    nothing in Gangway to catch it. `New` only guarantees that *some*
    non-nil `Verifier` is in place and actually gets called — never the
    correctness of what it decides. Writing a correct `Verifier` is on
    you.

!!! example "A static bearer token, for a server with exactly one caller"

    ```go
    package main

    import (
    	"context"
    	"fmt"
    	"log"

    	"github.com/strausmann/gangway/identity"
    	"github.com/strausmann/gangway/serve"
    )

    // staticTokenVerifier accepts exactly one bearer token and reports
    // back a fixed identity -- useful for a caller Gangway does not need
    // to distinguish from any other, such as a single backend service
    // calling on its own behalf.
    type staticTokenVerifier struct {
    	token string
    	id    *identity.Identity
    }

    func (v staticTokenVerifier) Verify(_ context.Context, rawToken string) (*identity.Identity, error) {
    	if rawToken != v.token {
    		// Wraps identity.ErrUnauthenticated, exactly as the built-in
    		// OIDC verifier's own failures do: a caller of Verify -- code
    		// outside this package, not just Gangway's own authenticate
    		// layer -- can then tell "this token was rejected" apart from
    		// some other failure (a database a real verifier looks a token
    		// up against being unreachable, say) via errors.Is. An error
    		// that does not wrap it breaks that contract silently: nothing
    		// here would fail to compile or even to run, it would just
    		// make every failure of this Verifier indistinguishable from
    		// a rejected token to any caller relying on errors.Is.
    		return nil, fmt.Errorf("%w: unrecognised token", identity.ErrUnauthenticated)
    	}
    	return v.id, nil
    }

    func main() {
    	ctx := context.Background()

    	// GANGWAY_ISSUER_URL and GANGWAY_AUDIENCE do not need to be set:
    	// LoadConfig no longer requires either (see Required for the
    	// default OIDC verifier above), and WithVerifier below means New
    	// never reads them anyway. GANGWAY_PUBLIC_BASE_URL and an allowlist
    	// (GANGWAY_ALLOWED_PREFIXES or GANGWAY_REMOTE_LIST_URL) are still
    	// required.
    	cfg, err := serve.LoadConfig()
    	if err != nil {
    		log.Fatal(err)
    	}

    	verifier := staticTokenVerifier{
    		token: "REPLACE_ME_WITH_A_LONG_RANDOM_TOKEN",
    		id: &identity.Identity{
    			Subject: "backend-service",
    			Claims:  map[string]any{"sub": "backend-service"},
    		},
    	}

    	gw, err := serve.New(ctx, cfg, serve.WithVerifier(verifier))
    	if err != nil {
    		log.Fatal(err)
    	}

    	// gw.AttachMCP(...) / gw.Run(ctx) as in Getting started.
    	_ = gw
    }
    ```

## Authorization: who may call a writing tool

Reading tools (`access.KindRead`, assigned via `serve.WithToolKinds`) are
open to any authenticated caller, regardless of these three. They govern
writing tools only.

| Variable | Purpose | Default |
|---|---|---|
| `GANGWAY_WRITERS_CLAIM` | The claim that carries roles, e.g. `roles` or `groups`. Accepts either shape a provider might send: a single string or a list. | empty |
| `GANGWAY_WRITERS_VALUE` | The value that grants writing, checked against `GANGWAY_WRITERS_CLAIM`. | empty |
| `GANGWAY_ALLOW_WRITE_BY_DEFAULT` | `true` permits writing for any authenticated caller, skipping the claim check entirely. Use only where every caller is trusted equally — a single-tenant deployment with no untrusted callers, for example. | `false` |

Leaving `GANGWAY_WRITERS_CLAIM` or `GANGWAY_WRITERS_VALUE` empty while
`GANGWAY_ALLOW_WRITE_BY_DEFAULT` is unset does not open writing to everyone
— it does the opposite. A forgotten setting must not open the server, so
every writing call is refused until both are configured or the default is
explicitly enabled.

### Replacing the decision entirely

The read/write claim check above is `access.NewGrid`, the default
decider `serve.New` builds from the three settings in this section. It
can be replaced outright with `serve.WithDecider(...)`. The one
alternative Gangway ships is `access.AllowAll()`, an exported `Decider`
that permits **every** authenticated caller to call **every** tool —
reading or writing, no claim check at all:

```go
gw, err := serve.New(ctx, cfg, serve.WithDecider(access.AllowAll()))
```

This is not a relaxed default to reach for casually — it collapses the
entire read/write distinction this section is about. It only makes sense
for a server whose tools are all equally harmless to any authenticated
caller (every tool reads, say, or the deployment has exactly one trusted
caller). For anything else, the three `GANGWAY_WRITERS_*` settings above
are the intended path.

### Hiding tools entirely: AttachMCPSelector

Everything above decides whether a *call* to a tool that exists on the
server succeeds. It does not change which tools a caller sees when it
asks for the tool list — every caller gets the same catalog from
[`AttachMCP`](getting-started.md), and a tool a caller may not call is
simply refused when they try.

`AttachMCPSelector` is a different attachment for a server whose tool
*catalog* should depend on who is calling — a caller without the writer
role never sees `purge-cache` in the list at all, rather than seeing it
and being refused when they call it:

```go
type MCPSelector func(ctx context.Context, id *identity.Identity) *mcp.Server

func (s *Server) AttachMCPSelector(selector MCPSelector)
```

`selector` runs once per HTTP request, before MCP-level handling, and
receives the same identity the tool-authorization middleware itself
would see. Build the fixed set of instances once — one per role, one per
tenant, however the catalogs are split — and have `selector` choose among
them; never build a `*mcp.Server` inside `selector` itself:

```go
reader, editor := buildServers() // built once, at startup

gw.AttachMCPSelector(func(_ context.Context, id *identity.Identity) *mcp.Server {
	if id == nil {
		return reader
	}
	if roles, _ := id.Claims["roles"].([]any); containsEditor(roles) {
		return editor
	}
	return reader
})
```

Both `AttachMCP` and `AttachMCPSelector` install the identical
tool-authorization middleware on every instance they wire, and both
force stateless sessions — see [`AttachMCP`](getting-started.md) for why.
Being reachable through a selector's catalog is not the same as being
allowed to call what is in it: `purge-cache` on the `editor` instance
above still goes through `access.Decider.Allow` like any other writing
tool, so the three `GANGWAY_WRITERS_*` settings above still decide who
may actually call it. The selector only decides who sees it.

If `selector` returns `nil`, the request gets an HTTP 400 — the SDK's own
behaviour for an empty `getServer` result — never a default instance. A
selector that cannot place a caller has no basis to guess what that
caller should see, and a silent default would reopen exactly the kind of
unreviewable widening the rest of this section exists to prevent.

`selector` is expected to choose from a small, fixed, long-lived set.
Every previously-unseen instance it returns gets counted, and once more
than 1024 distinct instances have been seen over the server's lifetime
— only plausible if `selector` is building a new instance per request or
per caller instead of choosing from a fixed set — every further
previously-unseen instance is refused the same way a `nil` return is:
HTTP 400, plus a diagnostic line naming the limit on the configured log
writer (`serve.WithLogWriter`, stdout by default). Instances already
admitted before that point keep working; nothing already wired is torn
down.

## Network

| Variable | Purpose | Default |
|---|---|---|
| `GANGWAY_ADDR` | The address the HTTP server listens on. | `:8080` |
