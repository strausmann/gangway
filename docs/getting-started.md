---
icon: lucide/rocket
---

# Getting started

This page builds the smallest Gangway server that actually runs: one tool,
five environment variables, one file.

## Get the module

```bash
go get github.com/strausmann/gangway
go get github.com/modelcontextprotocol/go-sdk
```

## Write the server

```go title="main.go"
package main

import (
	"context"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/strausmann/gangway/access"
	"github.com/strausmann/gangway/serve"
)

// pingArgs is the tool's input. It takes no arguments; the empty struct
// still gives the SDK a proper object schema instead of the "any" special
// case reserved for tools that accept literally anything.
type pingArgs struct{}

// pingResult is the tool's structured output.
type pingResult struct {
	Reply string `json:"reply"`
}

func main() {
	ctx := context.Background()

	cfg, err := serve.LoadConfig()
	if err != nil {
		log.Fatal(err)
	}

	gw, err := serve.New(ctx, cfg, serve.WithToolKinds(map[string]access.ToolKind{
		"ping": access.KindRead,
	}))
	if err != nil {
		log.Fatal(err)
	}

	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "example", Version: "0.1.0"}, nil)
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "ping", Description: "Replies pong."},
		func(_ context.Context, _ *mcp.CallToolRequest, _ pingArgs) (*mcp.CallToolResult, pingResult, error) {
			return nil, pingResult{Reply: "pong"}, nil
		})

	gw.AttachMCP(mcpServer)

	log.Fatal(gw.Run(ctx))
}
```

Two things in this file are not optional:

- `serve.WithToolKinds` is the only way Gangway's tool-authorization
  middleware can tell a reading tool from a writing one — the SDK does
  not expose a tool's annotations to receiving middleware. A tool absent
  from this map is treated as writing. See [Configuration](configuration.md)
  for the roles that unlock writing.
- `gw.AttachMCP` must run before `gw.Run`; a `Server` with nothing
  attached still serves `/healthz`, but `/mcp` does not exist.

Note what `AttachMCP` takes: a bare `*mcp.Server`, not an `http.Handler`.
That is deliberate, not an SDK inconvenience worked around — `AttachMCP`
wraps the server itself, installing the tool-authorization middleware and
building the streamable HTTP handler with `Stateless: true` internally.

!!! info "Why AttachMCP insists on the bare *mcp.Server"

    A streamable HTTP session can run stateful (the SDK's own default) or
    stateless. In a stateful session, every JSON-RPC message on it —
    including a `tools/call` arriving on a POST long after the session
    opened — is dispatched through a single context captured once, when
    the session was created. A later request's own context, and with it
    the outcome tracker the access log attaches to that specific HTTP
    request, never reaches the authorization middleware.

    This does not affect the authorization *decision* — a stateful server
    still refuses what it should refuse. What breaks is observability:
    the refusal happens, but the access-log line for it may attach to a
    session that has already moved on, invisible to anyone reading the
    log for that request. Rather than document "remember to set
    `Stateless: true`" as a rule a caller could forget, `AttachMCP` builds
    the handler itself and never offers a path that skips it — there is
    no exported way to reach a `Server`'s `/mcp` handler without it.

## Nothing survives past one call

The box above explains why `Stateless: true` is forced. It has a second
consequence, beyond observability, that a tool handler runs into
directly: under stateless mode there is no MCP session in the sense the
protocol usually means it. Per the SDK's own documentation for this
mode, no session ID a client sends is ever read or validated, and
**every request gets its own temporary session, created and closed
within that same request** — including whatever a handler can reach
through `req.Session` or its ID.

!!! danger "A caller-scoped value that lives on the session is gone on the very next call"

    Any state a tool handler keys to the session — a running list of
    which IDs it has already handed a caller, so a later "delete" tool
    can refuse an ID that caller was never shown; a multi-step
    workflow's progress; anything meant to carry over from one tool
    call to the next within what looks like a single client connection
    — is empty again on the next call, because that call runs in a
    session of its own that did not exist a moment ago and will not
    exist a moment later.

    Nothing about this fails loudly. No error, no panic: the map is
    simply always empty, so a check built on "have I seen this ID
    before" either always passes or always refuses, and whichever it is
    stays that way silently. This is exactly the failure mode Gangway
    exists to prevent everywhere else in this project — something that
    runs and looks like it is protecting a caller while it is not — and
    it is worth restating why it happens here anyway: `AttachMCP` and
    `AttachMCPSelector` force stateless mode specifically so the
    authorization decision the access log records always belongs to
    the request that actually made it (see the box above). Forcing that
    is the point, not an oversight; a tool handler that needs state
    across calls has to get it from somewhere other than the session.

That somewhere is the caller's own verified identity, not the session:
key whatever needs to persist to `serve.IdentityFrom(ctx)` — typically
`id.Subject`, or another stable claim — and store it in a durable place
your server owns (a database, a cache, anything outside the request's
lifetime), not in a package-level map keyed by session or by anything
the SDK hands out per connection. That store then needs its own
retention and expiry policy; under a stateful server a session's own
lifecycle would eventually clean up state tied to it, but a store keyed
to an identity that a caller may hold for months does not get that for
free.

## Set the environment

Five variables are enough to start:

```bash
export GANGWAY_PUBLIC_BASE_URL=https://mcp.example.com
export GANGWAY_ISSUER_URL=https://your-issuer.example.com
export GANGWAY_AUDIENCE=your-client-id
export GANGWAY_ALLOWED_PREFIXES=203.0.113.0/24
export GANGWAY_ADDR=:8080
```

- `GANGWAY_PUBLIC_BASE_URL` is required — `serve.LoadConfig` refuses to
  start without it.
- `GANGWAY_ISSUER_URL` and `GANGWAY_AUDIENCE` are required too, for this
  default setup (an OIDC verifier built by `serve.New`) — but the check
  for them lives in `serve.New` itself, not in `LoadConfig`: a server
  built with [`serve.WithVerifier`](configuration.md#replacing-the-verifier-entirely-withverifier)
  instead of the default OIDC verifier does not need either. If one is
  missing here, `go run .` still fails to start, just from `New` rather
  than `LoadConfig` — the error still names the `GANGWAY_*` variable, the
  same as it always has.
- `GANGWAY_ALLOWED_PREFIXES` is one of two ways to configure the origin
  allowlist (the other is `GANGWAY_REMOTE_LIST_URL`, for a list that
  refreshes itself); at least one is required, or the server refuses to
  start rather than come up with no filter at all.
- `GANGWAY_ADDR` defaults to `:8080` — set here only to make it explicit.

See [Configuration](configuration.md) for the complete list, including the
writer role that a real deployment needs before any writing tool can be
called by anyone.

## Run it

```bash
go run .
```

```
2026/01/01 00:00:00 gangway: GANGWAY_PUBLIC_BASE_URL is required
```

That is what you see if `GANGWAY_PUBLIC_BASE_URL` or the allowlist is
missing — `LoadConfig` names the offending variable and stops. A missing
`GANGWAY_ISSUER_URL` or `GANGWAY_AUDIENCE` still stops the process too,
naming that variable just the same, just one call later, from `serve.New`
(see the note above). Set all five and the process instead binds to
`GANGWAY_ADDR` and starts serving `/healthz` and `/mcp`.

```bash
curl http://localhost:8080/healthz
# ok
```

This returns `ok` from `localhost` even though `GANGWAY_ALLOWED_PREFIXES`
above was set to a documentation-only range that does not include your
machine — deliberately: `/healthz` is exempt from the origin allowlist. A
liveness or readiness probe runs from an address that will never appear
in a connector allowlist, and gating it the same way as `/mcp` would
invite the reflex fix of adding the prober's address to
`GANGWAY_ALLOWED_PREFIXES` — which widens *every* route Gangway serves,
not just this one (see [Behind a proxy](behind-a-proxy.md) for why that
is the single easiest way to defeat the allowlist without anything
failing loudly).

`/mcp` is not exempt: it needs a bearer token issued by the configured
issuer, and a peer address the allowlist actually accepts — that is the
point of this project, so with the example value above a local `curl` or
MCP client reaches neither `/mcp` nor the
`/.well-known/oauth-protected-resource` metadata document a connector
would fetch first. Set `GANGWAY_ALLOWED_PREFIXES` to a range that
actually covers your caller, then point an MCP-capable client (or
connector) at `http://localhost:8080/mcp` with a valid token to reach the
`ping` tool.

That metadata document names `GANGWAY_PUBLIC_BASE_URL` plus `/mcp` as
this server's resource — not the bare base URL — and is reachable at two
addresses: the root `/.well-known/oauth-protected-resource` above, which
is what the `WWW-Authenticate` challenge on a 401 points a connector to,
and the path-specific
`/.well-known/oauth-protected-resource/mcp` (RFC 9728 §3.1), for a
connector that probes for it before ever making an unauthenticated
request instead of waiting for the challenge. Both serve the identical
document.

## Next steps

- Configure a real identity provider: [Microsoft Entra ID](providers/entra.md)
  or [Authentik](providers/authentik.md).
- If a reverse proxy sits in front of this server, read
  [Behind a proxy](behind-a-proxy.md) before setting
  `GANGWAY_CLIENT_IP_HEADER` — the wrong choice here does not fail loudly,
  it just quietly stops filtering anyone.
- If different callers should see different tools — not just be refused
  when calling one they may not use — `AttachMCP` above is not the whole
  story: see [Hiding tools entirely: AttachMCPSelector](configuration.md#hiding-tools-entirely-attachmcpselector)
  in Configuration.
- If callers do not authenticate via an OIDC bearer token at all — a
  static token, a second identity provider — see
  [Replacing the verifier entirely: WithVerifier](configuration.md#replacing-the-verifier-entirely-withverifier)
  in Configuration.
