---
icon: lucide/plug
---

# Backend credentials

Everything on the other pages is about **who may call your server** —
identity providers, allowlists, roles. This page is about a different
credential: the one your own tool handlers use to call **the service
behind** your MCP server. Gangway's `backend` package supplies exactly
that, as one of the library's core building blocks — it does not get its
own attention anywhere else in this documentation, which undersells it.

`backend.TokenSource` is a one-method interface:

```go
type TokenSource interface {
	TokenFor(ctx context.Context, id *identity.Identity, incoming string) (string, error)
}
```

A tool handler calls `TokenFor` to get the credential it should use for
its own outbound call, then uses that credential however the backend
service expects (a header, a query parameter, whatever). Gangway ships
four implementations; which one fits depends on how the backend service
authenticates.

## StaticToken — one credential for everyone

```go
source := backend.StaticToken(apiToken)
```

Every caller gets the same credential. Correct when the backend service
does not distinguish between your MCP server's callers — a single shared
API key, a service account. Needs nothing from the verified caller at
all.

## PerUser — a credential per caller

```go
source := backend.PerUser(func(ctx context.Context, id *identity.Identity) (string, error) {
	// Map id.Subject (or another claim in id.Claims) onto this backend's
	// own account model, however that mapping is stored.
	return lookupBackendToken(ctx, id.Subject)
})
```

The lookup function is where your server's own account model lives —
Gangway has no opinion on it. `id` comes from `serve.IdentityFrom(ctx)`
inside a tool handler: the same request-scoped context that
[`AttachMCP`'s tool-authorization middleware](getting-started.md) reads
the identity from is the one your tool handler receives too — the
`ctx` argument the SDK passes to a `ToolHandlerFor`.

## PassThrough and Exchange — forwarding the caller's own token

```go
source := backend.PassThrough()
// or:
source := backend.Exchange(backend.ExchangeConfig{
	TokenURL:     "https://issuer.example.com/oauth/token",
	ClientID:     clientID,
	ClientSecret: clientSecret,
})
```

`PassThrough` forwards the caller's own bearer token unchanged — only
correct when the backend service accepts tokens from the same issuer
Gangway verifies against. `Exchange` trades that token for one the
backend accepts, via [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)
token exchange.

Both need the caller's raw incoming token as `TokenFor`'s `incoming`
parameter. Get it with `serve.TokenFrom(ctx)`, the same request-scoped
context your tool handler already receives:

```go
mcp.AddTool(mcpServer, &mcp.Tool{Name: "call-the-backend"},
	func(ctx context.Context, _ *mcp.CallToolRequest, _ noArgs) (*mcp.CallToolResult, any, error) {
		id, _ := serve.IdentityFrom(ctx)
		incoming, _ := serve.TokenFrom(ctx)
		source := backend.PassThrough() // or backend.Exchange(...)

		tok, err := source.TokenFor(ctx, id, incoming)
		if err != nil {
			return nil, nil, err
		}
		return callBackendWith(ctx, tok)
	})
```

`Server.Handler`'s authentication layer places the token in the context
only *after* it has passed verification, in the same success branch as
the identity — never earlier, never for a token that failed to verify.

!!! danger "What TokenFrom hands back is not your server's own credential"

    The value `TokenFrom` returns is a valid credential belonging to
    whichever caller made *this specific request* — not a secret your
    server owns, and not necessarily the only credential that caller
    holds. Treat it accordingly, in your own tool code exactly as
    strictly as Gangway treats it internally:

    - Never log it, and never put it anywhere a log write could reach it
      — an error message, a panic value, a debug dump of the context.
    - Never forward it anywhere except the one downstream service it was
      retrieved for (typically straight into `TokenSource.TokenFor`).
    - Do not cache or persist it beyond the request it was read from.

## Exchange's client authentication

`Exchange` sends `client_id` and `client_secret` as form fields in the
token-exchange POST body — the authentication method most token-exchange
endpoints accept. A provider that instead requires HTTP Basic client
authentication (`Authorization: Basic base64(id:secret)`) is not
supported by this source; see [Known limitations](index.md#known-limitations).

If `ExchangeConfig.TokenURL` itself carries a credential, a failed
exchange will not echo it back either — the same host-only error
messages `GANGWAY_REMOTE_LIST_URL` gets (see [Configuration](configuration.md))
apply here too.
