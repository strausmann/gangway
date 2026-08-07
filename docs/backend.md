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
parameter — and that is where a real gap sits today: `Server.Handler`'s
authentication layer verifies the bearer token and places the resulting
`*identity.Identity` into the request context (retrievable via
`serve.IdentityFrom`), but it does not also retain the **raw** token
anywhere a tool handler can reach it. There is currently no exported way
to recover the original bearer token inside a tool handler built on
`AttachMCP`'s documented flow. Until that changes, `PassThrough` and
`Exchange` are usable only if your own code captures the incoming token
through some other path — they are not yet wired end to end the way
`StaticToken` and `PerUser` are.

## Exchange's client authentication

`Exchange` sends `client_id` and `client_secret` as form fields in the
token-exchange POST body — the authentication method most token-exchange
endpoints accept. A provider that instead requires HTTP Basic client
authentication (`Authorization: Basic base64(id:secret)`) is not
supported by this source; see [Known limitations](index.md#known-limitations).
