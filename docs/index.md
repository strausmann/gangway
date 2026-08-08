---
icon: lucide/anchor
---

# Gangway

Gangway is a small set of Go building blocks for running a
[Model Context Protocol](https://modelcontextprotocol.io/) server on the open
internet. It handles the parts that have nothing to do with what your tools
actually do:

- **Authentication** — verifies bearer tokens against any OpenID Connect
  issuer (Entra ID, Authentik, Keycloak, Auth0, Google — anything that speaks
  standard OIDC discovery).
- **Origin filtering** — refuses connections from addresses outside an
  allowlist before the request body is even read. The allowlist can be a
  fixed set of CIDR prefixes, a periodically refreshed remote list (for
  example an AI provider's published outbound ranges), or both combined.
- **Per-tool authorization** — separates tools into reading and writing, and
  lets you require a specific claim (a role, a group) before a writing tool
  runs. Reading tools are open to any authenticated caller.
- **Access logging** — an NGINX-format access log that also records the
  outcome of every tool call, including refusals that the MCP transport
  itself reports as a normal HTTP 200.

Gangway does not implement MCP itself. It wraps the official
[`modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk)
— you register your tools with the SDK as usual, and Gangway supplies the
`http.Handler` chain and the SDK middleware that sit in front of them.

## Why this exists

Exposing an MCP server to AI providers such as Claude or ChatGPT means
exposing it to the internet: an OAuth-capable connector has to reach it from
outside your network. That single requirement drags in a full stack of
concerns — token verification, network-level filtering, and authorization
that a `nil`-checked bearer token alone does not give you. Gangway packages
that stack once so it does not have to be rebuilt, and rebuilt correctly,
for every server.

## Where to go next

- [Getting started](getting-started.md) walks through the smallest server
  that runs: five environment variables, one tool, `go run`.
- [Configuration](configuration.md) lists every environment variable
  Gangway reads.
- [Backend credentials](backend.md) covers the other credential: the one
  your tools use to call the service *behind* your MCP server.
- [Providers](providers/entra.md) covers the two identity providers this
  project has been run against: [Microsoft Entra ID](providers/entra.md) and
  [Authentik](providers/authentik.md).
- [Behind a proxy](behind-a-proxy.md) explains the one setting that, if
  chosen wrong, silently breaks the origin allowlist — and covers running
  behind Traefik, Caddy, NGINX, Pangolin, and Cloudflare.

## Known limitations

- **Authorization and access logging cover tool calls only.** The
  authorization middleware `AttachMCP` installs inspects exactly one MCP
  method, `tools/call` — it checks `method != "tools/call"` and, for
  everything else, passes the request straight through unchanged. A
  server that also registers MCP **resources** or **resource templates**
  (`Server.AddResource`, `Server.AddResourceTemplate`) or **prompts**
  (`Server.AddPrompt`) gets no authorization check and no access-log
  outcome for calls to them — the same authenticated caller a writing
  *tool* call correctly refuses can still read a resource's content
  outright. This matches the design brief's own framing —
  authorization *per tool* — but it is easy to miss if you assume every
  MCP capability is covered the same way tools are. If your server
  exposes resources or prompts with content that needs the same
  protection, that protection has to be added separately; Gangway does
  not provide it today.
- **Token exchange authenticates by form field only.** `backend.Exchange`
  implements [RFC 8693](https://datatracker.ietf.org/doc/html/rfc8693)
  token exchange by sending `client_id` and `client_secret` in the POST
  body, the form-based client authentication method most token-exchange
  endpoints accept. A provider that requires HTTP Basic client
  authentication instead — `Authorization: Basic base64(id:secret)` — is
  not currently supported by this source.
- **Only OIDC discovery, not opaque tokens or static keys.** `identity.NewOIDC`
  is the only verifier this project ships: it requires an issuer that
  serves a standard `/.well-known/openid-configuration` document and a
  JWKS endpoint. Opaque tokens verified through provider introspection, or
  statically configured signing keys for an issuer without discovery, are
  not implemented.
- **Provider IP allowlists are IPv4-only, by design.** `origin.ParseOpenAIPrefixes`
  reads only the `ipv4Prefix` field from a provider's published range and
  skips entries without one. This is not a gap in the parser: AI providers'
  outbound connector traffic is currently IPv4-only, so an entry never
  arrives on an IPv6 address regardless of whether Gangway itself also
  listens on IPv6.

## Status

In development. Interfaces may still change. See the
[repository](https://github.com/strausmann/gangway) for the current state of
the code.

This site is built from the `docs/` directory of that repository on every
push to `main`, so it always reflects the current state of the code.

## License

[MIT](https://github.com/strausmann/gangway/blob/main/LICENSE)
