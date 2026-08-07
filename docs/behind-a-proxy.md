---
icon: lucide/shield-check
---

# Behind a proxy

This is the page to read before setting `GANGWAY_CLIENT_IP_HEADER`. Getting
it wrong does not produce an error — the server starts, answers requests,
and appears to filter by origin. It just is not actually checking who is
calling.

## Which header to read

| Setup | Setting |
|---|---|
| No proxy | Leave `GANGWAY_TRUSTED_PROXIES` empty. Headers are ignored entirely — only the TCP peer address counts. |
| Exactly one proxy | `GANGWAY_CLIENT_IP_HEADER=x-real-ip` — unambiguous, no parsing rule. |
| Several proxies | `GANGWAY_CLIENT_IP_HEADER=x-forwarded-for` — read right to left, skipping entries from `GANGWAY_TRUSTED_PROXIES`. |
| Cloudflare outermost | `GANGWAY_CLIENT_IP_HEADER=cf-connecting-ip`. |

**Adding a proxy later invalidates this choice.** With `x-real-ip` behind a
chain, the header carries the address of the *last* proxy, not the caller —
because each proxy in the chain overwrites it with what it saw immediately
in front of it. And an allowlist that matches every caller coming through
that last proxy is no allowlist at all: it now says yes to anyone who can
reach that proxy, which after adding a second hop is no longer just your
known caller.

The same applies in reverse: removing a proxy, or moving from a single
reverse proxy to a chain (a CDN in front of a load balancer, say), is a
configuration change on this side too, not just on the proxy's.

## How the peer decides whether a header is trusted at all

`GANGWAY_TRUSTED_PROXIES` is checked first, unconditionally: the connection
that reached Gangway is only ever trusted to have written an honest
forwarding header if its own address falls inside that list. A request from
outside `GANGWAY_TRUSTED_PROXIES` has every header it presents ignored, and
only its own TCP peer address is used — so a caller cannot forge
`X-Forwarded-For` to impersonate an address the allowlist accepts. This is
why an empty `GANGWAY_TRUSTED_PROXIES` correctly disables header parsing
altogether: nothing is trusted, so nothing is read.

## Traefik

```yaml title="docker-compose.yml (excerpt)"
services:
  gangway:
    # ...
    environment:
      GANGWAY_CLIENT_IP_HEADER: x-forwarded-for
      GANGWAY_TRUSTED_PROXIES: 172.16.0.0/12  # Traefik's Docker network
```

Traefik sets `X-Forwarded-For` by default. If Gangway and Traefik share a
Docker network, `GANGWAY_TRUSTED_PROXIES` needs to cover that network's
subnet — not `127.0.0.1/32`, since the connection arrives from Traefik's
container address, not localhost.

## Caddy

Caddy's `reverse_proxy` also sets `X-Forwarded-For` by default:

```
example.com {
	reverse_proxy gangway:8080
}
```

```bash
GANGWAY_CLIENT_IP_HEADER=x-forwarded-for
GANGWAY_TRUSTED_PROXIES=<caddy's address or subnet>
```

## NGINX

NGINX does not set `X-Forwarded-For` on its own — it has to be configured:

```nginx
location /mcp {
    proxy_pass http://gangway:8080;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Real-IP $remote_addr;
}
```

With exactly this NGINX instance as the only proxy in front of Gangway,
`X-Real-IP` is the simpler and unambiguous choice:

```bash
GANGWAY_CLIENT_IP_HEADER=x-real-ip
GANGWAY_TRUSTED_PROXIES=<nginx's address or subnet>
```

## Pangolin

A [Pangolin](https://github.com/fosrl/pangolin) resource forwards through
its own Traefik instance; the same `x-forwarded-for` guidance as above
applies, with `GANGWAY_TRUSTED_PROXIES` covering the network Pangolin's
Traefik container reaches Gangway from — typically the shared Docker
network the resource's target is attached to, not Pangolin's public-facing
address.

## Cloudflare

Cloudflare sets `CF-Connecting-IP` to the original client address,
regardless of how many internal hops the request took inside Cloudflare's
own network — that is the point of the header, and why it is the right
choice only when Cloudflare is the outermost proxy:

```bash
GANGWAY_CLIENT_IP_HEADER=cf-connecting-ip
GANGWAY_TRUSTED_PROXIES=<Cloudflare's published IP ranges>
```

Running a streamable-HTTP MCP server behind Cloudflare's proxy (the "orange
cloud") works, but three separate settings can each silently break it —
none of them related to the header choice above:

!!! warning "Bot protection can drop the call before it is filtered"

    Cloudflare's Bot Fight Mode (and comparable WAF managed rules) can
    silently drop an authenticated, non-browser-looking POST to an MCP
    endpoint — a server-to-server call carrying an `Authorization: Bearer`
    header with no browser cookies or fingerprint matches the same pattern
    bot detection is built to catch. This is not hypothetical: it is the
    documented cause of Anthropic's own
    [`claude-ai-mcp` issue #327](https://github.com/anthropics/claude-ai-mcp/issues/327),
    where the entire OAuth exchange succeeded server-side but the following
    authenticated callback never reached the origin — no log entry, no
    error surfaced to the client beyond a generic "authorization failed".
    The fix was an explicit IP Access Rule with action **Allow** for
    Cloudflare's own request-source range. Since an origin allowlist is
    already the point of this project, add the same provider IP ranges you
    configure in `GANGWAY_ALLOWED_PREFIXES` as an explicit Bot
    Fight Mode / WAF allow rule too — otherwise Cloudflare's own edge can
    filter the traffic before Gangway ever sees it.

!!! warning "Response buffering delays or drops streamed events"

    Cloudflare's default response body buffering (`Standard`) inspects a
    prefix of the response before the rest streams through, which does not
    suit a long-lived MCP response stream. Set response body buffering to
    **`None`** for the `/mcp` path, via a Configuration Rule. Cloudflare's
    own documentation notes the trade-off: with buffering off, WAF and Bot
    Management body inspection no longer apply to that path — which is
    exactly why the Bot Fight Mode allowlist above still matters even after
    disabling buffering.

!!! warning "125-second idle timeout needs a heartbeat"

    Cloudflare's Proxy Read Timeout is 125 seconds by default (not
    adjustable below Enterprise) and, per Cloudflare's own definition, is a
    timeout "between two successive read operations to your origin server"
    — an idle timeout, not a hard cap on total connection length. In
    practice this means a streamed MCP connection that goes more than 125
    seconds without sending any bytes is liable to be cut with a 524, while
    one that emits some kind of keepalive at a shorter interval should stay
    open indefinitely. Cloudflare has not published this as a documented
    guarantee specifically for SSE or streamable HTTP, so treat it as
    something to verify against your own long-lived connections rather
    than as a settled fact.

None of these three interact with `GANGWAY_CLIENT_IP_HEADER` or
`GANGWAY_TRUSTED_PROXIES` — they can each break the connection while origin
filtering continues to work exactly as configured, which is what makes them
easy to misdiagnose as an allowlist problem when they are not one.
