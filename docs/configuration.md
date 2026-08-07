---
icon: lucide/settings
---

# Configuration

`serve.LoadConfig()` reads every setting from the environment — never from a
file — so that credentials never end up sitting on disk next to the binary.
It fails to start rather than come up with a gap: a missing issuer,
audience, public base URL, or allowlist is an error, not a silent default.

Error messages name the offending variable but never its value. Several of
these variables are not meant to be echoed back — allowlist prefixes, writer
claim values — and startup failures end up in logs.

## Required

| Variable | Purpose | Example |
|---|---|---|
| `GANGWAY_PUBLIC_BASE_URL` | The server's own externally reachable base URL. Sent back in the `WWW-Authenticate` challenge so a connector knows where to discover OAuth metadata. Never derived from request headers — that would let a caller redirect the sign-in flow to a server of its own choosing. | `https://mcp.example.com` |
| `GANGWAY_ISSUER_URL` | The OpenID Connect issuer, without the `/.well-known/...` suffix. `serve.New` fetches its discovery document at startup and refuses to start if it cannot be reached. | `https://login.microsoftonline.com/<tenant-id>/v2.0` |
| `GANGWAY_AUDIENCE` | The value the token's `aud` claim must contain. | `api://your-app-id` |

## The allowlist: one of these two, at least

| Variable | Purpose | Example |
|---|---|---|
| `GANGWAY_ALLOWED_PREFIXES` | Comma-separated CIDR prefixes. Fixed and read once at startup — use it for a provider's stable range or your own infrastructure. | `203.0.113.0/24,2001:db8::/32` |
| `GANGWAY_REMOTE_LIST_URL` | A URL fetched at startup and re-fetched on `GANGWAY_REMOTE_LIST_INTERVAL`, for a provider whose published range changes — the shipped parser reads the format OpenAI publishes for its connector IPs. A failed initial fetch stops the server from starting; a later failed refresh keeps the last good list rather than locking out every caller over a transient outage. | `https://example.com/published-ips.json` |

At least one of the two is required. Both may be set — the effective
allowlist is their union. Refusing to start with neither configured is
deliberate: without a filter, every caller would be let in.

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

## Network

| Variable | Purpose | Default |
|---|---|---|
| `GANGWAY_ADDR` | The address the HTTP server listens on. | `:8080` |
