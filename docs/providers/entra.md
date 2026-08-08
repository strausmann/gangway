---
icon: lucide/building-2
---

# Microsoft Entra ID

Gangway talks to Entra ID (formerly Azure AD) through standard OpenID
Connect discovery — nothing provider-specific in the code, only
configuration. This page covers the three settings that are easy to get
wrong: the application registration itself, the Application ID URI /
scope pair that becomes `GANGWAY_AUDIENCE`, and why the subject claim needs
to be `oid`, not `sub`.

## Register the application

In the Entra admin center, register a new application to represent this
MCP server (**App registrations → New registration**). No redirect URI is
required for this registration if the server itself never initiates a
sign-in flow — it only ever verifies tokens that a client already
obtained elsewhere. Note the **Application (client) ID** and the
**Directory (tenant) ID**; both feed into the issuer URL below.

## Application ID URI and scope

Gangway checks the token's `aud` claim against `GANGWAY_AUDIENCE`. For that
comparison to succeed, the application needs an **Application ID URI** and
at least one exposed **scope**:

1. **Expose an API → Application ID URI.** Accept the default
   (`api://<client-id>`) or set a custom value — either works, as long as
   the value configured here matches `GANGWAY_AUDIENCE` exactly.
2. **Add a scope**, for example `mcp.access`, with **Who can consent**
   set according to your deployment (admin-only for a service-to-service
   integration is the safer default).
3. Whatever client acquires tokens for this server must request that
   scope — `api://<client-id>/mcp.access` — so the resulting token's
   audience matches.

```bash
GANGWAY_ISSUER_URL=https://login.microsoftonline.com/<tenant-id>/v2.0
GANGWAY_AUDIENCE=api://<client-id>
```

The `v2.0` suffix on the issuer selects the v2.0 token endpoint; tokens
from the v1.0 endpoint carry a differently shaped `aud` (the bare client
ID rather than the Application ID URI) and issuer, so issuer and audience
have to be a matched pair from the same token version.

## Why `GANGWAY_SUBJECT_CLAIM=oid`, not `sub`

Leave `GANGWAY_SUBJECT_CLAIM` at Gangway's default (`sub`) for most OIDC
providers. Entra ID is the exception: its `sub` claim is pseudonymized —
computed per application (and, depending on configuration, per tenant) —
so the same human user can present a different `sub` value to two
different applications, or even after certain app reconfigurations. A
value used as a stable per-user identifier — for authorization decisions,
for audit log correlation, for anything that needs "this is the same
person as last time" — cannot rely on it holding steady.

The **`oid`** claim (object ID) is the tenant-stable identifier: the same
underlying user object in Entra ID, and therefore the same `oid`, no
matter which application requested the token. Set:

```bash
GANGWAY_SUBJECT_CLAIM=oid
```

Both claims are always present on a v2.0 token; only the choice of which
one Gangway reads as `identity.Identity.Subject` changes.

## Roles for the writer claim

`GANGWAY_WRITERS_CLAIM` / `GANGWAY_WRITERS_VALUE` (see
[Configuration](../configuration.md)) work with any claim Entra ID
includes in the token — most commonly **App roles**, defined under the
application's **App roles** blade and assigned to users or groups under
**Enterprise applications → \<this app\> → Users and groups**. An assigned
app role appears in the token as the `roles` claim, a list of strings:

```bash
GANGWAY_WRITERS_CLAIM=roles
GANGWAY_WRITERS_VALUE=mcp.write
```

Group-based authorization works the same way through the `groups` claim,
if the application is configured to emit group claims — that path tends
to hit Entra ID's optional-claims group-overage limits sooner than app
roles do, so app roles are the simpler default for a small, fixed set of
writers.
