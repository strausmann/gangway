---
icon: lucide/key-round
---

# Authentik

Authentik speaks standard OIDC discovery, so the same three Gangway
settings apply as for any provider: issuer, audience, subject claim.
This page covers creating the provider, finding the right issuer URL, and
exposing a groups claim for the writer role.

## Create the provider and application

In Authentik, a provider (the OAuth2/OIDC backend) and an application (the
thing a user or client sees) are separate objects, linked together:

1. **Providers → Create → OAuth2/OpenID Provider.** Set an **Authorization
   flow** appropriate for how tokens will be obtained — for a
   service-to-service integration acquiring tokens via the client
   credentials grant, no interactive flow is exercised at all, but
   Authentik still requires one to be selected.
2. Note the generated **Client ID** — this becomes `GANGWAY_AUDIENCE`,
   since Authentik's issued tokens carry the client ID as the `aud` claim.
3. **Applications → Create**, and link it to the provider created above.
   The application's **Slug** becomes part of the issuer URL.

## Issuer URL

Authentik's discovery document is scoped per provider, at:

```
https://<authentik-host>/application/o/<application-slug>/
```

```bash
GANGWAY_ISSUER_URL=https://authentik.example.com/application/o/<application-slug>/
GANGWAY_AUDIENCE=<client-id>
```

`GANGWAY_SUBJECT_CLAIM` can stay at Gangway's default, `sub` — Authentik
does not pseudonymize it per application the way Entra ID does.

## Roles for the writer claim

`GANGWAY_WRITERS_CLAIM` / `GANGWAY_WRITERS_VALUE` (see
[Configuration](../configuration.md)) need a claim to check against.
Authentik does not include group membership in a token by default; it has
to be added as a **Scope Mapping** on the provider (**Customization →
Property Mappings → Create → Scope Mapping**), with an expression that
reads the authenticated user's groups:

```python
return {
    "groups": [group.name for group in request.user.ak_groups.all()],
}
```

Attach the resulting mapping to the provider's list of scopes (alongside
the default `openid`, `email`, `profile` mappings most setups already
have), and it appears as the `groups` claim — a list of group names — on
every token the provider issues:

```bash
GANGWAY_WRITERS_CLAIM=groups
GANGWAY_WRITERS_VALUE=mcp-writers
```

With that in place, membership in an `mcp-writers` group (created under
**Directory → Groups**, with the intended callers added as members) is
what `access.NewGrid` checks before letting a writing tool run.

Exact menu names and the default scope mapping set shipped with a given
Authentik version can shift between releases; the property mapping
mechanism and expression API above are the stable part to rely on — verify
menu paths against the version actually deployed.
