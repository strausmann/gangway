# Multi-Stage Build: Zensical-Dokumentation -> nginx
#
# Baut die statische Doku-Site aus docs/ + zensical.toml und liefert sie ueber
# einen schlanken nginx-Layer aus. Kein Build-Werkzeug, kein Anwendungscode im
# Runtime-Image -- nur die fertigen Seiten.
#
# Bereitgestellt unter gangway.strausmann.cloud (siehe
# infrastructure/docker/gangway-docs auf git.strausmann.de fuer den Dockhand-
# Git-Stack, der dieses Image zieht).

FROM python:3.12-slim AS builder

WORKDIR /docs

RUN pip install --no-cache-dir zensical

COPY zensical.toml ./
COPY docs/ ./docs/

RUN zensical build --clean

FROM nginx:alpine

ARG VERSION=dev
ARG REVISION=unknown
ARG CREATED=unknown

LABEL org.opencontainers.image.source="https://github.com/strausmann/gangway" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="gangway-docs" \
      org.opencontainers.image.description="Statische Zensical-Dokumentation fuer Gangway (Go-Bausteine fuer internetseitige MCP-Server: OIDC, IP-Allowlisting, Tool-Autorisierung)."

COPY --from=builder /docs/site /usr/share/nginx/html
COPY docs/nginx.conf /etc/nginx/conf.d/default.conf

# curl explizit installieren statt auf ein zufaellig mitgeliefertes Binary im
# Basis-Image zu vertrauen -- der Healthcheck soll unabhaengig davon
# funktionieren, was nginx:alpine gerade buendelt.
RUN apk add --no-cache curl

EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost/ > /dev/null || exit 1
