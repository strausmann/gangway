# Gangway

Go building blocks for internet-facing [MCP](https://modelcontextprotocol.io/)
servers: OIDC authentication, IP allowlisting, and per-tool authorization —
wrapped around the official
[`modelcontextprotocol/go-sdk`](https://github.com/modelcontextprotocol/go-sdk),
not a replacement for it.

```go
cfg, _ := serve.LoadConfig()
gw, _ := serve.New(ctx, cfg, serve.WithToolKinds(map[string]access.ToolKind{
	"ping": access.KindRead,
}))

mcpServer := mcp.NewServer(&mcp.Implementation{Name: "example", Version: "0.1.0"}, nil)
mcp.AddTool(mcpServer, &mcp.Tool{Name: "ping"}, pingHandler)

gw.AttachMCP(mcpServer) // installs authorization + stateless sessions
log.Fatal(gw.Run(ctx))
```

Five environment variables and this file are a running server — see
**[Getting started](https://strausmann.github.io/gangway/getting-started/)**
for the full, runnable version.

## Documentation

Full documentation, including provider setup for Entra ID and Authentik,
the complete environment variable reference, and the one setting that
silently breaks the origin allowlist when a reverse proxy is involved, is
published at **<https://strausmann.github.io/gangway/>**.

Status: in development, interfaces may change.

## License

[MIT](LICENSE)
