# tunnelx

Self-hosted **Cloudflare Tunnel** alternative written in Rust.

One binary, two modes:

- **Edge** – public server with Web UI, QUIC listener, HTTP/TCP reverse proxy, TLS termination ready
- **Agent** – outbound-only connector that runs behind NAT/firewall

## Features (v0.1)

- QUIC transport between Edge and Agents
- Remote configuration (add hostnames / TCP ports on the Edge Web UI)
- Multiple Agents per tunnel (simple load balancing)
- HTTP reverse proxy (Host-based routing)
- TCP port forwarding (Edge binds a public port per rule)
- SQLite storage
- Simple HTTP Basic auth for the management panel
- Single static binary

## Requirements

- Rust 1.80+ (edition 2021)

## Quick start

### 1. Build

```bash
cargo build --release
# binary at target/release/tunnelx
```

### 2. Run Edge

```bash
mkdir -p /var/lib/tunnelx
./tunnelx edge -d /var/lib/tunnelx
```

Defaults:

| Flag | Default | Meaning |
|------|---------|---------|
| `-d` | `.` | Working directory (DB + certs) |
| `--quic-addr` | `0.0.0.0:7844` | QUIC listen for Agents |
| `--panel-addr` | `0.0.0.0:8080` | Management Web UI |
| `--http-addr` | `0.0.0.0:80` | Public HTTP |
| `--https-addr` | `0.0.0.0:443` | Public HTTPS (certs required) |
| `--panel-user` | `admin` | Basic auth user |
| `--panel-pass` | `tunnelx` | Basic auth password |

Open `http://<edge-ip>:8080`, login with `admin` / `tunnelx`.

1. Create a tunnel → copy the **token**
2. Add an HTTP rule: hostname `app.example.com` → target `http://127.0.0.1:3000`
3. (Optional) Add a TCP rule: target `tcp://127.0.0.1:22`, public port `2222`

### 3. Run Agent (behind NAT)

```bash
./tunnelx agent --server edge.example.com:7844 --token <the-long-token>
```

Point DNS of `app.example.com` to the Edge IP. Traffic will flow:

```
User → Edge:80 → QUIC → Agent → localhost:3000
```

## Directory layout (Edge)

```
/var/lib/tunnelx/
├── tunnelx.db              # SQLite
├── certs/
│   ├── quic-cert.pem       # auto-generated for QUIC
│   ├── quic-key.pem
│   ├── fullchain.pem       # put your public TLS cert here (future HTTPS)
│   └── privkey.pem
└── config.toml             # optional future global config
```

## Architecture

```
                    ┌──────────────────────────────────────┐
  Public traffic    │              Edge                     │
  ───────────────►  │  HTTP :80 / TCP :N                    │
                    │  Panel :8080                          │
                    │  QUIC  :7844  ◄──── Agent(s) ─────── │
                    │         │                             │
                    │      SQLite                           │
                    └──────────────────────────────────────┘
```

Agents only make outbound QUIC connections. No inbound ports needed on the private side.

## Roadmap

- [x] QUIC control + data streams
- [x] HTTP Host routing
- [x] TCP port binding
- [x] Web UI (create tunnel / rules)
- [x] Multi-agent
- [ ] Real HTTPS termination on Edge (load user certs)
- [ ] ACME / Let's Encrypt
- [ ] Push config updates to live Agents (hot reload)
- [ ] Metrics (Prometheus)
- [ ] Better HTTP streaming (avoid buffering whole body)

## License

MIT
