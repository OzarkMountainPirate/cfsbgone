# cfsbgone

> An OpenVPN endpoint that slips past content filter systems (CFS), deep packet inspection (DPI), and signature-based IDS/IPS — multiplexed onto TCP/443 alongside ordinary HTTPS traffic using sslh, with `tls-crypt` obfuscating the OpenVPN handshake.

---

## Scope — read this first

This stack has three components, but **you don't always need all three**.

- **VPN-only:** If you just want a tunnel that escapes restrictive networks, you only need the `openvpn/` stack. Skip `sslh/` and `traefik/`. OpenVPN can bind directly to TCP/443 on the host.
- **Full stack:** If you also want to host other web services (a Git server, a chat server, a personal website, etc.) on the same VPS and have them share port 443 with OpenVPN, deploy all three. `sslh` becomes the port-443 ingress and demultiplexes between OpenVPN and Traefik based on the first bytes of each connection.

The deploy instructions below cover the full stack. To run VPN-only, just skip the `sslh/` and `traefik/` sections and expose port 443 directly from the OpenVPN container.

---

## What this is

A pre-wired, cleanly-structured Docker stack that:

1. Terminates a hardened OpenVPN server on TCP/443 with `tls-crypt` enabled, making the handshake indistinguishable from random encrypted bytes to passive inspection.
2. Optionally shares port 443 with a Traefik reverse proxy via `sslh`, a protocol-aware TCP demultiplexer. Real HTTPS traffic goes to Traefik; OpenVPN traffic goes to OpenVPN. Both sides see real client IPs via the PROXY protocol.
3. Uses Cloudflare DNS-01 for ACME so no inbound port 80 challenge is required.

The result: a single public IP and single port (443) that simultaneously serves your websites *and* a covert OpenVPN endpoint, with no obvious VPN fingerprint visible to outside observers.

For the deep-dive on *why* this evades firewall/DPI/IDS-IPS inspection, see [HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md).

---

## Architecture

```
                                Internet :443
                                      │
                                      ▼
                              ┌──────────────┐
                              │    sslh      │  ← reads first bytes,
                              │  (demuxer)   │     classifies protocol
                              └───────┬──────┘
                                      │
                  ┌───────────────────┴───────────────────┐
                  │                                       │
              TLS bytes                            OpenVPN bytes
                  │                                       │
                  ▼                                       ▼
          ┌──────────────┐                       ┌──────────────┐
          │   Traefik    │                       │   OpenVPN    │
          │ (HTTPS:8443) │                       │ (TCP:1194)   │
          │  + PROXY v2  │                       │  + tls-crypt │
          └──────┬───────┘                       └──────┬───────┘
                 │                                      │
            web services                          VPN clients
            (your apps)                           (full-tunnel)
```

All three containers join a shared Docker network (`proxy`). Only sslh exposes port 443 to the host. Traefik and OpenVPN are reachable only inside the Docker network.

---

## Prerequisites

- A VPS with a public IPv4 address (any provider). A 1–2GB instance is plenty.
- A domain you control, with DNS at Cloudflare (or willing to migrate). Cloudflare DNS-01 challenge is used for cert issuance so port 80 isn't needed for ACME.
- A Cloudflare API token scoped to `Zone:DNS:Edit` for your zone.
- Docker Engine + Docker Compose v2 on the VPS.
- A spare DNS hostname for the VPS (e.g., `gateway.example.com`). **Set the record to DNS-only (grey cloud), not proxied** — Cloudflare's proxy mangles OpenVPN traffic.

---

## Repository layout

```
cfsbgone/
├── README.md                 ← this file
├── .gitignore
├── docs/
│   ├── HOW-IT-WORKS.md       ← protocol-level deep dive
│   ├── CLIENT-SETUP.md       ← per-platform client install (Win/Mac/Linux/Android/iOS)
│   └── HARDENING.md          ← VPS host hardening checklist
├── sslh/
│   ├── docker-compose.yml
│   └── config/sslh.cfg
├── traefik/
│   ├── docker-compose.yml
│   ├── traefik.yml
│   ├── .env.example
│   └── dynamic/              ← drop dynamic config files here
├── openvpn/
│   └── docker-compose.yml    ← PKI gets generated into ./data at first init
└── socket-proxy/             ← OPTIONAL: filtered Docker socket for Traefik (recommended)
    └── docker-compose.yml
```

---

## Deploy (full stack)

All commands assume you're deploying under `/opt/containers/`. Adjust paths to taste.

### 1. Get the project files

```bash
sudo mkdir -p /opt/containers
sudo chown $USER:$USER /opt/containers
cd /opt/containers

git clone https://github.com/YOUR_USERNAME/cfsbgone.git
cd cfsbgone
```

You'll have `sslh/`, `traefik/`, `openvpn/`, `socket-proxy/`, `docs/`, and `README.md`. The rest of the steps run from inside this directory (or move the contents up to `/opt/containers/` if you prefer a flatter layout — adjust paths accordingly).

### 2. Create the shared Docker network

```bash
docker network create proxy
```

### 3. Initialize the OpenVPN PKI

This is interactive — you'll set a CA passphrase. **Store it in a password manager** because you'll need it every time you issue or revoke a client cert.

```bash
cd /opt/containers/openvpn

# Replace gateway.example.com with your VPS hostname
docker run -v $PWD/data:/etc/openvpn --rm kylemanna/openvpn \
  ovpn_genconfig -u tcp://gateway.example.com:443 \
  -e "tls-crypt /etc/openvpn/pki/ta.key"

docker run -v $PWD/data:/etc/openvpn --rm -it kylemanna/openvpn \
  ovpn_initpki
```

Fix the kylemanna defaults that don't match our setup:

```bash
# The -e flag appended tls-crypt without removing the default tls-auth line.
# OpenVPN refuses to run with both — remove tls-auth.
sudo sed -i '/^tls-auth /d' data/openvpn.conf

# kylemanna's genconfig pushes Google DNS by default. Remove those lines so
# clients get only Cloudflare DNS (added below) and we stay on one resolver.
sudo sed -i '/^push "dhcp-option DNS 8\.8\.8\.8"/d; /^push "dhcp-option DNS 8\.8\.4\.4"/d' data/openvpn.conf

# Push full-tunnel routing and Cloudflare DNS to clients
cat >> data/openvpn.conf << 'EOF'

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 1.0.0.1"

# Performance tuning
fast-io
sndbuf 524288
rcvbuf 524288
push "sndbuf 524288"
push "rcvbuf 524288"
tun-mtu 1500
mssfix 1300
EOF

# Verify only tls-crypt is referenced, and only Cloudflare DNS is pushed
grep -E 'tls-(auth|crypt)' data/openvpn.conf
# Expected: tls-crypt /etc/openvpn/pki/ta.key
grep '^push "dhcp-option DNS' data/openvpn.conf
# Expected: only 1.1.1.1 and 1.0.0.1

# Bring it up
docker compose up -d
docker compose logs --tail=20 openvpn
```

### 4. Configure and bring up Traefik

```bash
cd /opt/containers/traefik

# Create your Cloudflare token env file from the example
cp .env.example .env
# Edit .env and set CF_DNS_API_TOKEN to your Cloudflare API token

# Edit traefik.yml — change the ACME email address to yours

# Prep the ACME storage with correct permissions
touch acme/acme.json && chmod 600 acme/acme.json

docker compose up -d
docker compose logs --tail=30 traefik
```

You should see the Cloudflare ACME provider initialize without errors. No certs are issued until you actually deploy a service with a `Host()` router rule.

### 5. Bring up sslh

```bash
cd /opt/containers/sslh

# IMPORTANT: the config file must exist BEFORE the container starts.
# If you let Docker create the bind-mount path, it'll make a directory
# instead of a file and sslh will crash-loop with "file I/O error".
ls -la config/sslh.cfg   # must be a FILE
chmod 644 config/sslh.cfg

docker compose up -d
docker compose logs -f sslh
```

A clean startup with no "could not resolve" errors confirms sslh can see `openvpn` and `traefik` via Docker DNS.

### 6. Open ports

- **Host firewall**: allow inbound TCP/22 (or your obscure SSH port), TCP/80 (for Traefik's HTTP→HTTPS redirect), and TCP/443 (sslh). Sample nftables config in [HARDENING.md](docs/HARDENING.md).
- **VPS provider firewall** (whatever cloud firewall / security group your provider offers): same three ports.

If you're using nftables, make sure your config uses `flush table inet filter` rather than `flush ruleset` — the latter wipes Docker's NAT rules every time you reload. See [HARDENING.md](docs/HARDENING.md) for the gotcha.

### 7. Verify

```bash
# From any external machine:
curl -vk https://gateway.example.com
# Should hit Traefik's default 404 — proves the TLS branch of the demux works

# From the VPS:
docker logs sslh
# Should show classifier output (tls:connection... or openvpn:connection...)
```

### 8. Generate and distribute client profiles

```bash
cd /opt/containers/openvpn

# One profile per device — easier to revoke later
docker compose exec openvpn easyrsa build-client-full laptop nopass
docker compose exec openvpn ovpn_getclient laptop > /tmp/laptop.ovpn

# kylemanna's export script hardcodes tls-auth in client configs even when
# the server uses tls-crypt. Patch the exported file to match:
sed -i 's|<tls-auth>|<tls-crypt>|; s|</tls-auth>|</tls-crypt>|; /^key-direction 1$/d' \
  /tmp/laptop.ovpn

# Verify
grep -E '<tls-crypt>|<tls-auth>' /tmp/laptop.ovpn
# Expected: <tls-crypt>
```

For per-platform client setup (Windows, macOS, Linux, Android, iOS), see [CLIENT-SETUP.md](docs/CLIENT-SETUP.md).

---

## Deploy (VPN-only, no sslh/Traefik)

If you don't need to host other services on this box, skip the demuxer entirely:

1. Follow steps 1–3 above to initialize the OpenVPN PKI.
2. Edit `openvpn/docker-compose.yml` and add a host port mapping:
   ```yaml
   ports:
     - "443:1194/tcp"
   ```
3. Skip steps 4–5 (no Traefik, no sslh).
4. Open only TCP/443 in your firewalls.
5. Generate client profiles per step 8.

The OpenVPN container binds directly to host port 443. Same evasion properties — `tls-crypt` is what makes the handshake unidentifiable, not sslh. sslh only exists to share the port with other services.

---

## Optional enhancements

- **Docker socket proxy** for Traefik — the highest-value hardening step on the box. Filters the Docker API down to the read-only endpoints Traefik needs so a Traefik compromise can't reach host root via the socket. Ships as the `socket-proxy/` stack. See [HARDENING.md](docs/HARDENING.md#optional-docker-socket-proxy).
- **TCP BBR** for better throughput over high-latency links. See [HARDENING.md](docs/HARDENING.md#performance).
- **CrowdSec** for behavioral firewalling. Add once you deploy your first login-bearing service behind Traefik — defer until then.
- **Wildcard certs** via Cloudflare DNS-01 if you want `*.gateway.example.com` covered by a single cert.

---

## Troubleshooting

A few issues this stack reliably hits on first deploy:

| Symptom | Cause | Fix |
|---|---|---|
| sslh in crash loop: `file I/O error` | `sslh.cfg` is a directory (Docker created it because the file didn't exist on the host before `up`) | `rm -rf` the dir, create the file, re-`up` |
| OpenVPN crash loop: `--tls-auth and --tls-crypt are mutually exclusive` | `ovpn_genconfig -e "tls-crypt..."` appends, doesn't replace | `sed -i '/^tls-auth /d' data/openvpn.conf` |
| Client connects but no internet | Either no `redirect-gateway` push, or no MASQUERADE on host | Check `iptables -t nat -L POSTROUTING` for Docker's MASQUERADE rules; if missing, you ran `nft flush ruleset` somewhere — see [HARDENING.md](docs/HARDENING.md) |
| Client gets internet but no DNS | OpenVPN pushed DNS but client didn't apply it | Linux: install `openvpn-systemd-resolved`. See [CLIENT-SETUP.md](docs/CLIENT-SETUP.md) |
| Linux client warning: `block-outside-dns` unknown option | Windows-only directive in pushed config | Harmless on Linux. To silence: `sed -i 's\|^push "block-outside-dns"\|#&\|' data/openvpn.conf` |

---

## License

MIT or whatever you prefer. The configs are derived from public Docker images (`kylemanna/openvpn`, `traefik`, `ghcr.io/yrutschle/sslh`).

---

## Further reading

- [HOW-IT-WORKS.md](docs/HOW-IT-WORKS.md) — protocol-level walkthrough of why this evades inspection
- [CLIENT-SETUP.md](docs/CLIENT-SETUP.md) — per-platform client install and import
- [HARDENING.md](docs/HARDENING.md) — VPS host hardening checklist
