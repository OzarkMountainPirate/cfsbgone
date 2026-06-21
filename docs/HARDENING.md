# Hardening

Recommended security configuration for the VPS host that runs this stack. None of this is strictly required for the VPN to *function*, but it's what takes the deployment from "works" to "clean and defensible." How far you take it is your call — apply what fits your threat model.

The stack itself is designed to coexist cleanly with all of the below. Several items reference gotchas encountered during the reference deployment.

---

## SSH hardening

**The most secure option is to not expose SSH to the internet at all.** Before hardening it, consider whether you need remote SSH on a public port in the first place. The strongest postures, roughly in order:

1. **No internet-facing SSH.** Administer the box through your VPS provider's out-of-band console (web-based serial/LISH/VNC terminal, depending on provider). SSH never listens on a public interface, so there is nothing on the internet to attack, scan, or exploit.
2. **SSH reachable only behind the VPN.** Once this stack's tunnel is up, bind SSH to the tunnel interface (or firewall it to the VPN subnet only) so you must be connected to the VPN before you can SSH. This folds SSH access into the same `tls-crypt`-protected channel as everything else.
3. **SSH internet-facing, but hardened.** If you do want SSH reachable from anywhere — for bootstrap convenience, break-glass access, or because you haven't set up the VPN yet — then the configuration below is how you reduce the risk: cert-only auth, no passwords, an obscure port, fail2ban, and a default-drop firewall. This is a legitimate choice; just go in knowing it's a larger attack surface than options 1 or 2, and treat the hardening steps as mandatory rather than optional.

Everything in this section assumes option 3. If you've chosen option 1 or 2, you can skip straight to the firewall and forwarding sections — though the SSH daemon config below is still worth applying as defense-in-depth even when SSH is VPN-only.

Drop-in config at `/etc/ssh/sshd_config.d/00-hardening.conf`:

```
PermitRootLogin prohibit-password
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
ClientAliveInterval 300
ClientAliveCountMax 2

# Optionally: move SSH off port 22 to a random high port
# to reduce scanner noise. Pick something 30000–60000 that
# doesn't collide with anything you run.
# Port 47823
```

Reload sshd in a *second* terminal after testing the config:

```bash
sudo sshd -t && sudo systemctl reload ssh
```

Verify you can still log in *before* closing your original session.

### Moving SSH off port 22

Obscurity isn't security, but it is **noise reduction**. Moving SSH off 22 dramatically reduces scanner traffic, fail2ban load, and the likelihood of being included in mass-scanning lists. Cert-only auth remains your real defense.

If you move it, update:

1. `/etc/ssh/sshd_config.d/00-hardening.conf` (add `Port 47823` or whatever you chose)
2. The host firewall rule (see nftables section below)
3. Your VPS provider's cloud firewall
4. Your `~/.ssh/config` on workstations

---

## Host firewall (nftables)

`/etc/nftables.conf`:

```
#!/usr/sbin/nft -f

# CRITICAL: flush only our own table, not the whole ruleset.
# `flush ruleset` wipes Docker's NAT rules (which live in nftables
# tables under the `ip` family because modern Docker uses iptables-nft).
# That breaks all outbound container traffic.
flush table inet filter

table inet filter {
  chain input {
    type filter hook input priority 0; policy drop;
    
    ct state established,related accept
    ct state invalid drop
    iif lo accept
    
    icmp type echo-request limit rate 5/second accept
    icmpv6 type { echo-request, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
    
    tcp dport 22  accept comment "SSH"           # or your obscure port
    tcp dport 80  accept comment "HTTP redirect"
    tcp dport 443 accept comment "sslh ingress"
  }
  
  chain forward {
    # Docker manages its own FORWARD rules in the `ip` family.
    # Don't get in the way.
    type filter hook forward priority 0; policy accept;
  }
  
  chain output {
    type filter hook output priority 0; policy accept;
  }
}
```

Load it:

```bash
sudo nft -f /etc/nftables.conf
sudo systemctl enable --now nftables
```

### The `flush ruleset` gotcha

If you use `flush ruleset` at the top of `/etc/nftables.conf` instead of `flush table inet filter`, every `nft -f` reload (and every reboot) wipes all of Docker's NAT rules. The symptom: containers can still talk to each other on the Docker network, but outbound traffic to the internet has its source NAT stripped. Tunnel traffic egresses the VPS with private (172.x.y.z) source IPs and gets black-holed.

If you've hit this and need to recover immediately:

```bash
# One-time fix: restart Docker so it reinstalls its NAT rules
sudo systemctl restart docker

# Then fix the nftables.conf to prevent recurrence
sudo sed -i 's|^flush ruleset|flush table inet filter|' /etc/nftables.conf
```

### IP forwarding

Required for the VPS to forward tunneled traffic to the internet:

```bash
echo "net.ipv4.ip_forward=1" | sudo tee /etc/sysctl.d/99-ip-forward.conf
sudo sysctl --system
```

---

## fail2ban

For SSH brute-force protection. The systemd backend reads `journalctl` directly, so port number doesn't matter — auth failures are caught regardless of which port SSH runs on.

```bash
sudo apt install -y fail2ban
```

`/etc/fail2ban/jail.local`:

```
[DEFAULT]
backend = systemd
findtime = 10m
bantime = 1h
maxretry = 5
ignoreip = 127.0.0.1/8 ::1 <your-static-IPs-if-any>

[sshd]
enabled = true
mode = aggressive
```

```bash
sudo systemctl enable --now fail2ban
sudo fail2ban-client status sshd
```

### Don't bother adding a fail2ban jail for OpenVPN

With `tls-crypt`, attackers can't even reach the TLS handshake without the pre-shared key. There's nothing to brute-force, no failed-auth event to log. Skip it.

### Don't bother adding a fail2ban jail for Traefik *yet*

Until you deploy a service with a login surface (Gitea, Matrix admin, etc.), Traefik is only serving 404s. Banning IPs for hitting nothing is pointless. Add behavioral protection when you actually have a target worth protecting — at that point, **CrowdSec** is the better answer than fail2ban for the Traefik layer.

---

## Unattended security upgrades

```bash
sudo apt install -y unattended-upgrades apt-listchanges
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

Verify it's working:

```bash
sudo unattended-upgrades --dry-run --debug 2>&1 | head -30
```

---

## Traefik dashboard exposure

The provided `traefik.yml` enables the dashboard but with `insecure: false` and no router pointing to `api@internal`. This means the dashboard is **not** reachable from outside as shipped. Verify:

```bash
curl -vk https://your-hostname/dashboard/   # should return Traefik 404
curl -v http://your-VPS-IP:8080/             # should not connect (port not listening)
```

If you want to use the dashboard, create a router that:

1. Binds it to a hostname that only resolves via the VPN tunnel, OR
2. Restricts access via an `IPAllowList` middleware to your VPN client subnet, OR
3. At minimum, add `basicAuth` middleware with a strong password.

Drop the router definition in `traefik/dynamic/dashboard.yml`:

```yaml
http:
  routers:
    dashboard:
      rule: "Host(`traefik.example.com`)"
      service: api@internal
      entryPoints: [websecure]
      tls:
        certResolver: cloudflare
      middlewares:
        - dashboard-auth
        - dashboard-vpn-only
  
  middlewares:
    dashboard-auth:
      basicAuth:
        users:
          - "admin:$2y$05$generated-via-htpasswd-nbB"
    
    dashboard-vpn-only:
      ipAllowList:
        sourceRange:
          - "192.168.255.0/24"   # adjust to your OpenVPN subnet
```

Generate a basicAuth hash:

```bash
htpasswd -nbB admin 'your-strong-password'
```

---

## OpenVPN client cert lifecycle

You set a CA passphrase during `ovpn_initpki`. **Store it somewhere durable.** You'll need it every time you:

- Issue a new client cert (`easyrsa build-client-full`)
- Revoke a client cert (`easyrsa revoke`)
- Generate or refresh the CRL (`easyrsa gen-crl`)

If you lose this passphrase, your only recovery is to rebuild the PKI from scratch and reissue all client profiles.

---

## Performance

### Enable TCP BBR

BBR is a modern TCP congestion control algorithm that significantly improves throughput on high-latency or slightly-lossy links — exactly the conditions a VPN-over-TCP usually faces.

```bash
sudo tee /etc/sysctl.d/99-bbr.conf << 'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
sudo sysctl --system

# Verify
sysctl net.ipv4.tcp_congestion_control
# Should output: net.ipv4.tcp_congestion_control = bbr
```

Expected improvement on a typical residential→VPS path: 30–50% throughput uplift. No downside.

### OpenVPN tuning

These directives in `openvpn.conf` (already included in the deploy steps) noticeably help TCP performance:

```
fast-io
sndbuf 524288
rcvbuf 524288
push "sndbuf 524288"
push "rcvbuf 524288"
tun-mtu 1500
mssfix 1300
```

`mssfix 1300` clamps the inner TCP MSS to avoid fragmentation, which kills throughput when the outer packet exceeds path MTU. The default value works well for most paths; adjust down if you observe stuttering on the tunnel.

### What not to bother with

- **LZO compression**: insecure (VORACLE attack), and modern web traffic is already compressed. Default is `comp-lzo no`, leave it.
- **Migrating to UDP**: faster, yes, but breaks the whole evasion premise. UDP/443 is often blocked or QoS'd. The TCP-over-TCP overhead is the cost of being firewall-friendly.
- **Migrating to WireGuard**: UDP-only, also defeats evasion. Use WG for internal/trusted-network tunnels, not for this stack.

---

## Optional: CrowdSec at the Traefik layer

When you deploy your first login-bearing service behind Traefik, add CrowdSec:

- The CrowdSec agent reads Traefik's JSON access logs.
- The CrowdSec Traefik bouncer plugin enforces decisions inline at the proxy.
- Community blocklists give preemptive bans against known-bad IPs.

This isn't included in the base stack because it's overkill until you have a real attack surface to protect. Add it as a separate compose stack on the same Docker network when ready.

---

## Container privilege reality

Running every container as a non-root user is the ideal, but it isn't fully achievable with this particular set of images, and it's worth being honest about why rather than claiming a security property the stack doesn't have.

Here's the actual situation per container:

| Container | Runs as | Why | Can it be non-root? |
|---|---|---|---|
| **sslh** | non-root (`sslh` user) | The image's init starts as root but drops privileges to an unprivileged user for the daemon itself. (This is exactly why the config file needed world-readable perms earlier — the dropped user couldn't read a root-only file.) | Already is |
| **traefik** | root | The official image defaults to root so it can read the Docker socket and bind ports. | Partially — see below |
| **openvpn** | root | `ovpn_run` needs `NET_ADMIN`, manipulates `iptables`, and manages the `tun` device. These require root inside the container. | Not really — root is inherent to what it does |

### Verify what's actually running as root on your box

```bash
for c in sslh traefik openvpn; do
  echo "--- $c ---"
  echo -n "  Config.User: "
  docker inspect "$c" --format '{{if .Config.User}}{{.Config.User}}{{else}}(empty = root){{end}}'
  echo -n "  Effective UID inside: "
  docker exec "$c" id -u 2>/dev/null || echo "(no shell in image)"
done
```

An empty `Config.User` and effective UID `0` means root. Expect sslh to show a non-root UID and the other two to show root (or no shell, in Traefik's case, depending on image variant).

### Mitigations that actually apply

Since you can't simply flip all three to non-root, the meaningful hardening is about containing the blast radius of the ones that must run privileged:

**For openvpn (root is unavoidable):**

- It already runs with only `cap_add: NET_ADMIN` rather than `privileged: true`. Keep it that way — never use `privileged: true` when a specific capability suffices. You can optionally drop all other capabilities explicitly:
  ```yaml
  cap_drop:
    - ALL
  cap_add:
    - NET_ADMIN
  ```
- Add `no-new-privileges` to stop privilege escalation within the container:
  ```yaml
  security_opt:
    - no-new-privileges:true
  ```
- The container only exposes `tun` and `NET_ADMIN` — a container escape would land in a namespace whose extra power is network manipulation, not arbitrary host root, though you should still treat any escape as serious.

**For traefik (root by default, reducible):**

- The official image can run as a non-root user if you give it a user mapping and ensure it can still read the Docker socket (typically by adding the user to the `docker` group's GID). This is fiddly and is a common source of "Traefik can't read the socket" breakage, so weigh the effort.
- A cleaner mitigation than chasing non-root is to **remove Traefik's need for the raw Docker socket** entirely by using a socket proxy. This is the single highest-value hardening step on the box, and the repo ships an optional `socket-proxy/` stack for exactly this. See "Optional: Docker socket proxy" below for deployment. The socket is the actual crown-jewel risk here — anything that can issue write calls to `/var/run/docker.sock` can spawn a privileged container and own the host, and mounting it `:ro` only blocks filesystem-level writes, not dangerous API calls that arrive as reads. The proxy enforces endpoint-level allowlisting, which `:ro` cannot.
- Add `no-new-privileges:true` to the Traefik service as well (already present in the provided compose).

**For all three:**

- Mount the Docker socket read-only (`:ro`) — already done in the provided compose for Traefik. A socket proxy is strictly better, but `:ro` is a reasonable baseline.
- Keep the images updated (`docker compose pull`) so privilege-related CVEs get patched.

### The honest summary

sslh is non-root. Traefik and openvpn run as root, openvpn unavoidably so. The realistic defense is least-capability (no `privileged: true`), `no-new-privileges`, a read-only or proxied Docker socket, and keeping images current — not pretending everything runs unprivileged. If host-level isolation matters more than the convenience of this image set, the next step up is running the whole stack in a dedicated VM (which you already get by using a dedicated VPS) or under rootless Docker / Podman, at the cost of additional setup complexity with the `tun` device and `NET_ADMIN`.

---

## Optional: Docker socket proxy

**Recommended, not required.** This is the highest-value single hardening step available for this stack, because the Docker socket is the one resource on the box whose compromise means immediate game-over (full host root). The base stack mounts the socket `:ro` into Traefik, which is a reasonable baseline — but `:ro` only prevents filesystem-level writes to the socket file. The Docker API can still be driven to do dangerous things through calls that aren't filesystem writes. A socket proxy fixes this properly by sitting between Traefik and the socket and allowing only the specific read-only API endpoints Traefik needs, denying everything else at the API level.

The repo ships this as a separate `socket-proxy/` stack so you can add it whenever you like without it being a prerequisite for the rest.

### Deploy

```bash
cd /opt/containers/socket-proxy
docker compose up -d
docker compose logs --tail=20 socket-proxy
```

The proxy joins the `proxy` network and exposes the filtered Docker API at `tcp://socket-proxy:2375` (internal to the Docker network only — it is never published to the host).

### Point Traefik at the proxy instead of the raw socket

Two changes to the Traefik stack:

**1. In `traefik/traefik.yml`**, tell the Docker provider to use the proxy endpoint:

```yaml
providers:
  docker:
    endpoint: "tcp://socket-proxy:2375"   # was: implicit unix socket
    exposedByDefault: false
    network: proxy
```

**2. In `traefik/docker-compose.yml`**, remove the direct socket mount — Traefik no longer touches it:

```yaml
    volumes:
      # DELETE this line once the socket proxy is in place:
      # - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./traefik.yml:/etc/traefik/traefik.yml:ro
      - ./dynamic:/etc/traefik/dynamic:ro
      - ./acme:/acme
```

Then recreate Traefik:

```bash
cd /opt/containers/traefik
docker compose up -d --force-recreate
docker compose logs -f traefik
```

Traefik should start cleanly and continue discovering containers via the proxy. If you see "cannot connect to Docker daemon" errors, confirm the socket-proxy container is up and on the `proxy` network, and that `CONTAINERS: 1` is set in its environment.

### What the proxy allows

The shipped configuration is default-deny. It permits only `CONTAINERS`, `SERVICES`, `TASKS`, and `NETWORKS` (read endpoints Traefik uses for discovery) and explicitly denies `POST` (all writes), `EXEC`, `IMAGES`, `VOLUMES`, `INFO`, and everything else. Even if Traefik were fully compromised, the attacker reaches only a read-only slice of the Docker API through the proxy — they cannot create containers, exec into anything, or escalate to host root via the socket.

---

## Threat-modeling note

Hardening is layered. The defenses above protect against:

- Mass-scanner brute force on SSH → cert-only auth + nftables drop + fail2ban
- VPS-level compromise via container escape → see "Container privilege reality" below for an honest per-container breakdown and the mitigations that actually apply
- Network-level abuse via tunneled traffic → IP reputation isolation (this VPS is dedicated, not shared with your mail server)
- DNS leaks → `push "dhcp-option DNS"` + clients that apply pushed DNS

What this doesn't protect against, and you should consider:

- **Endpoint compromise on a client**: if a phone or laptop with `.ovpn` is rooted/jailbroken or has spyware, the cert can be exfiltrated. Revoke promptly if a device is lost or suspected compromised.
- **VPS provider visibility**: Linode (or whoever) can see all traffic in/out of your VPS. They typically don't, but their network operations team can. This is a fundamental trust property of any VPS-based VPN.
- **Long-term traffic analysis**: a determined observer correlating flows over time can identify VPN endpoints by traffic patterns even when payloads are unidentifiable. If you need that level of evasion, see the §6 honest limitations section in [HOW-IT-WORKS.md](HOW-IT-WORKS.md).
