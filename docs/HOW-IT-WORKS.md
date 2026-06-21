# How it works

This document explains, in detail, *why* and *how* this stack slips past content filter systems (CFS), deep packet inspection (DPI), and signature-based IDS/IPS like Snort and Suricata.

Read this if you want to understand the mechanism deeply rather than just deploy the thing. It's also useful background if you ever need to debug why a connection isn't working — knowing exactly what's on the wire helps a lot.

---

## 1. The threat model

We are trying to make an outbound TCP connection from a client device to a VPN endpoint, in environments where one or more of the following is true:

- **Content Filter System (CFS)**: school/corporate/ISP/guest-network filters whose job is to classify and block categories of traffic — including "VPN/proxy" as a category. These range from DNS-based category blocking to inline appliances (Cisco Umbrella, Fortinet FortiGuard, Palo Alto, Zscaler, Sophos, etc.) that try to identify and drop VPN protocols regardless of port.
- **Deep Packet Inspection (DPI)**: the filter doesn't just look at port numbers, it inspects the payload bytes to identify protocols. This is the mechanism most content filters and next-gen firewalls use to spot VPNs. Also used by national-scale filters (China's GFW, Iran's filtering) and many corporate proxies.
- **Signature-based IDS/IPS**: Suricata, Snort, and similar tools maintain rulesets that fingerprint known protocols, including VPN protocols. They can alert on or actively block matching traffic.
- **Application-layer enforcement**: SNI inspection in TLS ClientHello, certificate validation, JA3/JA3S fingerprinting.

### The one thing that defeats this stack: TLS/SSL inspection

The entire design rests on one assumption: **the network is not performing TLS/SSL interception** (a.k.a. SSL inspection, break-and-inspect, or a transparent MITM proxy). If it is, the filter terminates your TLS connection at its own appliance, decrypts everything, inspects it, and re-encrypts to the destination — and it can see straight through to the OpenVPN protocol inside.

The good news is that TLS inspection is **self-announcing and easy to confirm you're free of**. For an appliance to MITM your TLS, your device must trust its CA certificate. That means one of two things has happened:

1. **Managed device**: an administrator pushed a custom root CA onto your device (via MDM, group policy, or a setup profile). If you own the device and never installed such a profile, this isn't in play.
2. **Captive portal CA prompt**: some guest networks, when you authenticate through the captive portal, instruct you to install a CA certificate on your device "to enable secure browsing." **If the portal is asking you to install a CA cert, that network is doing TLS inspection — this stack will not hide your VPN there.** If you authenticate to the portal and it does *not* ask you to install anything, the network cannot decrypt your TLS, and by extension cannot see the OpenVPN traffic riding inside port 443.

So the practical test is simple: if no CA certificate was ever installed on your device and the captive portal didn't demand one, TLS inspection isn't happening, and this stack works.

> **Note on captive portals themselves:** This stack does *not* bypass a captive portal's authentication wall. If a network forces you through a sign-in page before granting any internet access, you still have to authenticate normally. What this stack does is let your VPN traffic flow undetected *once you're past the portal and on the network*.

We are **not** trying to defeat:

- Networks performing TLS/SSL interception with a trusted CA on your device (see above).
- An active adversary with control over your endpoint or the VPS.
- Operators who specifically allowlist destination IPs and block everything else (this defeats almost all VPN approaches).
- Sophisticated traffic-shape analysis that doesn't rely on payload signatures.

---

## 2. The components and their roles

### 2.1 OpenVPN with tls-crypt

OpenVPN has two main channels:

- **Control channel** — sets up the tunnel: TLS handshake, key exchange, push directives. Carries metadata.
- **Data channel** — carries the actual tunneled IP packets after the tunnel is established.

The control channel uses TLS internally to negotiate session keys. This is what every DPI fingerprint targets, because the OpenVPN-specific wrapping around the TLS handshake is easily identifiable.

OpenVPN offers three options for protecting the control channel from passive inspection:

| Mode | What it does | Visible to DPI |
|---|---|---|
| Nothing (raw) | Plain control channel | Full OpenVPN protocol, easily fingerprinted |
| `tls-auth` | Adds HMAC to all control packets | OpenVPN signature still visible; HMAC adds nothing to obfuscation |
| `tls-crypt` | Encrypts + HMACs all control packets with a pre-shared key | Outer packet header (1 byte opcode + ID + HMAC + ciphertext) — no recognizable inner TLS handshake |

**This stack uses `tls-crypt`.** The pre-shared key (`ta.key`, generated at PKI init) is the same 256-byte file as for `tls-auth`, but it's used differently: the first 128 bytes encrypt the control packet, the last 128 bytes HMAC it. This means:

- Anyone without `ta.key` cannot even *begin* the TLS handshake — the server won't respond to unencrypted handshake attempts.
- A passive observer sees: TCP/443 connection → small fixed-format wrapper → encrypted noise. They never see the inner TLS handshake, the cert exchange, or anything else identifiable as OpenVPN.

### 2.2 sslh — TCP protocol demultiplexer

`sslh` listens on TCP/443 and decides what to do with each incoming connection based on the first bytes the client sends. It has built-in probes for many protocols including TLS, SSH, OpenVPN, XMPP, HTTP, and SOCKS5.

For this stack, two probes are configured:

- `openvpn`: matches the OpenVPN packet opcode in the first byte
- `tls`: matches the TLS record header (`0x16 0x03 0x0X`)

When a connection arrives, sslh reads a few bytes, classifies, and proxies the connection (and all subsequent bytes in both directions) to the appropriate backend. To the client, the connection looks like it went straight to the backend — they never know sslh is there.

**Why sslh is necessary if you also host websites:** OpenVPN can absolutely bind to TCP/443 by itself. But if you want a real HTTPS site (Traefik) on the same VPS, you need *something* to share the port. sslh is the cleanest answer — a small, purpose-built tool doing exactly one job.

### 2.3 Traefik with PROXY protocol

Traefik is the reverse proxy for any web services you host. It needs to know the real client IP for logging, rate limiting, and access control. Since sslh proxies the connection, by default Traefik would see sslh's IP as the client.

The PROXY protocol (v2) solves this. sslh prepends a small header to each forwarded TLS connection that contains the original source IP and port. Traefik's `proxyProtocol` entrypoint option parses this header and substitutes the real IP throughout.

Result: Traefik logs show real client IPs, IP-based middlewares work correctly, and certs get issued normally via Cloudflare DNS-01.

---

## 3. The full handshake, step by step

A client connects from a restrictive network to `gateway.example.com:443`.

### Step 1: TCP handshake on port 443

```
Client → SYN              → gateway:443
Client ← SYN/ACK          ← gateway
Client → ACK              → gateway
```

**To any observer:** At this stage the connection looks like any other TCP connection opening to port 443. There's no payload yet, so there's nothing to fingerprint — a firewall, DPI box, or IPS has only the destination port and IP to go on, and port 443 to an ordinary host doesn't distinguish a VPN from a web browser.

### Step 2: Client sends first bytes

The OpenVPN client's first packet is a `P_CONTROL_HARD_RESET_CLIENT_V2` packet. Without `tls-crypt`, this would contain the start of a TLS ClientHello. **With `tls-crypt`**, the packet structure is:

```
+---------+----------+--------+------------------+
| opcode  | packet ID| HMAC   | ENCRYPTED payload|
| 1 byte  | 8 bytes  | 16-32B | variable         |
+---------+----------+--------+------------------+
```

The opcode for `P_CONTROL_HARD_RESET_CLIENT_V2` is `0x38` (binary `00111000`) when key_id is 0.

### Step 3: sslh classification

sslh reads the first few bytes from the kernel socket buffer. It runs each configured probe in order:

- `openvpn` probe: checks if the first byte looks like an OpenVPN opcode. It does (0x38). **Match.**
- (TLS probe would have run if the first byte were 0x16, but it isn't.)

sslh opens a TCP connection to `openvpn:1194` on the internal Docker network and **splices** the two connections together at the kernel level (or proxies bytes in a loop, depending on version). All bytes — past and future — flow through sslh transparently.

The first bytes sslh already read are forwarded immediately so OpenVPN sees a complete packet.

### Step 4: OpenVPN control channel handshake

The OpenVPN server receives the `P_CONTROL_HARD_RESET_CLIENT_V2`, verifies the HMAC against `ta.key`, decrypts the inner payload, and validates the packet ID for replay protection. If any of this fails (wrong PSK, replay, tampering), the server silently drops the connection. **There is no error response that would identify it as an OpenVPN server.**

If everything validates, the server responds with its own `P_CONTROL_HARD_RESET_SERVER_V2`, also encrypted under `ta.key`. Client and server then exchange more control packets to negotiate the TLS session inside the encrypted control channel.

The inner TLS handshake (cert exchange, key derivation) happens entirely inside the `tls-crypt`-encrypted tunnel. **No observer sees any of it.**

### Step 5: Data channel establishment

After TLS completes inside the control channel, OpenVPN derives a separate data-channel key. From this point forward, data packets use AEAD encryption (AES-256-GCM by default in modern OpenVPN) and a different opcode in the packet header.

The data channel is *not* encrypted with `ta.key`. It's encrypted with the negotiated session key. But it's also unidentifiable as OpenVPN — the packet structure is minimal (opcode byte + sequence + ciphertext), and there are no protocol-specific tokens, version strings, or strings of any kind for DPI to match.

### Step 6: Tunnel up — traffic flow

```
Client → tun0 (encrypted) → TCP/443 → gateway → sslh → openvpn → 
   decrypt → forward to Internet via VPS public IP (after MASQUERADE)
```

Return traffic flows the reverse way. The client's tunneled IP is from the OpenVPN subnet (e.g., 192.168.255.0/24). The container MASQUERADEs this to its Docker network IP (e.g., 172.18.0.x), and the Docker host MASQUERADEs *that* to the VPS public IP. All this is invisible to the client.

---

## 4. What an observer sees vs. what's actually happening

Take a position somewhere between the client and the VPS — say, a content filter appliance on a corporate network, or an ISP-level DPI box.

**What they see:**

1. Many short HTTPS connections to your VPS (real web traffic).
2. One or more long-lived connections to the same VPS on the same port.
3. The long-lived connections start with a small packet of unrecognizable structure, followed by a stream of high-entropy bytes.

**What they *can't* see:**

1. That the long-lived connection is OpenVPN (no protocol signature).
2. The contents of the tunnel (data is encrypted with negotiated session keys).
3. Where the client is ultimately connecting to (all DNS lookups go through the tunnel after `push "dhcp-option DNS ..."`).
4. The fact that two different protocols are sharing the same port.

A naive DPI might fingerprint the long-lived connections as "unknown encrypted traffic" — a category that's so broad (it includes many proprietary apps, custom protocols, anything with TLS-tunneled inside, etc.) that blocking it would break too much legitimate traffic.

---

## 5. Why this evades, layer by layer

### 5.1 Content Filter Systems (CFS)

A content filter's job is to classify traffic into categories (social media, streaming, gaming, "VPN/proxy," etc.) and enforce policy per category. "Anonymizers / VPNs" is almost always a blockable category in products like Cisco Umbrella, FortiGuard, Zscaler, Palo Alto, and Sophos. The filter identifies VPN traffic through some combination of:

- **Destination reputation**: known VPN-provider IP ranges and domains are categorized and blocked. *This stack defeats that trivially* — your endpoint is your own VPS on a generic hosting IP with your own domain, not a known commercial VPN range.
- **Port/protocol heuristics**: blocking the default VPN ports (OpenVPN 1194, WireGuard 51820, IPsec 500/4500). *Defeated* — we ride TCP/443, which can't be blocked without breaking HTTPS.
- **DPI signature matching**: identifying the VPN protocol by its on-the-wire fingerprint regardless of port. This is the real test, and it's covered in §5.2 — `tls-crypt` is what defeats it.

Putting it together: a content filter trying to block VPNs has three levers (reputation, port, signature). This stack removes all three. Reputation doesn't fire because you're not a known VPN host. Port-blocking doesn't fire because you're on 443. Signature-matching doesn't fire because `tls-crypt` encrypts the OpenVPN fingerprint.

One of the few exceptions, again, is **TLS/SSL inspection** (§1). If the filter is a man-in-the-middle with a CA your device trusts, it decrypts the 443 stream and sees the OpenVPN protocol inside. Confirm you're free of TLS inspection (no custom CA installed, no captive-portal CA prompt) and this lever is also off the table.

> Note: This is distinct from a captive portal's *authentication* wall. Bypassing a sign-in page is not what this does — see the threat-model note in §1. This is purely about defeating *category/protocol-based blocking of VPNs* once you have network access.

### 5.2 Deep Packet Inspection (DPI)

DPI works by maintaining signatures for known protocols and matching them against packet contents. Major commercial DPI vendors (Palo Alto, Fortinet, Cisco Firepower) all have OpenVPN signatures, but they rely on observable patterns.

- **Without `tls-crypt`**: signatures match against the visible OpenVPN-wrapped TLS handshake. Detection rate is near-100%.
- **With `tls-crypt`**: signatures fail because the OpenVPN-specific bytes are encrypted under a key the DPI doesn't have. The 1-byte opcode at the start of each packet is technically visible, but it's not a strong enough signal alone — the false-positive rate of "block all TCP/443 connections that start with byte 0x38" would be unacceptable.

State-of-the-art DPI may use **traffic analysis** (packet timing, sizes, inter-arrival patterns) rather than signatures. This works on Tor and some other obfuscation systems. It's less reliable against OpenVPN-over-TCP/443 because the traffic shape *does* look reasonably similar to bulk HTTPS (large downloads, persistent connections).

If you're up against active traffic analysis, you need additional obfuscation (e.g., Shadowsocks-with-v2ray-plugin, obfs4, or Cloak). This stack does not include those. For most real-world environments — corporate networks, hotels, cafes, regional ISP filtering — `tls-crypt` + multiplexed 443 is sufficient.

### 5.3 Signature-based IDS/IPS (Snort, Suricata)

These tools come with rule sets (Emerging Threats, Snort Community, etc.) that fingerprint OpenVPN. Sample real rules include matching the OpenVPN handshake bytes, looking for the OpenVPN string in cert CNs, and matching control channel packet headers.

- **`tls-crypt` defeats handshake-byte signatures.** The bytes those rules match are encrypted.
- **`tls-crypt` defeats string-based content matching** in the control channel. Cert CNs, OpenVPN protocol strings — all encrypted.
- **The 1-byte opcode is theoretically detectable.** A custom rule that matches `tcp.dport == 443 && first_byte == 0x38` would catch this. But such a rule is fragile: anything that happens to start with byte 0x38 would false-positive, and any future OpenVPN protocol change would break it. Stock Suricata/Snort rulesets do not currently include this rule.
- **Data channel is also clean.** Each data packet starts with an opcode for the data channel (different from control), followed by an encrypted payload. Same analysis applies: theoretically fingerprintable, but no major ruleset does so reliably without high false-positive rates.

### 5.4 Multiplexing the port amplifies the evasion

Even if your VPS IP becomes the target of suspicion ("why is this IP getting so many long-lived encrypted connections?"), the fact that the *same* IP and port also serves real HTTPS to real websites provides cover. A blocklist entry for the IP would simultaneously block "legitimate" websites and service provide by the host. Heuristic rule writers have to weigh false positives, and a mixed-traffic IP is hard to confidently classify.

For high-stakes evasion, you can further muddy the waters by:
- Hosting genuinely-popular content on Traefik (CDN-like decoy services).
- Using a hostname with established history rather than a newly-registered one.
- Pointing several other unrelated DNS names at the same IP, each with different content.

---

## 6. Honest limitations

This stack is good at what it does, but it isn't magic.

- **TLS fingerprinting (JA3) of the *outer* connection** doesn't apply here because OpenVPN doesn't speak TLS on the outside; it speaks its own protocol that happens to be encrypted with a PSK. But if you reconfigure to actually wrap OpenVPN inside TLS (`stunnel` in front, or OpenVPN's experimental `tls-crypt-v2`), then JA3 fingerprinting could become a concern.
- **Active probing**: a sophisticated firewall can attempt to send crafted bytes to your endpoint and see how it responds. OpenVPN with `tls-crypt` will silently drop anything that doesn't authenticate, which itself is a signal ("this port doesn't speak TLS but also doesn't reset like nothing's listening"). A well-resourced adversary (state-level) can use this. Most enterprise firewalls won't.
- **Traffic analysis**: as noted in §5.2, packet timing and size patterns can leak protocol identity over many connections. This stack does not pad or shape traffic.
- **DNS leaks**: handled by the `push "dhcp-option DNS ..."` directives + clients that actually apply them. Linux clients without `openvpn-systemd-resolved` will leak DNS. iOS/Android/Windows official clients handle this correctly.
- **Endpoint compromise**: if the client device or the VPS itself is compromised, none of this matters. Keep both patched.

---

## 7. Comparison with alternatives

| Approach | Port flexibility | Obfuscation | Setup complexity | Real-world evasion |
|---|---|---|---|---|
| Raw OpenVPN/UDP/1194 | UDP only | None | Trivial | Fails on most CFS |
| OpenVPN/TCP/443 (this stack without tls-crypt) | 443 | None | Easy | Fails on DPI |
| **OpenVPN/TCP/443 + tls-crypt (this stack)** | **443** | **Strong PSK encryption** | **Moderate** | **Beats most CFS/DPI/IDS-IPS** |
| Wireguard | UDP only | None (visible WG handshake) | Trivial | Fails on UDP-block + DPI |
| Stunnel-wrapped OpenVPN | 443 | TLS-wrapped (real TLS) | Moderate | Beats CFS, possibly visible to JA3 |
| Shadowsocks + v2ray-plugin | 443 | Designed for active censorship | Higher | Strongest against state-level censorship |
| obfs4/meek (Tor pluggable) | Various | Highest available | Significant | Designed for adversarial networks |

This stack sits in a deliberately practical middle ground: stronger evasion than vanilla VPN setups, simpler than Tor pluggable transports, and capable of *also* hosting your real services on the same port. For most users in restrictive-but-not-state-level environments, it's the right trade-off.
