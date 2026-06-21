# Client setup

How to install an OpenVPN client and import your `.ovpn` profile on each major platform.

## Before you start

Generate one profile per device. Don't share a single `.ovpn` across multiple devices — if one is lost or compromised, you want to revoke that one cert without disrupting the others.

On the VPS:

```bash
cd /opt/containers/openvpn

# Build per-device certs and export
for name in laptop desktop phone tablet; do
  docker compose exec openvpn easyrsa build-client-full "$name" nopass
  docker compose exec openvpn ovpn_getclient "$name" | \
    sed 's|<tls-auth>|<tls-crypt>|; s|</tls-auth>|</tls-crypt>|; /^key-direction 1$/d' \
    > "/tmp/${name}.ovpn"
done
```

The `.ovpn` file contains the client's private key and the `tls-crypt` PSK. **Treat it like a credential.** Get it directly onto the device that will use it and avoid leaving copies scattered around. Direct transfer (USB, AirDrop, local LAN) is cleanest; if you route it through email or another store-and-forward channel, just clean up the copies afterward (see the per-platform notes). When you're done, delete the copy on the VPS:

```bash
shred -u /tmp/*.ovpn
```

## Transfer methods

| Source | Destination | Recommended method |
|---|---|---|
| VPS | Linux/Mac/Windows | `scp` from the desktop |
| Desktop | Phone/tablet | USB cable, AirDrop (Apple), or local LAN file share |
| VPS | Phone/tablet directly | `magic-wormhole` for one-time encrypted P2P transfer |

Direct transfer (USB, AirDrop, local LAN share) is ideal because nothing persists anywhere in transit. Store-and-forward channels — email, cloud sync, messaging apps — are fine too as long as you delete the copies afterward (including Sent and Trash folders). The point isn't that email is forbidden; it's that you shouldn't leave a credential sitting in a mailbox or a shared drive indefinitely.

---

## Linux

### Install OpenVPN

```bash
# Debian / Ubuntu / Mint
sudo apt install -y openvpn openvpn-systemd-resolved

# Fedora / RHEL
sudo dnf install -y openvpn openvpn-systemd-resolved

# Arch
sudo pacman -S openvpn openvpn-update-systemd-resolved
```

`openvpn-systemd-resolved` is critical — without it, the DNS servers pushed by the OpenVPN server won't actually be applied to your system, and you'll either have DNS leaks or no DNS at all.

### Edit the .ovpn for systemd-resolved integration

Append these lines to your `.ovpn` file:

```
script-security 2
up /etc/openvpn/update-systemd-resolved
up-restart
down /etc/openvpn/update-systemd-resolved
down-pre
dhcp-option DOMAIN-ROUTE .
```

### Connect (one-shot, foreground)

```bash
sudo openvpn --config ~/laptop.ovpn
```

Leave that terminal open. Look for `Initialization Sequence Completed` — the tunnel is up.

### Connect (background service)

For a persistent connection that comes up at boot:

```bash
# Copy the profile to OpenVPN's config dir
sudo cp ~/laptop.ovpn /etc/openvpn/client/laptop.conf

# Enable and start
sudo systemctl enable --now openvpn-client@laptop
sudo systemctl status openvpn-client@laptop
```

### Connect via NetworkManager (GUI)

If you'd rather click than type:

```bash
sudo apt install -y network-manager-openvpn-gnome
```

Then in your network settings, "Add VPN" → "Import from file" → select your `.ovpn`. Toggle on/off from the network applet.

### Verify the tunnel

```bash
# Should show the VPS public IP, not your home IP
curl -s ifconfig.me; echo

# DNS should go through the tunnel
resolvectl status tun0

# Default route should be via tun0
ip route get 1.1.1.1
```

### Common Linux issues

- **Linux warns about `block-outside-dns`**: harmless, Windows-only directive. Ignore.
- **`--cipher is not set` warning**: cosmetic, modern OpenVPN negotiates ciphers via NCP. Ignore.
- **DNS doesn't switch**: you forgot `openvpn-systemd-resolved` or the `up`/`down` script lines in the `.ovpn`.

---

## Windows

### Install OpenVPN Connect

Download the official client from <https://openvpn.net/client/>. The community edition (`openvpn-gui`) also works, but OpenVPN Connect is more user-friendly and handles modern features cleanly.

### Import the profile

1. Transfer `windows.ovpn` to your Windows machine.
2. Open OpenVPN Connect.
3. "File" tab → drag and drop the `.ovpn`, or click "Browse" and select it.
4. Click "Connect."

### Verify

- The OpenVPN Connect window shows "Connected" with the assigned tunnel IP.
- Visit <https://ifconfig.me> in a browser — should show the VPS public IP.

### Common Windows issues

- **"DNS leak" detected**: the `block-outside-dns` directive should prevent this. If you still see leaks, your client may be ignoring it — update OpenVPN Connect to the latest version.
- **Cert errors**: you're not getting cert errors. The OpenVPN tunnel uses your CA, which OpenVPN trusts because it's embedded in the `.ovpn`. If you see errors about the *VPS hostname's* cert, you're hitting Traefik via a browser, not connecting via OpenVPN.
- **Connection drops after sleep/resume**: in OpenVPN Connect settings, enable "Reconnect on suspend/resume."

---

## macOS

### Install Tunnelblick (recommended)

Tunnelblick is the most common free OpenVPN client for macOS. Download from <https://tunnelblick.net>.

Alternatively, OpenVPN Connect from <https://openvpn.net/client/> works on macOS too — pick whichever feels nicer.

### Import the profile (Tunnelblick)

1. Transfer `laptop.ovpn` to your Mac.
2. Double-click the `.ovpn` file. Tunnelblick will offer to install it.
3. Choose "Only Me" (don't install system-wide unless you specifically want to).
4. Authenticate when prompted.
5. Click the Tunnelblick icon in the menu bar → "Connect laptop."

### Verify

```bash
# In Terminal, while connected:
curl -s ifconfig.me; echo
# Should show your VPS public IP
```

### Common macOS issues

- **"Untrusted application"** warning on first launch: System Settings → Privacy & Security → "Open Anyway."
- **DNS not switching**: Tunnelblick's "Set nameserver" option should be set to "Set nameserver" or "Set nameserver (3.0b10)" in the configuration's Settings tab.
- **Killswitch**: Tunnelblick has a "Disable network access if disconnected unexpectedly" option. Enable it if you want fail-closed behavior.

---

## Android

### Install OpenVPN for Android (recommended)

Open-source, actively maintained, and handles modern OpenVPN features. Available on F-Droid or Play Store. Look for the icon by Arne Schwabe.

Alternative: **OpenVPN Connect** (official, also fine).

### Import the profile

Transfer `phone.ovpn` to the Android device:

- **USB cable**: connect to computer, copy file to Downloads.
- **Local network**: `python3 -m http.server 8000` on your computer, browse to it from your phone, download.
- **magic-wormhole on Termux**: `pkg install magic-wormhole`, then receive.

In OpenVPN for Android:

1. Tap the import button (folder icon).
2. Browse to the `.ovpn` file and import.
3. Tap the profile to connect.

Grant the VPN permission when prompted (Android requires this for any VPN app).

### Verify

In a browser, visit <https://ifconfig.me> — should show the VPS public IP.

### Connect on demand / always-on VPN

Android has system-level "always-on VPN" and "block connections without VPN" settings:

**Settings → Network & Internet → VPN → (gear icon next to OpenVPN for Android)** → enable "Always-on VPN" and "Block connections without VPN."

This forces all device traffic through the tunnel and prevents leaks if the VPN disconnects.

### Common Android issues

- **Battery optimization kills the connection**: in app settings, exclude the OpenVPN app from battery optimization.
- **Wi-Fi to cellular transition drops the tunnel**: enable "Persistent tun" in the profile settings within the app.

---

## iOS / iPadOS

### Install OpenVPN Connect

The only viable option — Apple's restrictions prevent third-party clients from providing the same VPN integration. Get it from the App Store: <https://apps.apple.com/app/openvpn-connect/id590379981>.

### Import the profile

You can't directly download an `.ovpn` and have iOS associate it with OpenVPN Connect. Use one of:

**Option 1 — AirDrop from Mac:**

1. On your Mac, right-click `phone.ovpn` → Share → AirDrop.
2. Accept on iPhone — iOS will offer to open with OpenVPN Connect.

**Option 2 — iCloud Drive:**

1. Drop the file into iCloud Drive from a trusted device.
2. On iPhone, open the Files app, navigate to the file, tap it, "Open in OpenVPN."
3. Delete from iCloud after import.

**Option 3 — Email it to yourself:**

Perfectly workable as long as you clean up afterward. Email the `.ovpn` to yourself, open it on the iPhone, and import it into OpenVPN Connect. Then delete the message from every box it touched — Sent on the sending device, Inbox on the phone, and Trash/Deleted in both. The `.ovpn` carries the client key and the `tls-crypt` PSK, so the goal is simply to not leave a lingering copy sitting in a mailbox. If the device is ever lost, you can revoke that one cert anyway (see below), so this is about reasonable hygiene, not paranoia.

**Option 4 — Pasteboard via Universal Clipboard:**

Copy the `.ovpn` contents on your Mac, paste into a text editor on iPhone via Universal Clipboard, save the file, open with OpenVPN Connect.

### Connect

In OpenVPN Connect:

1. The imported profile appears on the home screen.
2. Toggle the slider to connect.
3. iOS will request VPN permission on first use.

### Verify

In Safari, visit <https://ifconfig.me> — should show the VPS public IP.

### Connect on demand

OpenVPN Connect → Profile settings → "Connection" → enable "Connect on demand." You can configure rules: always-on, only on cellular, only on untrusted Wi-Fi, etc.

### Common iOS issues

- **App seems to hang**: iOS sometimes silently denies VPN permission. Open Settings → General → VPN & Device Management → look for OpenVPN, ensure it has permission.
- **Cellular networks blocking the connection**: rare, but some cellular carriers block uncommon traffic patterns. Usually a non-issue with this stack's design.

---

## Revoking a client cert

If a device is lost, stolen, or you just want to retire a profile:

```bash
ssh your-vps
cd /opt/containers/openvpn

# Revoke
docker compose exec openvpn easyrsa revoke <client-name>

# Regenerate the CRL (Certificate Revocation List)
docker compose exec openvpn easyrsa gen-crl

# Restart so the new CRL takes effect
docker compose restart openvpn
```

After this, the revoked cert can no longer authenticate, even if someone has the `.ovpn` file. You don't need to touch other clients.
