# PolyGP

Connect to **PolyU StaffVPN (GlobalProtect) from a plain Linux container** — no official Windows client required. A HIP report script reverse-engineered from a real Windows client lets a Linux `gpclient` pass PolyU's HIP (Host Information Profile) check. Built on a minimal Ubuntu image + [yuezk/GlobalProtect-openconnect](https://github.com/yuezk/GlobalProtect-openconnect)'s `gpclient`.

> 中文文档见 [README_zh.md](README_zh.md)。

## How it works

PolyU's GlobalProtect gateway requires a HIP report. In practice its policy **only strictly checks the `anti-malware` category** (Windows Defender present, real-time protection on, recent virus definitions); `disk-encryption`, `patch-management` etc. pass even when non-compliant. A stock Linux `gpclient` is rejected because the Linux branch of its built-in HIP template lacks anti-malware info.

This project ships `hip/polyu-hipreport.sh`, which hardcodes the anti-malware category after a real, already-accepted Windows host's HIP report (Windows Defender + real-time protection + today's definition date) and keeps the other categories as compliant stubs, so a Linux `gpclient` gets through.

> For connecting your own, authorized devices with an unofficial Linux client only. Follow PolyU's Acceptable Use Policy.

## Quick start

Prerequisites: a Linux (or WSL2) host with Docker and `/dev/net/tun` available.

```bash
git clone git@github.com:FanBB2333/PolyGP.git
cd PolyGP
cp .env.example .env          # set GP_USER etc.
docker compose run --rm polygp
```

The image builds on first run and starts the control panel without opening a
SAML login request. Open `http://127.0.0.1:11936/`, then click **Log in** when
you are ready, or submit an MFA code there to start a fresh request immediately.
This keeps the short-lived SAML URL from expiring while the container is idle.

## Authentication (SAML only)

`gpclient` runs in `--browser remote` mode: the container prints a URL like

```
http://<IP>:<port>/<uuid>
```

Open it in a browser → complete PolyU ADFS login + phone MFA → paste the returned `globalprotectcallback:...` string back into the terminal.

PolyU uses **two-stage** SAML (portal + gateway), so you authenticate **twice** (the second time is instant via ADFS SSO). A transient `status=512 ... Invalid username or password` in between is **normal** — ignore it. Once done, `gpclient` submits the bundled HIP and builds the tunnel; `HIP report submitted successfully` and `Connected to VPN` mean success.

### Can't open that URL?

The auth server binds whatever IP the container would use to reach the internet, so where you can open the URL depends on your setup:

- **Host has a desktop**: open the printed URL directly in the host's browser (`localhost` or the host LAN IP both work).
- **Host is remote but on your Tailnet** *(recommended)*: PolyGP auto-detects a [Tailscale](https://tailscale.com) interface (`100.64.0.0/10`) and pins the auth server to that IP, so the printed `http://100.x.y.z:<port>/<uuid>` URL is reachable **as-is from any device on your tailnet** — open it in your laptop's browser, no tunnel or proxy needed. You'll see `auth server will bind tailscale IP ...` in the banner when this kicks in. Toggle with `BIND_TAILSCALE` (see *Configuration*).

  <sup>Mechanism: `gpauth` picks its bind IP by opening a UDP socket to `1.1.1.1` and reading the local source address. The entrypoint adds a `1.1.1.1/32` route via the tailscale interface, so that source address — and thus the auth server — becomes the tailscale IP. The route is removed on exit.</sup>
- **No Tailscale**: fall back to a SOCKS tunnel from your own machine and route a browser through it:

  ```bash
  ssh -N -D 1080 <your-server>
  # then a browser via that proxy, e.g.:
  #   chrome --proxy-server="socks5://127.0.0.1:1080" --user-data-dir=/tmp/polygp
  ```

  Open the container's URL in that browser to finish auth.

## Using the tunnel

Under host networking the tunnel lives in the **host** namespace: once connected, both host and container reach PolyU's intranet (`10.21.0.0/16` etc. via `tun0`), e.g. `ssh someone@10.21.4.125`. To keep the tunnel container-only (no host route changes), see *Advanced: bridge mode* below.

## Disconnect / reconnect

- **Disconnect**: `Ctrl+C` in the login terminal, or `docker compose exec polygp gpclient disconnect`.
- **Stay connected**: `docker compose run` is **foreground**; closing the terminal drops the tunnel. Run it inside `tmux`/`screen` to keep it up.
- **Reconnect**: `docker compose run --rm polygp` again.

## Configuration (.env)

| Variable | Default | Description |
|----------|---------|-------------|
| `PORTAL` | `staffvpn.polyu.edu.hk` | GP portal address |
| `GP_USER` | *(empty)* | Login username; prompted at connect time if empty |
| `GP_OS` | `Windows` | Spoofed client OS; must match `<os>` in the HIP report |
| `GP_CLIENT_VERSION` | `6.2.8-243` | Spoofed GP client version |
| `BIND_TAILSCALE` | `auto` | Pin the SAML auth server to the Tailscale IP so its URL opens from anywhere on your tailnet. `auto` = use it when a tailscale (`100.64/10`) interface exists; `1` = require it (warn if none); `0` = disable. |
| `AUTO_LOGIN` | `0` | Start SAML at container boot (`1`) or wait for **Log in** / an MFA code (`0`). Waiting is recommended because the SAML request expires. |

## HIP script

The HIP generator is split into logic, shape and values:

| File | Role |
|------|------|
| `hip/polyu-hipreport.sh` | the script openconnect invokes (`--hip` / `--csd-wrapper`): parses the session args, loads the config, fills the template |
| `hip/hipreport.xml.tmpl` | the report itself, with `@NAME@` placeholders |
| `hip/gen-hipreport-conf.py` | mints a per-machine identity (Windows-style name, GUIDs, adapter MAC) into `hipreport.conf` |
| `hip/hipreport.conf` | this machine's values — **gitignored**, generated |
| `hip/hipreport.conf.example` | committed reference: the anti-malware / OS block, and the identity fallback |

At runtime openconnect passes `--cookie/--client-ip/--md5/--client-os/--client-version/--host-id`; those win over the config, which supplies the fallbacks. The user name is taken from the portal cookie when present. The virus-definition date is stamped to today automatically, so the anti-malware block stays "recent" without edits.

**Per-machine identity.** The HIP report claims a Windows machine's name, machine GUID and adapter GUID/MAC. So a shared image or repo does not carry one person's identity — and so every user does not report the *same* machine — these are generated, not shipped: `.dockerignore` keeps `hipreport.conf` out of the build, and the container mints a fresh identity on first boot, persisted on the `polygp-hip` volume (stable across recreation). Only the anti-malware / OS block, which PolyU validates, is copied verbatim from `hipreport.conf.example`.

**Keeping an existing identity.** If you already have a working `hip/hipreport.conf` (from an earlier setup, or generated by hand), seed the volume with it instead of letting the container mint a new one — do this before the first start, since generation only happens when the file is absent:

```sh
docker compose create                     # creates the volume without starting
docker run --rm --user root \
  -v polygp_polygp-hip:/dst -v "$PWD/hip":/src:ro \
  --entrypoint sh polygp:latest -c \
  'cp /src/hipreport.conf /dst/ && chown 1000:1000 /dst/hipreport.conf'
docker compose up -d
```

Running natively (no container): generate yours once with `python3 hip/gen-hipreport-conf.py` (`--force` to re-mint, `--print` to preview, `--netid <id>` to set the fallback user name). Without it the script falls back to `hipreport.conf.example`. Override the paths with `$POLYGP_HIP_CONF` / `$POLYGP_HIP_TEMPLATE`.

The script is POSIX `sh` (dash) because openconnect invokes it via `/bin/sh` — do not introduce bash-only syntax. If PolyU tightens policy and HIP is rejected, export `pan_gp_hrpt.xml` from a working real Windows client and use it to update `hipreport.xml.tmpl` (re-inserting the placeholders) or just the anti-malware values in the config.

## gpclient version

The image installs the **current** version from the yuezk PPA. This project was verified on **2.5.4**; 2.6.x is API-compatible. To pin:

```bash
docker compose build --build-arg GP_PIN=2.5.4-ppa2~ubuntu24.04
```

(The PPA usually keeps only the latest version; older ones may need a `.deb` from the Launchpad archive.)

> `gpclient` ≥ 2.6 refuses to run its `gpauth` browser as root, so the container runs as the non-root `ubuntu` user and `sudo`s only for the tun device and the tailscale route. This is wired into the image and entrypoint — no action needed.

## Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `unsafe legacy renegotiation disabled` | Legacy TLS server; `--fix-openssl` is already applied. |
| `arithmetic expression: expecting EOF` | HIP script run by a non-dash shell; this script is POSIX-clean, keep it so. |
| `status=512 Invalid username or password` | Normal portal→gateway two-stage transition; ignore. |
| Browser can't open the auth URL | See *Can't open that URL?* — Tailscale direct-connect (default) or a SOCKS tunnel. |
| `/dev/net/tun` missing | Load the module on the host: `sudo modprobe tun`. |

## Advanced: bridge mode (isolate the tunnel in the container)

Remove `network_mode: host` from `compose.yml`, map the auth-server port and run an in-container SOCKS proxy so the tunnel stays container-only and can serve other machines as a proxy. See the comments at the bottom of `compose.yml`.

## License

MIT (see `LICENSE`). Depends on [yuezk/GlobalProtect-openconnect](https://github.com/yuezk/GlobalProtect-openconnect).
