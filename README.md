# PolyGP

PolyU GlobalProtect VPN in a Docker container, managed from a web panel. The container runs `openconnect` and `ocproxy` in userspace and exposes a SOCKS5 proxy. Chromium and noVNC provide the university's sign-in page.

> 中文文档见 [README_zh.md](README_zh.md)。For devices and accounts you are authorized to use.

## Quick start

Install Docker with Compose, then:

```sh
cp .env.example .env
# Optionally set POLYGP_NETID and POLYGP_NETPASS in .env.
docker compose up -d --build
```

Open **http://127.0.0.1:11936/**.

1. Click **Log in**. Expand **Account & service** if you need to change the account or VPN service.
2. Choose **Use saved credentials**, or **Open login browser** to enter them yourself. Service options appear when the university asks you to choose one.
3. Enter the verification code when the panel asks for it, or finish MFA in the login browser.
4. When the status is **Connected**, click **Copy address** and configure your proxy app to use SOCKS5 at `127.0.0.1:11937`.

Only applications configured to use that proxy send traffic through the VPN. The default Docker setup needs no `/dev/net/tun`, `NET_ADMIN`, or changes to the host's routes.

## Everyday controls

- **Overview** shows the current login step, or the proxy address and session time remaining. Expiry is shown in your browser's local timezone.
- **Browser** opens the remote login view, with a shortcut back to the current step in Overview.
- **Logs** supports search, severity filters, and copying visible lines. Source filters are under **More filters**.
- **Settings** keeps account and service fields visible; server and timeout options are under **Connection**. Unsaved edits survive navigation between panes and status refreshes. **Save changes** applies them; **Discard** restores the last reported values.
- **Disconnect** ends the session. **Log in again** ends it and starts a fresh login. Both explain the interruption before proceeding. **Cancel login** abandons a sign-in attempt.

Saved panel settings apply to the next login and last until the container restarts or `.env` is reloaded. The service picker can also update a login in progress. Services discovered on the selection page are remembered across container restarts for the same server and account. Choose **Choose in browser** to make the selection during sign-in, or **Enter another service…** to type an exact service name. Previously lost options are learned again on the next login. Edit the host's `.env` file for permanent settings. An empty password field keeps the stored password.

The container stays running after you close the page. By default it saves the VPN session in the `polygp-session` volume and attempts to resume it after a container restart. Explicitly disconnecting ends and removes that session. Set `POLYGP_RESUME=off` to require a fresh login after every restart.

## Configuration

See [.env.example](.env.example) and [compose.yml](compose.yml) for all options.

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORTAL` | `researchvpn.polyu.edu.hk` | VPN server hostname |
| `SAML_ENDPOINT` | `gateway` | `gateway` or `portal` authentication |
| `CONTROL_PORT` / `SOCKS_PORT` / `VNC_PORT` | `11936` / `11937` / `6080` | Panel, proxy and remote browser ports |
| `CONTROL_BIND` / `SOCKS_BIND` / `VNC_BIND` | `127.0.0.1` | Host interfaces that publish those ports |
| `CONTROL_TOKEN` | empty | Require `?token=...` for panel requests |
| `POLYGP_NETID` / `POLYGP_NETPASS` | empty | Optional saved account |
| `POLYGP_FILL_MODE` | `auto` | `auto`, `manual`, or `off`; auto waits for a click inside the login browser |
| `POLYGP_VPN_CHOICE` | `research` in `.env.example` | Service text to select; empty means choose in the browser |
| `LOGIN_TIMEOUT` | `600` | Seconds allowed for sign-in |
| `RECONNECT_TIMEOUT` | `86400` | Seconds to retry an interrupted transport |
| `POLYGP_AUTO_RELOGIN` | `on` | Start another login if the VPN session ends unexpectedly |
| `POLYGP_RESUME` | `on` | Keep and resume the session after a restart |
| `AUTO_LOGIN` | `0` | Start a fresh login at boot when set to `1` |
| `VNC_SCREEN` | `1600x900x24` | Remote browser display size |

To access the panel from another machine, publish the required ports on a reachable host interface. Configure the proxy app with that host's address. The panel builds its proxy and browser links using the host you opened. Set `CONTROL_TOKEN` if the panel is accessible to others; the remote browser also has its VNC password.

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

## Project layout

| File | Purpose |
| --- | --- |
| `autologin/control.py` | HTTP API, settings and VPN lifecycle |
| `autologin/panel.html` | Panel HTML, CSS and JavaScript; read on each page request |
| `autologin/gp_saml_login.py` | SAML browser login, MFA state and openconnect handoff |
| `scripts/entrypoint.sh` | Virtual display, noVNC and service startup |
| `hip/polyu-hipreport.sh` | HIP report generation using a template and per-machine configuration |
| `hip/gen-hipreport-conf.py` | Creates the identity kept in the `polygp-hip` volume |
| `scripts/preview_panel.py` | Local UI preview with simulated connection states |

The HIP configuration and session are kept in named volumes. `.env`, generated HIP identity files and credentials do not belong in Git.

## Develop the panel

```sh
python3 scripts/preview_panel.py
# Open http://127.0.0.1:11938/
python3 -m unittest discover -s tests
```

The preview simulates actions without opening the university login page or changing your real VPN. Open `/mock?state=idle`, `connected`, `reconnecting`, `failed`, or `unavailable` to switch states. `/mock?state=awaiting-login&stage=code` holds at the code prompt; `000000` is rejected and another code completes the simulated login. Use `stage=credentials` or `stage=choice` for the other steps. `/mock?state=connected&fail_action=save` makes the next save fail so you can check draft preservation.

After editing `autologin/panel.html`, refresh the preview. On containers using the separate template, a UI-only update can be applied without interrupting the tunnel:

```sh
docker compose cp autologin/panel.html polygp:/opt/polygp/autologin/panel.html
```

Rebuild the image to include changes in future container creations. Python service changes require `docker compose up -d --build`; a service restart briefly interrupts the proxy while the saved session is resumed.

See [panel design notes](docs/panel-ux.md) for the design decisions and further improvement directions.

## License

MIT; see [LICENSE](LICENSE). The image includes openconnect, ocproxy, Chromium, Playwright and noVNC, each with its own license.
