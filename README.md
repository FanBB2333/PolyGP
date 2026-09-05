<p align="center">
  <img src="docs/assets/polygp-logo.png" width="144" alt="PolyGP logo">
</p>
<h1 align="center">PolyGP — a web panel for your VPN</h1>
<p align="center">
  <a href="#getting-started">Getting started</a> ·
  <a href="#features">Features</a> ·
  <a href="#hip-identity">HIP identity</a> ·
  <a href="#contributing">Contributing</a> ·
  <a href="README_zh.md">中文</a>
</p>

## Introduction

PolyGP runs a PolyU GlobalProtect VPN connection in a Docker container and gives it a small web control panel. Sign in through the university's browser flow, complete MFA, and use the resulting SOCKS5 proxy from your applications.

The tunnel runs in userspace with `openconnect` and `ocproxy`. The default deployment requires neither `/dev/net/tun` nor `NET_ADMIN`, and does not change the host's routes. Chromium handles SAML sign-in; noVNC makes that browser available in the panel.

PolyGP is an independent project, not an official PolyU or Palo Alto Networks client. It is intended for accounts and devices you are authorized to use.

## Getting started

You need Git, Docker with Compose, and a PolyU account with access to the selected VPN service. On macOS and Windows, run Docker with Linux containers.

```sh
git clone https://github.com/FanBB2333/PolyGP.git
cd PolyGP
cp .env.example .env
# Optional: set POLYGP_NETID and POLYGP_NETPASS in .env.
docker compose up -d --build
```

Open **http://127.0.0.1:11936/**.

1. Click **Log in**. Expand **Account & service** to change the account or service.
2. Use **Use saved credentials**, or **Open login browser** to sign in manually.
3. Select a service and complete verification when the university asks for them. MFA can also be completed in the login browser.
4. When the panel says **Connected**, click **Copy address** and configure your application to use SOCKS5 at `127.0.0.1:11937`.

Only applications configured to use that proxy send traffic through the VPN. Closing the panel does not stop the container.

| Local endpoint | Purpose |
| --- | --- |
| `http://127.0.0.1:11936/` | Control panel |
| `127.0.0.1:11937` | SOCKS5 proxy |
| `http://127.0.0.1:6080/vnc.html` | Standalone login browser; the panel opens it with its connection details |

## Features

### Actions for the current login step

**Overview** shows account entry, service selection or verification when needed. Once connected, it shows the proxy address and session time remaining. Expiry uses your browser's local timezone. **Browser** gives access to the university page whenever a step needs manual interaction.

### Settings that keep your edits

**Settings** groups account details, connection options, HIP identity and runtime information in consistent cards. Drafts survive pane changes and status refreshes. Failed saves keep your input; discard restores saved values.

The service picker remembers names actually discovered during sign-in, scoped to the server and account. It also offers **Choose in browser** and manual entry. A new installation learns its available names during login; it does not ship a guessed service list.

### Session recovery and readable logs

The saved VPN session can resume after a container restart while the gateway still accepts it. **Disconnect** ends and removes that session; **Log in again** starts a fresh one. **Logs** provides search, severity and source filters, and copying of visible lines.

## HIP identity

Open **Settings → HIP identity** to manage the four device identifiers included in HIP reports:

| Field | Meaning |
| --- | --- |
| Computer name | Reported device name, up to 15 characters |
| Machine GUID | Device UUID |
| Adapter GUID | Network adapter UUID |
| Adapter MAC | Network adapter address |

You can edit these fields, **Import file**, **Export JSON**, or **Generate new identity**. Import and generation fill the form first; click **Save HIP identity** to persist the result. They never change your identity merely by opening a file or generating a candidate.

- Import accepts a PolyGP identity JSON file or `hipreport.conf`, up to 64 KB. Only the four identity fields are read; imported shell commands are never executed.
- Export contains the displayed values, including unsaved edits. It includes no account password or VPN session cookie.
- Saving updates the private HIP configuration on the `polygp-hip` volume and preserves other HIP settings. It survives container recreation and `.env` reloads.
- A running VPN session keeps its identity, including periodic HIP checks and restart recovery. Saved changes take effect on the **next fresh login**. Use **Log in again** when ready; this briefly interrupts applications using the proxy.
- Missing or invalid fields, all-zero UUIDs and invalid MAC addresses are rejected on save. Incomplete existing configurations are shown with a repair message and are not silently changed. Reusing an exported identity or copying a HIP volume deliberately reuses those identifiers.

First boot generates a private identity. If generation fails, the panel remains available for repair and the report script refuses to use the bundled example as a fallback. For native use, generate a configuration with `python3 hip/gen-hipreport-conf.py` before connecting.

The identity editor changes device identifiers only. Report structure and other HIP fields remain in `hip/hipreport.xml.tmpl` and the private configuration. See [HIP management notes](docs/hip-identity.md) for the file format and implementation details.

## Configuration

Start with [.env.example](.env.example); [compose.yml](compose.yml) lists deployment defaults.

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORTAL` / `SAML_ENDPOINT` | `researchvpn.polyu.edu.hk` / `gateway` | VPN server and SAML entry point |
| `CONTROL_PORT` / `SOCKS_PORT` / `VNC_PORT` | `11936` / `11937` / `6080` | Published service ports |
| `CONTROL_BIND` / `SOCKS_BIND` / `VNC_BIND` | `127.0.0.1` | Interfaces on which ports are published |
| `POLYGP_NETID` / `POLYGP_NETPASS` | Empty | Optional saved credentials |
| `POLYGP_FILL_MODE` | `auto` in the example | `auto`, `manual`, or `off`; auto waits for a click in the login browser |
| `POLYGP_VPN_CHOICE` | `research` in the example | Service text to select automatically; empty means select in the browser |
| `CONTROL_TOKEN` | Empty | Require `?token=...` when opening the panel |
| `VNC_PASSWORD` | Generated at startup | Optional fixed VNC password; VNC uses at most 8 characters |
| `LOGIN_TIMEOUT` / `RECONNECT_TIMEOUT` | `600` / `86400` | Login and transport retry windows, in seconds |
| `POLYGP_AUTO_RELOGIN` / `POLYGP_RESUME` | `on` / `on` | Automatic fresh login after session loss / saved-session recovery |
| `AUTO_LOGIN` | `0` | Start a fresh login immediately at boot when set to `1` |

**Account and connection settings** saved in the panel last until restart or `.env` reload. Edit `.env` to keep those defaults. **HIP identity** has its own permanent save. Empty password fields retain the existing password.

For access from another machine, publish the required ports on a reachable host interface and use that host's address. Set `CONTROL_TOKEN` when exposing the panel beyond localhost; the panel can use saved credentials and open the login browser. The `polygp-session` volume contains a reusable session cookie. Private `.env`, HIP configuration and exported identity files are excluded from normal Git tracking and Docker build context.

## Development

The panel can be previewed without a VPN or university login:

```sh
python3 scripts/preview_panel.py
# Open http://127.0.0.1:11938/
python3 -m unittest discover -s tests
```

The preview keeps its settings and HIP identity in memory. `/mock?state=awaiting-login&stage=code` shows verification, while `/mock?state=connected&fail_action=hip` makes the next HIP save fail. Use `state=idle`, `failed`, `reconnecting` or `unavailable` for other states. Mock values are examples, not actual service availability.

| File | Responsibility |
| --- | --- |
| `autologin/panel.html` | Shared frontend for the preview and container |
| `autologin/control.py` | HTTP API, settings and VPN lifecycle |
| `autologin/gp_saml_login.py` | SAML, MFA and openconnect handoff |
| `hip/hip_identity.py` | Identity validation, import, generation and atomic persistence |
| `hip/polyu-hipreport.sh` | HIP report rendering; POSIX shell |
| `scripts/entrypoint.sh` | Container services and initial identity generation |

UI-only changes can be copied to a running container without restarting the tunnel:

```sh
docker compose cp autologin/panel.html polygp:/opt/polygp/autologin/panel.html
```

Use `docker compose up -d --build` for backend changes and to include updates in future containers. A restart briefly interrupts the proxy during session recovery. [Panel design notes](docs/panel-ux.md) describe possible next improvements; [the logo design brief](docs/logo-design.md) records the visual design and image-generation prompts.

## Contributing

Bug reports and focused improvements are welcome. Describe the steps to reproduce, expected behavior, relevant platform and sanitized logs. Avoid including credentials, cookies or private device identifiers. For code changes, explain the behavior change, run the relevant tests and include a screenshot for visual changes. Keep English and Chinese documentation in sync.

## License

[MIT](LICENSE). Bundled dependencies retain their own licenses. The project logo was generated for PolyGP; its design brief and prompts are included in this repository. No jj or university artwork is included.
