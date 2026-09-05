<p align="center">
  <img src="docs/assets/polygp-logo.png" width="144" alt="PolyGP 标志">
</p>
<h1 align="center">PolyGP — 通过网页管理 VPN</h1>
<p align="center">
  <a href="#快速开始">快速开始</a> ·
  <a href="#功能">功能</a> ·
  <a href="#hip-标识">HIP 标识</a> ·
  <a href="#参与贡献">参与贡献</a> ·
  <a href="README.md">English</a>
</p>

## 简介

PolyGP 在 Docker 容器中运行 PolyU GlobalProtect VPN，并提供简洁的网页控制面板。你可以在网页中完成学校登录和 MFA，再让应用通过 SOCKS5 代理访问 VPN。

隧道由 `openconnect` 与 `ocproxy` 在用户空间运行。默认部署不需要 `/dev/net/tun` 或 `NET_ADMIN`，也不会修改宿主机路由。Chromium 处理 SAML 登录，noVNC 将该浏览器显示在面板中。

PolyGP 是独立项目，并非 PolyU 或 Palo Alto Networks 的官方客户端。请用于你有权使用的账号和设备。

## 快速开始

需要 Git、支持 Compose 的 Docker，以及有权使用所选 VPN 服务的 PolyU 账号。在 macOS 和 Windows 上，请使用 Linux 容器。

```sh
git clone https://github.com/FanBB2333/PolyGP.git
cd PolyGP
cp .env.example .env
# 可选：在 .env 中填写 POLYGP_NETID 和 POLYGP_NETPASS。
docker compose up -d --build
```

打开 **http://127.0.0.1:11936/**。

1. 点击 **Log in**。需要修改账号或服务时，展开 **Account & service**。
2. 点击 **Use saved credentials** 使用已保存账号，或通过 **Open login browser** 手动登录。
3. 学校要求时再选择服务、完成验证。MFA 也可以在登录浏览器中完成。
4. 面板显示 **Connected** 后，点击 **Copy address**，将应用的代理设置为 SOCKS5，地址为 `127.0.0.1:11937`。

只有配置了该代理的应用才会通过 VPN 访问网络。关闭面板不会停止容器。

| 本地入口 | 用途 |
| --- | --- |
| `http://127.0.0.1:11936/` | 控制面板 |
| `127.0.0.1:11937` | SOCKS5 代理 |
| `http://127.0.0.1:6080/vnc.html` | 独立登录浏览器；从面板打开会自动带入连接信息 |

## 功能

### 根据登录步骤显示操作

**Overview** 在需要时显示账号、服务选择或验证步骤；连接后显示代理地址和会话剩余时间。到期时间使用你浏览器的本地时区。遇到需要手动处理的页面时，可随时打开 **Browser**。

### 保留编辑内容的设置页

**Settings** 使用一致的卡片组织账号、连接、HIP 标识和运行信息。切换页面、自动刷新状态时保留草稿；保存失败保留输入，点击放弃则恢复已保存的值。

服务选择器记录登录时实际出现过的服务名称，按服务器和账号保存，同时提供 **Choose in browser** 和手动输入。新安装需要在登录时收集可用名称，不会预置未经确认的服务列表。

### 会话恢复与日志查看

容器重启后，只要网关仍接受已保存的会话，就可以恢复连接。**Disconnect** 结束并删除会话，**Log in again** 发起全新登录。**Logs** 支持搜索、按级别和来源筛选，以及复制可见日志。

## HIP 标识

打开 **Settings → HIP identity**，管理 HIP 报告中的四个设备标识：

| 字段 | 含义 |
| --- | --- |
| Computer name | 报告中的设备名称，最多 15 个字符 |
| Machine GUID | 设备 UUID |
| Adapter GUID | 网卡 UUID |
| Adapter MAC | 网卡地址 |

可以直接编辑，也可以点击 **Import file** 导入、**Export JSON** 导出，或用 **Generate new identity** 重新随机生成。导入和生成只填写表单；点击 **Save HIP identity** 后才会保存，不会因为打开文件或生成候选值就更换标识。

- 导入支持 PolyGP 标识 JSON 和 `hipreport.conf`，最大 64 KB。只读取四个标识字段，不执行导入文件中的 Shell 命令。
- 导出包含当前表单中的值，包括未保存的编辑；不包含账号密码和 VPN 会话 Cookie。
- 保存会更新 `polygp-hip` 卷中的私有 HIP 配置，保留其他 HIP 内容。容器重建或重新加载 `.env` 后仍然有效。
- 当前 VPN 会话继续使用原标识，周期性 HIP 检查和容器重启恢复也保持一致。新值在**下一次全新登录**时生效。准备切换时点击 **Log in again**；使用代理的应用会短暂断开。
- 保存时会拒绝缺失或格式错误的字段、全零 UUID 和无效 MAC。已有不完整配置会显示修复提示，不会自动改动。导入同一份导出文件、复制同一份 HIP 数据卷，会有意复用其中的标识。

首次启动会生成私有标识。生成失败时，面板仍可用于修复，报告脚本不会退回共用示例。原生运行时，应先执行 `python3 hip/gen-hipreport-conf.py` 生成配置，再进行连接。

标识编辑器只修改设备标识；报告结构和其他 HIP 字段仍由 `hip/hipreport.xml.tmpl` 与私有配置管理。文件格式和实现说明见 [HIP 标识管理说明](docs/hip-identity.md)。

## 配置

从 [.env.example](.env.example) 开始配置；[compose.yml](compose.yml) 列出了部署默认值。

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `PORTAL` / `SAML_ENDPOINT` | `researchvpn.polyu.edu.hk` / `gateway` | VPN 服务器和 SAML 入口 |
| `CONTROL_PORT` / `SOCKS_PORT` / `VNC_PORT` | `11936` / `11937` / `6080` | 发布的服务端口 |
| `CONTROL_BIND` / `SOCKS_BIND` / `VNC_BIND` | `127.0.0.1` | 端口发布到的宿主机接口 |
| `POLYGP_NETID` / `POLYGP_NETPASS` | 空 | 可选的已保存账号密码 |
| `POLYGP_FILL_MODE` | 示例为 `auto` | `auto`、`manual` 或 `off`；auto 等待登录浏览器内的一次点击 |
| `POLYGP_VPN_CHOICE` | 示例为 `research` | 自动选择的服务文字；留空表示在浏览器中选择 |
| `CONTROL_TOKEN` | 空 | 打开面板时要求提供 `?token=...` |
| `VNC_PASSWORD` | 启动时生成 | 可选的固定 VNC 密码；VNC 最多使用 8 个字符 |
| `LOGIN_TIMEOUT` / `RECONNECT_TIMEOUT` | `600` / `86400` | 登录和网络重试时限，单位为秒 |
| `POLYGP_AUTO_RELOGIN` / `POLYGP_RESUME` | `on` / `on` | 会话丢失后自动发起新登录／恢复已保存会话 |
| `AUTO_LOGIN` | `0` | 设为 `1` 时启动即发起新登录 |

面板中的**账号和连接设置**保留到容器重启或重新加载 `.env`；需要永久保存这些默认值时，编辑 `.env`。**HIP 标识**使用独立的永久保存按钮。密码输入框留空会保留已有密码。

从其他机器访问时，需要将相应端口发布到可访问的宿主机接口，并使用该宿主机地址。面板对 localhost 以外的地址开放时，请设置 `CONTROL_TOKEN`，因为面板可以使用已保存账号并打开登录浏览器。`polygp-session` 卷包含可复用的会话 Cookie。私有 `.env`、HIP 配置及默认名称的标识导出文件，均已从正常 Git 跟踪和 Docker 构建上下文中排除。

## 开发

无需连接 VPN 或登录学校账号，就能预览面板：

```sh
python3 scripts/preview_panel.py
# 打开 http://127.0.0.1:11938/
python3 -m unittest discover -s tests
```

预览中的设置和 HIP 标识只保存在内存中。`/mock?state=awaiting-login&stage=code` 显示验证码步骤，`/mock?state=connected&fail_action=hip` 让下一次 HIP 保存失败。其他状态可使用 `state=idle`、`failed`、`reconnecting` 或 `unavailable`。模拟值只用于预览，不代表实际服务列表。

| 文件 | 职责 |
| --- | --- |
| `autologin/panel.html` | 预览和容器共用的前端 |
| `autologin/control.py` | HTTP 接口、设置和 VPN 生命周期 |
| `autologin/gp_saml_login.py` | SAML、MFA 和 openconnect 认证交接 |
| `hip/hip_identity.py` | 标识校验、导入、生成和原子保存 |
| `hip/polyu-hipreport.sh` | HIP 报告生成，使用 POSIX Shell |
| `scripts/entrypoint.sh` | 容器服务与首次标识生成 |

仅修改界面时，可以直接复制到正在运行的容器，无需重启隧道：

```sh
docker compose cp autologin/panel.html polygp:/opt/polygp/autologin/panel.html
```

后端修改和未来容器的更新，使用 `docker compose up -d --build`。重启期间，代理会在恢复会话时短暂中断。[面板改进说明](docs/panel-ux.md) 记录了后续方向；[Logo 设计稿](docs/logo-design.md) 保存了设计思路和图像生成提示词。

## 参与贡献

欢迎提交问题报告和范围明确的改进。报告问题时，请提供复现步骤、预期行为、运行平台及去除敏感信息的日志，不要附带账号密码、Cookie 或私有设备标识。修改代码时，说明行为变化，运行相关测试；涉及界面时附上截图，并同步维护中英文文档。

## 许可证

[MIT](LICENSE)。镜像内依赖遵循各自的许可证。项目 Logo 为 PolyGP 生成，设计稿和提示词保存在仓库中，未使用 jj 或大学的图形素材。
