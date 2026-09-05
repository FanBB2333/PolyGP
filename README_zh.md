# PolyGP

通过网页管理的 PolyU GlobalProtect VPN 容器。`openconnect` 与 `ocproxy` 在用户空间运行，提供 SOCKS5 代理；Chromium 和 noVNC 用于完成学校的登录认证。

> English: [README.md](README.md)。仅用于你有权使用的设备和账号。

## 快速开始

安装支持 Compose 的 Docker，然后执行：

```sh
cp .env.example .env
# 可选：在 .env 中填写 POLYGP_NETID、POLYGP_NETPASS。
docker compose up -d --build
```

打开 **http://127.0.0.1:11936/**。

1. 点击 **Log in**。需要修改账号或服务时，展开 **Account & service**。
2. 点击 **Use saved credentials** 使用已保存账号，或通过 **Open login browser** 手动登录。学校要求选择 VPN 服务时，网页会显示选择入口。
3. 出现验证码输入框后再填写验证码，也可以在登录浏览器中完成 MFA。
4. 状态变为 **Connected** 后，点击 **Copy address**，将代理软件设为 SOCKS5，地址为 `127.0.0.1:11937`。

只有配置了该代理的应用才会通过 VPN 访问网络。默认容器不需要 `/dev/net/tun`、`NET_ADMIN`，也不会修改宿主机路由。

## 日常操作

- **Overview**：登录时显示当前步骤，连接后显示代理地址、剩余时间。到期时间使用你浏览器的本地时区。
- **Browser**：学校登录页面；可直接返回 Overview 继续填写验证码或查看连接。
- **Logs**：搜索、按级别筛选、复制可见日志；来源筛选位于 **More filters**。
- **Settings**：常用账号和服务选项直接显示，服务器和超时配置折叠在 **Connection** 中。切换页面、自动刷新状态都会保留未保存内容；**Save changes** 保存，**Discard** 恢复服务器最后报告的值。
- **Disconnect**：结束会话。**Log in again**：结束当前会话并重新登录。两者执行前都会说明连接将中断；**Cancel login** 只取消正在进行的登录。

网页保存的设置通常从下次登录开始生效，容器重启或重新加载 `.env` 后会被替换。VPN 服务选择也可以更新正在进行的登录。服务选择页出现的名称会按服务器和账号保存，容器重启后仍可使用；此前已经丢失的选项会在下次登录时重新收集。选择 **Choose in browser** 可在学校页面中选择，**Enter another service…** 可手动输入准确名称。需要永久保存时，修改宿主机的 `.env` 文件。密码留空会保留已有密码。

关闭网页不会停止容器。默认情况下，会话保存在 `polygp-session` 卷中，容器重启后会尝试恢复。点击 Disconnect 会结束并移除会话。设置 `POLYGP_RESUME=off` 可关闭会话保存与恢复。

## 配置

完整选项见 [.env.example](.env.example) 和 [compose.yml](compose.yml)。

| 变量 | 默认值 | 用途 |
| --- | --- | --- |
| `PORTAL` | `researchvpn.polyu.edu.hk` | VPN 服务器地址 |
| `SAML_ENDPOINT` | `gateway` | `gateway` 或 `portal` 认证入口 |
| `CONTROL_PORT` / `SOCKS_PORT` / `VNC_PORT` | `11936` / `11937` / `6080` | 面板、代理、远程浏览器端口 |
| `CONTROL_BIND` / `SOCKS_BIND` / `VNC_BIND` | `127.0.0.1` | 宿主机发布端口的接口地址 |
| `CONTROL_TOKEN` | 空 | 要求面板请求附带 `?token=...` |
| `POLYGP_NETID` / `POLYGP_NETPASS` | 空 | 可选的已保存账号 |
| `POLYGP_FILL_MODE` | `auto` | `auto`、`manual`、`off`；auto 等待登录页面内的一次点击 |
| `POLYGP_VPN_CHOICE` | 示例配置为 `research` | 自动选择的服务文字；留空可在浏览器中选择 |
| `LOGIN_TIMEOUT` | `600` | 允许完成登录的秒数 |
| `RECONNECT_TIMEOUT` | `86400` | 连接中断后重试的秒数 |
| `POLYGP_AUTO_RELOGIN` | `on` | 会话意外结束后发起新登录 |
| `POLYGP_RESUME` | `on` | 保存会话，并在重启后恢复 |
| `AUTO_LOGIN` | `0` | 设为 `1` 时启动即发起新登录 |
| `VNC_SCREEN` | `1600x900x24` | 远程浏览器的屏幕尺寸 |

从其他机器访问时，需要将相应端口发布到可访问的宿主机接口。代理软件填写该宿主机地址；面板也会根据你打开的主机生成代理地址和浏览器链接。面板对他人可访问时应设置 `CONTROL_TOKEN`；远程浏览器另有 VNC 密码。

## HIP 脚本

HIP 生成拆成了逻辑、结构、取值三部分:

| 文件 | 作用 |
|------|------|
| `hip/polyu-hipreport.sh` | openconnect 调用的脚本(`--hip` / `--csd-wrapper`):解析会话参数、载入配置、填充模板 |
| `hip/hipreport.xml.tmpl` | 报告本体,含 `@NAME@` 占位符 |
| `hip/hipreport.conf` | 本机的取值——**已 gitignore** |
| `hip/hipreport.conf.example` | 随仓库提交的兜底配置,没有 `hipreport.conf` 时使用 |

运行时 openconnect 传入 `--cookie/--client-ip/--md5/--client-os/--client-version/--host-id`,这些**优先于配置**,配置只提供 fallback。用户名优先从 portal cookie 里取。病毒定义日期自动打成当天,所以 anti-malware 块无需手动维护就一直是"近期"。

换成你自己的身份:`cp hip/hipreport.conf.example hip/hipreport.conf` 后编辑即可。路径可用 `$POLYGP_HIP_CONF` / `$POLYGP_HIP_TEMPLATE` 覆盖。

脚本用 POSIX `sh`(dash) 编写(openconnect 以 `/bin/sh` 调用),勿引入 bash 专有语法。若某天 PolyU 收紧策略导致 HIP 被拒,用一台能连的真实 Windows 客户端导出 `pan_gp_hrpt.xml`,据此更新 `hipreport.xml.tmpl`(记得把占位符补回去),或只改配置里的 anti-malware 取值。

## 项目结构

| 文件 | 职责 |
| --- | --- |
| `autologin/control.py` | HTTP 接口、设置、VPN 生命周期 |
| `autologin/panel.html` | 面板 HTML、CSS、JavaScript；每次请求页面时读取 |
| `autologin/gp_saml_login.py` | SAML 登录、MFA 状态、openconnect 认证 |
| `scripts/entrypoint.sh` | 虚拟屏幕、noVNC 和服务启动 |
| `hip/polyu-hipreport.sh` | 根据模板和机器配置生成 HIP 报告 |
| `hip/gen-hipreport-conf.py` | 生成保存在 `polygp-hip` 卷中的机器标识 |
| `scripts/preview_panel.py` | 使用模拟状态的本地界面预览 |

HIP 配置和会话使用独立的数据卷保存。`.env`、生成的机器标识和登录凭据不应提交到 Git。

## 修改和验证界面

```sh
python3 scripts/preview_panel.py
# 打开 http://127.0.0.1:11938/
python3 -m unittest discover -s tests
```

预览不会访问学校登录页，也不会操作真实 VPN。通过 `/mock?state=idle`、`connected`、`reconnecting`、`failed`、`unavailable` 切换状态。使用 `/mock?state=awaiting-login&stage=code` 固定在验证码步骤：`000000` 会被拒绝，其他验证码会完成模拟登录。`stage=credentials` 和 `stage=choice` 对应账号、服务步骤。`/mock?state=connected&fail_action=save` 会让下一次保存失败，用于检查输入是否保留。

编辑 `autologin/panel.html` 后刷新预览即可。已经采用独立模板的容器可以直接更新界面，无需中断 VPN：

```sh
docker compose cp autologin/panel.html polygp:/opt/polygp/autologin/panel.html
```

重新构建镜像后，未来创建的容器也会包含修改。Python 服务修改需要执行 `docker compose up -d --build`；服务重启会在恢复会话期间短暂中断代理连接。

设计决策和后续方向见 [面板改进说明](docs/panel-ux.md)。

## 许可证

MIT，见 [LICENSE](LICENSE)。镜像内的 openconnect、ocproxy、Chromium、Playwright、noVNC 分别遵循各自许可证。
