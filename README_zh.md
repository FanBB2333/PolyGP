# PolyGP(中文)

> English version: [README.md](README.md)

在**纯 Linux 容器**里连接 PolyU StaffVPN(GlobalProtect)——无需官方 Windows 客户端,靠内置的、逆向自真实客户端的 HIP 报告脚本通过 PolyU 的 HIP(Host Information Profile)校验。基于最小 Ubuntu 镜像 + [yuezk/GlobalProtect-openconnect](https://github.com/yuezk/GlobalProtect-openconnect) 的 `gpclient`。

## 原理

PolyU 的 GlobalProtect 网关要求客户端提交 HIP 报告,其策略**实测只强校验 `anti-malware` 分类**(必须存在 Windows Defender、实时保护开启、病毒定义近期);`disk-encryption`、`patch-management` 等分类即便不合规也放行。原生 Linux `gpclient` 因内置 HIP 模板的 Linux 分支缺少杀软信息而被网关拒绝。

本项目内置 `hip/polyu-hipreport.sh`:它把 anti-malware 分类按一台真实、已通过校验的 Windows 主机的 HIP 报告硬编码(Windows Defender + 实时保护 + 当天病毒定义日期),其余分类保留合规结构,从而让 Linux `gpclient` 顺利过关。

> 仅用于让本人有权访问的设备,以官方不支持的 Linux 客户端接入自己的 VPN;请遵守 PolyU 的可接受使用政策。

## 快速开始

前置:一台 Linux(或 WSL2)主机,装好 Docker,`/dev/net/tun` 可用。

```bash
git clone git@github.com:FanBB2333/PolyGP.git
cd PolyGP
cp .env.example .env          # 按需填 GP_USER 等
docker compose run --rm polygp
```

首次会自动 build 镜像,随后进入交互式登录。

## 认证(只需 SAML)

`gpclient` 用 `--browser remote` 模式:容器会打印一个形如

```
http://<IP>:<port>/<uuid>
```

的地址。**在浏览器打开它 → 完成 PolyU ADFS 登录 + 手机 MFA → 把浏览器给出的 `globalprotectcallback:...` 整段粘回终端。**

PolyU 是 **portal + gateway 两段式** SAML,会认证**两次**(第二次因 ADFS SSO 通常秒过)。中途出现 `status=512 ... Invalid username or password` 是切换到 gateway 认证的**正常中间态**,忽略即可。认证完成后 `gpclient` 自动提交内置 HIP、建立隧道;看到 `HIP report submitted successfully` 与 `Connected to VPN` 即成功。

### 浏览器打不开那个地址?

auth server 绑的是容器访问外网所用的那个 IP,所以在哪能打开取决于你的部署环境:

- **宿主有桌面**:直接用宿主浏览器打开打印的地址(`localhost` 或宿主局域网 IP 均可)。
- **宿主是远程、但在你的 Tailnet 内**(推荐):PolyGP 会自动探测 [Tailscale](https://tailscale.com) 接口(`100.64.0.0/10`)并把 auth server 绑到该 IP,于是打印出的 `http://100.x.y.z:<port>/<uuid>` 地址**可直接在你 tailnet 内的任意设备(如自己笔记本)的浏览器里打开**,无需任何隧道或代理。生效时 banner 会打印 `auth server will bind tailscale IP ...`。可用 `BIND_TAILSCALE` 开关(见「配置」)。

  <sup>原理:`gpauth` 通过向 `1.1.1.1` 建一个 UDP socket、读取本地源地址来决定绑哪个 IP。entrypoint 预先把 `1.1.1.1/32` 路由指向 tailscale 接口,于是该源地址(以及 auth server)就变成了 tailscale IP;退出时自动删除该路由。</sup>
- **没有 Tailscale**:退回到从你自己电脑开一条 SOCKS 隧道、让浏览器走它:

  ```bash
  ssh -N -D 1080 <你的服务器>
  # 另开一个走该代理的浏览器,例如:
  #   chrome --proxy-server="socks5://127.0.0.1:1080" --user-data-dir=/tmp/polygp
  ```

  然后在这个浏览器里打开容器打印的地址完成认证。

## 使用隧道

`host` 网络模式下隧道建在**宿主**命名空间:连上后宿主与容器都能访问 PolyU 内网(`10.21.0.0/16` 等经 `tun0`),例如 `ssh someone@10.21.4.125`。想让隧道只在容器内、不改宿主路由,见文末「进阶:bridge 模式」。

## 断开 / 重连

- **断开**:登录终端按 `Ctrl+C`,或 `docker compose exec polygp gpclient disconnect`。
- **保持连接**:`docker compose run` 是**前台**的,关终端会断。要长期挂着,在 `tmux`/`screen` 里跑。
- **重连**:再次 `docker compose run --rm polygp`。

## 配置(.env)

| 变量 | 默认 | 说明 |
|------|------|------|
| `PORTAL` | `staffvpn.polyu.edu.hk` | GP 门户地址 |
| `GP_USER` | *(空)* | 登录用户名;留空则连接时由门户提示 |
| `GP_OS` | `Windows` | 伪装的客户端 OS,须与 HIP 里的 `<os>` 一致 |
| `GP_CLIENT_VERSION` | `6.2.8-243` | 伪装的 GP 客户端版本 |
| `BIND_TAILSCALE` | `auto` | 把 SAML auth server 绑到 Tailscale IP,使其地址能从 tailnet 内任意设备打开。`auto` = 探测到 tailscale(`100.64/10`)接口时启用;`1` = 强制(没有则告警);`0` = 关闭。 |

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

## gpclient 版本

镜像默认从 yuezk PPA 装**当前版本**。本项目验证于 **2.5.4**;2.6.x 接口兼容。固定版本:

```bash
docker compose build --build-arg GP_PIN=2.5.4-ppa2~ubuntu24.04
```

(PPA 通常只保留最新版,旧版可能需从 Launchpad 存档取 `.deb`。)

> `gpclient` ≥ 2.6 拒绝以 root 运行其 `gpauth` 浏览器,所以容器以非 root 的 `ubuntu` 用户运行,仅在建 tun 设备与加 tailscale 路由时 `sudo`。这些已内建在镜像与 entrypoint 里,无需额外操作。

## 故障排查

| 现象 | 原因 / 解决 |
|------|------|
| `unsafe legacy renegotiation disabled` | 门户是老 TLS 服务器;已默认加 `--fix-openssl`。 |
| `arithmetic expression: expecting EOF` | HIP 脚本被非 dash 的 shell 跑;本项目脚本已 POSIX 化,勿改坏。 |
| `status=512 Invalid username or password` | portal→gateway 两段认证的正常中间态,忽略。 |
| 浏览器打不开 auth 地址 | 见「浏览器打不开那个地址?」——Tailscale 直连(默认)或 SOCKS 隧道。 |
| `/dev/net/tun` 不存在 | 宿主需加载 tun 模块:`sudo modprobe tun`。 |

## 进阶:bridge 模式(隧道隔离在容器内)

去掉 `compose.yml` 里的 `network_mode: host`,改用端口映射把 auth server 与容器内的 SOCKS 代理暴露出来,从而让隧道只在容器内、并作为代理供其他机器使用。要点见 `compose.yml` 底部注释。

## 许可

MIT(见 `LICENSE`)。依赖 [yuezk/GlobalProtect-openconnect](https://github.com/yuezk/GlobalProtect-openconnect)。
