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

容器用 `network_mode: host`,auth server 绑在**宿主**的 IP 上:

- **宿主有桌面**:直接用宿主浏览器打开打印的地址(`localhost` 或宿主局域网 IP 均可)。
- **宿主是远程 / 无桌面服务器**:在你自己的电脑上开一条 SOCKS 隧道,让浏览器走它:

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

## HIP 脚本

`hip/polyu-hipreport.sh` 是 openconnect 的 HIP 生成脚本(经 `gpclient --hip <script>` 调用)。运行时 `gpclient` 传入 `--cookie/--client-ip/--md5/--client-os/--client-version` 等,脚本据此填充动态字段,anti-malware 块按标准答案硬编码、病毒定义日期自动打成当天。用 POSIX `sh`(dash) 编写(openconnect 以 `/bin/sh` 调用),勿引入 bash 专有语法。若某天 PolyU 收紧策略导致 HIP 被拒,用一台能连的真实 Windows 客户端导出 `pan_gp_hrpt.xml`,据此更新脚本里的 anti-malware 块即可。

## gpclient 版本

镜像默认从 yuezk PPA 装**当前版本**。本项目验证于 **2.5.4**;2.6.x 接口兼容。固定版本:

```bash
docker compose build --build-arg GP_PIN=2.5.4-ppa2~ubuntu24.04
```

(PPA 通常只保留最新版,旧版可能需从 Launchpad 存档取 `.deb`。)

## 故障排查

| 现象 | 原因 / 解决 |
|------|------|
| `unsafe legacy renegotiation disabled` | 门户是老 TLS 服务器;已默认加 `--fix-openssl`。 |
| `arithmetic expression: expecting EOF` | HIP 脚本被非 dash 的 shell 跑;本项目脚本已 POSIX 化,勿改坏。 |
| `status=512 Invalid username or password` | portal→gateway 两段认证的正常中间态,忽略。 |
| 浏览器打不开 auth 地址 | 见「认证」一节的 SOCKS 方案。 |
| `/dev/net/tun` 不存在 | 宿主需加载 tun 模块:`sudo modprobe tun`。 |

## 进阶:bridge 模式(隧道隔离在容器内)

去掉 `compose.yml` 里的 `network_mode: host`,改用端口映射把 auth server 与容器内的 SOCKS 代理暴露出来,从而让隧道只在容器内、并作为代理供其他机器使用。要点见 `compose.yml` 底部注释。

## 许可

MIT(见 `LICENSE`)。依赖 [yuezk/GlobalProtect-openconnect](https://github.com/yuezk/GlobalProtect-openconnect)。
