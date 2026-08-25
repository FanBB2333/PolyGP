# PolyGP autologin — 免手动粘贴的 SAML 登录

PolyGP 原本的登录要人肉走完「开浏览器 → 登录 → 手输 6 位验证码 → 把
`globalprotectcallback` 整段粘回终端」。本目录提供两条替代路线,按平台和口味选一条:

- **[macOS:交互式登录 + 本地 SOCKS](#macos交互式登录--本地-socks)** — 登录仍由你本人在
  浏览器里完成,脚本负责抓认证结果并驱动 openconnect。不需要 TOTP 种子、不需要存密码、
  不改系统路由。
- **[Linux/gpclient:全自动 TOTP 方案](#linuxgpclient全自动-totp-方案)** — 连登录都不用人,
  代价是 TOTP 种子要落到本机。

## 组件

| 文件 | 作用 | 状态 |
|------|------|------|
| `mfa.py` | 从 Keychain/env 取种子,`oathtool` 生成当前 6 位码 | ✅ 已测 |
| `auth.py` | Playwright 驱动 SAML+MFA,输出 `globalprotectcallback` | ⚠️ 选择器待真机校正 |
| `connect.py` | 编排 gpclient + auth.py(Linux/gpclient 侧) | ⚠️ 待真机联调 |
| `gp_saml_login.py` | 交互式 SAML 登录 + openconnect(macOS 侧,见下) | ✅ 登录与 HIP 已实测通过 |

---

# macOS:交互式登录 + 本地 SOCKS

`gp_saml_login.py` 是另一条路线,不依赖 Docker、不依赖 gpclient,直接用 macOS 上
brew 装的 `openconnect` 配合本仓库的 HIP 脚本。登录仍由**你本人**在浏览器里完成
(NetID + 密码 + 手机 MFA),所以**不需要 TOTP 种子,也不用存密码**。

## 为什么需要它

openconnect 的 `--external-browser` **接不住 GlobalProtect 的 SAML REDIRECT 流程**
(上游 issue #446 / #672 / #829):浏览器明明已经显示 `Login Successful!`,openconnect
侧却报 `Failed to parse XML server response`。原因是 GP 把认证结果放在
**HTTP 响应头** `prelogin-cookie` / `saml-username` 里返回,普通浏览器窗口不显示这两个值,
openconnect 也没接住。

本脚本就补这一段:开一个真实 Chromium 窗口让你登录,在旁边监听响应头把这两个值抓下来,
再连同 HIP 脚本一起交给 openconnect。

## 依赖

```bash
brew install openconnect ocproxy
pip install playwright
PLAYWRIGHT_DOWNLOAD_HOST=https://cdn.npmmirror.com/binaries/playwright \
  python3 -m playwright install chromium
```

## 运行

```bash
./autologin/gp_saml_login.py          # 或 python3 autologin/gp_saml_login.py
```

会依次发生:脚本做 GP prelogin 拿到 SAML 入口 → 弹出浏览器 → **你手动登录并过 MFA** →
抓到 `prelogin-cookie` 后浏览器自动关闭 → openconnect 提交 HIP、建立连接 →
在 `127.0.0.1:11937` 提供 SOCKS5。`Ctrl+C` 断开。

默认连 `researchvpn.polyu.edu.hk`;换门户直接当位置参数传:

```bash
python3 autologin/gp_saml_login.py staffvpn.polyu.edu.hk
```

## 两种模式

| 模式 | 行为 | sudo |
|------|------|------|
| `--mode socks`(默认) | `openconnect --script-tun` + `ocproxy`,整个 TCP/IP 栈跑在用户态的 lwIP 里。**不建网卡、不改路由、不碰 DNS**,只开本地 SOCKS5 | 不需要 |
| `--mode tun` | 传统方案:建 utun 设备 + 下发 PolyU 各网段的系统路由 | 需要 |

默认选 socks 是有原因的:本机由 Surge 接管网络并启用 fake-ip,`--mode tun` 会与之冲突,
见下面「排查」。

其他常用参数:`--socks-port`(默认 11937)、`--portal`(改用 portal 端点做 SAML)、
`--print-only`(只打印 cookie 不连接)、`--browser chrome`(用已装的 Chrome 而非自带
Chromium)、`--timeout`(等待登录的秒数,默认 300)。

## 自动填充 NetID / 密码(可选)

存了凭证后,脚本会把 ADFS 表单替你填好并提交,**只剩手机上点一下 MFA**:

```bash
security add-generic-password -U -s polygp-netid   -a polygp -w '<你的NetID>'
security add-generic-password -U -s polygp-netpass -a polygp -w '<你的NetPassword>'
```

环境变量 `$POLYGP_NETID` / `$POLYGP_NETPASS` 优先级更高;`--no-fill` 可临时关掉。
没存凭证时不影响使用,只是要自己在浏览器里输入。

选择器是对着真实登录页校验过的(PolyU 用的是**经典 ADFS 页面**,不是微软 AAD):
`#userNameInput`、`#passwordInput`,提交按钮是个 `<span id="submitButton">`,
所以是点击而非表单 submit。哪天页面改版,用
`python3 -m playwright codegen "<prelogin 打出的 auth URL>"` 重新取。

> 这里只自动化「知道的东西」(密码),不碰「持有的东西」(手机),MFA 仍是真正的第二
> 因素。若想连 MFA 也自动化,那是本目录另一条路线(需要 TOTP 种子,见文末)。

## 更省事的启动方式

脚本已带可执行位,可以直接 `./autologin/gp_saml_login.py`。想在任意目录一条命令拉起,
在 `~/.zshrc` 里加:

```zsh
# 前台运行，Ctrl+C 断开
alias polygp='/Users/l1ght/repos/PolyGP/autologin/gp_saml_login.py'

# 或：丢进 tmux，关掉终端也不断
polygp() {
  tmux new-session -A -s polygp \
    '/Users/l1ght/repos/PolyGP/autologin/gp_saml_login.py; read -k1'
}
```

tmux 版本用 `tmux attach -t polygp` 回到会话看状态,`tmux kill-session -t polygp` 断开。

## 让流量走进去(Surge)

socks 模式不改系统路由,所以要由代理工具把目标流量指过去。Surge 侧加一个节点和一条规则:

```
[Proxy]
PolyU-VPN = socks5, 127.0.0.1, 11937

[Rule]
IP-CIDR,10.21.4.0/24,PolyU-VPN,no-resolve
```

两个要点:

- **规则顺序**。Surge 是**从上往下第一条匹配即生效**,不按最长前缀匹配。若配置里已有
  `IP-CIDR,10.0.0.0/8,<别的策略>`,PolyU 这条必须排在它**之前**,否则会被先吃掉。
- **别用 `DOMAIN-SUFFIX,polyu.edu.hk,PolyU-VPN`**,那会把 VPN 服务器自己的连接也塞进
  隧道,形成环路。VPN 门户域名应继续走原来能连通它的策略。

网关实际下发的 PolyU 网段包括 `158.132.0.0/16` 和一批 10.x(`10.21.0.0/16`、
`10.13`、`10.14`、`10.22.30`、`10.100` 等);按需取最小集合即可,不必全加。

## 验证

`ocproxy` 只代理 TCP 和 DNS,**ping 不通是正常的**,别用 ICMP 判断:

```bash
curl -x socks5h://127.0.0.1:11937 -sv --max-time 10 http://10.21.4.125 2>&1 | head
ssh -o ProxyCommand='nc -X 5 -x 127.0.0.1:11937 %h %p' someone@10.21.4.125
```

## 排查

| 现象 | 原因 / 解决 |
|------|------|
| `Failed to parse XML server response`(浏览器却显示 Login Successful) | openconnect `--external-browser` 的已知缺陷,正是本脚本要绕开的;别再用那条路 |
| `Dead Peer Detection detected dead peer!` 后无限重连 | 用了 `--mode tun` 且系统开着 fake-ip 代理:openconnect 给"VPN 服务器自身"加的绕行路由指向物理网关,而 fake-ip 在那儿是黑洞,隧道自己把自己掐断。改用默认的 socks 模式 |
| 断开后该域名整个访问不了 | 上一条的残留路由还在。`sudo pkill -f 'openconnect --protocol=gp'`,再确认 `netstat -rn -f inet \| grep utun` 已清空 |
| ` is not a recognized network service.` | `--mode tun` 下 vpnc-script 没能把 utun 映射到 macOS 网络服务、DNS 没设成;socks 模式不涉及 |
| `Temporary failure in name resolution` | Docker 或宿主 DNS 的瞬时故障；prelogin 会按 1/2/4/8 秒间隔最多发起 5 次请求，无需重新点击 Login |
| 超时没抓到 cookie | MFA 太慢就加 `--timeout 600`(注意服务器侧 SAML 请求本身只有 600 秒有效期);想看浏览器停在哪一步用 `--keep-open` |

---

# Linux/gpclient:全自动 TOTP 方案

`mfa.py` / `auth.py` / `connect.py` 这套连登录都不用人。核心机制:**Microsoft
Authenticator 的 6 位验证码是标准 RFC 6238 TOTP**,只要拿到注册时的种子(seed),
`oathtool` 就能算出与手机一致的码,无需手机。

```
gpclient --browser remote  ──打印 auth URL──▶  connect.py 捕获
                                                    │
                                    auth.py(Playwright 无头浏览器)
                                    填 NetID/NetPass → 选「use a verification
                                    code」→ 填 mfa.py 生成的码 → 截获
                                    globalprotectcallback:...
                                                    │
                            ──回喂 gpclient stdin──▶ gpclient 提交 HIP、建隧道
```

gpclient 仍负责两段式 SAML、HIP 提交和隧道;这套只替掉「那个人」。

## 依赖

```bash
brew install oath-toolkit                 # oathtool(macOS)
pip install playwright                     # Linux 侧同理
PLAYWRIGHT_DOWNLOAD_HOST=https://cdn.npmmirror.com/binaries/playwright \
  python3 -m playwright install chromium
```

## 前置:拿到微软账号的 TOTP 种子(整套的命门)

登录必须能走「use a verification code」(已确认 PolyU 提供),且你需要一份种子:

1. 优先试 **`polyu.edu.hk/mfasetup`** → 添加验证器 app → 选
   **"I want to use a different authenticator app"** → 页面会显示二维码,底下有
   **"Can't scan? Secret key: XXXX"**,那串就是种子。用它生成一个码填回去完成注册:
   ```bash
   oathtool --totp -b '<SECRET>'
   ```
2. 若门户禁用了「其他 app」选项:用一台 **rooted 安卓模拟器/旧手机**装 Microsoft
   Authenticator、注册本账号,再从
   `/data/data/com.azure.authenticator/databases/PhoneFactor` 的 `oath_secret_key`
   导出种子。导完设备即可弃用。

> 安全含义:种子落地后,这台机器上「第二因素」与密码同处一地,2FA 实际退化为
> 1FA。仅限本人自用设备。种子/密码不入 git、不写代码,统一放 Keychain。

## 存凭证(macOS Keychain)

```bash
# 种子
printf '<SECRET>' | python3 mfa.py store
python3 mfa.py check                                  # 应打印当前码

# NetID / NetPassword
security add-generic-password -U -s polygp-netid   -a polygp -w '<你的NetID>'
security add-generic-password -U -s polygp-netpass -a polygp -w '<你的NetPassword>'
```

Linux 侧改用环境变量(建议放 `~/.secrets`,chmod 600):
`POLYGP_TOTP_SEED` / `POLYGP_NETID` / `POLYGP_NETPASS`。

## 校正登录页选择器(联调第一步)

`auth.py` 顶部 `SEL` 用的是 Microsoft AAD 默认选择器。PolyU 若经 ADFS,选择器可能
不同。跑一次录制,对着真实页面把 `SEL` 改准:

```bash
python3 -m playwright codegen "<gpclient 打印的那个 auth URL>"
```

先用 `--headful` 观察几次:
```bash
python3 auth.py --headful --debug-dir /tmp "<auth URL>"   # 失败会存截图
```

## 运行

单测 auth(手动把 gpclient 打印的 URL 传进来):
```bash
python3 auth.py "<auth URL>"        # 成功则 stdout 打印 globalprotectcallback:...
```

全自动(Linux/gpclient 侧):
```bash
POLYGP_HIP=/opt/polygp/hip/polyu-hipreport.sh python3 connect.py
```

## 部署形态

- **推荐**:automation + gpclient 跑在 Linux 服务器(现有 Docker 已含 gpclient),
  Mac 经 tailscale 消费。需把 Playwright/Chromium 装进运行环境。
- **macOS 原生**:无官方 gpclient,需改用 openconnect + 自行实现 GP prelogin 的
  SAML 抓取(类似 gp-saml-gui),`auth.py` 的浏览器驱动可复用,入口需另写。
