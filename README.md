# Proxy Rule Manager

一个基于 `Go + Wails + React + TypeScript` 的 Windows 桌面小工具，用来同时处理两类分流场景：

- `WEB`：浏览器或遵守系统 PAC 的应用，先进入本地分流代理，再按规则决定：
  - 命中 `PROXY` 的网站：`本程序 -> 上游代理 127.0.0.1:xxxx -> 实际出口`
  - 命中 `DIRECT` 的网站：`本程序 -> 目标网站 -> Windows 默认路由/指定直连网卡`
  - 命中 `REJECT` 的网站：本程序直接拒绝
- `APP`：桌面应用透明接管。Windows 上可按进程名或路径接管指定应用的 TCP 连接，优先识别 `TLS SNI / HTTP Host` 后再按同一套规则决定 `PROXY / DIRECT / REJECT`

本项目不做 HTTPS 解密，不做 MITM，不安装根证书。`WEB` 日志来自真实经过本地代理的连接，`APP` 日志来自真实经过透明接管数据面的连接。

## 功能

- 本地 PAC 服务：`http://127.0.0.1:18088/proxy.pac`
- 本地 HTTP/HTTPS CONNECT 分流代理：`127.0.0.1:18089`
- Windows 应用透明接管：按进程名/路径接管指定桌面应用 TCP 连接
- 应用级域名分流：对被接管应用优先识别 `TLS SNI / HTTP Host`，再复用同一套规则引擎
- 透明接管应用预设：设置页内置按分类下拉预设，可一键加入 `Codex Desktop`、`Steam Desktop`
- Windows 当前用户系统 PAC 启用/停用与恢复
- 规则管理：新增、编辑、删除、启用/禁用、排序
- 实时流量日志：规则命中、目标路径、上下行字节数、耗时、状态、错误
- 配置持久化：`%USERPROFILE%/.PRM/config.json`
- 配置导入/导出

## 为什么不要开启 代理 的系统代理

如果让 代理 自己全局接管系统代理，代理 内部的 `DIRECT` 连接仍可能由 Core 发起，这会让本应走 Windows 默认有线路由的流量继续从 Wi-Fi 发出。这个项目的设计是：

1. 浏览器先通过系统 PAC 进入本程序的本地分流代理。
2. 只有命中 `PROXY` 的目标才转发给 代理 `127.0.0.1:7892`。
3. 命中 `DIRECT` 的目标由本程序直接建立连接，因此才会走 Windows 默认路由。

## 为什么不能只生成 PAC

PAC 只能告诉浏览器“把流量发给哪个代理”，但它本身不会真正转发流量，也不会产生日志。只有本程序自己实现本地分流代理，才能做到：

- 浏览器流量统一先进本程序
- 本程序按规则决定 `PROXY / DIRECT / REJECT`
- 本程序记录真实命中日志

## 为什么 DIRECT 流量只有经过本程序本地分流代理后才能被记录

如果浏览器绕过本程序直接访问网站，那这些连接根本不会进入本程序，自然也不会有日志。本项目只记录“通过系统 PAC 指向本程序代理”的请求，这一点是刻意设计，不是抓包。

## 为什么不做 HTTPS 解密

项目只处理 HTTPS 的 `CONNECT` 隧道，不解密 TLS 内容。因此 HTTPS 日志只记录：

- 域名
- 端口
- 命中规则
- 目标走向
- 上传/下载字节数
- 耗时
- 状态和错误

这能满足“看见访问了哪个站点，以及它走了哪条规则”的需求，同时避免 MITM 和根证书安装。

## 默认规则

- `OpenAI`：`openai.com`、`chatgpt.com`、`oaistatic.com`、`oaiusercontent.com`
- `GitHub`：`github.com`、`githubassets.com`、`githubusercontent.com`、`github.dev`
- `Google`：`google.com`、`google.com.hk`、`googleapis.com`、`googleusercontent.com`、`gstatic.com`、`ggpht.com`、`gvt1.com`、`gvt2.com`
- `Anthropic`：`anthropic.com`、`claude.ai`
- `Perplexity`：`perplexity.ai`、`pplx.ai`
- `xAI`：`x.ai`、`grok.com`
- `Steam`：`steampowered.com`、`steamcommunity.com`、`steam-chat.com`、`steamusercontent.com`、`steamstatic.com`、`store.steampowered.com`、`help.steampowered.com`、`api.steampowered.com`
- `Microsoft 连通性`：`msftconnecttest.com`、`cloudmessaging.edge.microsoft.com`
- `MATCH -> DIRECT`

其中 `MATCH,DIRECT` 会始终保留在最后一条，作为兜底规则。Steam 下载 CDN（例如 SteamPipe 内容分发域名）不在内置 `Steam` 代理域名里，会继续落到 `MATCH,DIRECT`。

## 默认透明接管应用名单

初始默认值会保留 `Codex` 之前的配置：

- `Codex.exe`
- `codex.exe`
- `codex-command-runner-*.exe`

这组默认值会覆盖 Codex 桌面主进程、CLI 子进程和带版本号的命令执行子进程。

如果你需要接管其他桌面应用，例如 `Steam`，推荐直接在设置页的“透明接管应用名单”里通过分类下拉选择预设，再点“加入名单”。Steam 预设是监控优先的安全预设：默认绕过透明接管数据面，避免破坏成就、Overlay、好友、云存档和游戏联网。

## 开发环境

已验证目标环境具备以下版本：

- Go `1.26.2`
- Node.js `24.14.1`
- Wails `2.12.0`

## 安装依赖

```powershell
go mod tidy
cd frontend
npm install
cd ..
```

## 开发运行

```powershell
wails dev
```

开发模式下：

- Wails 会启动 Go 后端
- Vite 会启动 React 前端
- 前端通过 Wails 绑定直接调用后端方法

## 构建 Windows 可执行文件

```powershell
wails build
```

默认会生成 Windows 可执行文件 `build/bin/ProxyRuleManager.exe`。

## GitHub Tag Release

项目提供 GitHub Actions 自动发布流程：

- push / pull request 到 `main` 时运行格式检查、`go vet` 和测试
- push `v*` 标签时构建 Windows amd64 发布包
- 自动创建 GitHub Release，并上传 `ProxyRuleManager-<tag>-windows-amd64.zip`

发布新版本：

```powershell
git tag v0.1.0
git push origin v0.1.0
```

当前项目只发布 Windows 版本，不构建 Linux 包。

## 在其他设备部署

如果你要把这个项目部署到另一台 Windows 设备，推荐按下面的顺序操作：

1. 在构建机上安装 `Go`、`Node.js` 和 `Wails CLI`，并确认本项目可以正常执行 `wails build`。
2. 拉取项目源码，在项目根目录执行：

```powershell
go mod tidy
cd frontend
npm install
cd ..
wails build
```

3. 如果目标设备不能稳定联网，建议在构建机上提前准备运行时依赖，并随程序一起带过去：
   - `third_party/windivert/WinDivert.dll`
   - `third_party/windivert/WinDivert64.sys`
   - `third_party/wintun/wintun.dll`
   - `third_party/sing-box/sing-box.exe`
4. 从构建机复制以下内容到目标设备：
   - `build/bin/ProxyRuleManager.exe`
   - 可选的 `third_party/` 目录
5. 在目标设备上先准备上游代理程序，并确认它提供的本地端口可用，例如 `127.0.0.1:7892`。
6. 首次启动 `ProxyRuleManager.exe` 时，程序会把运行时文件整理到当前用户目录下的 `.PRM`：
   - `C:\Users\<用户名>\.PRM\config.json`
   - `C:\Users\<用户名>\.PRM\tun-runtime\`
   - `C:\Users\<用户名>\.PRM\core\`
   - `C:\Users\<用户名>\.PRM\diagnostics\`
7. 如果 `third_party/` 目录中已经带好了依赖文件，程序会优先从应用目录旁边复制到 `.PRM`；如果没带齐，则会尝试自动下载缺失组件。
8. 如果需要使用“应用透明接管”或“代理进程出口限制”，请以管理员身份启动程序；仅使用 PAC 和本地分流代理时，通常不需要管理员权限。
9. 启动后先确认以下项目全部正常：
   - `PAC 服务` 已运行
   - `本地分流代理` 已运行
   - 上游代理端口可连接
   - 需要时再开启 `系统 PAC` 和 `应用透明接管`
10. 如需整体迁移现有配置，可把旧设备的 `C:\Users\<用户名>\.PRM\config.json` 复制到新设备相同位置；如需一起迁移诊断与运行时状态，也可以整个复制 `.PRM` 目录，但建议先关闭程序再操作。

## 使用方式

### 仅做网页分流

1. 启动程序。
2. 点击“启动 PAC 服务”。
3. 点击“启动本地分流代理”。
4. 点击“启用系统 PAC”。
5. 确认状态栏里 `AutoConfigURL` 指向 `http://127.0.0.1:18088/proxy.pac`。
6. 保持上游代理可用，例如 `127.0.0.1:7892`。
7. 用浏览器访问目标站点，并在实时日志里观察命中结果。

### 开启桌面应用透明接管

1. 启动程序。
2. 以管理员身份运行。
3. 在“系统设置 -> 透明接管应用名单”里配置要接管的进程名或路径。
4. 可直接从分类下拉中选择 `Codex Desktop`、`Steam Desktop` 或 `Steam Games Auto`，点“加入名单”。
5. 保存设置。
6. 点击“启动应用透明接管”。
7. 保持上游代理可用，例如 `127.0.0.1:7892`。
8. 打开目标桌面应用，并在实时日志里观察 `Source=process` 的命中结果。

### Steam 推荐配置

如果你的目标是：

- `Steam 商店 / 社区 / 登录 / 聊天 / 客户端 Web API -> 走代理`
- `Steam 下载游戏 / 游戏进程 / 成就 / Overlay / 云存档 / 好友与游戏联网 -> 不进入透明接管，按系统默认路由或 Steam 自身机制工作`

推荐这样配置：

1. 启动 `PAC 服务`、`本地分流代理`，并启用 `系统 PAC`。
2. 保留内置 `Steam` 域名规则为 `PROXY`。
3. 保持最后的 `MATCH,DIRECT` 兜底规则。
4. 如需在应用列表里看到 Steam 连接，可加入 `Steam Desktop` 和 `Steam Games Auto` 预设；这两个预设默认绕过透明接管数据面，只做安全监控。

这时：

- 命中 `steampowered.com`、`steamcommunity.com`、`steam-chat.com`、`steamusercontent.com`、`steamstatic.com` 等 Steam Web/账号/社区域名的连接会走代理。
- Steam 下载 CDN 和其它未命中的连接会落到 `MATCH,DIRECT`，继续走默认直连出口，适合用有线网下载游戏。
- Steam 客户端和 `steamapps/common` 下的游戏进程不会被透明接管，也不会被 PRM 添加 UDP 阻断规则，从而避免影响 Steam 成就、Overlay、云存档和游戏联网。

## 验证方法

访问 `chat.openai.com` 后，实时日志应出现类似：

```text
chat.openai.com -> PROXY
```

访问 `bilibili.com` 后，实时日志应出现类似：

```text
bilibili.com -> DIRECT
```

访问 `douyin.com` 后，实时日志应出现类似：

```text
douyin.com -> DIRECT
```

接管 `Steam` 后，访问社区页或商店页时，日志应出现类似：

```text
steamcommunity.com -> PROXY
store.steampowered.com -> PROXY
```

如果命中的是非内置 Steam 社区/商店域名，且未单独配置为 `PROXY`，则会继续落到当前规则结果，通常是：

```text
<download-or-cdn-host> -> DIRECT
```

## 浏览器没有进入本程序时如何排查

- 确认系统 PAC 已启用
- 确认浏览器使用系统代理
- 可尝试关闭浏览器 QUIC / HTTP3
- 确认本地分流代理 `127.0.0.1:18089` 正在运行
- 确认 PAC 地址 `http://127.0.0.1:18088/proxy.pac` 可以访问

## 配置文件

默认路径：

```text
%USERPROFILE%/.PRM/config.json
```

配置内容包括：

- `rules`
- `pacListenAddr`
- `proxyListenAddr`
- `upstreamProxyAddr`
- `upstreamProxyType`
- `proxyInterfaceName`
- `upstreamProxyRouteEnabled`
- `upstreamProxyRouteInterface`
- `upstreamProxyRouteTargets`
- `proxyGuardEnabled`
- `proxyGuardInterface`
- `proxyGuardProgramPaths`
- `directInterfaceName`
- `tunInterfaceName`
- `tunAddressCidr`
- `tunMtu`
- `tunIncludedApps`
- `autoStartTunService`
- `autoStartPacService`
- `autoStartProxyService`
- `autoEnableSystemPac`
- `disableSystemPacOnExit`
- `maxLogEntries`
- `savedWindowsProxyConfig`

## 应用透明接管的工作方式

当前透明接管链路是：

1. WinDivert 在 Windows 上按进程拦截指定应用的 TCP 连接。
2. 程序读取应用首包，优先尝试识别：
   - `TLS ClientHello` 里的 `SNI`
   - 明文 HTTP 请求里的 `Host`
3. 如果识别到主机名，就复用现有规则引擎决定 `PROXY / DIRECT / REJECT`。
4. 如果没有识别到主机名，会尝试按目标 IP 命中 `IP-CIDR`。
5. 如果仍然无法匹配，为了尽量避免应用“无代理即不可用”，当前会回退到 `PROXY`。

这意味着它非常适合：

- `Codex Desktop`、Electron、浏览器辅助进程等 TCP 为主的应用
- Steam 这类同时包含商店/社区、下载、同步、Overlay、好友和游戏联网的客户端只建议使用监控型预设，不建议送入透明接管数据面

## 限制说明

- `WEB` 链路只处理走系统代理/PAC 的流量
- `APP` 链路当前只透明接管 TCP，不直接转发 UDP / QUIC / HTTP3
- 对已识别到实际路径的目标进程，程序会额外下发 UDP 出站阻断规则，尽量压住 QUIC/UDP 旁路，但 Steam 客户端和 Steam 游戏预设会绕过透明接管以避免影响成就、Overlay 与游戏联网
- 应用透明接管需要管理员权限
- 若应用首包里既没有可识别的 `TLS SNI`，也没有可识别的明文 HTTP `Host`，当前会回退走代理
- `IP-CIDR` 只对“host 本身就是 IP”时生效，当前不会主动解析域名再做 CIDR 匹配
- HTTPS 日志只记录 CONNECT 级别信息，不记录解密后的 URL 路径

## 是否能管理应用流量，例如 Codex / Steam

可以，而且现在有两条路径：

- `WEB`：如果应用本身愿意走 Windows 系统代理或系统 PAC，它会像浏览器一样进入本地分流代理。
- `APP`：如果应用不走系统代理，但你把它加入“透明接管应用名单”，程序会按进程在 Windows 上直接接管它的 TCP 连接。

对 `Codex`：

- 默认透明接管应用名单已经覆盖 `Codex.exe`、`codex.exe`、`codex-command-runner-*.exe`
- 即使它的某些子进程不走系统 PAC，也可以通过应用透明接管进入分流链路

对 `Steam`：

- 推荐通过 `Steam Desktop` 和 `Steam Games Auto` 预设做进程监控，但默认绕过透明接管数据面
- 社区、商店、账号、聊天、客户端 Web API 相关域名默认已经内置为 `PROXY`
- 下载 CDN 和其它未命中的连接会继续按规则落到 `DIRECT`

仍然要注意：

- 非 TCP 协议、强自定义加密握手、纯 UDP/QUIC 应用不一定能被完整管理
- 某些没有 `SNI`、也没有明文 `Host` 的连接，当前只能回退到代理或靠 `IP-CIDR` 规则处理

## 项目结构

```text
.
├─ app.go
├─ main.go
├─ go.mod
├─ internal/
│  ├─ config/
│  ├─ logs/
│  ├─ model/
│  ├─ pac/
│  ├─ proxy/
│  ├─ rules/
│  └─ winproxy/
└─ frontend/
   ├─ src/
   ├─ package.json
   └─ vite.config.ts
```
