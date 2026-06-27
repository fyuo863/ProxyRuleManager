# Proxy Rule Manager

一个基于 `Go + Wails + React + TypeScript` 的 Windows 桌面小工具，用来把浏览器流量先引入本地分流代理，再按规则决定：

- 命中 `PROXY` 的网站：`本程序 -> 代理 127.0.0.1:xxxx -> Wi-Fi`
- 命中 `DIRECT` 的网站：`本程序 -> 目标网站 -> Windows 默认路由/有线`
- 命中 `REJECT` 的网站：本程序直接拒绝

本项目不做 HTTPS 解密，不做 MITM，不安装根证书，不抓包。日志完全来自真实经过本地代理的浏览器连接。

## 功能

- 本地 PAC 服务：`http://127.0.0.1:18088/proxy.pac`
- 本地 HTTP/HTTPS CONNECT 分流代理：`127.0.0.1:18089`
- Windows 当前用户系统 PAC 启用/停用与恢复
- 规则管理：新增、编辑、删除、启用/禁用、排序
- 实时流量日志：规则命中、目标路径、上下行字节数、耗时、状态、错误
- 配置持久化：`%APPDATA%/ProxyRuleManager/config.json`
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

- `openai.com -> PROXY`
- `chatgpt.com -> PROXY`
- `oaistatic.com -> PROXY`
- `oaiusercontent.com -> PROXY`
- `MATCH -> DIRECT`

其中 `MATCH,DIRECT` 会始终保留在最后一条，作为兜底规则。

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

默认会生成 Windows 可执行文件 `ProxyRuleManager.exe`。

## 使用方式

1. 启动程序。
2. 点击“启动 PAC 服务”。
3. 点击“启动本地分流代理”。
4. 点击“启用系统 PAC”。
5. 确认状态栏里 `AutoConfigURL` 指向 `http://127.0.0.1:18088/proxy.pac`。
6. 保持 代理 本地 HTTP 代理可用：`127.0.0.1:7892`。
7. 用浏览器访问目标站点，并在实时日志里观察命中结果。

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

## 浏览器没有进入本程序时如何排查

- 确认系统 PAC 已启用
- 确认浏览器使用系统代理
- 可尝试关闭浏览器 QUIC / HTTP3
- 确认本地分流代理 `127.0.0.1:18089` 正在运行
- 确认 PAC 地址 `http://127.0.0.1:18088/proxy.pac` 可以访问

## 配置文件

默认路径：

```text
%APPDATA%/ProxyRuleManager/config.json
```

配置内容包括：

- `rules`
- `pacListenAddr`
- `proxyListenAddr`
- `fastLinkProxyAddr`
- `autoStartPacService`
- `autoStartProxyService`
- `autoEnableSystemPac`
- `disableSystemPacOnExit`
- `maxLogEntries`
- `savedWindowsProxyConfig`

## 限制说明

- 只处理走系统代理/PAC 的应用流量
- 不捕获不遵守系统代理的程序
- 不捕获 UDP / QUIC / HTTP3
- `IP-CIDR` 只对“host 本身就是 IP”时生效，当前不会主动解析域名再做 CIDR 匹配
- HTTPS 日志只记录 CONNECT 级别信息，不记录解密后的 URL 路径

## 是否能管理应用流量，例如 Codex

可以，但前提是该应用本身愿意走 Windows 系统代理或系统 PAC。

这意味着：

- 如果某个桌面应用和浏览器一样遵守系统代理设置，那么它的 HTTP / HTTPS 流量也可能进入本程序，并被按规则分流记录。
- 如果某个应用使用自己的网络栈、自己直连、自己维护代理配置，或者走的是非 HTTP 协议，那么它可能完全绕过本程序。
- 因此像 `Codex` 这类桌面应用，是否会被本程序接管，取决于它运行时是否真的采用 Windows 当前用户的系统 PAC，而不是只取决于“它是桌面应用”。

换句话说，本程序当前能力是：

- 能管理“遵守系统 PAC 的应用流量”
- 不能强制接管“绕过系统代理的应用流量”

如果你后续希望进一步覆盖更多应用，方向通常有两类：

1. 继续走“系统代理/PAC”路线

- 适合浏览器、部分 Electron 应用、部分系统代理兼容应用
- 无需管理员权限
- 实现简单、风险低

2. 改做“透明代理 / 驱动层 / WFP / TUN”路线

- 才有机会管理那些不走系统代理的应用
- 复杂度会显著上升
- 往往需要管理员权限
- 也会超出当前这个“本地 HTTP/HTTPS 分流代理”的设计范围

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
