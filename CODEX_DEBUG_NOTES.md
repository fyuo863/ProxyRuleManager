# Codex 排障记录

这个文件用于持续记录与 Codex 可用性、网络链路、代理、日志相关的排障线索。

维护约定：

- 新线索追加到文末，按时间倒序或顺序保持一致。
- 尽量记录“现象、证据、结论、下一步”四项。
- 只记录已观察到的事实，推断要明确标注为“推断”。

## 2026-06-28

### 现象

- Codex 仍然无法正常使用。
- 用户希望先验证是否是 Codex 的 IPv6 / 长连接路径不稳定。
- 用户已重启 Codex，并启动了本机代理 `127.0.0.1:7892`。

### 已确认事实

- 当前 Codex 安装路径：
  - `C:\Program Files\WindowsApps\OpenAI.Codex_26.623.5546.0_x64__2p2nqsd0c76g0\app\Codex.exe`
  - `C:\Program Files\WindowsApps\OpenAI.Codex_26.623.5546.0_x64__2p2nqsd0c76g0\app\resources\codex.exe`
- 已存在并启用仅针对 Codex 的 IPv6 出站阻断规则：
  - `Codex_Block_IPv6_Outbound_Main`
  - `Codex_Block_IPv6_Outbound_Resources`
- 重启后检查 `Codex` / `codex` 当前连接，未见新的 IPv6 外连。
- 复查时看到的外连为 IPv4，说明“只阻断 Codex 的 IPv6 出站”规则已经生效。

### 代理与系统网络配置

- Windows 用户代理已启用：
  - `ProxyEnable = 1`
  - `ProxyServer = 127.0.0.1:7892`
- `WinHTTP` 当前为直连，无单独代理。
- 当前 shell 环境中未看到额外的 `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` 环境变量。

### 日志位置

- Codex 桌面日志目录：
  - `C:\Users\23576\AppData\Local\Packages\OpenAI.Codex_2p2nqsd0c76g0\LocalCache\Local\Codex\Logs\2026\06\28`

### 日志证据

在当天日志中反复出现以下错误：

- `net::ERR_PROXY_CONNECTION_FAILED`
- `net::ERR_SSL_PROTOCOL_ERROR`
- `net::ERR_CONNECTION_TIMED_OUT`
- `net::ERR_CONNECTION_CLOSED`

这些错误出现在 Codex 自身请求上，包括但不限于：

- `/wham/tasks/list`
- `/wham/accounts/check`
- `/wham/usage`
- `/beacons/home`

另见非核心但相关的 UI / 状态异常：

- `Received turn/completed for unknown conversation`
- `Received turn/started for unknown conversation`
- `Item not found in turn state`

另见与 git turn diff 相关的非致命告警：

- `Failed to retain a turn diff tree snapshot`
- 多次 `git update-ref ... exitCode=128`

目前看这些 git / turn diff 告警更像伴随问题，不像主因。

### 额外验证

- 本机 `127.0.0.1:7892` 端口可连通。
- 通过该代理执行：
  - `curl -I -x http://127.0.0.1:7892 https://chatgpt.com`
  - `curl -I -x http://127.0.0.1:7892 https://api.openai.com/v1/models`
- 上述请求能完成 TLS 建连并收到远端响应，说明代理不是“完全不可用”。

### 当前结论

- “只封 Codex 的 IPv6 出站”已经生效，但没有解决 Codex 不可用的问题。
- 目前更像是 Codex 经过本机代理 `127.0.0.1:7892` 时，出现了间歇性的代理连接失败、连接关闭、超时或 TLS 协议异常。
- 推断：根因更接近“代理链路不稳定 / 与 Codex(Electron) 请求模式兼容性不足”，而不是单纯 IPv6 路径问题。

### 建议的下一步

- 做最小化 A/B：
  - 临时关闭 Windows 系统代理。
  - 重启 Codex。
  - 立即复测是否恢复。
- 如果关闭系统代理后恢复，优先继续排查：
  - PRM 的代理模式
  - 是否存在 TLS 中间处理/分流规则
  - 是否对 Electron / Store App / OpenAI 域名有特殊分流
