# Project Notes for Codex

## PRM Runtime Safety

- Do not launch `ProxyRuleManager.exe`, `wails dev`, or any command that starts the PRM runtime from Codex unless the user explicitly asks for it in that turn.
- PRM can take over the Windows system PAC/proxy path and interrupt Codex's own network connection.
- To diagnose PRM PAC/proxy issues, use a separate evidence collection script that only reads state and logs, such as `scripts/collect-network-evidence.ps1 -Once`.
- The intended verification flow is: Codex edits code/config or prepares diagnostics, the user manually starts or stops PRM, then Codex collects or reviews logs without starting PRM itself.
