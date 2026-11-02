<h1 align="center">eMudhra CA MITM</h1>

<p align="center">基于 mitmproxy 与 eMudhra CA 的移动端 HTTPS 调试工具，将 HTTP 或 SOCKS5 流量转发至 Reqable 等上游抓包代理。</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white&style=flat-square" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/mitmproxy-12.2.3-1D9BF0?style=flat-square" alt="mitmproxy 12.2.3">
  <img src="https://img.shields.io/badge/pywebview-6.2.1-2F6FED?style=flat-square" alt="pywebview 6.2.1">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-4B5563?style=flat-square" alt="Windows and Linux">
  <img src="https://img.shields.io/badge/License-MIT-22C55E?style=flat-square" alt="MIT License">
</p>

## ✨ 核心功能


- **上游转发**：将解密后的流量转交给 Reqable 等 HTTP(S) 抓包代理，便于继续分析请求与响应。
- **热点共享**：Windows 使用 WinDivert 拦截热点客户端的 TCP `80/443`，Linux 使用 `nftables` 透明转发。
- **Android 调试**：集成 Windows、Linux 版 ADB，支持设备发现、系统代理设置、Frida 启动和 SSL Pinning 绕过。
- **命令行模式**：不启动 GUI，直接运行 HTTP/HTTPS 与 SOCKS5 代理，适合脚本化和无图形环境。

## 🚀 快速开始

环境要求：Python 3.12+，支持 Windows 和 Linux。

```bash
git clone https://github.com/bytehola/emudhra-ca-mitm.git
cd emudhra-ca-mitm
```

### Windows

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[android]"
.\.venv\Scripts\python.exe main.py
```

### Linux

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -e ".[android]"
./.venv/bin/python main.py
```

仓库也提供一键启动脚本。Windows 可运行 `.\start.ps1`，Linux 可运行 `./start.sh`；脚本会创建或复用 `.venv`，并在依赖变化时重新安装。

## 🧭 使用指南

1. 启动 Reqable 等上游抓包软件，并让其 HTTP(S) 代理监听 `127.0.0.1:9000`。
2. 启动 GUI，选择 CA、确认 HTTP 与 SOCKS5 端口，然后启动代理。
3. 将待调试设备的 HTTP 代理设为 GUI 显示的地址；SOCKS5 客户端使用对应的 SOCKS5 端口。
4. Android 调试、设备系统代理和 Frida 功能可在 GUI 的“Android 抓包”页面配置。

默认监听配置为 HTTP `0.0.0.0:28081`、SOCKS5 `0.0.0.0:28082`、上游 `http://127.0.0.1:9000`。客户端需要信任所选 CA，否则 HTTPS 握手会失败。

### 命令行启动

Linux：

```bash
./.venv/bin/emudhra-mitm-cli \
  --ca-name 01-EM-OV-TLS-CA-G3C \
  --listen-host 0.0.0.0 \
  --listen-port 28081 \
  --socks-port 28082 \
  --upstream http://127.0.0.1:9000
```

Windows：

```powershell
.\.venv\Scripts\emudhra-mitm-cli.exe `
  --ca-name 01-EM-OV-TLS-CA-G3C `
  --listen-host 0.0.0.0 `
  --listen-port 28081 `
  --socks-port 28082 `
  --upstream http://127.0.0.1:9000
```

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--ca-name` | `01-EM-OV-TLS-CA-G3C` | `cas/` 目录中的 CA 名称 |
| `--listen-host` | `0.0.0.0` | HTTP/HTTPS 代理监听地址 |
| `--listen-port` | `28081` | HTTP/HTTPS 代理监听端口 |
| `--socks-port` | `28082` | SOCKS5 代理监听端口 |
| `--upstream` | `http://127.0.0.1:9000` | 上游 HTTP(S) 代理地址 |
| `--verify-upstream` | 关闭 | 校验上游代理证书 |

按 `Ctrl+C` 停止。CLI 只读取命令行参数，不读取或写入 `config/settings.json`。

## 📶 热点共享

热点共享目前为实验性功能。Windows 需要以管理员身份运行；Linux 需要 `root` 或 `pkexec`，并安装 NetworkManager 或 `create_ap`，以及 `nftables` 和 `iproute2`。

> **平台兼容性：** 无线网卡需要支持 AP 模式；Windows 热点模式通过 WinDivert 拦截 TCP `80/443`，并在热点期间丢弃客户端 UDP `443` 流量以促使 QUIC 回落至 TCP。

客户端连接热点后仍需信任所选 CA，否则 HTTPS 请求无法正常完成。

## 🤝 致谢

感谢 [christarcher/emudhra-ca-mitm](https://github.com/christarcher/emudhra-ca-mitm) 提供项目基础与实现参考。

## 🌐 LinuxDo 社区友链

[LinuxDo 社区](https://linux.do/)

## 📄 License

本项目采用 [MIT License](https://opensource.org/license/mit) 发布。
