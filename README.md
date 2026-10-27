# emudhra-ca-mitm

![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)
![mitmproxy 12.2.3](https://img.shields.io/badge/mitmproxy-12.2.3-1D9BF0)
![pywebview 6.2.1](https://img.shields.io/badge/pywebview-6.2.1-2F6FED)
![MIT License](https://img.shields.io/badge/License-MIT-00BA7C)

基于 mitmproxy 的 MITM 工具。利用泄露的 eMudhra证书 中间 CA 解密 HTTPS，再把代理流量转发到 Reqable 等上游 HTTP(S) 抓包代理，便于APP调试等场景。

## 🚀 快速开始

需要 Python 3.12+，支持 Windows 和 Linux。

启动脚本会创建或复用 `.venv`，仅在首次运行、Python 版本变化或 `pyproject.toml` 变化时安装依赖，然后启动 GUI。

### Windows

```powershell
git clone https://github.com/bytehola/emudhra-ca-mitm.git
cd emudhra-ca-mitm
.\start.ps1
```

### Linux

```bash
git clone https://github.com/bytehola/emudhra-ca-mitm.git
cd emudhra-ca-mitm
chmod +x start.sh
./start.sh
```

## 🧭 使用

### 图形界面

1. 启动抓包软件，并按该软件的实际监听地址设置上游代理。默认值 `127.0.0.1:9000` 对应 Reqable，其他软件可能不同。
2. 启动 GUI，选择 CA 和代理参数，点击“启动”。
3. Android 抓包时，在“Android 抓包”页选择设备。启动 Frida 会同时启动代理并应用设备系统代理。
4. 仅需系统代理抓包时，可直接点击“启动并应用代理”；其他设备可手动配置 GUI 中显示的 HTTP 或 SOCKS5 代理。

### 纯命令行

纯命令行模式不启动 pywebview 窗口，也不提供 ADB、设备代理设置或 Frida 功能。首次使用：

Windows：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[android]"
```

Linux：

```bash
python3 -m venv .venv
./.venv/bin/python -m pip install -e ".[android]"
```

先让上游抓包软件监听 `--upstream` 指定的地址，再启动 HTTP 与 SOCKS5 代理。

Windows：

```powershell
.\.venv\Scripts\emudhra-mitm-cli.exe `
  --ca-name 01-EM-OV-TLS-CA-G3C `
  --listen-host 0.0.0.0 `
  --listen-port 28081 `
  --socks-port 28082 `
  --upstream http://127.0.0.1:9000
```

Linux：

```bash
./.venv/bin/emudhra-mitm-cli \
  --ca-name 01-EM-OV-TLS-CA-G3C \
  --listen-host 0.0.0.0 \
  --listen-port 28081 \
  --socks-port 28082 \
  --upstream http://127.0.0.1:9000
```

使用 `Ctrl+C` 停止。还可使用 `--verify-upstream` 校验上游证书；CLI 只读取命令行参数，不读取或写入 `config/settings.json`。

## 📱 Android 与 Frida

- 内置 Windows、Linux 版 ADB `37.0.1`，支持 USB、无线调试配对和系统代理恢复。
- ADB 设备与应用列表每 5 秒自动刷新，应用选择框显示名称与包名。
- 有 root 时下载并启动匹配版本的 frida-server。
- 无 root 且 App 可调试时准备 Frida Gadget；不可调试 App 需要重打包注入。
- SSL Pinning 脚本覆盖 SSLContext、Conscrypt、OkHttp、HostnameVerifier 和 WebView。

## 📄 License

MIT License
