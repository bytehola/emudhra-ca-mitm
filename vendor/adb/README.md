# Android Platform Tools

本项目内置 Android Debug Bridge，避免运行时依赖系统 `PATH`。

## 来源

- Windows: `https://dl.google.com/android/repository/platform-tools-latest-windows.zip`
- Linux: `https://dl.google.com/android/repository/platform-tools-latest-linux.zip`
- 版本: `37.0.1`
- 下载日期: `2026-10-27`

只保留 ADB 运行需要的文件。许可证见同目录 `NOTICE.txt`。

## 目录

```text
vendor/adb/
├── NOTICE.txt
├── README.md
├── manifest.json
├── linux/
│   ├── adb
│   └── source.properties
└── windows/
    ├── adb.exe
    ├── AdbWinApi.dll
    ├── AdbWinUsbApi.dll
    ├── libwinpthread-1.dll
    └── source.properties
```
