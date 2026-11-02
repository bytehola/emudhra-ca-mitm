const elements = {
  backendState: document.querySelector("#backend-state"),
  versionLabel: document.querySelector("#version-label"),
  runtimePill: document.querySelector("#runtime-pill"),
  runtimeText: document.querySelector("#runtime-text"),
  refreshButton: document.querySelector("#refresh-button"),
  proxyTab: document.querySelector("#proxy-tab"),
  fridaTab: document.querySelector("#frida-tab"),
  hotspotTab: document.querySelector("#hotspot-tab"),
  proxyView: document.querySelector("#proxy-view"),
  fridaView: document.querySelector("#frida-view"),
  hotspotView: document.querySelector("#hotspot-view"),
  configForm: document.querySelector("#config-form"),
  caName: document.querySelector("#ca-name"),
  caSummaryName: document.querySelector("#ca-summary-name"),
  caSummaryValidity: document.querySelector("#ca-summary-validity"),
  listenHost: document.querySelector("#listen-host"),
  listenPort: document.querySelector("#listen-port"),
  socksPort: document.querySelector("#socks-port"),
  upstream: document.querySelector("#upstream"),
  startButton: document.querySelector("#start-button"),
  stopButton: document.querySelector("#stop-button"),
  feedback: document.querySelector("#feedback"),
  httpEndpoint: document.querySelector("#http-endpoint"),
  socksEndpoint: document.querySelector("#socks-endpoint"),
  upstreamEndpoint: document.querySelector("#upstream-endpoint"),
  updatedLabel: document.querySelector("#updated-label"),
  diagnosticsState: document.querySelector("#diagnostics-state"),
  diagnosticsOutput: document.querySelector("#diagnostics-output"),
  copyDiagnosticsButton: document.querySelector("#copy-diagnostics-button"),
  adbDeviceSelect: document.querySelector("#adb-device-select"),
  adbAppSelect: document.querySelector("#adb-app-select"),
  refreshAdbButton: document.querySelector("#refresh-adb-button"),
  adbStatusLine: document.querySelector("#adb-status-line"),
  adbProxyStatus: document.querySelector("#adb-proxy-status"),
  applyAdbProxyButton: document.querySelector("#apply-adb-proxy-button"),
  restoreAdbProxyButton: document.querySelector("#restore-adb-proxy-button"),
  wirelessDeviceEndpoint: document.querySelector("#wireless-device-endpoint"),
  wirelessPairingEndpoint: document.querySelector("#wireless-pairing-endpoint"),
  wirelessPairingCode: document.querySelector("#wireless-pairing-code"),
  wirelessStatus: document.querySelector("#wireless-status"),
  adbConnectButton: document.querySelector("#adb-connect-button"),
  adbPairButton: document.querySelector("#adb-pair-button"),
  adbDisconnectButton: document.querySelector("#adb-disconnect-button"),
  fridaPackage: document.querySelector("#frida-package"),
  fridaScriptPath: document.querySelector("#frida-script-path"),
  fridaStatus: document.querySelector("#frida-status"),
  fridaStartButton: document.querySelector("#frida-start-button"),
  fridaStopButton: document.querySelector("#frida-stop-button"),
  copyFridaCommandButton: document.querySelector("#copy-frida-command-button"),
  fridaLogState: document.querySelector("#frida-log-state"),
  fridaLogOutput: document.querySelector("#frida-log-output"),
  copyFridaLogButton: document.querySelector("#copy-frida-log-button"),
  hotspotForm: document.querySelector("#hotspot-form"),
  hotspotSsid: document.querySelector("#hotspot-ssid"),
  hotspotPassword: document.querySelector("#hotspot-password"),
  hotspotNetworkFields: document.querySelector("#hotspot-network-fields"),
  hotspotInterfaceField: document.querySelector("#hotspot-interface-field"),
  hotspotInterface: document.querySelector("#hotspot-interface"),
  hotspotTransparentPort: document.querySelector("#hotspot-transparent-port"),
  hotspotStartButton: document.querySelector("#hotspot-start-button"),
  hotspotStartLabel: document.querySelector("#hotspot-start-label"),
  hotspotStopButton: document.querySelector("#hotspot-stop-button"),
  hotspotStatusChip: document.querySelector("#hotspot-status-chip"),
  hotspotUpdatedLabel: document.querySelector("#hotspot-updated-label"),
  hotspotSsidStatus: document.querySelector("#hotspot-ssid-status"),
  hotspotNetworkStatus: document.querySelector("#hotspot-network-status"),
  hotspotEndpointStatus: document.querySelector("#hotspot-endpoint-status"),
  hotspotClientProxyRow: document.querySelector("#hotspot-client-proxy-row"),
  hotspotClientProxyStatus: document.querySelector(
    "#hotspot-client-proxy-status",
  ),
  hotspotFlowRow: document.querySelector("#hotspot-flow-row"),
  hotspotFlowStatus: document.querySelector("#hotspot-flow-status"),
  hotspotClientStatus: document.querySelector("#hotspot-client-status"),
  hotspotClientCount: document.querySelector("#hotspot-client-count"),
  hotspotClientList: document.querySelector("#hotspot-client-list"),
  hotspotSummary: document.querySelector("#hotspot-summary"),
  hotspotNote: document.querySelector("#hotspot-note"),
  hotspotLogState: document.querySelector("#hotspot-log-state"),
  hotspotLogOutput: document.querySelector("#hotspot-log-output"),
};

const ADB_AUTO_REFRESH_INTERVAL_MS = 5000;
const HOTSPOT_STATUS_REFRESH_INTERVAL_MS = 5000;

const state = {
  backendReady: false,
  initialized: false,
  running: false,
  busy: false,
  activeView: "proxy",
  fridaAvailable: false,
  fridaRunning: false,
  fridaBusy: false,
  hotspotAvailable: false,
  hotspotReady: false,
  hotspotRunning: false,
  hotspotBusy: false,
  hotspotPlatform: "",
  adbDevices: [],
  adbLoading: false,
  adbAppsLoaded: false,
  adbProxyValue: "",
  adbProxyBusy: false,
  wirelessBusy: false,
  casByName: new Map(),
  pollTimer: null,
  adbRefreshTimer: null,
  hotspotRefreshTimer: null,
  feedbackTimer: null,
};

function api() {
  return window.pywebview?.api ?? null;
}

function setRuntime(stateName, label) {
  elements.runtimePill.dataset.state = stateName;
  elements.runtimeText.textContent = label;
}

function showFeedback(message, tone = "error") {
  if (state.feedbackTimer !== null) {
    window.clearTimeout(state.feedbackTimer);
  }
  elements.feedback.hidden = false;
  elements.feedback.dataset.tone = tone;
  elements.feedback.textContent = message;
  state.feedbackTimer = window.setTimeout(
    () => {
      elements.feedback.hidden = true;
      state.feedbackTimer = null;
    },
    tone === "error" ? 7000 : 4500,
  );
}

function clearFeedback() {
  if (state.feedbackTimer !== null) {
    window.clearTimeout(state.feedbackTimer);
    state.feedbackTimer = null;
  }
  elements.feedback.hidden = true;
  elements.feedback.textContent = "";
}

function setDiagnostics(text) {
  const diagnosticText = text || "";
  elements.diagnosticsOutput.textContent = diagnosticText || "暂无诊断输出";
  elements.copyDiagnosticsButton.disabled = diagnosticText.length === 0;
}

function setBusy(isBusy) {
  state.busy = isBusy;
  elements.startButton.disabled = isBusy || !state.backendReady || state.running;
  elements.stopButton.disabled =
    isBusy
    || !state.backendReady
    || !state.running
    || state.hotspotRunning;
  for (const control of elements.configForm.querySelectorAll("input, select")) {
    control.disabled = isBusy || state.running;
  }
}

function setFridaBusy(isBusy) {
  state.fridaBusy = isBusy;
  elements.fridaPackage.disabled = isBusy || state.fridaRunning;
  elements.fridaStartButton.disabled =
    isBusy || !state.fridaAvailable || state.fridaRunning;
  elements.fridaStopButton.disabled = isBusy || !state.fridaRunning;
  elements.copyFridaCommandButton.disabled = isBusy;
  updateAdbControlState();
}

function setHotspotBusy(isBusy) {
  state.hotspotBusy = isBusy;
  updateHotspotControls();
}

function updateHotspotControls() {
  const formLocked = state.hotspotBusy || state.hotspotRunning;
  for (const control of elements.hotspotForm.querySelectorAll("input, select")) {
    control.disabled = formLocked;
  }
  elements.hotspotInterface.disabled = (
    formLocked
    || state.hotspotPlatform !== "linux"
    || elements.hotspotInterface.options.length <= 1
  );
  elements.hotspotStartButton.disabled = (
    state.hotspotBusy
    || !state.backendReady
    || !state.hotspotAvailable
    || state.hotspotRunning
    || (
      state.hotspotPlatform === "linux"
      && !elements.hotspotInterface.value
    )
  );
  elements.hotspotStartLabel.textContent = (
    state.hotspotPlatform === "linux"
    && state.hotspotAvailable
    && !state.hotspotReady
  )
    ? "安装依赖并启动"
    : "启动热点";
  elements.hotspotStopButton.disabled = (
    state.hotspotBusy
    || !state.hotspotRunning
  );
  elements.stopButton.disabled = (
    state.busy
    || !state.backendReady
    || !state.running
    || state.hotspotRunning
  );
}

function updateAdbControlState() {
  const locked = state.fridaBusy || state.fridaRunning;
  const hasAvailableDevice = state.adbDevices.some(
    (device) => device.state === "device",
  );
  elements.adbDeviceSelect.disabled = locked || !hasAvailableDevice;
  elements.adbAppSelect.disabled = locked || !state.adbAppsLoaded;
  elements.refreshAdbButton.disabled = locked || state.adbLoading;
  updateAdbProxyControls();
}

function updateAdbProxyControls() {
  const hasDevice = Boolean(elements.adbDeviceSelect.value);
  const fridaControlsLocked = state.fridaBusy || state.fridaRunning;
  elements.applyAdbProxyButton.disabled =
    state.adbProxyBusy || fridaControlsLocked || !hasDevice;
  elements.restoreAdbProxyButton.disabled =
    state.adbProxyBusy
    || fridaControlsLocked
    || !hasDevice
    || !state.adbProxyValue;
}

function setAdbProxyValue(proxyValue) {
  state.adbProxyValue = proxyValue || "";
  elements.adbProxyStatus.textContent = state.adbProxyValue || "未设置";
  elements.adbProxyStatus.title = state.adbProxyValue;
  elements.adbProxyStatus.dataset.state = state.adbProxyValue
    ? "available"
    : "stopped";
  updateAdbProxyControls();
}

function setAdbStatus(message, stateName) {
  elements.adbStatusLine.textContent = message;
  elements.adbStatusLine.dataset.state = stateName;
}

function resetAppSelect(message) {
  state.adbAppsLoaded = false;
  elements.adbAppSelect.replaceChildren();
  const option = document.createElement("option");
  option.value = "";
  option.textContent = message;
  elements.adbAppSelect.append(option);
  updateAdbControlState();
}

function renderAdbStatus(status) {
  state.adbDevices = Array.isArray(status.devices) ? status.devices : [];
  const previousSerial = elements.adbDeviceSelect.value;
  elements.adbDeviceSelect.replaceChildren();

  if (!state.adbDevices.length) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "未发现 Android 设备";
    elements.adbDeviceSelect.append(option);
    resetAppSelect("请先连接并授权设备");
    setAdbStatus(
      status.error || "未发现设备",
      "error",
    );
    return "";
  }

  for (const device of state.adbDevices) {
    const option = document.createElement("option");
    option.value = device.serial;
    const deviceName = device.model || device.serial;
    option.textContent =
      device.state === "device"
        ? `${deviceName} (${device.serial})`
        : `${deviceName} (${device.serial}, ${device.state})`;
    option.disabled = device.state !== "device";
    elements.adbDeviceSelect.append(option);
  }

  const availableDevices = state.adbDevices.filter(
    (device) => device.state === "device",
  );
  if (!availableDevices.length) {
    elements.adbDeviceSelect.value = state.adbDevices[0].serial;
    resetAppSelect("设备未授权或不可用");
    setAdbStatus(
      status.error || "设备未授权或不可用",
      "error",
    );
    return "";
  }

  const previousDeviceAvailable = availableDevices.some(
    (device) => device.serial === previousSerial,
  );
  elements.adbDeviceSelect.value = previousDeviceAvailable
    ? previousSerial
    : availableDevices[0].serial;
  setAdbStatus(`${availableDevices.length} 台设备可用`, "available");
  return elements.adbDeviceSelect.value;
}

async function loadAndroidApps(deviceSerial = "", { silent = false } = {}) {
  const selectedSerial = deviceSerial || elements.adbDeviceSelect.value;
  if (!selectedSerial) {
    resetAppSelect("请先连接并授权设备");
    return;
  }

  const previousPackage = (
    elements.adbAppSelect.value
    || elements.fridaPackage.value.trim()
  );
  if (!silent) {
    resetAppSelect("正在读取应用列表");
    elements.adbAppSelect.disabled = true;
  }
  try {
    const result = await api().list_android_packages({
      device_serial: selectedSerial,
    });
    if (!result.ok) {
      throw new Error(result.error);
    }

    elements.adbAppSelect.replaceChildren();
    const placeholder = document.createElement("option");
    placeholder.value = "";
    placeholder.textContent = "选择第三方应用";
    elements.adbAppSelect.append(placeholder);
    for (const app of result.packages) {
      const option = document.createElement("option");
      option.value = app.package_name;
      option.textContent = app.label === app.package_name
        ? app.package_name
        : `${app.label} (${app.package_name})`;
      elements.adbAppSelect.append(option);
    }
    if (
      previousPackage
      && Array.from(elements.adbAppSelect.options).some(
        (option) => option.value === previousPackage,
      )
    ) {
      elements.adbAppSelect.value = previousPackage;
    }
    state.adbAppsLoaded = result.packages.length > 0;
    setAdbStatus(
      result.packages.length
        ? `已读取 ${result.packages.length} 个应用`
        : "没有第三方应用",
      result.packages.length ? "available" : "error",
    );
  } catch (error) {
    if (!silent || !state.adbAppsLoaded) {
      resetAppSelect("应用列表读取失败");
    }
    setAdbStatus(
      error instanceof Error ? error.message : String(error),
      "error",
    );
    if (!silent) {
      showFeedback(error instanceof Error ? error.message : String(error));
    }
  } finally {
    updateAdbControlState();
  }
}

async function refreshAdbStatus({ silent = false } = {}) {
  if (
    !state.backendReady
    || state.adbLoading
    || state.fridaBusy
    || state.fridaRunning
    || state.adbProxyBusy
    || state.wirelessBusy
  ) {
    return;
  }

  state.adbLoading = true;
  if (!silent) {
    elements.refreshAdbButton.classList.add("spinning");
    setAdbStatus("正在检测 ADB", "checking");
  }
  updateAdbControlState();
  try {
    const status = await api().get_adb_status();
    if (!status.ok) {
      throw new Error(status.error || "ADB 状态读取失败");
    }
    const selectedSerial = renderAdbStatus(status);
    if (selectedSerial) {
      await loadAndroidApps(selectedSerial, { silent });
      await loadAdbProxyStatus();
    } else {
      setAdbProxyValue("");
    }
  } catch (error) {
    state.adbDevices = [];
    elements.adbDeviceSelect.replaceChildren();
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "ADB 不可用";
    elements.adbDeviceSelect.append(option);
    resetAppSelect("请检查 ADB 和设备连接");
    setAdbStatus(
      error instanceof Error ? error.message : String(error),
      "error",
    );
    if (!silent) {
      showFeedback(error instanceof Error ? error.message : String(error));
    }
  } finally {
    state.adbLoading = false;
    if (!silent) {
      elements.refreshAdbButton.classList.remove("spinning");
    }
    updateAdbControlState();
  }
}

function setFridaLog(text, hasContent = Boolean(text)) {
  elements.fridaLogOutput.textContent = text || "暂无 Frida 日志";
  elements.copyFridaLogButton.disabled = !hasContent;
}

function renderFridaStatus(status) {
  if (!status) {
    return;
  }

  state.fridaAvailable = Boolean(status.available);
  state.fridaRunning = Boolean(status.running);
  if (status.script_path) {
    elements.fridaScriptPath.textContent = status.script_path;
    elements.fridaScriptPath.title = status.script_path;
  }
  if (status.package_name && !elements.fridaPackage.value) {
    elements.fridaPackage.value = status.package_name;
  }

  if (!state.fridaAvailable) {
    elements.fridaStatus.textContent = "不可用";
    elements.fridaStatus.dataset.state = "error";
    elements.fridaLogState.textContent = "工具未就绪";
  } else if (state.fridaRunning) {
    elements.fridaStatus.textContent = "运行中";
    elements.fridaStatus.dataset.state = "running";
    elements.fridaLogState.textContent = "注入中";
  } else {
    elements.fridaStatus.textContent = "工具可用";
    elements.fridaStatus.dataset.state = "available";
    elements.fridaLogState.textContent = "已停止";
  }
  if (state.fridaBusy && !state.fridaRunning) {
    elements.fridaStatus.textContent = "准备中";
    elements.fridaStatus.dataset.state = "starting";
    elements.fridaLogState.textContent = "正在准备环境";
  }

  const setupProgress = Array.isArray(status.setup_progress)
    ? status.setup_progress
    : [];
  const logLines = Array.isArray(status.log) ? status.log : [];
  const logText = [...setupProgress, ...logLines].join("\n");
  if (logText) {
    setFridaLog(logText, true);
  } else if (!state.fridaAvailable) {
    setFridaLog(status.unavailable_reason || "Frida 不可用", true);
  } else {
    setFridaLog("", false);
  }
  if (!state.fridaBusy) {
    setFridaBusy(false);
  }
}

function setHotspotLog(text) {
  const logText = text || "暂无热点日志";
  elements.hotspotLogOutput.textContent = logText;
}

function populateHotspotInterfaces(interfaces) {
  const previousInterface = elements.hotspotInterface.value;
  elements.hotspotInterface.replaceChildren();

  if (!Array.isArray(interfaces) || interfaces.length === 0) {
    const option = document.createElement("option");
    option.value = "";
    option.textContent = "未发现无线网卡";
    elements.hotspotInterface.append(option);
    updateHotspotControls();
    return;
  }

  for (const interfaceInfo of interfaces) {
    const option = document.createElement("option");
    option.value = interfaceInfo.name;
    option.textContent = interfaceInfo.state
      ? `${interfaceInfo.name} (${interfaceInfo.state})`
      : interfaceInfo.name;
    elements.hotspotInterface.append(option);
  }

  const previousInterfaceExists = interfaces.some(
    (interfaceInfo) => interfaceInfo.name === previousInterface,
  );
  elements.hotspotInterface.value = previousInterfaceExists
    ? previousInterface
    : interfaces[0].name;
  updateHotspotControls();
}

function formatHotspotClientState(clientState) {
  const normalizedState = String(clientState || "").toUpperCase();
  if (
    ["REACHABLE", "PERMANENT", "CONNECTED", "DELAY", "PROBE"].includes(
      normalizedState,
    )
  ) {
    return "在线";
  }
  if (normalizedState === "STALE") {
    return "空闲";
  }
  return clientState || "已连接";
}

function renderHotspotClients(clientDevices, clientCount, clientsAvailable) {
  elements.hotspotClientCount.textContent = clientsAvailable
    ? `${clientCount} 台`
    : "不可用";
  elements.hotspotClientList.replaceChildren();

  if (clientDevices.length === 0) {
    const emptyMessage = document.createElement("p");
    emptyMessage.className = "hotspot-client-empty";
    emptyMessage.textContent = clientsAvailable
      ? "暂无已连接设备"
      : "当前平台不提供设备列表";
    elements.hotspotClientList.append(emptyMessage);
    return;
  }

  for (const clientDevice of clientDevices) {
    const clientRow = document.createElement("div");
    clientRow.className = "hotspot-client-row";

    const address = document.createElement("code");
    address.textContent = clientDevice.ip_address || "-";
    address.title = clientDevice.ip_address || "未获取到 IP 地址";

    const macAddress = document.createElement("code");
    macAddress.textContent = clientDevice.mac_address || "-";
    macAddress.title = clientDevice.mac_address || "未获取到 MAC 地址";

    const clientState = document.createElement("span");
    clientState.className = "hotspot-client-state";
    clientState.textContent = formatHotspotClientState(
      clientDevice.state,
    );

    clientRow.append(address, macAddress, clientState);
    elements.hotspotClientList.append(clientRow);
  }
}

function renderHotspotStatus(response) {
  const hotspot = response?.hotspot || {};
  const transparent = response?.transparent || {};
  state.hotspotAvailable = Boolean(hotspot.available);
  state.hotspotReady = hotspot.ready === undefined
    ? state.hotspotAvailable
    : Boolean(hotspot.ready);
  state.hotspotRunning = Boolean(hotspot.running || transparent.running);
  state.hotspotPlatform = hotspot.platform || "";

  elements.hotspotNetworkFields.hidden = state.hotspotPlatform !== "linux";
  elements.hotspotInterfaceField.hidden = state.hotspotPlatform !== "linux";
  const interfaceHasFocus = document.activeElement === elements.hotspotInterface;
  if (
    state.hotspotPlatform === "linux"
    && !state.hotspotBusy
    && !state.hotspotRunning
    && !interfaceHasFocus
  ) {
    populateHotspotInterfaces(hotspot.interfaces);
  }

  if (!hotspot.running && transparent.running) {
    elements.hotspotStatusChip.textContent = "透明桥运行中";
    elements.hotspotStatusChip.dataset.state = "starting";
    elements.hotspotLogState.textContent = "需要清理";
    elements.hotspotLogState.dataset.state = "starting";
  } else if (state.hotspotRunning) {
    elements.hotspotStatusChip.textContent = "运行中";
    elements.hotspotStatusChip.dataset.state = "running";
    elements.hotspotLogState.textContent = "运行中";
    elements.hotspotLogState.dataset.state = "running";
  } else if (!state.hotspotAvailable) {
    elements.hotspotStatusChip.textContent = "不可用";
    elements.hotspotStatusChip.dataset.state = "error";
    elements.hotspotLogState.textContent = "不可用";
    elements.hotspotLogState.dataset.state = "error";
  } else if (!state.hotspotReady) {
    elements.hotspotStatusChip.textContent = "待安装";
    elements.hotspotStatusChip.dataset.state = "starting";
    elements.hotspotLogState.textContent = "依赖未就绪";
    elements.hotspotLogState.dataset.state = "starting";
  } else {
    elements.hotspotStatusChip.textContent = "未启动";
    elements.hotspotStatusChip.dataset.state = "stopped";
    elements.hotspotLogState.textContent = "已停止";
    elements.hotspotLogState.dataset.state = "stopped";
  }

  const ssid = response?.ssid || hotspot.ssid || "";
  const interfaceName = state.hotspotRunning
    ? (response?.interface || hotspot.interface || "")
    : "";
  const address = state.hotspotRunning ? (hotspot.address || "") : "";
  const networkParts = [interfaceName, address].filter(Boolean);
  const clients = Number(hotspot.clients || 0);
  const clientDevices = Array.isArray(hotspot.client_devices)
    ? hotspot.client_devices
    : [];
  const transparentPort = (
    response?.transparent_port
    || transparent.listen_port
    || Number(elements.hotspotTransparentPort.value)
  );
  const forwardedFlows = Number(transparent.forwarded_flows || 0);
  const ignoredFlows = Number(transparent.ignored_flows || 0);
  const returnedFlows = Number(transparent.returned_flows || 0);
  const lastForwardFlow = transparent.last_forward_flow || null;
  const lastIgnoredFlow = transparent.last_ignored_flow || null;
  const connectionMode = response?.connection_mode || "transparent";
  const clientProxyEndpoint = response?.client_proxy_endpoint || "";
  const installSteps = Array.isArray(hotspot.install_steps)
    ? hotspot.install_steps
    : [];
  const dependencyMessage = [
    hotspot.error,
    installSteps.length
      ? `安装步骤:\n${installSteps.join("\n")}`
      : "",
  ].filter(Boolean).join("\n");
  const manualProxyMode = connectionMode === "manual-proxy";

  elements.hotspotSsidStatus.textContent = ssid || "未启动";
  elements.hotspotNetworkStatus.textContent = networkParts.length
    ? networkParts.join(" / ")
    : "-";
  elements.hotspotEndpointStatus.textContent = transparent.running
    ? `0.0.0.0:${transparentPort}`
    : "-";
  elements.hotspotFlowStatus.textContent = (
    `入 ${forwardedFlows} / 回 ${returnedFlows} / 忽略 ${ignoredFlows}`
  );
  elements.hotspotFlowRow.hidden = manualProxyMode;
  elements.hotspotClientProxyRow.hidden = false;
  elements.hotspotClientProxyStatus.textContent = manualProxyMode
    ? (clientProxyEndpoint || "等待热点网关")
    : "无需设置";
  elements.hotspotClientStatus.textContent = hotspot.clients_available
    ? String(clients)
    : "-";
  renderHotspotClients(
    clientDevices,
    clients,
    Boolean(hotspot.clients_available),
  );
  elements.hotspotUpdatedLabel.textContent = new Intl.DateTimeFormat(
    "zh-CN",
    {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    },
  ).format(new Date());

  if (!hotspot.running && transparent.running) {
    elements.hotspotNote.textContent = "热点未运行，但透明桥仍在运行";
    elements.hotspotNote.dataset.tone = "warning";
    elements.hotspotSummary.textContent = (
      "请点击“停止热点”清理透明桥和系统重定向。"
    );
    elements.hotspotSummary.dataset.tone = "warning";
  } else if (!state.hotspotAvailable) {
    const message = dependencyMessage || "当前系统无法启动热点透明转发";
    elements.hotspotNote.textContent = message;
    elements.hotspotNote.dataset.tone = "error";
    elements.hotspotSummary.textContent = message;
    elements.hotspotSummary.dataset.tone = "error";
  } else if (state.hotspotRunning) {
    elements.hotspotNote.textContent = manualProxyMode
      ? (
        "Windows 热点使用手动代理。请在设备 Wi-Fi 设置中填写上方"
        + "“设备代理”地址，并信任当前 CA。"
      )
      : (
        "客户端无需设置代理。若系统提示“无网络”，"
        + "请安装并信任当前 CA 后重新连接。"
      );
    elements.hotspotNote.dataset.tone = "";
    let hotspotSummaryText = (
      `热点“${ssid || "未命名"}”已启动，HTTP/HTTPS 流量会经透明桥`
      + " 转发到当前上游代理。"
    );
    if (manualProxyMode) {
      hotspotSummaryText = (
        `热点“${ssid || "未命名"}”已启动。设备 Wi-Fi 代理请设置为 `
        + `${clientProxyEndpoint || "电脑热点网关地址"}。`
      );
    }
    if (!manualProxyMode) {
      if (lastForwardFlow?.destination) {
        hotspotSummaryText += (
          `\n最近目标: ${lastForwardFlow.client || "-"} -> `
          + lastForwardFlow.destination
        );
      } else if (forwardedFlows === 0) {
        hotspotSummaryText += "\n尚未捕获到 HTTP/HTTPS 连接。";
        if (lastIgnoredFlow?.client) {
          hotspotSummaryText += (
            `\n最后一个未处理连接: ${lastIgnoredFlow.client} -> `
            + lastIgnoredFlow.destination
          );
        }
      }
    }
    elements.hotspotSummary.textContent = hotspotSummaryText;
    elements.hotspotSummary.dataset.tone = "";
  } else if (!state.hotspotReady) {
    elements.hotspotNote.textContent = (
      "启动热点时会先尝试自动安装缺失的系统依赖"
    );
    elements.hotspotNote.dataset.tone = "warning";
    elements.hotspotSummary.textContent = dependencyMessage;
    elements.hotspotSummary.dataset.tone = "warning";
  } else if (hotspot.error) {
    elements.hotspotNote.textContent = dependencyMessage || hotspot.error;
    elements.hotspotNote.dataset.tone = "warning";
    elements.hotspotSummary.textContent = dependencyMessage || hotspot.error;
    elements.hotspotSummary.dataset.tone = "warning";
  } else {
    const platformNote = state.hotspotPlatform === "windows"
      ? "Windows 移动热点和 WinDivert 透明转发需要管理员权限。"
      : "Linux 使用 NetworkManager/create_ap 与 nftables。";
    elements.hotspotNote.textContent = platformNote;
    elements.hotspotNote.dataset.tone = "";
    elements.hotspotSummary.textContent = (
      "热点未启动。启动时会同时启动代理并配置 HTTP/HTTPS 透明转发。"
    );
    elements.hotspotSummary.dataset.tone = "";
  }

  const logParts = [];
  if (dependencyMessage) {
    logParts.push(dependencyMessage);
  }
  const transparentLog = Array.isArray(transparent.stderr)
    ? transparent.stderr
    : [];
  logParts.push(...transparentLog);
  setHotspotLog(logParts.join("\n"));
  updateHotspotControls();
}

async function refreshHotspotStatus() {
  if (!state.backendReady || state.hotspotBusy) {
    return;
  }
  try {
    const result = await api().get_hotspot_status();
    if (!result.ok) {
      throw new Error(result.error || "热点状态读取失败");
    }
    renderHotspotStatus(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    state.hotspotAvailable = false;
    state.hotspotReady = false;
    state.hotspotRunning = false;
    elements.hotspotStatusChip.textContent = "状态异常";
    elements.hotspotStatusChip.dataset.state = "error";
    elements.hotspotNote.textContent = message;
    elements.hotspotNote.dataset.tone = "error";
    elements.hotspotSummary.textContent = message;
    elements.hotspotSummary.dataset.tone = "error";
    setHotspotLog(message);
    updateHotspotControls();
  }
}

async function startHotspot() {
  if (
    !state.backendReady
    || !state.hotspotAvailable
    || state.hotspotRunning
    || state.hotspotBusy
  ) {
    return;
  }
  if (!elements.hotspotForm.reportValidity()) {
    return;
  }
  if (
    state.hotspotPlatform === "linux"
    && !elements.hotspotInterface.value
  ) {
    showFeedback("请选择用于创建热点的无线网卡", "error");
    return;
  }

  clearFeedback();
  setHotspotBusy(true);
  elements.hotspotStatusChip.textContent = "启动中";
  elements.hotspotStatusChip.dataset.state = "starting";
  elements.hotspotLogState.textContent = "正在启动";
  elements.hotspotLogState.dataset.state = "starting";
  setHotspotLog(
    state.hotspotReady
      ? "正在启动热点并配置透明重定向"
      : "正在安装 Linux 系统依赖，随后启动热点",
  );
  try {
    const result = await api().start_hotspot({
      ...collectConfiguration(),
      ssid: elements.hotspotSsid.value.trim(),
      password: elements.hotspotPassword.value,
      interface: elements.hotspotInterface.value,
      transparent_port: Number(elements.hotspotTransparentPort.value),
    });
    if (!result.ok) {
      if (result.status) {
        renderHotspotStatus(result.status);
      }
      throw new Error(
        [result.error, result.warning].filter(Boolean).join("\n"),
      );
    }
    if (result.proxy_status) {
      renderStatus(result.proxy_status);
    }
    renderHotspotStatus(result.status);
    setHotspotBusy(false);
    showFeedback("热点和透明代理已启动", "success");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    setHotspotLog(message);
    setHotspotBusy(false);
    showFeedback(message);
  }
}

async function stopHotspot() {
  if (!state.hotspotRunning || state.hotspotBusy) {
    return;
  }
  clearFeedback();
  setHotspotBusy(true);
  elements.hotspotStatusChip.textContent = "停止中";
  elements.hotspotStatusChip.dataset.state = "starting";
  try {
    const result = await api().stop_hotspot();
    if (!result.ok) {
      throw new Error(result.error || "停止热点失败");
    }
    if (result.proxy_status) {
      renderStatus(result.proxy_status);
    }
    renderHotspotStatus(result.status);
    setHotspotBusy(false);
    if (result.warning) {
      showFeedback(result.warning, "warning");
    } else {
      showFeedback("热点已停止", "success");
    }
  } catch (error) {
    setHotspotBusy(false);
    showFeedback(error instanceof Error ? error.message : String(error));
  }
}

function switchView(viewName) {
  if (!["proxy", "frida", "hotspot"].includes(viewName)) {
    return;
  }
  const isProxyView = viewName === "proxy";
  const isFridaView = viewName === "frida";
  const isHotspotView = viewName === "hotspot";
  state.activeView = viewName;
  elements.proxyTab.setAttribute("aria-selected", String(isProxyView));
  elements.fridaTab.setAttribute("aria-selected", String(isFridaView));
  elements.hotspotTab.setAttribute("aria-selected", String(isHotspotView));
  elements.proxyTab.classList.toggle("is-active", isProxyView);
  elements.fridaTab.classList.toggle("is-active", isFridaView);
  elements.hotspotTab.classList.toggle("is-active", isHotspotView);
  elements.proxyView.hidden = !isProxyView;
  elements.fridaView.hidden = !isFridaView;
  elements.hotspotView.hidden = !isHotspotView;
  window.history.replaceState(null, "", `#${viewName}`);
  if (isFridaView) {
    refreshFridaStatus();
    refreshAdbStatus();
  }
  if (isHotspotView) {
    refreshHotspotStatus();
  }
}

function updateCaSummary() {
  const selected = state.casByName.get(elements.caName.value);
  elements.caSummaryName.textContent = selected?.cn || elements.caName.value;
  elements.caSummaryValidity.textContent = selected?.validity || "";
}

function applyDefaults(defaults) {
  if (!defaults) {
    return;
  }
  elements.listenHost.value = defaults.listen_host;
  elements.listenPort.value = defaults.listen_port;
  elements.socksPort.value = defaults.socks_port;
  elements.upstream.value = defaults.upstream;
  if (defaults.ca_name) {
    elements.caName.value = defaults.ca_name;
  }
}

function populateCas(casEntries) {
  state.casByName.clear();
  elements.caName.replaceChildren();
  for (const entry of casEntries) {
    state.casByName.set(entry.name, entry);
    const option = document.createElement("option");
    option.value = entry.name;
    option.textContent = entry.name;
    elements.caName.append(option);
  }
  updateCaSummary();
}

function renderStatus(status) {
  if (!status) {
    return;
  }
  state.running = Boolean(status.running);
  elements.httpEndpoint.textContent = status.http_endpoint;
  elements.socksEndpoint.textContent = status.socks_endpoint;
  elements.upstreamEndpoint.textContent = status.upstream;
  elements.updatedLabel.textContent = new Intl.DateTimeFormat("zh-CN", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date());

  if (state.running) {
    setRuntime("running", "运行中");
    elements.diagnosticsState.textContent = "代理已启动";
    elements.diagnosticsState.dataset.state = "running";
  } else {
    setRuntime("stopped", "已停止");
    elements.diagnosticsState.textContent = "等待启动";
    elements.diagnosticsState.dataset.state = "stopped";
  }

  const stderrLines = Array.isArray(status.stderr) ? status.stderr : [];
  setDiagnostics(stderrLines.join("\n"));
  setBusy(false);
}

function collectConfiguration() {
  return {
    ca_name: elements.caName.value,
    listen_host: elements.listenHost.value.trim(),
    listen_port: Number(elements.listenPort.value),
    socks_port: Number(elements.socksPort.value),
    upstream: elements.upstream.value.trim(),
    verify_upstream: false,
  };
}

async function loadBootstrap() {
  const bridge = api();
  if (!bridge) {
    elements.backendState.textContent = "本地服务未连接";
    setRuntime("error", "不可用");
    setBusy(false);
    return;
  }

  try {
    const result = await bridge.bootstrap();
    if (!result.ok) {
      throw new Error(result.error);
    }
    state.backendReady = true;
    elements.backendState.textContent = "本地服务已连接";
    elements.versionLabel.textContent = `v${result.version}`;
    populateCas(result.cas);
    applyDefaults(result.defaults);
    setBusy(false);
    if (result.warning) {
      showFeedback(result.warning, "warning");
    }
  } catch (error) {
    state.backendReady = false;
    elements.backendState.textContent = "本地服务不可用";
    setRuntime("error", "不可用");
    showFeedback(error instanceof Error ? error.message : String(error));
    setBusy(false);
  }
}

async function refreshStatus() {
  if (!state.backendReady || state.busy) {
    return;
  }
  try {
    const status = await api().get_status();
    renderStatus(status);
  } catch (error) {
    setRuntime("error", "状态异常");
    elements.diagnosticsState.textContent = "状态读取失败";
    elements.diagnosticsState.dataset.state = "error";
    setDiagnostics(error instanceof Error ? error.message : String(error));
  }
}

async function refreshFridaStatus() {
  if (!state.backendReady) {
    return;
  }
  try {
    const status = await api().get_frida_status();
    if (!status.ok) {
      throw new Error(status.error || "Frida 状态读取失败");
    }
    renderFridaStatus(status);
  } catch (error) {
    state.fridaAvailable = false;
    state.fridaRunning = false;
    elements.fridaStatus.textContent = "状态异常";
    elements.fridaStatus.dataset.state = "error";
    elements.fridaLogState.textContent = "状态读取失败";
    setFridaLog(
      error instanceof Error ? error.message : String(error),
      true,
    );
    if (!state.fridaBusy) {
      setFridaBusy(false);
    }
  }
}

async function loadAdbProxyStatus() {
  const deviceSerial = elements.adbDeviceSelect.value;
  if (!deviceSerial) {
    setAdbProxyValue("");
    return;
  }
  try {
    const result = await api().get_adb_proxy_status({
      device_serial: deviceSerial,
    });
    if (!result.ok) {
      throw new Error(result.error);
    }
    setAdbProxyValue(result.proxy);
  } catch (error) {
    setAdbProxyValue("");
    showFeedback(error instanceof Error ? error.message : String(error));
  }
}

async function applyDeviceProxy() {
  const deviceSerial = elements.adbDeviceSelect.value;
  if (!deviceSerial) {
    showFeedback("请先选择 Android 设备", "error");
    return;
  }
  if (!elements.configForm.reportValidity()) {
    showFeedback("请先完成代理配置", "error");
    return;
  }

  clearFeedback();
  state.adbProxyBusy = true;
  updateAdbProxyControls();
  let proxyStartedHere = false;
  try {
    if (!state.running) {
      proxyStartedHere = await startProxy(false);
      if (!proxyStartedHere) {
        return;
      }
    }

    const result = await api().set_adb_proxy({
      device_serial: deviceSerial,
      local_port: Number(elements.listenPort.value),
    });
    if (!result.ok) {
      throw new Error(result.error);
    }
    setAdbProxyValue(result.proxy.proxy);
    showFeedback("设备代理已设置，代理已启动", "success");
  } catch (error) {
    if (proxyStartedHere) {
      await stopProxy(false);
    }
    showFeedback(error instanceof Error ? error.message : String(error));
  } finally {
    state.adbProxyBusy = false;
    updateAdbProxyControls();
  }
}

async function restoreDeviceProxy() {
  const deviceSerial = elements.adbDeviceSelect.value;
  if (!deviceSerial) {
    showFeedback("请先选择 Android 设备", "error");
    return;
  }

  clearFeedback();
  state.adbProxyBusy = true;
  updateAdbProxyControls();
  try {
    const result = await api().restore_adb_proxy({
      device_serial: deviceSerial,
    });
    if (!result.ok) {
      throw new Error(result.error);
    }
    setAdbProxyValue(result.proxy.proxy);
    showFeedback("设备代理已恢复", "success");
  } catch (error) {
    showFeedback(error instanceof Error ? error.message : String(error));
  } finally {
    state.adbProxyBusy = false;
    updateAdbProxyControls();
  }
}

function setWirelessStatus(message, stateName) {
  elements.wirelessStatus.textContent = message;
  elements.wirelessStatus.dataset.state = stateName;
}

function setWirelessBusy(isBusy) {
  state.wirelessBusy = isBusy;
  for (const control of [
    elements.wirelessDeviceEndpoint,
    elements.wirelessPairingEndpoint,
    elements.wirelessPairingCode,
    elements.adbConnectButton,
    elements.adbPairButton,
    elements.adbDisconnectButton,
  ]) {
    control.disabled = isBusy;
  }
}

async function connectWirelessAdb() {
  if (!elements.wirelessDeviceEndpoint.reportValidity()) {
    return;
  }

  clearFeedback();
  setWirelessBusy(true);
  setWirelessStatus("连接中", "checking");
  try {
    const result = await api().connect_adb({
      endpoint: elements.wirelessDeviceEndpoint.value.trim(),
    });
    if (!result.ok) {
      throw new Error(result.error);
    }
    const selectedSerial = renderAdbStatus(result.status);
    if (selectedSerial) {
      await loadAndroidApps(selectedSerial);
    }
    setWirelessStatus("已连接", "available");
    showFeedback("无线 ADB 已连接", "success");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    setWirelessStatus("连接失败", "error");
    showFeedback(message, "error");
  } finally {
    setWirelessBusy(false);
  }
}

async function pairAndConnectWirelessAdb() {
  if (!elements.wirelessDeviceEndpoint.reportValidity()) {
    return;
  }
  if (
    !elements.wirelessPairingEndpoint.value.trim()
    || !elements.wirelessPairingCode.value.trim()
  ) {
    showFeedback("请输入无线调试中的配对地址和 6 位配对码", "error");
    return;
  }
  if (
    !elements.wirelessPairingEndpoint.reportValidity()
    || !elements.wirelessPairingCode.reportValidity()
  ) {
    return;
  }

  clearFeedback();
  setWirelessBusy(true);
  setWirelessStatus("配对中", "checking");
  try {
    const result = await api().pair_and_connect_adb({
      device_endpoint: elements.wirelessDeviceEndpoint.value.trim(),
      pairing_endpoint: elements.wirelessPairingEndpoint.value.trim(),
      pairing_code: elements.wirelessPairingCode.value.trim(),
    });
    if (!result.ok) {
      throw new Error(result.error);
    }
    const selectedSerial = renderAdbStatus(result.status);
    if (selectedSerial) {
      await loadAndroidApps(selectedSerial);
    }
    setWirelessStatus("已连接", "available");
    showFeedback("无线 ADB 配对并连接成功", "success");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    setWirelessStatus("配对失败", "error");
    showFeedback(message, "error");
  } finally {
    elements.wirelessPairingCode.value = "";
    setWirelessBusy(false);
  }
}

async function disconnectWirelessAdb() {
  const internalEndpoint = elements.adbDeviceSelect.value.includes(":")
    ? elements.adbDeviceSelect.value
    : "";
  const endpoint =
    elements.wirelessDeviceEndpoint.value.trim() || internalEndpoint;
  if (!endpoint) {
    showFeedback("请输入无线设备地址或先选择无线设备", "error");
    return;
  }

  clearFeedback();
  setWirelessBusy(true);
  setWirelessStatus("断开中", "checking");
  try {
    const result = await api().disconnect_adb({ endpoint });
    if (!result.ok) {
      throw new Error(result.error);
    }
    const selectedSerial = renderAdbStatus(result.status);
    if (selectedSerial) {
      await loadAndroidApps(selectedSerial);
    }
    setWirelessStatus("未连接", "stopped");
    showFeedback("无线 ADB 已断开", "success");
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    setWirelessStatus("断开失败", "error");
    showFeedback(message, "error");
  } finally {
    setWirelessBusy(false);
  }
}

async function startFrida() {
  if (
    !state.backendReady ||
    !state.fridaAvailable ||
    state.fridaRunning ||
    state.fridaBusy
  ) {
    return;
  }
  if (!elements.adbDeviceSelect.value) {
    showFeedback("请先选择 Android 设备", "error");
    return;
  }
  if (!elements.fridaPackage.reportValidity()) {
    return;
  }

  clearFeedback();
  setFridaBusy(true);
  elements.fridaStatus.textContent = "启动中";
  elements.fridaStatus.dataset.state = "starting";
  elements.fridaLogState.textContent = "正在准备环境";
  setFridaLog(
    "正在启动代理并准备 Frida 环境。\n首次使用会下载匹配版本的 frida-server 或 Gadget，可能需要几分钟。",
    true,
  );

  try {
    const result = await api().start_frida({
      package_name: elements.fridaPackage.value.trim(),
      device_id: elements.adbDeviceSelect.value,
      ...collectConfiguration(),
    });
    if (!result.ok) {
      if (result.proxy_status) {
        renderStatus(result.proxy_status);
      }
      if (result.warning) {
        setFridaLog(`${result.error}\n${result.warning}`, true);
      }
      throw new Error(result.error);
    }
    renderFridaStatus(result.status);
    renderStatus(result.proxy_status);
    setAdbProxyValue(result.device_proxy?.proxy || "");
    setFridaBusy(false);
    showFeedback("Frida 与设备代理已启动", "success");
  } catch (error) {
    setFridaBusy(false);
    elements.fridaStatus.textContent = "启动失败";
    elements.fridaStatus.dataset.state = "error";
    elements.fridaLogState.textContent = "启动失败";
    const message = error instanceof Error ? error.message : String(error);
    setFridaLog(message, true);
    showFeedback(message, "error");
  }
}

async function stopFrida() {
  if (!state.fridaRunning || state.fridaBusy) {
    return;
  }

  clearFeedback();
  setFridaBusy(true);
  elements.fridaStatus.textContent = "停止中";
  elements.fridaStatus.dataset.state = "starting";
  elements.fridaLogState.textContent = "正在停止";

  try {
    const result = await api().stop_frida();
    if (!result.ok) {
      throw new Error(result.error);
    }
    renderFridaStatus(result.status);
    setFridaBusy(false);
    showFeedback("Frida 已停止", "success");
  } catch (error) {
    setFridaBusy(false);
    elements.fridaStatus.textContent = "停止失败";
    elements.fridaStatus.dataset.state = "error";
    showFeedback(error instanceof Error ? error.message : String(error));
  }
}

async function copyFridaCommand() {
  if (!elements.fridaPackage.reportValidity()) {
    return;
  }
  try {
    const result = await api().get_frida_command({
      package_name: elements.fridaPackage.value.trim(),
      device_id: elements.adbDeviceSelect.value,
    });
    if (!result.ok) {
      throw new Error(result.error);
    }
    await copyText(result.command);
    showFeedback("Frida 命令已复制", "success");
  } catch (error) {
    showFeedback(error instanceof Error ? error.message : String(error));
  }
}

async function startProxy(showSuccessMessage = true) {
  if (!state.backendReady || state.running || state.busy) {
    return false;
  }
  clearFeedback();
  if (!elements.configForm.reportValidity()) {
    return false;
  }
  setBusy(true);
  setRuntime("starting", "启动中");
  elements.diagnosticsState.textContent = "正在启动";
  elements.diagnosticsState.dataset.state = "starting";

  try {
    const result = await api().start_proxy(collectConfiguration());
    if (!result.ok) {
      throw new Error(result.error);
    }
    renderStatus(result.status);
    if (result.warning) {
      showFeedback(result.warning, "warning");
    } else if (showSuccessMessage) {
      showFeedback("代理已启动", "success");
    }
    return true;
  } catch (error) {
    setBusy(false);
    setRuntime("error", "启动失败");
    elements.diagnosticsState.textContent = "启动失败";
    elements.diagnosticsState.dataset.state = "error";
    setDiagnostics(error instanceof Error ? error.message : String(error));
    showFeedback(error instanceof Error ? error.message : String(error));
    return false;
  }
}

async function stopProxy(showSuccessMessage = true) {
  if (!state.backendReady || !state.running || state.busy) {
    return false;
  }
  clearFeedback();
  setBusy(true);
  setRuntime("starting", "停止中");
  elements.diagnosticsState.textContent = "正在停止";
  elements.diagnosticsState.dataset.state = "starting";

  try {
    const result = await api().stop_proxy();
    if (!result.ok) {
      throw new Error(result.error);
    }
    renderStatus(result.status);
    if (result.warning) {
      showFeedback(result.warning, "warning");
    } else if (showSuccessMessage) {
      showFeedback("代理已停止", "success");
    }
    await loadAdbProxyStatus();
    return true;
  } catch (error) {
    setBusy(false);
    setRuntime("error", "停止失败");
    elements.diagnosticsState.dataset.state = "error";
    showFeedback(error instanceof Error ? error.message : String(error));
    return false;
  }
}

async function refreshAll() {
  clearFeedback();
  elements.refreshButton.classList.add("spinning");
  elements.refreshButton.disabled = true;
  try {
    await loadBootstrap();
    await refreshStatus();
    await refreshFridaStatus();
    await refreshAdbStatus();
    await refreshHotspotStatus();
  } finally {
    elements.refreshButton.classList.remove("spinning");
    elements.refreshButton.disabled = false;
  }
}

async function copyDiagnostics() {
  if (elements.copyDiagnosticsButton.disabled) {
    return;
  }

  const diagnosticText = elements.diagnosticsOutput.textContent;
  try {
    await copyText(diagnosticText);
    showFeedback("运行诊断已复制", "success");
  } catch {
    showFeedback("复制失败，请手动选择诊断文本", "error");
  }
}

async function copyFridaLog() {
  if (elements.copyFridaLogButton.disabled) {
    return;
  }
  try {
    await copyText(elements.fridaLogOutput.textContent);
    showFeedback("Frida 日志已复制", "success");
  } catch {
    showFeedback("复制失败，请手动选择 Frida 日志", "error");
  }
}

async function copyText(text) {
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return;
    } catch {
      fallbackCopy(text);
      return;
    }
  }
  fallbackCopy(text);
}

function fallbackCopy(text) {
  const textarea = document.createElement("textarea");
  textarea.value = text;
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.opacity = "0";
  document.body.append(textarea);
  textarea.select();
  const copied = document.execCommand("copy");
  textarea.remove();
  if (!copied) {
    throw new Error("浏览器未允许复制");
  }
}

function bindEvents() {
  elements.proxyTab.addEventListener("click", () => switchView("proxy"));
  elements.fridaTab.addEventListener("click", () => switchView("frida"));
  elements.hotspotTab.addEventListener("click", () => switchView("hotspot"));
  elements.caName.addEventListener("change", updateCaSummary);
  elements.startButton.addEventListener("click", () => startProxy());
  elements.stopButton.addEventListener("click", () => stopProxy());
  elements.refreshButton.addEventListener("click", refreshAll);
  elements.copyDiagnosticsButton.addEventListener("click", copyDiagnostics);
  elements.adbDeviceSelect.addEventListener("change", async () => {
    await loadAndroidApps();
    await loadAdbProxyStatus();
  });
  elements.adbAppSelect.addEventListener("change", () => {
    if (elements.adbAppSelect.value) {
      elements.fridaPackage.value = elements.adbAppSelect.value;
    }
  });
  elements.refreshAdbButton.addEventListener(
    "click",
    () => refreshAdbStatus(),
  );
  elements.applyAdbProxyButton.addEventListener("click", applyDeviceProxy);
  elements.restoreAdbProxyButton.addEventListener(
    "click",
    restoreDeviceProxy,
  );
  elements.adbConnectButton.addEventListener("click", connectWirelessAdb);
  elements.adbPairButton.addEventListener("click", pairAndConnectWirelessAdb);
  elements.adbDisconnectButton.addEventListener(
    "click",
    disconnectWirelessAdb,
  );
  elements.fridaStartButton.addEventListener("click", startFrida);
  elements.fridaStopButton.addEventListener("click", stopFrida);
  elements.hotspotStartButton.addEventListener("click", startHotspot);
  elements.hotspotStopButton.addEventListener("click", stopHotspot);
  elements.hotspotInterface.addEventListener("change", updateHotspotControls);
  elements.copyFridaCommandButton.addEventListener("click", copyFridaCommand);
  elements.copyFridaLogButton.addEventListener("click", copyFridaLog);
  elements.configForm.addEventListener("submit", (event) => {
    event.preventDefault();
    startProxy();
  });
  elements.hotspotForm.addEventListener("submit", (event) => {
    event.preventDefault();
    startHotspot();
  });
  window.addEventListener("beforeunload", () => {
    if (state.pollTimer !== null) {
      window.clearInterval(state.pollTimer);
    }
    if (state.adbRefreshTimer !== null) {
      window.clearInterval(state.adbRefreshTimer);
    }
    if (state.hotspotRefreshTimer !== null) {
      window.clearInterval(state.hotspotRefreshTimer);
    }
  });
}

async function initialize() {
  if (state.initialized) {
    return;
  }
  state.initialized = true;
  bindEvents();
  const requestedView = window.location.hash.replace(/^#/, "");
  switchView(
    ["proxy", "frida", "hotspot"].includes(requestedView)
      ? requestedView
      : "proxy",
  );
  await loadBootstrap();
  await refreshStatus();
  await refreshFridaStatus();
  if (state.activeView === "frida") {
    await refreshAdbStatus();
  }
  if (state.activeView === "hotspot") {
    await refreshHotspotStatus();
  }
  if (state.pollTimer === null) {
    state.pollTimer = window.setInterval(() => {
      refreshStatus();
      if (state.activeView === "frida") {
        refreshFridaStatus();
      }
    }, 1000);
  }
  if (state.adbRefreshTimer === null) {
    state.adbRefreshTimer = window.setInterval(() => {
      const adbControlHasFocus = (
        document.activeElement === elements.adbDeviceSelect
        || document.activeElement === elements.adbAppSelect
      );
      if (
        state.activeView === "frida"
        && !adbControlHasFocus
        && !document.hidden
      ) {
        refreshAdbStatus({ silent: true });
      }
    }, ADB_AUTO_REFRESH_INTERVAL_MS);
  }
  if (state.hotspotRefreshTimer === null) {
    state.hotspotRefreshTimer = window.setInterval(() => {
      if (
        state.activeView === "hotspot"
        && !document.hidden
        && !state.hotspotBusy
      ) {
        refreshHotspotStatus();
      }
    }, HOTSPOT_STATUS_REFRESH_INTERVAL_MS);
  }
}

window.addEventListener("pywebviewready", initialize);
window.addEventListener("DOMContentLoaded", () => {
  window.setTimeout(() => {
    if (!state.initialized) {
      initialize();
    }
  }, 500);
});
