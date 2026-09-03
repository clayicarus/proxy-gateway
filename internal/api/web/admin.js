document.documentElement.classList.add("js");

const sections = {
  overview: { title: "基本信息", kicker: "运行概览" },
  users: { title: "用户管理", kicker: "账户与策略" },
  connections: { title: "活跃连接", kicker: "实时会话" },
  costs: { title: "成本分析", kicker: "流量与出口" },
  faults: { title: "故障分析", kicker: "运行诊断" },
};

const sidebar = document.querySelector("#sidebar");
const backdrop = document.querySelector("[data-sidebar-backdrop]");

function showSection(name) {
  if (!sections[name]) name = "overview";
  document.querySelectorAll("[data-view]").forEach((element) => {
    element.classList.toggle("active", element.dataset.view === name);
  });
  document.querySelectorAll("[data-nav]").forEach((element) => {
    const active = element.dataset.nav === name;
    element.classList.toggle("active", active);
    if (active) element.setAttribute("aria-current", "page");
    else element.removeAttribute("aria-current");
  });
  document.querySelector("#section-title").textContent = sections[name].title;
  document.querySelector("#section-kicker").textContent = sections[name].kicker;
  sidebar?.classList.remove("open");
  backdrop?.classList.remove("open");
}

function routeFromHash() {
  showSection(location.hash.slice(1) || "overview");
}

window.addEventListener("hashchange", routeFromHash);
routeFromHash();

document.querySelector("[data-menu-toggle]")?.addEventListener("click", () => {
  sidebar?.classList.toggle("open");
  backdrop?.classList.toggle("open");
});
backdrop?.addEventListener("click", () => {
  sidebar?.classList.remove("open");
  backdrop.classList.remove("open");
});
document.querySelectorAll("[data-jump]").forEach((element) => {
  element.addEventListener("click", () => showSection(element.dataset.jump));
});

document.querySelectorAll("[data-open-dialog]").forEach((button) => {
  button.addEventListener("click", () => document.getElementById(button.dataset.openDialog)?.showModal());
});
document.querySelectorAll("[data-close-dialog]").forEach((button) => {
  button.addEventListener("click", () => button.closest("dialog")?.close());
});
document.querySelectorAll("dialog").forEach((dialog) => {
  dialog.addEventListener("click", (event) => {
    if (event.target === dialog) dialog.close();
  });
});

const confirmDialog = document.querySelector("#confirm-dialog");
const confirmButton = confirmDialog?.querySelector("[data-confirm-submit]");
let pendingConfirmForm;

document.querySelectorAll("form[data-confirm-title]").forEach((form) => {
  form.addEventListener("submit", (event) => {
    if (form.dataset.confirmed === "true") {
      delete form.dataset.confirmed;
      return;
    }
    event.preventDefault();
    pendingConfirmForm = form;
    setText("#confirm-dialog [data-confirm-title]", form.dataset.confirmTitle);
    setText("#confirm-dialog [data-confirm-summary]", form.dataset.confirmSummary);
    setText("#confirm-dialog [data-confirm-risk]", form.dataset.confirmRisk);
    if (confirmButton) {
      confirmButton.textContent = form.dataset.confirmLabel || "确认操作";
      confirmButton.classList.toggle("danger", form.dataset.confirmTone === "danger");
    }
    confirmDialog?.showModal();
  });
});

confirmButton?.addEventListener("click", () => {
  const form = pendingConfirmForm;
  pendingConfirmForm = undefined;
  confirmDialog?.close();
  if (!form) return;
  form.dataset.confirmed = "true";
  form.requestSubmit();
});
confirmDialog?.addEventListener("close", () => {
  pendingConfirmForm = undefined;
});

function formatRate(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B/s";
  const units = ["B/s", "KiB/s", "MiB/s", "GiB/s"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const digits = value >= 100 || unit === 0 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(digits)} ${units[unit]}`;
}

function formatBytes(bytes) {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const digits = value >= 100 || unit === 0 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(digits)} ${units[unit]}`;
}

function formatDuration(milliseconds) {
  const totalSeconds = Math.max(0, Math.floor(milliseconds / 1000));
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;
  if (hours) return `${hours}h ${minutes}m`;
  if (minutes) return `${minutes}m ${seconds}s`;
  return `${seconds}s`;
}

function rate(current, previous, seconds) {
  if (!previous || seconds <= 0 || current < previous) return 0;
  return (current - previous) / seconds;
}

function setText(selector, value) {
  const element = document.querySelector(selector);
  if (element) element.textContent = value;
}

function updateSpeedElements(selector, currentMap, previousMap, seconds, keyName) {
  document.querySelectorAll(selector).forEach((element) => {
    const key = element.dataset[keyName];
    const current = currentMap[key] || { txBytes: 0, rxBytes: 0, online: 0 };
    const previous = previousMap?.[key];
    const tx = previous ? rate(current.txBytes, previous.txBytes, seconds) : 0;
    const rx = previous ? rate(current.rxBytes, previous.rxBytes, seconds) : 0;
    const txElement = element.querySelector("[data-tx]");
    const rxElement = element.querySelector("[data-rx]");
    const onlineElement = element.querySelector("[data-online]");
    if (txElement) txElement.textContent = formatRate(tx);
    if (rxElement) rxElement.textContent = formatRate(rx);
    if (onlineElement) onlineElement.textContent = Math.max(0, current.online || 0);
  });
}

function appendCell(row, text, className) {
  const cell = document.createElement("td");
  cell.textContent = text;
  if (className) cell.className = className;
  row.appendChild(cell);
  return cell;
}

function renderConnections(connections) {
  const body = document.querySelector("#connection-rows");
  if (!body) return;
  body.replaceChildren();
  setText("#connection-count", connections.length);
  if (!connections.length) {
    const row = document.createElement("tr");
    const cell = appendCell(row, "暂无活跃连接");
    cell.colSpan = 7;
    cell.className = "empty-state";
    body.appendChild(row);
    return;
  }
  const now = Date.now();
  connections.forEach((connection) => {
    const row = document.createElement("tr");
    appendCell(row, connection.clientIp, "mono");
    appendCell(row, connection.clientAddr, "mono");
    appendCell(row, connection.username);
    appendCell(row, connection.node);
    const duration = now - new Date(connection.connectedAt).getTime();
    const durationCell = appendCell(row, formatDuration(duration));
    durationCell.dataset.sortValue = String(duration);
    const requestCell = appendCell(row, String(connection.requests?.length || 0));
    requestCell.dataset.sortValue = String(connection.requests?.length || 0);
    const targets = (connection.requests || []).map((request) => `${request.protocol} ${request.target}`);
    const targetCell = appendCell(row, targets.join("\n") || "—", "target-list mono");
    targetCell.title = targets.join("\n");
    body.appendChild(row);
  });
}

let previousSample;

async function sampleLiveTraffic() {
  try {
    const response = await fetch("/live", { cache: "no-store", headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const current = await response.json();
    const seconds = previousSample ? Math.max(.001, (current.sampledAt - previousSample.sampledAt) / 1000) : 0;
    const tx = previousSample ? rate(current.total.txBytes, previousSample.total.txBytes, seconds) : 0;
    const rx = previousSample ? rate(current.total.rxBytes, previousSample.total.rxBytes, seconds) : 0;
    setText("#total-tx-speed", formatRate(tx));
    setText("#total-rx-speed", formatRate(rx));
    setText("#cost-tx-speed", formatRate(tx));
    setText("#cost-rx-speed", formatRate(rx));
    setText("#live-online", Math.max(0, current.total.online || 0));
    updateSpeedElements("[data-user-speed]", current.users, previousSample?.users, seconds, "userSpeed");
    updateSpeedElements("[data-node-speed]", current.nodes, previousSample?.nodes, seconds, "nodeSpeed");
    renderConnections(current.connections || []);
    document.querySelectorAll("[data-live-dot]").forEach((dot) => dot.className = "live-dot online");
    document.querySelectorAll("[data-live-label]").forEach((label) => label.textContent = "实时数据已连接");
    document.querySelectorAll("[data-sampled-at]").forEach((element) => element.textContent = `更新于 ${new Date(current.sampledAt).toLocaleTimeString()}`);
    previousSample = current;
  } catch (_) {
    document.querySelectorAll("[data-live-dot]").forEach((dot) => dot.className = "live-dot offline");
    document.querySelectorAll("[data-live-label]").forEach((label) => label.textContent = "实时数据已断开");
  }
}

sampleLiveTraffic();
window.setInterval(sampleLiveTraffic, 2000);

document.querySelectorAll("[data-sort-table]").forEach((table) => {
  table.querySelectorAll("thead th").forEach((header, column) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "sort-button";
    button.textContent = header.textContent;
    button.title = `按${header.textContent}排序`;
    header.replaceChildren(button);
    button.addEventListener("click", () => {
      const ascending = header.dataset.sortDirection !== "asc";
      table.querySelectorAll("th").forEach((item) => delete item.dataset.sortDirection);
      header.dataset.sortDirection = ascending ? "asc" : "desc";
      const numeric = header.dataset.sortType === "number";
      const rows = Array.from(table.tBodies[0]?.rows || []).filter((row) => row.cells.length > column);
      rows.sort((left, right) => {
        const aCell = left.cells[column];
        const bCell = right.cells[column];
        const a = aCell.dataset.sortValue ?? aCell.textContent.trim();
        const b = bCell.dataset.sortValue ?? bCell.textContent.trim();
        const comparison = numeric
          ? (Number(a) || 0) - (Number(b) || 0)
          : a.localeCompare(b, "zh-CN", { numeric: true, sensitivity: "base" });
        return ascending ? comparison : -comparison;
      });
      rows.forEach((row) => table.tBodies[0].appendChild(row));
    });
  });
});

const rangeForm = document.querySelector("#traffic-range-form");
const rangeTimezone = rangeForm?.closest(".range-panel")?.querySelector("#range-timezone")?.textContent.replace("查询时区：", "") || "UTC";

function localInputValue(date) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: rangeTimezone,
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", hourCycle: "h23",
  }).formatToParts(date).reduce((result, part) => {
    result[part.type] = part.value;
    return result;
  }, {});
  return `${parts.year}-${parts.month}-${parts.day}T${parts.hour}:${parts.minute}`;
}

function setRangePreset(preset) {
  if (!rangeForm) return;
  const now = new Date();
  let start = new Date(now);
  if (preset === "day") start = new Date(now.getTime() - 24 * 60 * 60 * 1000);
  if (preset === "week") start = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  if (preset === "month") {
    const endValue = localInputValue(now);
    start = new Date(now);
    rangeForm.elements.start.value = `${endValue.slice(0, 8)}01T00:00`;
    rangeForm.elements.end.value = endValue;
    return;
  }
  rangeForm.elements.start.value = localInputValue(start);
  rangeForm.elements.end.value = localInputValue(now);
}

function renderHourlyChart(hours) {
  const chart = document.querySelector("#hourly-chart");
  if (!chart) return;
  chart.replaceChildren();
  if (!hours.length) {
    chart.textContent = "所选范围暂无流量";
    chart.className = "hourly-chart empty-state";
    return;
  }
  chart.className = "hourly-chart";
  const peak = Math.max(...hours.map((hour) => hour.txBytes + hour.rxBytes));
  hours.forEach((hour) => {
    const total = hour.txBytes + hour.rxBytes;
    const bar = document.createElement("div");
    const level = Math.max(1, Math.ceil(total / peak * 10));
    bar.className = `hour-bar level-${level}`;
    bar.title = `${new Date(hour.hour).toLocaleString("zh-CN", { timeZone: rangeTimezone })} · ${formatBytes(total)}`;
    chart.appendChild(bar);
  });
}

function renderRangeBreakdown(data) {
  const body = document.querySelector("#range-breakdown");
  if (!body) return;
  body.replaceChildren();
  const entries = [
    ...data.users.map((item) => ({ ...item, kind: "用户", egress: item.egressBytes })),
    ...data.nodes.map((item) => ({ ...item, kind: "节点", egress: item.egressBytes })),
  ];
  if (!entries.length) {
    const row = document.createElement("tr");
    const cell = appendCell(row, "所选范围暂无流量");
    cell.colSpan = 6;
    cell.className = "empty-state";
    body.appendChild(row);
    return;
  }
  entries.forEach((item) => {
    const row = document.createElement("tr");
    appendCell(row, item.kind);
    appendCell(row, item.name);
    [item.txBytes, item.rxBytes, item.txBytes + item.rxBytes, item.egress].forEach((value) => {
      const cell = appendCell(row, formatBytes(value));
      cell.dataset.sortValue = String(value);
    });
    body.appendChild(row);
  });
}

async function queryTrafficRange() {
  if (!rangeForm || !rangeForm.reportValidity()) return;
  const query = new URLSearchParams({ start: rangeForm.elements.start.value, end: rangeForm.elements.end.value });
  const response = await fetch(`/traffic-range?${query}`, { cache: "no-store", headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error(await response.text());
  const data = await response.json();
  const gateway = data.total.txBytes + data.total.rxBytes;
  const peak = data.hours.reduce((best, hour) => hour.txBytes + hour.rxBytes > best.txBytes + best.rxBytes ? hour : best, { txBytes: 0, rxBytes: 0 });
  setText("#range-gateway", formatBytes(gateway));
  setText("#range-node", formatBytes(data.nodeEgressBytes));
  setText("#range-peak", formatBytes(peak.txBytes + peak.rxBytes));
  setText("#range-peak-time", peak.hour ? new Date(peak.hour).toLocaleString("zh-CN", { timeZone: data.timezone }) : "无流量");
  renderHourlyChart(data.hours || []);
  renderRangeBreakdown(data);
}

document.querySelectorAll("[data-range-preset]").forEach((button) => {
  button.addEventListener("click", () => {
    setRangePreset(button.dataset.rangePreset);
    queryTrafficRange().catch((error) => setText("#range-peak-time", error.message));
  });
});
rangeForm?.addEventListener("submit", (event) => {
  event.preventDefault();
  queryTrafficRange().catch((error) => setText("#range-peak-time", error.message));
});
setRangePreset("day");
queryTrafficRange().catch((error) => setText("#range-peak-time", error.message));
