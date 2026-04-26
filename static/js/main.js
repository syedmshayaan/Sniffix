// ============================================================
// main.js — Sniffix Frontend Logic
// ============================================================
// All client-side JavaScript for the Sniffix application.
// Loaded by index.html via:
//   <script src="/static/js/main.js"></script>
//
// Responsibilities:
//   1. Connect to Flask-SocketIO via WebSocket
//   2. Handle "Scan Network" — fetch devices, render table
//   3. Handle device selection
//   4. Handle "Scan Ports" — POST to server, show progress
//   5. Listen for WebSocket events and render results
//   6. Log all activity to the console panel
// ============================================================


// ============================================================
// STATE — tracks what the user has selected
// ============================================================
let selectedIP = null;    // The IP address the user clicked on
let isScanning = false;   // Prevents double-clicking scan buttons


// ============================================================
// WEBSOCKET SETUP
// ============================================================

// Connect to the Flask-SocketIO server.
// By default it connects to the same host that served the page.
const socket = io();

// Fires when the WebSocket connection is established
socket.on("connect", () => {
  log("WebSocket connected to Sniffix server.", "ok");
  document.getElementById("status-dot").classList.add("connected");
  document.getElementById("status-text").textContent = "CONNECTED";
});

// Fires when disconnected
socket.on("disconnect", () => {
  log("WebSocket disconnected.", "error");
  document.getElementById("status-dot").classList.remove("connected");
  document.getElementById("status-text").textContent = "DISCONNECTED";
});

// Server confirmed it received our connection
socket.on("connected", (data) => {
  log(data.message, "accent");
});

// Server says the scan has begun
socket.on("scan_started", (data) => {
  log(`Port scan initiated on ${data.ip}...`, "accent");
});

// Live progress updates emitted by portscan.py during the scan
socket.on("scan_progress", (data) => {
  log(data.message, "info");
  // Update the progress bar label with live feedback
  const label = document.querySelector(".progress-label");
  if (label) label.textContent = data.message.toUpperCase();
});

// Server finished the scan and sent back results
socket.on("scan_complete", (data) => {
  log(`Scan complete for ${data.ip}.`, "ok");
  hideProgress();
  renderResults(data);
  isScanning = false;
});

// Something went wrong during the scan
socket.on("scan_error", (data) => {
  log(`Scan error: ${data.error}`, "error");
  showScanError(data.error);
  hideProgress();
  isScanning = false;
});


// ============================================================
// NETWORK SCAN — Step 1
// ============================================================

async function startNetworkScan() {
  /*
    Called when the user clicks "Scan Network".
    Sends a GET request to /api/scan-network.
    On success, populates the device table.
  */

  if (isScanning) return;
  isScanning = true;

  // Reset UI
  document.getElementById("btn-scan-network").disabled = true;
  document.getElementById("scan-status-text").innerHTML =
    `<span class="spinner-wrap"><span class="spinner"></span> scanning network...</span>`;
  document.getElementById("network-error").style.display = "none";
  document.getElementById("device-tbody").innerHTML =
    `<tr><td colspan="4" class="table-empty">
       <span class="spinner-wrap" style="justify-content:center">
         <span class="spinner"></span> sending ARP broadcast...
       </span>
     </td></tr>`;

  log("Starting ARP network scan...", "accent");

  try {
    const response = await fetch("/api/scan-network");
    const data     = await response.json();

    if (!data.success) throw new Error(data.error || "Unknown error");

    log(`Network scan complete. Found ${data.devices.length} device(s).`, "ok");
    renderDeviceTable(data.devices);

  } catch (err) {
    log(`Network scan failed: ${err.message}`, "error");
    document.getElementById("network-error").textContent = `Error: ${err.message}`;
    document.getElementById("network-error").style.display = "block";
    document.getElementById("device-tbody").innerHTML =
      `<tr><td colspan="4" class="table-empty">scan failed — see error above</td></tr>`;
  }

  document.getElementById("btn-scan-network").disabled = false;
  document.getElementById("scan-status-text").textContent = "— scan complete";
  isScanning = false;
}


// ============================================================
// RENDER DEVICE TABLE
// ============================================================

function renderDeviceTable(devices) {
  /*
    Takes the array of devices from the API and builds
    HTML table rows dynamically.
  */
  const tbody = document.getElementById("device-tbody");

  if (devices.length === 0) {
    tbody.innerHTML =
      `<tr><td colspan="4" class="table-empty">no devices found on this subnet</td></tr>`;
    return;
  }

  tbody.innerHTML = "";

  devices.forEach((device, index) => {
    const tr = document.createElement("tr");
    tr.className = "device-row";
    tr.style.animationDelay = `${index * 0.06}s`;   // Stagger row reveal

    tr.innerHTML = `
      <td class="td-ip">${device.ip}</td>
      <td class="td-mac">${device.mac}</td>
      <td class="td-hostname">${device.hostname}</td>
      <td>
        <button class="btn" style="padding:4px 14px; font-size:11px"
          onclick="selectDevice('${device.ip}', this)">
          <span>Select</span>
        </button>
      </td>
    `;

    tbody.appendChild(tr);
  });

  log(`Rendered ${devices.length} device(s) in the table.`, "info");
}


// ============================================================
// DEVICE SELECTION
// ============================================================

function selectDevice(ip, buttonEl) {
  /*
    Called when user clicks "Select" on a device row.
    Highlights the row and enables the port scan button.
  */

  selectedIP = ip;

  // Remove "selected" from all rows, highlight this one
  document.querySelectorAll("#device-tbody tr").forEach(r => r.classList.remove("selected"));
  buttonEl.closest("tr").classList.add("selected");

  // Update target label
  document.getElementById("selected-target-label").innerHTML =
    `TARGET: <span>${ip}</span>`;

  // Enable port scan button
  document.getElementById("btn-scan-ports").disabled = false;

  // Hide old results and errors
  document.getElementById("results-section").style.display = "none";
  document.getElementById("scan-error").style.display     = "none";

  log(`Selected target: ${ip}`, "accent");
}


// ============================================================
// PORT SCAN — Step 2
// ============================================================

async function startPortScan() {
  /*
    Called when the user clicks "Scan Ports".
    POSTs the selected IP to /api/scan-device.
    Actual results come back later via WebSocket.
  */

  if (!selectedIP || isScanning) return;
  isScanning = true;

  showProgress();
  document.getElementById("results-section").style.display = "none";
  document.getElementById("scan-error").style.display      = "none";
  document.getElementById("btn-scan-ports").disabled       = true;

  log(`Initiating port scan on ${selectedIP}...`, "accent");

  try {
    const response = await fetch("/api/scan-device", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ ip: selectedIP })
    });

    const data = await response.json();

    if (!data.success) throw new Error(data.error || "Unknown error");

    log(`Server acknowledged scan request for ${selectedIP}.`, "ok");

  } catch (err) {
    log(`Failed to start port scan: ${err.message}`, "error");
    showScanError(err.message);
    hideProgress();
    document.getElementById("btn-scan-ports").disabled = false;
    isScanning = false;
  }
}


// ============================================================
// RENDER RESULTS
// ============================================================

function renderResults(data) {
  /*
    Renders device info cards and open ports table
    using data from the "scan_complete" WebSocket event.
  */

  const section = document.getElementById("results-section");
  section.style.display = "block";
  section.scrollIntoView({ behavior: "smooth", block: "start" });

  // --- Device Info Cards ---
  const cards = [
    { label: "IP Address",  value: data.ip,      highlight: true  },
    { label: "Hostname",    value: data.hostname, highlight: false },
    { label: "OS Guess",    value: data.os,       highlight: false },
    { label: "MAC Address", value: data.mac,      highlight: false },
    { label: "NIC Vendor",  value: data.vendor,   highlight: false },
  ];

  document.getElementById("info-cards").innerHTML = cards.map(card => `
    <div class="info-card">
      <div class="info-card-label">${card.label}</div>
      <div class="info-card-value ${card.highlight ? 'highlight' : ''}">
        ${card.value || "—"}
      </div>
    </div>
  `).join("");

  // --- Open Ports Table ---
  const tbody = document.getElementById("ports-tbody");
  const ports = data.ports || [];

  document.getElementById("port-count-badge").textContent = `${ports.length} OPEN`;

  if (ports.length === 0) {
    tbody.innerHTML =
      `<tr><td colspan="5" class="table-empty">no open ports found</td></tr>`;
  } else {
    tbody.innerHTML = ports.map((p, i) => `
      <tr class="port-row" style="animation-delay:${i * 0.05}s">
        <td><span class="port-pill">${p.port}</span></td>
        <td class="td-protocol">${p.protocol.toUpperCase()}</td>
        <td><span class="state-open">● OPEN</span></td>
        <td class="td-service">${p.service || "—"}</td>
        <td class="td-version">${p.version  || "—"}</td>
      </tr>
    `).join("");
  }

  document.getElementById("btn-scan-ports").disabled = false;
  log(`Results rendered: ${ports.length} open port(s) on ${data.ip}.`, "ok");
}


// ============================================================
// HELPERS
// ============================================================

function showProgress() {
  document.getElementById("progress-wrap").style.display = "block";
}

function hideProgress() {
  document.getElementById("progress-wrap").style.display = "none";
}

function showScanError(message) {
  const el = document.getElementById("scan-error");
  el.textContent  = `Scan error: ${message}`;
  el.style.display = "block";
}

function log(message, type = "info") {
  /*
    Appends a timestamped line to the activity log console.
    type: "info" | "ok" | "warn" | "error" | "accent"
  */
  const console_el = document.getElementById("log-console");
  const timestamp  = new Date().toLocaleTimeString("en-GB");   // HH:MM:SS

  const line = document.createElement("div");
  line.className   = `log-line ${type}`;
  line.textContent = `[${timestamp}] ${message}`;

  console_el.appendChild(line);
  console_el.scrollTop = console_el.scrollHeight;   // Auto-scroll to bottom
}
