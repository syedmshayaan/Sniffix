# ============================================================
# app.py — Sniffix Main Server
# ============================================================

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from scanner.network import scan_network
from scanner.portscan import scan_device

# ============================================================
# APP SETUP
# ============================================================

app = Flask(__name__)
app.config["SECRET_KEY"] = "sniffix-secret"

# async_mode="threading" avoids eventlet monkey-patching issues
# that cause background tasks to silently drop emitted events
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


# ============================================================
# HTTP ROUTES
# ============================================================

@app.route("/")
def index():
    """Serves the main UI page."""
    return render_template("index.html")


@app.route("/api/scan-network", methods=["GET"])
def api_scan_network():
    """
    Runs ARP scan and returns discovered devices as JSON.
    Called when user clicks 'Scan Network'.
    """
    try:
        devices = scan_network()
        return jsonify({ "success": True, "devices": devices })
    except Exception as e:
        print(f"[!] Network scan error: {e}")
        return jsonify({ "success": False, "error": str(e) }), 500


@app.route("/api/scan-device", methods=["POST"])
def api_scan_device():
    """
    Starts a port scan on the target IP in a background task.
    Returns immediately — results come back via WebSocket.
    """
    data = request.get_json()

    if not data or "ip" not in data:
        return jsonify({ "success": False, "error": "No IP provided." }), 400

    target_ip = data["ip"]
    print(f"[*] Scan request received for: {target_ip}")

    # socketio.start_background_task is the correct way to run
    # background jobs with Flask-SocketIO — it works with all async modes
    socketio.start_background_task(run_scan, target_ip)

    return jsonify({ "success": True, "message": f"Scan started for {target_ip}" })


# ============================================================
# BACKGROUND SCAN TASK
# ============================================================

def run_scan(ip_address):
    """
    Runs the port scan and emits results via WebSocket.
    broadcast=True ensures the event reaches all connected clients
    regardless of which socket context started this task.
    """
    print(f"[*] Background scan starting for {ip_address}")
    socketio.emit("scan_started", { "ip": ip_address })

    try:
        result = scan_device(ip_address, socketio=socketio)
        print(f"[+] Emitting scan_complete for {ip_address}")
        socketio.emit("scan_complete", result)

    except Exception as e:
        print(f"[!] Scan failed for {ip_address}: {e}")
        socketio.emit("scan_error", { "ip": ip_address, "error": str(e) })


# ============================================================
# WEBSOCKET EVENTS
# ============================================================

@socketio.on("connect")
def on_connect():
    print("[+] Client connected.")
    emit("connected", { "message": "Connected to Sniffix server." })

@socketio.on("disconnect")
def on_disconnect():
    print("[-] Client disconnected.")


# ============================================================
# START SERVER
# ============================================================

if __name__ == "__main__":
    print("=" * 50)
    print("  Sniffix — Network Port Scanner")
    print("  http://localhost:5000")
    print("  Run with: sudo python3 app.py")
    print("=" * 50)
    socketio.run(app, debug=False, host="0.0.0.0", port=5000)
