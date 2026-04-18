# ============================================================
# app.py
# ============================================================
# This is the MAIN entry point of the Sniffix application.
#
# It does two things:
#   1. Acts as a web server (using Flask) that serves the UI
#      and handles API requests from the browser.
#   2. Uses WebSockets (via Flask-SocketIO) to push real-time
#      scan progress updates to the browser.
#
# FLASK BASICS (for context):
#   Flask is a lightweight Python web framework — similar to
#   Express.js in the MERN stack. Instead of app.get() and
#   app.post(), Flask uses @app.route() decorators.
#
# WEBSOCKETS (for context):
#   Normal HTTP is "ask and answer" — the browser asks, server replies.
#   WebSockets are a persistent two-way connection — the server can
#   PUSH data to the browser at any time. We use this to stream
#   scan progress live instead of making the user wait with a blank screen.
# ============================================================

from flask import Flask, render_template, jsonify, request
# Flask        — the web framework
# render_template — serves HTML files from the /templates folder
# jsonify      — converts Python dicts to JSON responses (like res.json() in Express)
# request      — lets us read incoming request data (like req.body in Express)

from flask_socketio import SocketIO, emit
# SocketIO     — adds WebSocket support to Flask
# emit         — sends a WebSocket event to the connected browser

import threading
# threading    — lets us run the port scan in a background thread
#                so the server doesn't freeze while scanning

from scanner.network import scan_network      # Our ARP network discovery function
from scanner.portscan import scan_device      # Our nmap port scanning function

# ============================================================
# APP SETUP
# ============================================================

app = Flask(__name__)                         # Create the Flask app
app.config["SECRET_KEY"] = "sniffix-secret"  # Required by Flask-SocketIO for session security

# Initialize SocketIO with eventlet for async support
# cors_allowed_origins="*" allows the browser to connect from any origin
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="eventlet")


# ============================================================
# ROUTES (HTTP endpoints — like Express routes)
# ============================================================

@app.route("/")
def index():
    """
    Serves the main HTML page when the user opens the app in their browser.
    Flask looks for index.html inside the /templates folder automatically.
    This is equivalent to: app.get("/", (req, res) => res.sendFile("index.html"))
    """
    return render_template("index.html")


@app.route("/api/scan-network", methods=["GET"])
def api_scan_network():
    """
    API endpoint that triggers a network scan and returns
    the list of discovered devices as JSON.

    The browser calls this when the user clicks "Scan Network".

    Returns JSON like:
    {
        "success": true,
        "devices": [
            { "ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "hostname": "router.local" },
            ...
        ]
    }
    """
    try:
        devices = scan_network()   # Runs ARP scan (from scanner/network.py)
        return jsonify({ "success": True, "devices": devices })

    except Exception as e:
        # If something goes wrong (e.g. not running as root), return an error
        print(f"[!] Network scan error: {e}")
        return jsonify({ "success": False, "error": str(e) }), 500


@app.route("/api/scan-device", methods=["POST"])
def api_scan_device():
    """
    API endpoint that starts a port scan on a specific device.

    The browser sends a POST request with the target IP:
        { "ip": "192.168.1.5" }

    Because port scanning can take 30–90 seconds, we run it in a
    BACKGROUND THREAD and stream results back via WebSocket.
    This way the browser doesn't sit waiting for an HTTP response.

    Returns JSON immediately:
        { "success": true, "message": "Scan started" }

    Then the actual results come through WebSocket events.
    """
    data = request.get_json()           # Parse the JSON body of the POST request

    if not data or "ip" not in data:
        return jsonify({ "success": False, "error": "No IP address provided." }), 400

    target_ip = data["ip"]
    print(f"[*] Received scan request for: {target_ip}")

    # Run the scan in a background thread so Flask can immediately return a response
    # The thread will emit WebSocket events as the scan progresses
    thread = threading.Thread(target=run_scan_in_background, args=(target_ip,))
    thread.daemon = True                # Daemon thread = dies when main program exits
    thread.start()

    return jsonify({ "success": True, "message": f"Scan started for {target_ip}" })


# ============================================================
# BACKGROUND SCAN + WEBSOCKET EVENTS
# ============================================================

def run_scan_in_background(ip_address):
    """
    Runs the port scan in a separate thread and emits
    WebSocket events to update the browser in real-time.

    WebSocket events emitted:
        "scan_started"   — tells the UI to show a loading state
        "scan_complete"  — sends the full results to the UI
        "scan_error"     — sends an error message if something fails
    """

    # Emit "scan_started" so the UI can show a spinner/progress indicator
    socketio.emit("scan_started", { "ip": ip_address })
    print(f"[*] Background scan started for {ip_address}")

    try:
        # Run the actual nmap scan (this is the slow part — can take ~60 seconds)
        result = scan_device(ip_address, socketio=socketio)

        # Once done, emit the results to the browser via WebSocket
        # The browser listens for "scan_complete" and renders the results
        socketio.emit("scan_complete", result)
        print(f"[+] Scan complete for {ip_address}, results emitted.")

    except Exception as e:
        # If the scan crashes for any reason, let the browser know
        print(f"[!] Scan error for {ip_address}: {e}")
        socketio.emit("scan_error", { "ip": ip_address, "error": str(e) })


# ============================================================
# WEBSOCKET CONNECTION HANDLERS
# ============================================================

@socketio.on("connect")
def on_connect():
    """
    Fires when a browser client connects via WebSocket.
    Just logs it — useful for debugging.
    """
    print("[+] Client connected via WebSocket.")
    emit("connected", { "message": "Connected to Sniffix server." })


@socketio.on("disconnect")
def on_disconnect():
    """
    Fires when a browser client disconnects.
    """
    print("[-] Client disconnected.")


# ============================================================
# START THE SERVER
# ============================================================

if __name__ == "__main__":
    print("=" * 50)
    print("  Sniffix — Network Port Scanner")
    print("  Running at http://localhost:5000")
    print("  Run with: sudo python app.py")
    print("=" * 50)

    # debug=True  — auto-restarts server on code changes (like nodemon)
    # host="0.0.0.0" — makes the server accessible on all network interfaces
    socketio.run(app, debug=True, host="0.0.0.0", port=5000)
