"""
-----------------------------------------------------------------------------
PROJ     : NetPulse-Audit (Network Intelligence Suite)
VER      : 9.9.9 [Stable]
AUTHOR   : Nosrat Jahan
ACADEMIC : BSc in Computer Science & Engineering
-----------------------------------------------------------------------------
"""

import os
import socket
import psutil
import logging
import webbrowser
from flask import Flask, render_template_string, jsonify

# Global Config & Logging
app = Flask(__name__)

# Custom log format for a more professional terminal output
logging.basicConfig(
    level=logging.INFO, 
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    datefmt='%H:%M:%S'
)
audit_log = logging.getLogger("NetPulse")

class TelemetryEngine:
    """
    Handles low-level hardware abstraction and socket-level reconnaissance.
    """
    
    def __init__(self):
        audit_log.info("Initializing Telemetry Engine...")

    def get_network_footprint(self):
        """
        Scans for active IPv4/IPv6 established connections.
        """
        established_nodes = []
        try:
            # Querying system net-stats
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == 'ESTABLISHED':
                    # Building endpoint mapping
                    local = f"{conn.laddr.ip}:{conn.laddr.port}"
                    remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                    
                    established_nodes.append({
                        "proto": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                        "l_addr": local,
                        "r_addr": remote,
                        "process_id": conn.pid or "System"
                    })
        except (PermissionError, Exception) as e:
            audit_log.error(f"Failed to pull socket data: {str(e)}")
            
        return established_nodes

    def perform_integrity_check(self):
        """
        Run heuristic checks on CPU load and entry points.
        """
        current_load = psutil.cpu_percent(interval=None)
        return {
            "entry_points": len(psutil.net_connections()),
            "utilization": f"{current_load}%",
            "health_index": "OPTIMAL" if current_load < 80 else "WARNING",
            "active_users": len(psutil.users())
        }

# Logic Instance
engine = TelemetryEngine()

# --- Dashboard UI (Industrial Dark Aesthetics) ---

DASHBOARD_UI = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>NetPulse | Network Intelligence</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@500;700&family=Inter:wght@400;700;900&display=swap');
        
        :root {
            --bg: #050608; --panel: #0d1117; --accent: #00ff41;
            --warn: #ff3e3e; --text: #f1f5f9; --border: #1f2937;
        }

        body {
            background: var(--bg); color: var(--text);
            font-family: 'Inter', sans-serif; margin: 0; padding: 50px;
            display: flex; flex-direction: column; align-items: center;
        }

        .container {
            width: 100%; max-width: 1100px; background: var(--panel);
            border: 1px solid var(--border); border-radius: 12px; padding: 40px;
            box-shadow: 0 40px 100px rgba(0,0,0,0.8);
        }

        .header { border-left: 4px solid var(--accent); padding-left: 20px; margin-bottom: 40px; }
        .header h1 { font-size: 1.8rem; font-weight: 900; color: var(--accent); margin: 0; letter-spacing: 1px; }

        .metrics { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }
        .card { background: #000; border: 1px solid var(--border); padding: 25px; border-radius: 8px; text-align: center; }
        .card span { font-size: 0.75rem; color: #6b7280; text-transform: uppercase; font-weight: 700; }
        .card b { display: block; font-family: 'JetBrains Mono'; font-size: 1.8rem; color: var(--accent); margin-top: 10px; }

        .console { 
            margin-top: 40px; background: #000; border: 1px solid var(--border); 
            padding: 20px; border-radius: 8px; font-family: 'JetBrains Mono'; 
            font-size: 0.85rem; height: 350px; overflow-y: auto; color: #9ca3af;
        }
        .log-entry { margin-bottom: 10px; padding-bottom: 8px; border-bottom: 1px solid #111; }
        .log-entry b { color: var(--accent); }

        footer { margin-top: 50px; text-align: center; color: #4b5563; font-weight: 700; font-size: 0.9rem; }
    </style>
</head>
<body>

    <div class="container">
        <div class="header">
            <h1>NETPULSE AUDIT <small style="font-size: 10px; vertical-align: middle; opacity: 0.5;">V9.9.9</small></h1>
            <p style="color:#4b5563; font-size:12px; font-weight:700; margin-top:5px;">SYSTEM TELEMETRY & NETWORK RECONNAISSANCE</p>
        </div>

        <div class="metrics">
            <div class="card"><span>Active Nodes</span><b id="m_nodes">0</b></div>
            <div class="card"><span>System Health</span><b id="m_health">SCANNING</b></div>
            <div class="card"><span>Processor Load</span><b id="m_load">0%</b></div>
        </div>

        <div class="console" id="terminal">
            </div>
    </div>

    <footer>
        Developed by <b>Nosrat Jahan</b> | BSc in Computer Science & Engineering | <b>2026</b>
    </footer>

    <script>
        async function refreshTelemetry() {
            try {
                const res = await fetch('/api/v1/telemetry');
                const data = await res.json();
                
                document.getElementById('m_nodes').innerText = data.stats.entry_points;
                document.getElementById('m_load').innerText = data.stats.utilization;
                
                const health = document.getElementById('m_health');
                health.innerText = data.stats.health_index;
                health.style.color = data.stats.health_index === 'WARNING' ? 'var(--warn)' : 'var(--accent)';
                
                const console = document.getElementById('terminal');
                console.innerHTML = data.nodes.map(n => `
                    <div class="log-entry">
                        [<b>${n.proto}</b>] PID: ${n.process_id} | ${n.l_addr} <span style="color:#444;">>></span> <b>${n.r_addr}</b>
                    </div>
                `).join('');
            } catch (err) {
                console.log("Telemetry Sync Failed.");
            }
        }
        setInterval(refreshTelemetry, 3000);
    </script>
</body>
</html>
"""

# --- Controller Handlers ---

@app.route("/")
def dashboard():
    return render_template_string(DASHBOARD_UI)

@app.route("/api/v1/telemetry")
def stream_telemetry():
    """
    API endpoint for real-time system audit data.
    """
    return jsonify({
        "nodes": engine.get_network_footprint(),
        "stats": engine.perform_integrity_check()
    })

if __name__ == "__main__":
    PORT = 8080
    audit_log.info(f"System audit engine live on port {PORT}")
    webbrowser.open(f"http://127.0.0.1:{PORT}")
    app.run(port=PORT, debug=False)
