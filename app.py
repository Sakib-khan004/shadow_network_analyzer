"""
Shadow Network Analyzer
------------------------
A real-time network packet analyzer with a live web dashboard.

Run:
    sudo ./fix_mac_permissions.sh  (Run once on macOS to enable non-root packet capture)
    ./venv/bin/python app.py       (Start Flask web dashboard)

Then open: http://127.0.0.1:5000
"""

from flask import Flask, jsonify, request, Response, render_template

from capture_engine import CaptureEngine

app = Flask(__name__)
engine = CaptureEngine()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/interfaces")
def api_interfaces():
    return jsonify({"interfaces": engine.available_interfaces()})


@app.route("/api/start", methods=["POST"])
def api_start():
    data = request.get_json(silent=True) or {}
    interface = data.get("interface") or None
    bpf_filter = data.get("filter") or None
    ok = engine.start(interface=interface, bpf_filter=bpf_filter)
    if not ok:
        return jsonify({"status": "already_running"}), 200
    return jsonify({"status": "started", "interface": interface})


@app.route("/api/stop", methods=["POST"])
def api_stop():
    ok = engine.stop()
    return jsonify({"status": "stopped" if ok else "was_not_running"})


@app.route("/api/reset", methods=["POST"])
def api_reset():
    engine.reset()
    return jsonify({"status": "reset"})


@app.route("/api/packets")
def api_packets():
    protocol = request.args.get("protocol", "ALL")
    ip = request.args.get("ip", "").strip()
    limit = int(request.args.get("limit", 250))
    return jsonify({"packets": engine.get_packets(protocol=protocol, ip=ip, limit=limit)})


@app.route("/api/packet/<int:pkt_id>")
def api_packet_detail(pkt_id):
    pkt = engine.get_packet_by_id(pkt_id)
    if not pkt:
        return jsonify({"error": "Packet not found"}), 404
    return jsonify(pkt)


@app.route("/api/stats")
def api_stats():
    return jsonify(engine.get_stats())


@app.route("/api/alerts")
def api_alerts():
    return jsonify({"alerts": engine.get_alerts()})


@app.route("/api/export")
def api_export():
    csv_data = engine.export_csv()
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=shadow_network_capture.csv"},
    )


if __name__ == "__main__":
    print("=" * 60)
    print(" 🕶️ SHADOW NETWORK ANALYZER")
    print(" Dashboard: http://127.0.0.1:5000")
    print("============================================================")
    app.run(debug=False, host="127.0.0.1", port=5000)
