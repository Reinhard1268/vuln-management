# app.py

import os
import logging
from datetime import datetime
from flask import Flask, jsonify, request, abort
from flask_cors import CORS
from dotenv import load_dotenv

from database import Database
from risk_scorer import RiskScorer

load_dotenv()

app = Flask(__name__)
CORS(app)
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

DB_PATH = os.getenv("DATABASE_PATH", "dashboard/backend/vulndb.sqlite")
db      = Database(DB_PATH)
scorer  = RiskScorer()


@app.before_request
def log_request():
    logger.info(f"{request.method} {request.path} - {request.remote_addr}")


@app.errorhandler(400)
def bad_request(e):
    return jsonify({"error": "Bad request", "message": str(e)}), 400


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def server_error(e):
    logger.error(f"Server error: {e}")
    return jsonify({"error": "Internal server error"}), 500


# ── Vulnerabilities ────────────────────────────────────────────────────────────

@app.route("/api/vulnerabilities", methods=["GET"])
def get_vulnerabilities():
    severity  = request.args.get("severity")
    host      = request.args.get("host")
    source    = request.args.get("source")
    status    = request.args.get("status")
    limit     = int(request.args.get("limit",  50))
    offset    = int(request.args.get("offset",  0))

    filters = {}
    if severity: filters["severity"] = severity
    if host:     filters["host"]     = host
    if source:   filters["source"]   = source
    if status:   filters["status"]   = status

    vulns = db.get_vulnerabilities(filters=filters, limit=limit, offset=offset)
    total = db.count_vulnerabilities(filters=filters)

    return jsonify({
        "total":  total,
        "limit":  limit,
        "offset": offset,
        "data":   vulns,
    })


@app.route("/api/vulnerabilities/<vuln_id>", methods=["GET"])
def get_vulnerability(vuln_id):
    vuln = db.get_vulnerability_by_id(vuln_id)
    if not vuln:
        abort(404)
    return jsonify(vuln)


@app.route("/api/vulnerabilities/<vuln_id>/status", methods=["POST"])
def update_status(vuln_id):
    body   = request.get_json(force=True)
    status = body.get("status", "")
    valid  = {"open", "in-progress", "resolved", "accepted"}
    if status not in valid:
        abort(400, description=f"status must be one of: {valid}")
    db.update_vulnerability_status(vuln_id, status)
    return jsonify({"id": vuln_id, "status": status, "updated_at": datetime.utcnow().isoformat()})


# ── Stats ──────────────────────────────────────────────────────────────────────

@app.route("/api/stats", methods=["GET"])
def get_stats():
    return jsonify(db.get_stats())


@app.route("/api/risk-scores", methods=["GET"])
def get_risk_scores():
    limit  = int(request.args.get("limit", 50))
    vulns  = db.get_vulnerabilities(filters={"status": "open"}, limit=limit, offset=0)
    scored = scorer.batch_score(vulns)
    return jsonify({"total": len(scored), "data": scored})


# ── Reports ────────────────────────────────────────────────────────────────────

@app.route("/api/reports/summary", methods=["GET"])
def get_report_summary():
    stats  = db.get_stats()
    top10  = db.get_vulnerabilities(filters={"status": "open"}, limit=10, offset=0)
    scored = scorer.batch_score(top10)
    return jsonify({
        "generated_at":    datetime.utcnow().isoformat(),
        "overall_stats":   stats,
        "top_10_priority": scored[:10],
    })


# ── TheHive ────────────────────────────────────────────────────────────────────

@app.route("/api/thehive/tickets", methods=["GET"])
def get_thehive_tickets():
    tickets = db.get_thehive_tickets()
    return jsonify({"total": len(tickets), "data": tickets})


# ── Scan History ───────────────────────────────────────────────────────────────

@app.route("/api/scans", methods=["GET"])
def get_scans():
    scans = db.get_scan_history()
    return jsonify({"total": len(scans), "data": scans})


# ── Docs ───────────────────────────────────────────────────────────────────────

@app.route("/api/docs", methods=["GET"])
def api_docs():
    return jsonify({
        "version": "1.0.0",
        "endpoints": [
            {"method": "GET",  "path": "/api/vulnerabilities",             "description": "List vulnerabilities with filters"},
            {"method": "GET",  "path": "/api/vulnerabilities/<id>",        "description": "Get single vulnerability"},
            {"method": "POST", "path": "/api/vulnerabilities/<id>/status", "description": "Update vulnerability status"},
            {"method": "GET",  "path": "/api/stats",                       "description": "Aggregated statistics"},
            {"method": "GET",  "path": "/api/risk-scores",                 "description": "Prioritized vuln list with risk scores"},
            {"method": "GET",  "path": "/api/reports/summary",             "description": "Executive summary data"},
            {"method": "GET",  "path": "/api/thehive/tickets",             "description": "TheHive linked tickets"},
            {"method": "GET",  "path": "/api/scans",                       "description": "Scan history"},
        ]
    })


if __name__ == "__main__":
    db.init_db()
    db.seed_sample_data()
    port = int(os.getenv("DASHBOARD_PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
