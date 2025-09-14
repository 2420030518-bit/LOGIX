# app.py
import os
from flask import (
    Flask, render_template, request, send_file,
    make_response, flash, redirect, url_for
)
from werkzeug.utils import secure_filename
from datetime import datetime
import analyzer as analyzer_module

# Configuration
UPLOAD_FOLDER = "uploads"
REPORTS_FOLDER = "reports"
ALLOWED_EXT = {"log", "txt", "evtx"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

app = Flask(__name__)
app.secret_key = "change_this_secret_in_prod"

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

# Home / Upload (log -> analysis)
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

# User guide page (webpage — no download)
from flask import redirect

@app.route("/user-guide", methods=["GET"])
def user_guide():
    # Redirect server-side to the YouTube guide (opens in same tab)
    return redirect("https://www.youtube.com/watch?v=TMpLx3SXuNk", code=302)


# original upload -> analyze -> solution page
@app.route("/upload", methods=["POST"])
def upload():
    if "logfile" not in request.files:
        flash("No file part")
        return redirect(url_for("index"))
    file = request.files["logfile"]
    if file.filename == "":
        flash("No selected file")
        return redirect(url_for("index"))
    if not allowed_file(file.filename):
        flash("Only .log, .txt, .evtx files allowed")
        return redirect(url_for("index"))

    safe_name = secure_filename(file.filename)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    upload_name = f"{ts}_{safe_name}"
    upload_path = os.path.join(UPLOAD_FOLDER, upload_name)
    file.save(upload_path)

    # Analyze (use analyzer module)
    try:
        res = analyzer_module.analyze_log(upload_path)
    except Exception as e:
        res = {"summary": "Analyzer error", "findings": [], "metadata": {"error": str(e)}}

    # Create text report (full)
    if isinstance(res, dict) and "findings" in res and hasattr(analyzer_module, "render_report_text"):
        report_text = analyzer_module.render_report_text(res)
    else:
        report_text = f"SUMMARY:\n{res.get('summary','No summary')}\n\nRAW OUTPUT:\n{repr(res)}\n"

    # Append beginner user guide file content if exists
    guide_path = os.path.join("static", "user_guide_windows.txt")
    if os.path.exists(guide_path):
        try:
            with open(guide_path, "r", encoding="utf-8") as g:
                guide_content = g.read()
            report_text += "\n\n" + "----- BEGIN BEGINNER WINDOWS LOG GUIDE -----\n\n"
            report_text += guide_content
            report_text += "\n\n" + "----- END BEGINNER WINDOWS LOG GUIDE -----\n"
        except Exception:
            report_text += "\n\n[Could not append user guide due to read error]\n"
    else:
        report_text += "\n\n[No local user guide found]\n"

    # Precautions summary
    precautions_text = """
IMMEDIATE PRECAUTIONS:
- If a compromise is suspected: disconnect the device from the network immediately.
- Preserve evidence: do not reboot the host if possible; collect logs/images only by trained personnel.
- Change passwords for affected accounts from a separate clean device.
"""
    report_text += precautions_text

    # Save report on disk
    report_name = f"Logix_report_{ts}_{safe_name}.txt"
    report_path = os.path.join(REPORTS_FOLDER, report_name)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    # Render solution page with parsed data and report download link
    return render_template(
        "solution.html",
        summary=res.get("summary", "No summary"),
        findings=res.get("findings", []),
        metadata=res.get("metadata", {}),
        report_name=report_name,
        report_text=report_text
    )

# Download saved report (used on solution page)
@app.route("/download/<path:report_name>", methods=["GET"])
def download_report(report_name):
    rp = os.path.join(REPORTS_FOLDER, report_name)
    if os.path.exists(rp):
        response = make_response(send_file(rp, as_attachment=True, download_name=report_name))
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
        return response
    else:
        flash("Report not found")
        return redirect(url_for("index"))

# ========== NEW: Want a solution page (upload an existing report or paste it) ==========
@app.route("/want-solution", methods=["GET", "POST"])
def want_solution():
    """
    GET: show a small form letting user upload a previously generated report (.txt)
         or paste the report text.
    POST: parse the submitted report text for signatures (using analyzer signatures)
          and render a page with attack-specific solutions.
    """
    if request.method == "GET":
        return render_template("want_solution.html")

    # POST: accept file upload or pasted text
    report_text = ""
    # If user uploaded a file:
    if "reportfile" in request.files and request.files["reportfile"].filename != "":
        rfile = request.files["reportfile"]
        try:
            report_text = rfile.read().decode("utf-8", errors="ignore")
        except Exception:
            report_text = ""
    # Or if user pasted text:
    if not report_text:
        report_text = request.form.get("report_text", "") or ""

    if not report_text.strip():
        flash("No report text uploaded or pasted.")
        return redirect(url_for("want_solution"))

    # Parse report_text for known signatures (use analyzer_module.SIGNATURES)
    found = []
    signatures = getattr(analyzer_module, "SIGNATURES", None)
    if signatures is None:
        # fallback: try to use findings names from analyzer output format
        # We'll do a simple substring match of known names
        signatures = []

    # For each signature, check if regex matches or name appears in report_text
    for s in signatures:
        sname = s.get("name", "")
        sid = s.get("id", "")
        matched_lines = []
        # check compiled regex patterns if present
        comps = s.get("compiled") or [__import__("re").compile(p, __import__("re").IGNORECASE) for p in s.get("regex", [])]
        for cre in comps:
            for ln in report_text.splitlines():
                if cre.search(ln):
                    matched_lines.append(ln.strip())
        # also check name mentions
        if not matched_lines and sname and sname.lower() in report_text.lower():
            # collect nearby lines containing the name
            for ln in report_text.splitlines():
                if sname.lower() in ln.lower():
                    matched_lines.append(ln.strip())

        if matched_lines:
            found.append({
                "id": sid,
                "name": sname,
                "remediation": s.get("remediation", []),
                "precaution": s.get("precaution", ""),
                "evidence": matched_lines[:20]
            })

    # If nothing matched, try heuristics: look for common keywords in report
    if not found:
        heur = {
            "brute_force": ["failed password", "failed login", "authentication failure"],
            "sql_injection": ["union select", "or '1'='1'", "sqlmap", "drop table"],
            "ransomware": ["encrypted", ".locked", "FILES.ENCRYPTED", "ransom"],
            "reverse_shell": ["/bin/bash -i", "dev/tcp", "reverse shell", "nc -e"]
        }
        for key, keywords in heur.items():
            for kw in keywords:
                if kw.lower() in report_text.lower():
                    # try to find signature entry in analyzer SIGNATURES for details
                    detail = next((x for x in signatures if x.get("id")==key), None)
                    found.append({
                        "id": detail.get("id") if detail else key,
                        "name": detail.get("name") if detail else key,
                        "remediation": detail.get("remediation", []) if detail else ["Investigate and isolate host."],
                        "precaution": detail.get("precaution","") if detail else "",
                        "evidence": [l for l in report_text.splitlines() if kw.lower() in l.lower()][:20]
                    })
                    break

    # Render a focused solution page
    return render_template("attack_solution.html", found=found, report_text=report_text)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
