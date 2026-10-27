from __future__ import annotations

import csv
import io
import os
import socket
import sqlite3
from datetime import datetime
from datetime import date, timedelta
from pathlib import Path

from flask import Flask, flash, g, redirect, render_template, request, session, url_for

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "flowguard.db"
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "flowguard-local-demo-key")

STAGES = ["Draft", "Scrutiny", "Re-scrutiny", "EVC", "SAC/SHC", "Closed"]
ROLES = ["System Administrator", "Institution User", "Regional Officer", "Bureau Officer", "EVC Coordinator", "Compliance Verifier", "Auditor"]
REGIONS = ["Northern", "Southern", "Eastern", "Western", "Central"]


def today(offset: int = 0) -> str:
    return (date.today() + timedelta(days=offset)).isoformat()


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_: object) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql: str, args: tuple = (), one: bool = False):
    rows = get_db().execute(sql, args).fetchall()
    return (rows[0] if rows else None) if one else rows


def init_db() -> None:
    db = sqlite3.connect(DATABASE)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS applications (
          id TEXT PRIMARY KEY, institution TEXT NOT NULL, type TEXT NOT NULL,
          region TEXT NOT NULL, stage TEXT NOT NULL, status TEXT NOT NULL,
          officer TEXT NOT NULL, submitted TEXT NOT NULL, due TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tasks (
          id INTEGER PRIMARY KEY AUTOINCREMENT, application_id TEXT NOT NULL,
          title TEXT NOT NULL, due TEXT NOT NULL, owner TEXT NOT NULL, done INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS activity (
          id INTEGER PRIMARY KEY AUTOINCREMENT, application_id TEXT NOT NULL,
          actor TEXT NOT NULL, text TEXT NOT NULL, created TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS evc (
          id INTEGER PRIMARY KEY AUTOINCREMENT, application_id TEXT NOT NULL,
          visit_date TEXT, coordinator TEXT, status TEXT NOT NULL, notes TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS compliance (
          id INTEGER PRIMARY KEY AUTOINCREMENT, institution TEXT NOT NULL,
          obligation TEXT NOT NULL, due TEXT NOT NULL, status TEXT NOT NULL,
          verifier TEXT NOT NULL, evidence TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS documents (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, category TEXT NOT NULL,
          institution TEXT NOT NULL, application_id TEXT NOT NULL, expires TEXT NOT NULL,
          verification TEXT NOT NULL
        );
        """
    )
    if db.execute("SELECT COUNT(*) FROM applications").fetchone()[0] == 0:
        institutions = ["Riverbend Institute of Technology", "Lakeview College of Engineering", "Sunrise Polytechnic", "Hillcrest School of Management", "Meridian Institute of Pharmacy"]
        statuses = [("Scrutiny", "In Progress"), ("EVC", "In Progress"), ("Scrutiny", "Returned"), ("Re-scrutiny", "In Progress"), ("Draft", "Draft"), ("SAC/SHC", "In Progress"), ("Closed", "Completed"), ("EVC", "In Progress")]
        for i, (stage, status) in enumerate(statuses):
            app_id = f"FG-2026-{101 + i}"
            submitted = today(-(i + 2) * 5)
            db.execute("INSERT INTO applications VALUES (?,?,?,?,?,?,?,?,?)", (app_id, institutions[i % len(institutions)], ["New Institution", "Increase in Intake", "New Course", "Extension of Approval"][i % 4], REGIONS[i % 5], stage, status, ["R. Sharma", "A. Menon", "S. Banerjee"][i % 3], submitted, today((i - 2) * 7)))
            db.execute("INSERT INTO activity(application_id,actor,text,created) VALUES (?,?,?,?)", (app_id, "System", "Application record initialized", submitted))
        db.executemany("INSERT INTO tasks(application_id,title,due,owner,done) VALUES (?,?,?,?,?)", [
            ("FG-2026-101", "Scrutinise land documents", today(-4), "R. Sharma", 0),
            ("FG-2026-103", "Applicant to resubmit affidavit", today(3), "Institution User", 0),
            ("FG-2026-104", "Re-scrutiny of faculty data", today(-1), "A. Menon", 0),
            ("FG-2026-106", "SAC review note", today(10), "K. Patil", 0),
        ])
        db.executemany("INSERT INTO evc(application_id,visit_date,coordinator,status,notes) VALUES (?,?,?,?,?)", [
            ("FG-2026-102", "", "", "Awaiting scheduling", ""),
            ("FG-2026-108", today(5), "M. Iyer", "Scheduled", ""),
        ])
        db.executemany("INSERT INTO compliance(institution,obligation,due,status,verifier,evidence) VALUES (?,?,?,?,?,?)", [
            (institutions[0], "Submit faculty recruitment plan", today(4), "Pending", "V. Rao", "Not submitted"),
            (institutions[1], "Fire safety certificate", today(20), "Submitted", "V. Rao", "Under review"),
            (institutions[2], "Library resources undertaking", today(-3), "Correction requested", "P. Nair", "Invoices unreadable"),
            (institutions[3], "Lab equipment installation", today(-30), "Verified", "V. Rao", "Accepted"),
        ])
        db.executemany("INSERT INTO documents(name,category,institution,application_id,expires,verification) VALUES (?,?,?,?,?,?)", [
            ("Land title deed", "Legal", institutions[0], "FG-2026-101", today(25), "Verified"),
            ("Fire NOC", "Safety", institutions[1], "FG-2026-102", today(-12), "Pending verification"),
            ("Society registration", "Legal", institutions[3], "FG-2026-106", today(300), "Verified"),
        ])
    db.commit()
    db.close()


init_db()


def safe_redirect_target(target: str | None) -> str:
    """Only allow login redirects to local application paths."""
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("dashboard")


@app.context_processor
def inject_globals():
    return {
        "today": date.today().isoformat(),
        "current_hour": datetime.now().hour,
        "stages": STAGES,
        "roles": ROLES,
        "current_user": session.get("user"),
    }


@app.before_request
def require_login():
    if request.endpoint not in {"login", "static", "health"} and "user" not in session:
        return redirect(url_for("login", next=request.full_path))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        name = request.form.get("name", "").strip() or "Demo User"
        role = request.form.get("role", ROLES[0])
        if role not in ROLES:
            role = ROLES[0]
        session["user"] = {"name": name[:60], "role": role}
        destination = safe_redirect_target(request.args.get("next"))
        return redirect(destination)
    if "user" in session:
        return redirect(url_for("dashboard"))
    return render_template("login.html", title="Sign in")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def dashboard():
    stats = {
        "applications": query("SELECT COUNT(*) n FROM applications", one=True)["n"],
        "active": query("SELECT COUNT(*) n FROM applications WHERE status='In Progress'", one=True)["n"],
        "tasks": query("SELECT COUNT(*) n FROM tasks WHERE done=0", one=True)["n"],
        "overdue": query("SELECT COUNT(*) n FROM tasks WHERE done=0 AND due < ?", (today(),), one=True)["n"],
        "evc": query("SELECT COUNT(*) n FROM evc WHERE status='Awaiting scheduling'", one=True)["n"],
        "compliance": query("SELECT COUNT(*) n FROM compliance WHERE status!='Verified' AND due BETWEEN ? AND ?", (today(), today(7)), one=True)["n"],
    }
    stage_counts = query("SELECT stage, COUNT(*) n FROM applications GROUP BY stage")
    upcoming = query("SELECT * FROM tasks WHERE done=0 ORDER BY due LIMIT 6")
    activity = query("SELECT * FROM activity ORDER BY id DESC LIMIT 6")
    return render_template("dashboard.html", title="Dashboard", stats=stats, stage_counts=stage_counts, upcoming=upcoming, activity=activity)


@app.route("/applications")
def applications():
    term = request.args.get("q", "").strip()
    status = request.args.get("status", "")
    where, args = [], []
    if term:
        where.append("(id LIKE ? OR institution LIKE ?)")
        args += [f"%{term}%", f"%{term}%"]
    if status:
        where.append("status=?")
        args.append(status)
    clause = f"WHERE {' AND '.join(where)}" if where else ""
    rows = query(f"SELECT * FROM applications {clause} ORDER BY id DESC", tuple(args))
    return render_template("applications.html", title="Applications", applications=rows, term=term, status=status)


@app.route("/applications/new", methods=["POST"])
def create_application():
    form = request.form
    institution = form.get("institution", "").strip()
    application_type = form.get("type", "").strip()
    region = form.get("region", "").strip()
    due = form.get("due", "").strip()
    if not institution or application_type not in {
        "New Institution",
        "Increase in Intake",
        "New Course",
        "Extension of Approval",
    } or region not in REGIONS:
        flash("Enter a valid institution, application type, and region.", "error")
        return redirect(url_for("applications"))
    try:
        datetime.strptime(due, "%Y-%m-%d")
    except ValueError:
        flash("Enter a valid due date.", "error")
        return redirect(url_for("applications"))
    app_id = f"FG-{date.today().year}-{query('SELECT COUNT(*) n FROM applications', one=True)['n'] + 101}"
    db = get_db()
    db.execute("INSERT INTO applications VALUES (?,?,?,?,?,?,?,?,?)", (app_id, institution, application_type, region, "Draft", "Draft", "Unassigned", today(), due))
    db.execute("INSERT INTO activity(application_id,actor,text,created) VALUES (?,?,?,?)", (app_id, "System Administrator", "Draft application created", today()))
    db.commit()
    flash(f"{app_id} created successfully.", "success")
    return redirect(url_for("applications"))


@app.route("/applications/<app_id>")
def application_detail(app_id: str):
    record = query("SELECT * FROM applications WHERE id=?", (app_id,), one=True)
    if record is None:
        return "Application not found", 404
    return render_template("application.html", title=app_id, record=record, tasks=query("SELECT * FROM tasks WHERE application_id=?", (app_id,)), activity=query("SELECT * FROM activity WHERE application_id=? ORDER BY id DESC", (app_id,)))


@app.route("/applications/<app_id>/advance", methods=["POST"])
def advance_application(app_id: str):
    record = query("SELECT * FROM applications WHERE id=?", (app_id,), one=True)
    if not record or record["status"] == "Completed":
        flash("This application cannot be advanced.", "error")
        return redirect(url_for("application_detail", app_id=app_id))
    current = STAGES.index(record["stage"])
    next_stage = STAGES[min(current + 1, len(STAGES) - 1)]
    status = "Completed" if next_stage == "Closed" else "In Progress"
    db = get_db()
    db.execute("UPDATE applications SET stage=?, status=? WHERE id=?", (next_stage, status, app_id))
    db.execute("INSERT INTO activity(application_id,actor,text,created) VALUES (?,?,?,?)", (app_id, "Bureau Officer", f"Moved workflow to {next_stage}", today()))
    db.commit()
    flash("Workflow updated.", "success")
    return redirect(url_for("application_detail", app_id=app_id))


@app.route("/tasks/<int:task_id>/toggle", methods=["POST"])
def toggle_task(task_id: int):
    get_db().execute("UPDATE tasks SET done = CASE done WHEN 1 THEN 0 ELSE 1 END WHERE id=?", (task_id,))
    get_db().commit()
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/evc")
def evc():
    return render_template("evc.html", title="EVC Scheduling", visits=query("SELECT evc.*, applications.institution FROM evc JOIN applications ON applications.id=evc.application_id ORDER BY evc.id DESC"))


@app.route("/compliance")
def compliance():
    return render_template("compliance.html", title="Compliance", records=query("SELECT * FROM compliance ORDER BY due"))


@app.route("/documents")
def documents():
    return render_template("documents.html", title="Documents", documents=query("SELECT * FROM documents ORDER BY expires"))


@app.route("/reports")
def reports():
    return render_template("reports.html", title="Reports", stage_counts=query("SELECT stage, COUNT(*) n FROM applications GROUP BY stage"), regions=query("SELECT region, COUNT(*) n FROM applications GROUP BY region"), compliance_counts=query("SELECT status, COUNT(*) n FROM compliance GROUP BY status"))


@app.route("/export/applications.csv")
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Application", "Institution", "Type", "Region", "Stage", "Status", "Due"])
    writer.writerows(query("SELECT id,institution,type,region,stage,status,due FROM applications"))
    return app.response_class(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=flowguard-applications.csv"})


@app.get("/health")
def health():
    query("SELECT 1", one=True)
    return {"status": "ok"}


if __name__ == "__main__":
    init_db()
    requested_port = int(os.environ.get("PORT", "5001"))
    port = requested_port
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            if probe.connect_ex(("127.0.0.1", port)) != 0:
                break
        port += 1
    if port != requested_port:
        print(f"Port {requested_port} is busy; using http://127.0.0.1:{port}")
    app.run(debug=False, host="127.0.0.1", port=port)
