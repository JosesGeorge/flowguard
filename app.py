from __future__ import annotations

import csv
import io
import json
import os
import socket
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash

from auth import (
    ALL_ROLES,
    PERM_APPLICATIONS_ADVANCE,
    PERM_APPLICATIONS_CREATE,
    PERM_APPLICATIONS_CORRECTION,
    PERM_APPLICATIONS_HOLD,
    PERM_APPLICATIONS_REJECT,
    PERM_APPLICATIONS_VIEW_ALL,
    PERM_APPLICATIONS_VIEW_OWN,
    PERM_APPLICATIONS_VIEW_REGION,
    PERM_AUDIT_VIEW,
    PERM_COMPLIANCE_VIEW,
    PERM_COMPLIANCE_UPDATE,
    PERM_DASHBOARD_VIEW,
    PERM_DOCUMENTS_VIEW,
    PERM_EVC_VIEW,
    PERM_REPORTS_EXPORT,
    PERM_REPORTS_VIEW,
    PERM_ROLES_ASSIGN,
    PERM_TASKS_TOGGLE,
    PERM_USERS_CREATE,
    PERM_USERS_DEACTIVATE,
    PERM_USERS_UPDATE,
    PERM_USERS_VIEW,
    ROLE_LABELS,
    ROLE_SYSTEM_ADMIN,
    SESSION_ABSOLUTE_TIMEOUT_HOURS,
    SESSION_IDLE_TIMEOUT_MINUTES,
    check_session_valid,
    csrf_protect,
    generate_csrf_token,
    get_current_user,
    has_permission,
    login_required,
    require_permission,
    validate_csrf_token,
)
from workflow import ACTION_LABELS, REASON_REQUIRED_ACTIONS, resolve_transition

# ---------------------------------------------------------------------------
# Application setup
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "flowguard.db"

app = Flask(__name__)

# Secret key — must be set via env var in production; local dev gets a warning
_secret = os.environ.get("SECRET_KEY", "")
if not _secret:
    import secrets as _sec
    import sys as _sys
    _secret = _sec.token_hex(32)
    print(
        "WARNING: SECRET_KEY env var is not set. "
        "A random key was generated; sessions will not persist across restarts.",
        file=_sys.stderr,
    )
app.config["SECRET_KEY"] = _secret

# Cookie security
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
# Secure=True only when running over HTTPS (set FORCE_HTTPS=1 in production)
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FORCE_HTTPS", "0") == "1"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=SESSION_ABSOLUTE_TIMEOUT_HOURS)

STAGES = ["Draft", "Scrutiny", "Re-scrutiny", "EVC", "SAC/SHC", "Closed"]
REGIONS = ["Northern", "Southern", "Eastern", "Western", "Central"]
APPLICATION_TYPES = ["New Institution", "Increase in Intake", "New Course", "Extension of Approval"]

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        import sqlite3
        db = g.db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def query(sql: str, args: tuple = (), one: bool = False):
    rows = get_db().execute(sql, args).fetchall()
    return (rows[0] if rows else None) if one else rows


def today(offset: int = 0) -> str:
    return (date.today() + timedelta(days=offset)).isoformat()


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

def audit(
    event_type: str,
    entity_type: str = None,
    entity_id: str = None,
    outcome: str = "success",
    metadata: dict = None,
    reason: str = None,
):
    """Write a structured audit record. Never raises — failures are logged to stderr."""
    import sys
    try:
        user = get_current_user()
        actor_id = user["id"] if user else None
        actor_username = user["username"] if user else None
        ts = datetime.now(timezone.utc).isoformat()
        meta_str = json.dumps(metadata) if metadata else None

        # Verify audit_log table exists before inserting
        db = get_db()
        tables = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_log'"
        )}
        if not tables:
            return  # Table not yet created; skip silently

        db.execute(
            "INSERT INTO audit_log "
            "(actor_id, actor_username, event_type, entity_type, entity_id, outcome, timestamp, metadata, reason) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (actor_id, actor_username, event_type, entity_type, entity_id, outcome, ts, meta_str, reason),
        )
        db.commit()
    except Exception as exc:
        print(f"AUDIT ERROR: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# DB Initialization  (idempotent — preserves existing data)
# ---------------------------------------------------------------------------

def init_db() -> None:
    import sqlite3 as _sqlite3
    db = _sqlite3.connect(DATABASE)
    db.executescript("""
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
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT  NOT NULL,
            role        TEXT    NOT NULL,
            region      TEXT    DEFAULT NULL,
            institution TEXT    DEFAULT NULL,
            is_active   INTEGER NOT NULL DEFAULT 1,
            created_at  TEXT    NOT NULL,
            updated_at  TEXT    NOT NULL,
            last_login  TEXT    DEFAULT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id        INTEGER DEFAULT NULL,
            actor_username  TEXT    DEFAULT NULL,
            event_type      TEXT    NOT NULL,
            entity_type     TEXT    DEFAULT NULL,
            entity_id       TEXT    DEFAULT NULL,
            outcome         TEXT    NOT NULL DEFAULT 'success',
            timestamp       TEXT    NOT NULL,
            metadata        TEXT    DEFAULT NULL,
            reason          TEXT    DEFAULT NULL
        );
        CREATE TABLE IF NOT EXISTS workflow_transitions (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            application_id  TEXT NOT NULL,
            actor_id        INTEGER DEFAULT NULL,
            actor_username  TEXT NOT NULL,
            action          TEXT NOT NULL,
            from_stage      TEXT NOT NULL,
            to_stage        TEXT NOT NULL,
            from_status     TEXT NOT NULL,
            to_status       TEXT NOT NULL,
            reason          TEXT DEFAULT NULL,
            created_at      TEXT NOT NULL
        );
    """)

    # Seed demo data only if no applications exist
    if db.execute("SELECT COUNT(*) FROM applications").fetchone()[0] == 0:
        institutions = [
            "Riverbend Institute of Technology", "Lakeview College of Engineering",
            "Sunrise Polytechnic", "Hillcrest School of Management", "Meridian Institute of Pharmacy",
        ]
        statuses = [
            ("Scrutiny", "In Progress"), ("EVC", "In Progress"), ("Scrutiny", "Returned"),
            ("Re-scrutiny", "In Progress"), ("Draft", "Draft"), ("SAC/SHC", "In Progress"),
            ("Closed", "Completed"), ("EVC", "In Progress"),
        ]
        for i, (stage, status) in enumerate(statuses):
            app_id = f"FG-2026-{101 + i}"
            submitted = (date.today() + timedelta(days=-(i + 2) * 5)).isoformat()
            db.execute(
                "INSERT INTO applications VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    app_id,
                    institutions[i % len(institutions)],
                    APPLICATION_TYPES[i % 4],
                    REGIONS[i % 5],
                    stage,
                    status,
                    ["R. Sharma", "A. Menon", "S. Banerjee"][i % 3],
                    submitted,
                    (date.today() + timedelta(days=(i - 2) * 7)).isoformat(),
                ),
            )
            db.execute(
                "INSERT INTO activity(application_id,actor,text,created) VALUES (?,?,?,?)",
                (app_id, "System", "Application record initialized", submitted),
            )
        db.executemany(
            "INSERT INTO tasks(application_id,title,due,owner,done) VALUES (?,?,?,?,?)",
            [
                ("FG-2026-101", "Scrutinise land documents",
                 (date.today() + timedelta(days=-4)).isoformat(), "R. Sharma", 0),
                ("FG-2026-103", "Applicant to resubmit affidavit",
                 (date.today() + timedelta(days=3)).isoformat(), "Institution User", 0),
                ("FG-2026-104", "Re-scrutiny of faculty data",
                 (date.today() + timedelta(days=-1)).isoformat(), "A. Menon", 0),
                ("FG-2026-106", "SAC review note",
                 (date.today() + timedelta(days=10)).isoformat(), "K. Patil", 0),
            ],
        )
        db.executemany(
            "INSERT INTO evc(application_id,visit_date,coordinator,status,notes) VALUES (?,?,?,?,?)",
            [
                ("FG-2026-102", "", "", "Awaiting scheduling", ""),
                ("FG-2026-108", (date.today() + timedelta(days=5)).isoformat(), "M. Iyer", "Scheduled", ""),
            ],
        )
        db.executemany(
            "INSERT INTO compliance(institution,obligation,due,status,verifier,evidence) VALUES (?,?,?,?,?,?)",
            [
                (institutions[0], "Submit faculty recruitment plan",
                 (date.today() + timedelta(days=4)).isoformat(), "Pending", "V. Rao", "Not submitted"),
                (institutions[1], "Fire safety certificate",
                 (date.today() + timedelta(days=20)).isoformat(), "Submitted", "V. Rao", "Under review"),
                (institutions[2], "Library resources undertaking",
                 (date.today() + timedelta(days=-3)).isoformat(), "Correction requested", "P. Nair", "Invoices unreadable"),
                (institutions[3], "Lab equipment installation",
                 (date.today() + timedelta(days=-30)).isoformat(), "Verified", "V. Rao", "Accepted"),
            ],
        )
        db.executemany(
            "INSERT INTO documents(name,category,institution,application_id,expires,verification) VALUES (?,?,?,?,?,?)",
            [
                ("Land title deed", "Legal", institutions[0], "FG-2026-101",
                 (date.today() + timedelta(days=25)).isoformat(), "Verified"),
                ("Fire NOC", "Safety", institutions[1], "FG-2026-102",
                 (date.today() + timedelta(days=-12)).isoformat(), "Pending verification"),
                ("Society registration", "Legal", institutions[3], "FG-2026-106",
                 (date.today() + timedelta(days=300)).isoformat(), "Verified"),
            ],
        )
    db.commit()
    db.close()


init_db()


# ---------------------------------------------------------------------------
# Context processor
# ---------------------------------------------------------------------------

@app.context_processor
def inject_globals():
    user = get_current_user()
    return {
        "today": date.today().isoformat(),
        "current_hour": datetime.now().hour,
        "stages": STAGES,
        "roles": ALL_ROLES,
        "role_labels": ROLE_LABELS,
        "current_user": user,
        "csrf_token": generate_csrf_token,
        "has_permission": has_permission,
        "PERM_APPLICATIONS_CREATE": PERM_APPLICATIONS_CREATE,
        "PERM_APPLICATIONS_ADVANCE": PERM_APPLICATIONS_ADVANCE,
        "PERM_APPLICATIONS_CORRECTION": PERM_APPLICATIONS_CORRECTION,
        "PERM_APPLICATIONS_HOLD": PERM_APPLICATIONS_HOLD,
        "PERM_APPLICATIONS_REJECT": PERM_APPLICATIONS_REJECT,
        "PERM_REPORTS_EXPORT": PERM_REPORTS_EXPORT,
        "PERM_USERS_VIEW": PERM_USERS_VIEW,
        "PERM_AUDIT_VIEW": PERM_AUDIT_VIEW,
        "PERM_TASKS_TOGGLE": PERM_TASKS_TOGGLE,
    }


# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

def safe_redirect_target(target: str | None) -> str:
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("dashboard")


UNAUTHENTICATED_ENDPOINTS = {"login", "static", "health"}


@app.before_request
def enforce_auth():
    """Enforce authentication and session validity on all non-public routes."""
    if request.endpoint in UNAUTHENTICATED_ENDPOINTS:
        return
    if not check_session_valid():
        if "user" in session:
            flash("Your session has expired. Please sign in again.", "error")
        return redirect(url_for("login", next=request.full_path))


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(403)
def forbidden(e):
    return render_template("403.html", title="Access denied"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("404.html", title="Page not found"), 404


# ---------------------------------------------------------------------------
# Authentication routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session and check_session_valid():
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")

        # Generic error — never reveal whether username exists
        auth_error = "Invalid username or password."

        if not username or not password:
            flash(auth_error, "error")
            audit(
                "login.attempt",
                entity_type="user",
                entity_id=username or "(empty)",
                outcome="failure",
                metadata={"reason": "missing credentials"},
            )
            return render_template("login.html", title="Sign in"), 401

        user_row = query("SELECT * FROM users WHERE username=?", (username,), one=True)

        if user_row is None:
            flash(auth_error, "error")
            audit(
                "login.attempt",
                entity_type="user",
                entity_id=username,
                outcome="failure",
                metadata={"reason": "user not found"},
            )
            return render_template("login.html", title="Sign in"), 401

        if not user_row["is_active"]:
            flash(auth_error, "error")
            audit(
                "login.attempt",
                entity_type="user",
                entity_id=username,
                outcome="failure",
                metadata={"reason": "account inactive"},
            )
            return render_template("login.html", title="Sign in"), 401

        if not check_password_hash(user_row["password_hash"], password):
            flash(auth_error, "error")
            audit(
                "login.attempt",
                entity_type="user",
                entity_id=username,
                outcome="failure",
                metadata={"reason": "wrong password"},
            )
            return render_template("login.html", title="Sign in"), 401

        # Successful login — rotate session to prevent fixation
        session.clear()
        now = datetime.now(timezone.utc).isoformat()
        session["user"] = {
            "id": user_row["id"],
            "username": user_row["username"],
            "role": user_row["role"],
            "region": user_row["region"],
            "institution": user_row["institution"],
            # name alias for template compatibility
            "name": user_row["username"],
        }
        session["login_at"] = now
        session["last_active"] = now

        # Update last_login timestamp
        db = get_db()
        db.execute("UPDATE users SET last_login=? WHERE id=?", (now, user_row["id"]))
        db.commit()

        audit(
            "login.success",
            entity_type="user",
            entity_id=str(user_row["id"]),
            metadata={"username": user_row["username"], "role": user_row["role"]},
        )

        destination = safe_redirect_target(request.args.get("next"))
        return redirect(destination)

    return render_template("login.html", title="Sign in")


@app.post("/logout")
@csrf_protect
def logout():
    user = get_current_user()
    if user:
        audit("logout", entity_type="user", entity_id=str(user.get("id", "")))
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.route("/")
@require_permission(PERM_DASHBOARD_VIEW)
def dashboard():
    user = get_current_user()

    # Scope queries based on role
    if has_permission(user, PERM_APPLICATIONS_VIEW_ALL):
        where, args = "", ()
    elif has_permission(user, PERM_APPLICATIONS_VIEW_REGION) and user.get("region"):
        where, args = "WHERE region=?", (user["region"],)
    elif has_permission(user, PERM_APPLICATIONS_VIEW_OWN) and user.get("institution"):
        where, args = "WHERE institution=?", (user["institution"],)
    else:
        where, args = "WHERE 1=0", ()

    and_kw = "AND" if where else "WHERE"
    stats = {
        "applications": query(f"SELECT COUNT(*) n FROM applications {where}", args, one=True)["n"],
        "active": query(
            f"SELECT COUNT(*) n FROM applications {where} {and_kw} status='In Progress'",
            args,
            one=True,
        )["n"],
        "tasks": query("SELECT COUNT(*) n FROM tasks WHERE done=0", one=True)["n"],
        "overdue": query("SELECT COUNT(*) n FROM tasks WHERE done=0 AND due<?", (today(),), one=True)["n"],
        "evc": query("SELECT COUNT(*) n FROM evc WHERE status='Awaiting scheduling'", one=True)["n"],
        "compliance": query(
            "SELECT COUNT(*) n FROM compliance WHERE status!='Verified' AND due BETWEEN ? AND ?",
            (today(), today(7)),
            one=True,
        )["n"],
    }

    stage_counts = query("SELECT stage, COUNT(*) n FROM applications GROUP BY stage")
    upcoming = query("SELECT * FROM tasks WHERE done=0 ORDER BY due LIMIT 6")
    activity = query("SELECT * FROM activity ORDER BY id DESC LIMIT 6")
    return render_template(
        "dashboard.html",
        title="Dashboard",
        stats=stats,
        stage_counts=stage_counts,
        upcoming=upcoming,
        activity=activity,
    )


# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------

def get_scoped_application_filter(user: dict) -> tuple[str, tuple]:
    """Return a (WHERE condition, args) tuple scoping applications to the user's access."""
    if has_permission(user, PERM_APPLICATIONS_VIEW_ALL):
        return "", ()
    if has_permission(user, PERM_APPLICATIONS_VIEW_REGION) and user.get("region"):
        return "region=?", (user["region"],)
    if has_permission(user, PERM_APPLICATIONS_VIEW_OWN) and user.get("institution"):
        return "institution=?", (user["institution"],)
    return "1=0", ()  # deny all


@app.route("/applications")
@require_permission(PERM_APPLICATIONS_VIEW_OWN)
def applications():
    user = get_current_user()
    term = request.args.get("q", "").strip()
    status = request.args.get("status", "")

    scope_clause, scope_args = get_scoped_application_filter(user)
    conditions = []
    args = list(scope_args)

    if scope_clause:
        conditions.append(scope_clause)

    if term:
        conditions.append("(id LIKE ? OR institution LIKE ?)")
        args += [f"%{term}%", f"%{term}%"]
    if status:
        conditions.append("status=?")
        args.append(status)

    clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    rows = query(f"SELECT * FROM applications {clause} ORDER BY id DESC", tuple(args))
    return render_template(
        "applications.html", title="Applications", applications=rows, term=term, status=status
    )


@app.route("/applications/new", methods=["POST"])
@csrf_protect
@require_permission(PERM_APPLICATIONS_CREATE)
def create_application():
    user = get_current_user()
    form = request.form
    institution = form.get("institution", "").strip()
    application_type = form.get("type", "").strip()
    region = form.get("region", "").strip()
    due = form.get("due", "").strip()

    if not institution or application_type not in APPLICATION_TYPES or region not in REGIONS:
        flash("Enter a valid institution, application type, and region.", "error")
        return redirect(url_for("applications"))
    try:
        datetime.strptime(due, "%Y-%m-%d")
    except ValueError:
        flash("Enter a valid due date.", "error")
        return redirect(url_for("applications"))

    # Scoped region restriction for non-admin roles
    if has_permission(user, PERM_APPLICATIONS_VIEW_REGION) and not has_permission(
        user, PERM_APPLICATIONS_VIEW_ALL
    ):
        if user.get("region") and region != user["region"]:
            flash("You can only create applications in your assigned region.", "error")
            audit(
                "application.create",
                outcome="failure",
                metadata={"reason": "region mismatch", "attempted_region": region},
            )
            return redirect(url_for("applications"))

    count = query("SELECT COUNT(*) n FROM applications", one=True)["n"]
    app_id = f"FG-{date.today().year}-{count + 101}"
    actor_name = user["username"]

    db = get_db()
    db.execute(
        "INSERT INTO applications VALUES (?,?,?,?,?,?,?,?,?)",
        (app_id, institution, application_type, region, "Draft", "Draft", "Unassigned", today(), due),
    )
    db.execute(
        "INSERT INTO activity(application_id,actor,text,created) VALUES (?,?,?,?)",
        (app_id, actor_name, "Draft application created", today()),
    )
    db.commit()

    audit(
        "application.create",
        entity_type="application",
        entity_id=app_id,
        outcome="success",
        metadata={"institution": institution, "type": application_type, "region": region},
    )
    flash(f"{app_id} created successfully.", "success")
    return redirect(url_for("applications"))


@app.route("/applications/<app_id>")
@require_permission(PERM_APPLICATIONS_VIEW_OWN)
def application_detail(app_id: str):
    user = get_current_user()
    record = query("SELECT * FROM applications WHERE id=?", (app_id,), one=True)
    if record is None:
        abort(404)

    # Scope check
    scope_clause, scope_args = get_scoped_application_filter(user)
    if scope_clause and scope_clause != "1=0":
        scoped = query(
            f"SELECT id FROM applications WHERE id=? AND {scope_clause}",
            (app_id,) + scope_args,
            one=True,
        )
        if scoped is None:
            abort(404)  # 404 to avoid revealing existence of out-of-scope records
    elif scope_clause == "1=0":
        abort(404)

    tasks = query("SELECT * FROM tasks WHERE application_id=?", (app_id,))
    activity = query("SELECT * FROM activity WHERE application_id=? ORDER BY id DESC", (app_id,))
    transitions = query(
        "SELECT * FROM workflow_transitions WHERE application_id=? ORDER BY id DESC",
        (app_id,),
    )
    return render_template(
        "application.html",
        title=app_id,
        record=record,
        tasks=tasks,
        activity=activity,
        transitions=transitions,
        workflow_actions=ACTION_LABELS,
    )


@app.route("/applications/<app_id>/advance", methods=["POST"])
@csrf_protect
@require_permission(PERM_APPLICATIONS_ADVANCE)
def advance_application(app_id: str):
    return transition_application(app_id, default_action="advance")


def transition_application(app_id: str, default_action: str | None = None):
    user = get_current_user()
    record = query("SELECT * FROM applications WHERE id=?", (app_id,), one=True)
    if not record:
        abort(404)

    # Scope check
    scope_clause, scope_args = get_scoped_application_filter(user)
    if scope_clause and scope_clause != "1=0":
        scoped = query(
            f"SELECT id FROM applications WHERE id=? AND {scope_clause}",
            (app_id,) + scope_args,
            one=True,
        )
        if scoped is None:
            abort(403)
    elif scope_clause == "1=0":
        abort(403)

    action = default_action or request.form.get("action", "").strip()
    reason = request.form.get("reason", "").strip()
    if action in REASON_REQUIRED_ACTIONS and len(reason) < 10:
        flash("Provide a reason of at least 10 characters for this workflow action.", "error")
        return redirect(url_for("application_detail", app_id=app_id))

    try:
        transition = resolve_transition(STAGES, record["stage"], record["status"], action)
    except ValueError as exc:
        flash(str(exc), "error")
        audit(
            "application.transition",
            entity_type="application",
            entity_id=app_id,
            outcome="failure",
            metadata={"action": action},
            reason=reason or str(exc),
        )
        return redirect(url_for("application_detail", app_id=app_id))

    actor_name = user["username"]
    transition_reason = reason or "Authorized workflow advancement."
    now = datetime.now(timezone.utc).isoformat()

    db = get_db()
    db.execute(
        "UPDATE applications SET stage=?, status=? WHERE id=?",
        (transition.to_stage, transition.status, app_id),
    )
    db.execute(
        "INSERT INTO activity(application_id,actor,text,created) VALUES (?,?,?,?)",
        (
            app_id,
            actor_name,
            f"{ACTION_LABELS[action]}: {record['stage']} -> {transition.to_stage}",
            today(),
        ),
    )
    db.execute(
        """
        INSERT INTO workflow_transitions
        (application_id, actor_id, actor_username, action, from_stage, to_stage,
         from_status, to_status, reason, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            app_id,
            user["id"],
            actor_name,
            action,
            transition.from_stage,
            transition.to_stage,
            record["status"],
            transition.status,
            transition_reason,
            now,
        ),
    )
    db.commit()

    audit(
        "application.transition",
        entity_type="application",
        entity_id=app_id,
        outcome="success",
        metadata={
            "action": action,
            "from_stage": record["stage"],
            "to_stage": transition.to_stage,
            "from_status": record["status"],
            "to_status": transition.status,
        },
        reason=transition_reason,
    )
    flash(f"{ACTION_LABELS[action]} completed.", "success")
    return redirect(url_for("application_detail", app_id=app_id))


@app.route("/applications/<app_id>/transition", methods=["POST"])
@csrf_protect
def application_transition(app_id: str):
    action = request.form.get("action", "").strip()
    permission_by_action = {
        "advance": PERM_APPLICATIONS_ADVANCE,
        "request_correction": PERM_APPLICATIONS_CORRECTION,
        "hold": PERM_APPLICATIONS_HOLD,
        "resume": PERM_APPLICATIONS_ADVANCE,
        "resubmit": PERM_APPLICATIONS_ADVANCE,
        "reject": PERM_APPLICATIONS_REJECT,
    }
    permission = permission_by_action.get(action)
    if permission is None:
        abort(400, description="Unsupported workflow action.")
    return require_permission(permission)(transition_application)(app_id)


# ---------------------------------------------------------------------------
# Tasks
# ---------------------------------------------------------------------------

@app.route("/tasks/<int:task_id>/toggle", methods=["POST"])
@csrf_protect
@require_permission(PERM_TASKS_TOGGLE)
def toggle_task(task_id: int):
    task = query("SELECT * FROM tasks WHERE id=?", (task_id,), one=True)
    if not task:
        abort(404)

    db = get_db()
    db.execute(
        "UPDATE tasks SET done = CASE done WHEN 1 THEN 0 ELSE 1 END WHERE id=?", (task_id,)
    )
    db.commit()

    audit(
        "task.toggle",
        entity_type="task",
        entity_id=str(task_id),
        outcome="success",
        metadata={"application_id": task["application_id"]},
    )
    return redirect(request.referrer or url_for("dashboard"))


# ---------------------------------------------------------------------------
# EVC
# ---------------------------------------------------------------------------

@app.route("/evc")
@require_permission(PERM_EVC_VIEW)
def evc():
    visits = query(
        "SELECT evc.*, applications.institution FROM evc "
        "JOIN applications ON applications.id=evc.application_id ORDER BY evc.id DESC"
    )
    return render_template("evc.html", title="EVC Scheduling", visits=visits)


# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------

@app.route("/compliance")
@require_permission(PERM_COMPLIANCE_VIEW)
def compliance():
    records = query("SELECT * FROM compliance ORDER BY due")
    return render_template("compliance.html", title="Compliance", records=records)


# ---------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------

@app.route("/documents")
@require_permission(PERM_DOCUMENTS_VIEW)
def documents():
    docs = query("SELECT * FROM documents ORDER BY expires")
    return render_template("documents.html", title="Documents", documents=docs)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@app.route("/reports")
@require_permission(PERM_REPORTS_VIEW)
def reports():
    stage_counts = query("SELECT stage, COUNT(*) n FROM applications GROUP BY stage")
    regions = query("SELECT region, COUNT(*) n FROM applications GROUP BY region")
    compliance_counts = query("SELECT status, COUNT(*) n FROM compliance GROUP BY status")
    return render_template(
        "reports.html",
        title="Reports",
        stage_counts=stage_counts,
        regions=regions,
        compliance_counts=compliance_counts,
    )


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

@app.route("/export/applications.csv")
@require_permission(PERM_REPORTS_EXPORT)
def export_csv():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Application", "Institution", "Type", "Region", "Stage", "Status", "Due"])
    writer.writerows(
        query("SELECT id,institution,type,region,stage,status,due FROM applications")
    )
    return app.response_class(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=flowguard-applications.csv"},
    )


# ---------------------------------------------------------------------------
# Admin — User management
# ---------------------------------------------------------------------------

@app.route("/admin/users")
@require_permission(PERM_USERS_VIEW)
def admin_users():
    users = query(
        "SELECT id, username, role, region, institution, is_active, created_at, last_login "
        "FROM users ORDER BY id"
    )
    return render_template(
        "admin_users.html",
        title="User management",
        users=users,
        all_roles=ALL_ROLES,
        role_labels=ROLE_LABELS,
        regions=REGIONS,
    )


@app.route("/admin/users/new", methods=["POST"])
@csrf_protect
@require_permission(PERM_USERS_CREATE)
def admin_create_user():
    from werkzeug.security import generate_password_hash

    username = request.form.get("username", "").strip().lower()
    password = request.form.get("password", "")
    role = request.form.get("role", "").strip()
    region = request.form.get("region", "").strip() or None

    if not username or len(username) < 3:
        flash("Username must be at least 3 characters.", "error")
        return redirect(url_for("admin_users"))
    if len(password) < 10:
        flash("Password must be at least 10 characters.", "error")
        return redirect(url_for("admin_users"))
    if role not in ALL_ROLES:
        flash("Invalid role.", "error")
        return redirect(url_for("admin_users"))

    existing = query("SELECT id FROM users WHERE username=?", (username,), one=True)
    if existing:
        flash(f"Username '{username}' is already taken.", "error")
        return redirect(url_for("admin_users"))

    now = datetime.now(timezone.utc).isoformat()
    db = get_db()
    db.execute(
        "INSERT INTO users (username, password_hash, role, region, is_active, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, 1, ?, ?)",
        (username, generate_password_hash(password), role, region, now, now),
    )
    db.commit()

    audit(
        "user.create",
        entity_type="user",
        entity_id=username,
        outcome="success",
        metadata={"role": role, "region": region},
    )
    flash(f"Account '{username}' created.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/deactivate", methods=["POST"])
@csrf_protect
@require_permission(PERM_USERS_DEACTIVATE)
def admin_deactivate_user(user_id: int):
    current = get_current_user()
    if current and current["id"] == user_id:
        flash("You cannot deactivate your own account.", "error")
        return redirect(url_for("admin_users"))

    target = query("SELECT * FROM users WHERE id=?", (user_id,), one=True)
    if not target:
        abort(404)

    db = get_db()
    db.execute(
        "UPDATE users SET is_active=0, updated_at=? WHERE id=?",
        (datetime.now(timezone.utc).isoformat(), user_id),
    )
    db.commit()

    audit(
        "user.deactivate",
        entity_type="user",
        entity_id=str(user_id),
        outcome="success",
        metadata={"username": target["username"]},
    )
    flash(f"Account '{target['username']}' deactivated.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/activate", methods=["POST"])
@csrf_protect
@require_permission(PERM_USERS_UPDATE)
def admin_activate_user(user_id: int):
    target = query("SELECT * FROM users WHERE id=?", (user_id,), one=True)
    if not target:
        abort(404)

    db = get_db()
    db.execute(
        "UPDATE users SET is_active=1, updated_at=? WHERE id=?",
        (datetime.now(timezone.utc).isoformat(), user_id),
    )
    db.commit()

    audit(
        "user.activate",
        entity_type="user",
        entity_id=str(user_id),
        outcome="success",
        metadata={"username": target["username"]},
    )
    flash(f"Account '{target['username']}' activated.", "success")
    return redirect(url_for("admin_users"))


# ---------------------------------------------------------------------------
# Admin — Audit log viewer
# ---------------------------------------------------------------------------

@app.route("/admin/audit")
@require_permission(PERM_AUDIT_VIEW)
def admin_audit():
    logs = query(
        "SELECT * FROM audit_log ORDER BY id DESC LIMIT 200"
    )
    return render_template("admin_audit.html", title="Audit log", logs=logs)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    query("SELECT 1", one=True)
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
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
