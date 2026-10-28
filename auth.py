"""
FlowGuard — Centralized authentication and authorization layer.

Roles and permissions are defined here and enforced server-side.
Never trust role or permission information submitted by the browser.
"""
from __future__ import annotations

import functools
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from flask import abort, flash, redirect, request, session, url_for

# ---------------------------------------------------------------------------
# Role identifiers  (stable snake_case strings used in DB and session)
# ---------------------------------------------------------------------------
ROLE_INSTITUTION_USER = "institution_user"
ROLE_REGIONAL_OFFICER = "regional_officer"
ROLE_BUREAU_OFFICER = "bureau_officer"
ROLE_EVC_COORDINATOR = "evc_coordinator"
ROLE_COMPLIANCE_VERIFIER = "compliance_verifier"
ROLE_AUDITOR = "auditor"
ROLE_SYSTEM_ADMIN = "system_admin"

ALL_ROLES = [
    ROLE_INSTITUTION_USER,
    ROLE_REGIONAL_OFFICER,
    ROLE_BUREAU_OFFICER,
    ROLE_EVC_COORDINATOR,
    ROLE_COMPLIANCE_VERIFIER,
    ROLE_AUDITOR,
    ROLE_SYSTEM_ADMIN,
]

# Human-readable display labels for UI
ROLE_LABELS = {
    ROLE_INSTITUTION_USER: "Institution User",
    ROLE_REGIONAL_OFFICER: "Regional Officer",
    ROLE_BUREAU_OFFICER: "Bureau Officer",
    ROLE_EVC_COORDINATOR: "EVC Coordinator",
    ROLE_COMPLIANCE_VERIFIER: "Compliance Verifier",
    ROLE_AUDITOR: "Auditor",
    ROLE_SYSTEM_ADMIN: "System Administrator",
}

# ---------------------------------------------------------------------------
# Permission identifiers
# ---------------------------------------------------------------------------
PERM_APPLICATIONS_VIEW_OWN = "applications.view_own"
PERM_APPLICATIONS_VIEW_REGION = "applications.view_region"
PERM_APPLICATIONS_VIEW_ALL = "applications.view_all"
PERM_APPLICATIONS_CREATE = "applications.create"
PERM_APPLICATIONS_UPDATE_OWN = "applications.update_own"
PERM_APPLICATIONS_REVIEW = "applications.review"
PERM_APPLICATIONS_ADVANCE = "applications.advance_workflow"
PERM_APPLICATIONS_ASSIGN = "applications.assign_officer"
PERM_APPLICATIONS_CORRECTION = "applications.request_correction"
PERM_APPLICATIONS_HOLD = "applications.hold"
PERM_APPLICATIONS_REJECT = "applications.reject"

PERM_DOCUMENTS_UPLOAD = "documents.upload"
PERM_DOCUMENTS_VIEW = "documents.view"
PERM_DOCUMENTS_VERIFY = "documents.verify"

PERM_EVC_VIEW = "evc.view"
PERM_EVC_SCHEDULE = "evc.schedule"
PERM_EVC_MANAGE = "evc.manage"

PERM_COMPLIANCE_VIEW = "compliance.view"
PERM_COMPLIANCE_UPDATE = "compliance.update"

PERM_REPORTS_VIEW = "reports.view"
PERM_REPORTS_EXPORT = "reports.export"

PERM_AUDIT_VIEW = "audit.view"

PERM_USERS_VIEW = "users.view"
PERM_USERS_CREATE = "users.create"
PERM_USERS_UPDATE = "users.update"
PERM_USERS_DEACTIVATE = "users.deactivate"
PERM_ROLES_ASSIGN = "roles.assign"
PERM_REGIONS_MANAGE = "regions.manage"
PERM_SYSTEM_SETTINGS = "system.settings.manage"

PERM_TASKS_TOGGLE = "tasks.toggle"
PERM_DASHBOARD_VIEW = "dashboard.view"

# ---------------------------------------------------------------------------
# Role → Permission mapping  (deny by default; only listed permissions apply)
# ---------------------------------------------------------------------------
ROLE_PERMISSIONS: dict[str, set[str]] = {
    ROLE_INSTITUTION_USER: {
        PERM_DASHBOARD_VIEW,
        PERM_APPLICATIONS_VIEW_OWN,
        PERM_APPLICATIONS_CREATE,
        PERM_APPLICATIONS_UPDATE_OWN,
        PERM_DOCUMENTS_UPLOAD,
        PERM_DOCUMENTS_VIEW,
        PERM_EVC_VIEW,
        PERM_COMPLIANCE_VIEW,
        PERM_REPORTS_VIEW,
        PERM_TASKS_TOGGLE,
    },
    ROLE_REGIONAL_OFFICER: {
        PERM_DASHBOARD_VIEW,
        PERM_APPLICATIONS_VIEW_OWN,
        PERM_APPLICATIONS_VIEW_REGION,
        PERM_APPLICATIONS_REVIEW,
        PERM_APPLICATIONS_CORRECTION,
        PERM_APPLICATIONS_HOLD,
        PERM_DOCUMENTS_VIEW,
        PERM_EVC_VIEW,
        PERM_COMPLIANCE_VIEW,
        PERM_REPORTS_VIEW,
        PERM_TASKS_TOGGLE,
    },
    ROLE_BUREAU_OFFICER: {
        PERM_DASHBOARD_VIEW,
        PERM_APPLICATIONS_VIEW_OWN,
        PERM_APPLICATIONS_VIEW_ALL,
        PERM_APPLICATIONS_REVIEW,
        PERM_APPLICATIONS_ADVANCE,
        PERM_APPLICATIONS_ASSIGN,
        PERM_APPLICATIONS_CORRECTION,
        PERM_APPLICATIONS_HOLD,
        PERM_APPLICATIONS_REJECT,
        PERM_DOCUMENTS_VIEW,
        PERM_EVC_VIEW,
        PERM_COMPLIANCE_VIEW,
        PERM_REPORTS_VIEW,
        PERM_REPORTS_EXPORT,
        PERM_TASKS_TOGGLE,
    },
    ROLE_EVC_COORDINATOR: {
        PERM_DASHBOARD_VIEW,
        PERM_APPLICATIONS_VIEW_OWN,
        PERM_APPLICATIONS_VIEW_ALL,
        PERM_EVC_VIEW,
        PERM_EVC_SCHEDULE,
        PERM_EVC_MANAGE,
        PERM_DOCUMENTS_VIEW,
        PERM_COMPLIANCE_VIEW,
        PERM_REPORTS_VIEW,
        PERM_TASKS_TOGGLE,
    },
    ROLE_COMPLIANCE_VERIFIER: {
        PERM_DASHBOARD_VIEW,
        PERM_APPLICATIONS_VIEW_OWN,
        PERM_APPLICATIONS_VIEW_ALL,
        PERM_DOCUMENTS_VIEW,
        PERM_DOCUMENTS_VERIFY,
        PERM_EVC_VIEW,
        PERM_COMPLIANCE_VIEW,
        PERM_COMPLIANCE_UPDATE,
        PERM_REPORTS_VIEW,
        PERM_TASKS_TOGGLE,
    },
    ROLE_AUDITOR: {
        PERM_DASHBOARD_VIEW,
        PERM_APPLICATIONS_VIEW_OWN,
        PERM_APPLICATIONS_VIEW_ALL,
        PERM_DOCUMENTS_VIEW,
        PERM_EVC_VIEW,
        PERM_COMPLIANCE_VIEW,
        PERM_REPORTS_VIEW,
        PERM_AUDIT_VIEW,
        # Auditors are strictly read-only; no create/update/delete permissions
    },
    ROLE_SYSTEM_ADMIN: {
        PERM_DASHBOARD_VIEW,
        PERM_APPLICATIONS_VIEW_OWN,
        PERM_APPLICATIONS_VIEW_ALL,
        PERM_APPLICATIONS_CREATE,
        PERM_APPLICATIONS_REVIEW,
        PERM_APPLICATIONS_ADVANCE,
        PERM_APPLICATIONS_ASSIGN,
        PERM_APPLICATIONS_CORRECTION,
        PERM_APPLICATIONS_HOLD,
        PERM_APPLICATIONS_REJECT,
        PERM_DOCUMENTS_VIEW,
        PERM_DOCUMENTS_UPLOAD,
        PERM_DOCUMENTS_VERIFY,
        PERM_EVC_VIEW,
        PERM_EVC_SCHEDULE,
        PERM_EVC_MANAGE,
        PERM_COMPLIANCE_VIEW,
        PERM_COMPLIANCE_UPDATE,
        PERM_REPORTS_VIEW,
        PERM_REPORTS_EXPORT,
        PERM_AUDIT_VIEW,
        PERM_USERS_VIEW,
        PERM_USERS_CREATE,
        PERM_USERS_UPDATE,
        PERM_USERS_DEACTIVATE,
        PERM_ROLES_ASSIGN,
        PERM_REGIONS_MANAGE,
        PERM_SYSTEM_SETTINGS,
        PERM_TASKS_TOGGLE,
    },
}

# ---------------------------------------------------------------------------
# Session configuration
# ---------------------------------------------------------------------------
SESSION_IDLE_TIMEOUT_MINUTES = 30
SESSION_ABSOLUTE_TIMEOUT_HOURS = 8


# ---------------------------------------------------------------------------
# Core auth helpers
# ---------------------------------------------------------------------------

def get_current_user() -> Optional[dict]:
    """Return the authenticated user dict from session, or None."""
    return session.get("user")


def has_permission(user: Optional[dict], permission: str) -> bool:
    """Return True if the user's server-side role grants the given permission."""
    if user is None:
        return False
    role = user.get("role", "")
    return permission in ROLE_PERMISSIONS.get(role, set())


def check_session_valid() -> bool:
    """
    Validate session timing.
    Returns False if the session has expired (idle or absolute).
    Mutates session to update last_active on success.
    """
    user = session.get("user")
    if user is None:
        return False

    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()

    # Absolute lifetime check
    login_at_str = session.get("login_at")
    if login_at_str:
        try:
            login_at = datetime.fromisoformat(login_at_str)
            if (now - login_at) > timedelta(hours=SESSION_ABSOLUTE_TIMEOUT_HOURS):
                session.clear()
                return False
        except ValueError:
            session.clear()
            return False

    # Idle timeout check
    last_active_str = session.get("last_active")
    if last_active_str:
        try:
            last_active = datetime.fromisoformat(last_active_str)
            if (now - last_active) > timedelta(minutes=SESSION_IDLE_TIMEOUT_MINUTES):
                session.clear()
                return False
        except ValueError:
            session.clear()
            return False

    # Update last active timestamp
    session["last_active"] = now_iso
    return True


def generate_csrf_token() -> str:
    """Generate and store a CSRF token in the session."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf_token(submitted_token: str) -> bool:
    """Validate submitted CSRF token against session token using constant-time compare."""
    expected = session.get("csrf_token", "")
    if not expected or not submitted_token:
        return False
    return secrets.compare_digest(expected, submitted_token)


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def login_required(f):
    """Decorator: redirect to login if user is not authenticated or session expired."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not check_session_valid():
            flash("Your session has expired. Please sign in again.", "error")
            return redirect(url_for("login", next=request.full_path))
        return f(*args, **kwargs)
    return wrapper


def require_permission(permission: str):
    """Decorator factory: enforce a specific permission, returning 403 if denied."""
    def decorator(f):
        @functools.wraps(f)
        @login_required
        def wrapper(*args, **kwargs):
            user = get_current_user()
            if not has_permission(user, permission):
                if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
                    abort(403)
                flash("You do not have permission to perform this action.", "error")
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorator


def csrf_protect(f):
    """Decorator: validate CSRF token on state-changing requests (POST, PUT, PATCH, DELETE)."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            submitted = request.form.get("csrf_token", "")
            if not validate_csrf_token(submitted):
                flash("Invalid or missing security token. Please try again.", "error")
                abort(403)
        return f(*args, **kwargs)
    return wrapper
