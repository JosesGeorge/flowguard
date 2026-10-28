# FlowGuard

## Approval Operations Command Centre

FlowGuard is a secure, role-aware workflow platform for managing the lifecycle
of AICTE-style approval operations. It brings application intake, scrutiny,
re-scrutiny, evaluation visits, compliance obligations, document control,
reporting, user administration, and audit evidence into one operational
workspace.

The project is intentionally designed as a **local-first, synthetic-data
workspace**. It is not an official AICTE system and does not connect to
government services. That makes it useful for demonstrating workflow design,
security controls, operational dashboards, and a roadmap toward a larger
approval-management product without handling real institutional records.

> **Current maturity:** security-hardened Flask foundation with SQLite
> persistence, server-side RBAC, session controls, CSRF protection, structured
> audit events, administration tooling, and a 46-test security regression suite.
> Several domain capabilities are intentionally represented as read-only
> operational views and are planned for the next product phases.

---

## Product vision

FlowGuard is intended to become a **single source of operational truth** for
approval work:

1. An institution submits an application.
2. The system validates the intake and required evidence.
3. Officers review, assign tasks, and request corrections.
4. Evaluation visits are scheduled and tracked.
5. Compliance evidence is verified against obligations.
6. Authorized officers advance the application through governed stages.
7. Auditors can reconstruct who did what, when, and why.
8. Leadership receives SLA, pendency, throughput, and regional insight.

The core design principle is simple:

> **Make every approval action visible, permissioned, traceable, and
> measurable.**

---

## What is implemented today

### Operational workspace

- Dashboard with live application, task, overdue, EVC, and compliance metrics
- Application registry with search, status filtering, and CSV export
- Application detail pages with workflow stage track
- Linked task queue and completion actions
- Activity timeline for application events
- EVC scheduling view
- Compliance obligation view
- Document control view
- Reports for stage, region, and compliance distributions
- Responsive visual system with shared navigation, panels, tables, badges,
  modals, empty states, and error pages

### Security foundation

- Password-based authentication using Werkzeug password hashes
- Generic login failure messages to reduce account enumeration
- Session rotation after successful login
- Idle session timeout: 30 minutes
- Absolute session lifetime: 8 hours
- HTTP-only and SameSite session cookies
- Optional secure cookies through `FORCE_HTTPS=1`
- Random development secret when `SECRET_KEY` is not configured
- Server-side permission checks with deny-by-default RBAC
- CSRF protection on state-changing requests
- Safe local redirect validation after login
- Custom 403 and 404 responses
- Region and institution-aware application visibility
- Protection against auditors performing write operations

### Administration and governance

- System administrator user-management page
- Account creation, activation, and deactivation
- Role assignment
- Region assignment
- CLI account management
- Structured audit events for authentication, user administration,
  application creation, workflow actions, and task changes
- Audit-log viewer for authorized auditors and administrators
- Idempotent database migration script

### Quality baseline

- 46 automated tests currently passing
- Authentication and session regression coverage
- CSRF rejection and acceptance tests
- Role and permission enforcement tests
- Route access-control tests
- Audit logging tests
- Isolated temporary database fixture for tests

---

## Workflow model

The current application pipeline is:

```text
Draft
  ↓
Scrutiny
  ↓
Re-scrutiny
  ↓
EVC
  ↓
SAC/SHC
  ↓
Closed
```

An application record currently includes:

- Application identifier
- Institution
- Application type
- Region
- Current stage
- Status
- Responsible officer
- Submission date
- Due date

FlowGuard now extends the linear stage track with an explicit transition
engine supporting advance, return-for-correction, hold, resume, reject, and
resubmit actions. Approval-specific and stage-specific validation rules remain
part of the next workflow milestone.

### Governed workflow engine

The first production-oriented workflow module is now implemented in
`workflow.py`. State-changing actions are validated centrally rather than
being treated as arbitrary database updates.

Supported actions:

| Action | Behavior | Reason |
|---|---|---|
| Advance workflow | Move to the next configured stage | Optional |
| Request correction | Return the application to the institution/review queue | Required |
| Place on hold | Pause the current review without losing the stage | Required |
| Resume review | Resume an application that is on hold | Required |
| Resubmit | Move a returned application back into active review | Required |
| Reject | Close the application with a rejected outcome | Required |

Each successful transition records:

- Application and actor
- Source and destination stage
- Source and destination status
- Action name
- Human-readable reason
- UTC timestamp
- Operational activity entry
- Structured audit event

The transition history is displayed on the application detail page and is
protected by the same scope and permission checks as the application itself.
Auditors remain read-only, while bureau officers and administrators receive
the governed actions appropriate to their roles.

---

## Role and permission model

FlowGuard uses stable role identifiers in the database and resolves permissions
on the server. Browser-submitted role values are never trusted.

| Role | Intended responsibility |
|---|---|
| Institution User | Submit and update institution-owned applications and evidence |
| Regional Officer | Review applications within an assigned region |
| Bureau Officer | Manage the full application pipeline and workflow movement |
| EVC Coordinator | Coordinate and manage evaluation visits |
| Compliance Verifier | Verify compliance evidence and obligations |
| Auditor | Read-only access to operational records and audit history |
| System Administrator | Manage users, roles, settings, and platform access |

Permission families already defined in the authorization layer include:

- Application visibility, creation, review, assignment, correction, and
  workflow advancement
- Document upload, viewing, and verification
- EVC viewing, scheduling, and management
- Compliance viewing and updating
- Report viewing and export
- Audit access
- User administration and role assignment
- Region and system settings management
- Task updates and dashboard access

This permission vocabulary provides a strong foundation for adding routes
without scattering authorization logic throughout templates and controllers.

---

## Architecture

```text
Browser
  │
  ├── Jinja templates + shared CSS/JavaScript
  │
  ▼
Flask application (app.py)
  │
  ├── Request authentication and session enforcement
  ├── Route-level permission decorators
  ├── CSRF validation
  ├── Application workflow actions
  ├── Audit event recording
  └── Dashboard/report queries
  │
  ▼
SQLite database (flowguard.db)
  ├── applications
  ├── tasks
  ├── activity
  ├── evc
  ├── compliance
  ├── documents
  ├── users
  └── audit_log
```

### Repository map

| Path | Responsibility |
|---|---|
| `app.py` | Flask application, routes, database access, workflow actions, audit calls |
| `auth.py` | Roles, permissions, session validation, CSRF, authorization decorators |
| `workflow.py` | Central workflow actions, state validation, and transition outcomes |
| `migrate.py` | Idempotent creation of security-related tables |
| `manage.py` | CLI for creating and listing user accounts |
| `templates/` | Jinja pages for workspace, administration, and error states |
| `static/app.css` | Shared visual design system and responsive layout |
| `static/app.js` | Modal behavior and small client-side interactions |
| `tests/test_security.py` | Authentication, authorization, CSRF, session, workflow, and audit tests |
| `flowguard.db` | Local development database; ignored by Git |

---

## Quick start

### Requirements

- Python 3.10 or newer
- A virtual environment
- SQLite 3

### Install

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### Prepare the database

For a new database:

```bash
.venv/bin/python migrate.py
```

The application also initializes its core tables on startup. Migrations are
idempotent and preserve existing records.

### Create the first administrator

```bash
.venv/bin/python manage.py create-admin
```

The CLI validates the username, role, region, and a minimum ten-character
password. To inspect accounts:

```bash
.venv/bin/python manage.py list-users
```

### Run the application

```bash
.venv/bin/python app.py
```

Open the URL printed in the terminal. The server defaults to port `5001` and
automatically selects the next available local port if that port is busy.

### Run tests

```bash
.venv/bin/pytest -q
```

Expected baseline:

```text
46 passed
```

---

## Configuration

| Variable | Purpose | Local default |
|---|---|---|
| `SECRET_KEY` | Persistent Flask session signing key | Random key per process |
| `FORCE_HTTPS` | Enables the `Secure` session-cookie flag when set to `1` | `0` |
| `PORT` | Preferred local server port | `5001` |

Example:

```bash
export SECRET_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export FORCE_HTTPS=1
export PORT=5001
.venv/bin/python app.py
```

For production, provide the secret through a secret manager or deployment
environment. Never commit it, place it in a README, or use the generated
development key as an operational credential.

---

## Endpoint inventory

### Public

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/login` | Login form |
| `POST` | `/login` | Authenticate a user |
| `GET` | `/health` | Basic database-backed health check |

### Workspace

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/` | Role-aware dashboard |
| `GET` | `/applications` | Application registry |
| `POST` | `/applications/new` | Create a draft application |
| `GET` | `/applications/<app_id>` | Application detail and timeline |
| `POST` | `/applications/<app_id>/advance` | Advance an authorized workflow |
| `POST` | `/tasks/<task_id>/toggle` | Toggle an authorized task |
| `GET` | `/evc` | EVC scheduling workspace |
| `GET` | `/compliance` | Compliance obligations |
| `GET` | `/documents` | Document control |
| `GET` | `/reports` | Operational reporting |
| `GET` | `/export/applications.csv` | Authorized application export |
| `POST` | `/logout` | End the current session |

### Administration

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/admin/users` | User-management workspace |
| `POST` | `/admin/users/new` | Create a user account |
| `POST` | `/admin/users/<id>/activate` | Reactivate an account |
| `POST` | `/admin/users/<id>/deactivate` | Deactivate an account |
| `GET` | `/admin/audit` | View authorized audit events |

All state-changing routes require a valid CSRF token and the appropriate
server-side permission.

---

## Enhancement programme

The project has a strong security baseline. The largest opportunity now is to
turn the foundation into a complete, multi-role operations product.

### Phase 1 — Close the domain workflow gap

- Introduce a formal workflow-transition table
- Support approve, reject, hold, return, correction, resubmission, and close
- Require transition reasons and supporting notes
- Add stage-specific mandatory checklists
- Block advancement when required tasks or evidence are incomplete
- Assign applications to named officers and teams
- Add escalation and SLA breach states
- Add bulk assignment and bulk status actions
- Add optimistic locking to prevent conflicting updates

### Phase 2 — Build true document control

- Secure multipart document upload
- Allowed MIME types, extension validation, size limits, and malware scanning
- Private storage outside the static directory
- Document versions and immutable revision history
- Preview and authorized download
- SHA-256 file checksums
- Required-document templates by application type
- Verification comments and correction requests
- Expiry reminders and replacement workflows
- Retention and legal-hold policies

### Phase 3 — Make EVC operational

- Create, edit, and cancel visits
- Evaluator roster and availability management
- Conflict detection for coordinators and evaluators
- Calendar and agenda views
- Visit letters and calendar invitations
- Structured visit findings and recommendations
- Report upload and versioning
- Automatic application-stage updates after report submission
- Visit-level audit events and SLA metrics

### Phase 4 — Deliver institutional collaboration

- Institution profile and authorized contacts
- Applicant portal
- Draft autosave
- Applicant comments and clarification threads
- Secure correction-response workflow
- Email verification and password reset
- Institution-specific document checklists
- Applicant-facing status timeline
- Notifications for every material state change

### Phase 5 — Turn dashboards into decision intelligence

- Date-range, region, officer, type, and stage filters
- Average time per stage
- Median and percentile processing time
- SLA compliance percentage
- Aging buckets for pending applications
- Return, rejection, and correction rates
- EVC scheduling latency
- Document verification turnaround time
- Regional workload balancing
- CSV, Excel, and PDF exports
- Scheduled reports and leadership digests
- Chart-based trend visualizations

### Phase 6 — Integrate and scale

- Move domain models to SQLAlchemy
- Add Alembic migrations and migration version tracking
- Add PostgreSQL support
- Add object storage for documents
- Add a background job queue for notifications and exports
- Add REST API and OpenAPI documentation
- Add webhook/event publishing
- Add SSO/OIDC integration
- Add multi-tenant institution boundaries
- Add database backups and tested restore procedures
- Add structured logging, metrics, tracing, and error monitoring

---

## Honest current gaps

The current implementation is intentionally a foundation rather than a
finished production service. Before handling real institutional data, address
the following:

- EVC, compliance, and document screens are primarily read-only views
- Document records do not yet represent secure file uploads and downloads
- Application advancement is still a linear next-stage action
- Some permission constants are defined before their complete CRUD surfaces
  exist
- Several operational queries should receive the same region/institution
  scoping as the application registry
- SQLite is suitable for local and small-team use, but PostgreSQL is the
  stronger production target
- Audit records should eventually include request metadata, IP address,
  user-agent, before/after values, and retention controls
- `/health` should expose richer dependency checks and be protected or
  separated from public traffic in a production deployment
- The project needs deployment automation, backups, observability, and
  documented incident response before production use

Documenting these gaps is part of the product quality standard: FlowGuard
should look ambitious while remaining explicit about what is implemented,
what is simulated, and what still requires engineering.

---

## Recommended next milestone

The highest-value next milestone is **Governed Application Processing**:

1. Add an application assignment model.
2. Add explicit workflow transitions and transition reasons.
3. Add task creation, ownership, due dates, and mandatory-task rules.
4. Add correction and resubmission states.
5. Add application-scoped document requirements.
6. Add complete audit before/after snapshots.
7. Add route tests for every new permission and transition.

This milestone connects the existing authentication, RBAC, audit, dashboard,
and application surfaces into a real end-to-end approval workflow.

---

## Security notes

FlowGuard contains security controls for demonstration and development use,
not a completed security certification. Before deployment:

- Perform a threat model and independent security review.
- Run dependency and container vulnerability scans.
- Put the application behind HTTPS and a production WSGI server.
- Keep secrets in a managed secret store.
- Restrict database and document-storage access.
- Configure backups, restore drills, and retention.
- Add rate limiting, account lockout policy, and password reset controls.
- Review authorization at every data access boundary.
- Do not load real personal, institutional, or statutory records into the
  demo database.

---

## License and data status

This repository is a local demonstration and product-development workspace.
The seeded records are synthetic. It should not be represented as an official
AICTE integration or used to make statutory approval decisions without the
required governance, validation, security review, and institutional
authorization.
