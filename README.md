# FlowGuard

Lightweight Flask and SQLite demo workspace for AICTE approval operations.

## Run locally

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python app.py
```

Open the URL printed in the terminal. The application automatically selects
the next available local port if the default port is busy.

The demo stores data in a local `flowguard.db` file, which is intentionally
ignored by Git.

## Backend endpoints

The Flask server provides the workspace pages and workflow actions, including
application creation, stage advancement, task completion, CSV export, and a
public health check:

```text
GET /health
```

For deployments outside the local demo, set a persistent `SECRET_KEY` before
starting the server. The default key is only intended for local use.
