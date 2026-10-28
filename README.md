# FAKELENS Backend

FastAPI backend MVP for FAKELENS, including JWT registration/login, text audit submission, SQLite persistence, review actions, comments, audit event history, guideline management, workspace settings, asset upload/download, and analytics.

## Run locally (Windows)
1. Install Python 3.10+.
2. Open terminal in this `backend` folder.
3. Run:
   ```powershell
   py -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   $env:JWT_SECRET="use-a-long-random-secret-for-local-testing"
   uvicorn main:app --reload
   ```
4. Open `http://127.0.0.1:8000/docs`.
5. Register at `POST /api/auth/register`, then click **Authorize** and enter `Bearer <accessToken>`.

## Render deployment
Deploy the repository as a Render Web Service. Set Root Directory to `backend`, Build Command to `pip install -r requirements.txt`, Start Command to `uvicorn main:app --host 0.0.0.0 --port $PORT`. Set `JWT_SECRET` to a long random value and `CORS_ORIGINS` to the exact deployed frontend origin. If using persistent storage, mount a disk at `/var/data` and set `DATABASE_PATH=/var/data/fakelens.db`, `UPLOAD_DIR=/var/data/uploads`.

## API routes
- `POST /api/auth/register`, `POST /api/auth/login`, `GET /api/auth/me`
- `GET /api/health`
- `POST /api/audits`, `GET /api/audits`, `GET /api/audits/{id}`
- `POST /api/audits/{id}/review` (reviewer/manager/admin)
- `GET/POST /api/audits/{id}/comments`, `GET /api/audits/{id}/events`
- `GET /api/guidelines`, `PATCH /api/guidelines/{id}`
- `GET/PATCH /api/settings`
- `GET/POST /api/assets`, `GET /api/assets/{id}/download`
- `GET /api/analytics`

## Honest limitations
- The audit engine is transparent keyword/heuristic checking, not an LLM, factual verification, legal review or RAG system.
- PDF extraction, OCR, vision/logo matching, AI correction generation, invitation/forgot-password flow and frontend integration are not yet implemented.
- New accounts get the `creator` role. A database administrator must assign reviewer/manager roles before those endpoints can be used; there is no public role escalation endpoint.
- SQLite and local uploads need a persistent Render disk or managed database for durable production use. This is an MVP scaffold, not production-hardened multi-tenant software.
- Do not upload confidential content until access controls, storage, retention and security review are complete.
