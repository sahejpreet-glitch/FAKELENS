
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime, timezone

app = FastAPI(title="FAKELENS API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://fakelens-two.vercel.app",
        "http://localhost:5173",
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/")
def home():
    return {"message": "FAKELENS API is running"}

@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "service": "FAKELENS API",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

@app.get("/api")
def api_info():
    return {
        "name": "FAKELENS",
        "status": "running",
        "docs": "/docs",
    }

@app.get("/api/audits")
def list_audits():
    return {"audits": [], "total": 0}

@app.post("/api/audits")
def create_audit():
    return {
        "status": "received",
        "message": "Backend connected. AI analysis is not enabled yet."
    }
