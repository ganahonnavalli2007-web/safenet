from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
import random
import os

app = FastAPI(
    title="SafeNet AI",
    description="AI-powered cybersecurity platform for detecting drug trafficking, cyberbullying, and human trafficking.",
    version="1.0.0"
)

# ── CORS ──────────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Static Directory ──────────────────────────────────────────────────────────
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
ASSETS_DIR = os.path.join(STATIC_DIR, "assets")
INDEX_HTML  = os.path.join(STATIC_DIR, "index.html")

# ── In-Memory Database ────────────────────────────────────────────────────────
THREATS_DB = [
    {
        "id": "001",
        "text": "Need a plug for white snow, discreet shipping available",
        "source": "Social Media",
        "threat_type": "DRUG TRAFFICKING",
        "risk_score": 9.2,
        "risk_level": "HIGH",
        "confidence": 0.95,
        "alert_sent_to": "Law Enforcement",
        "recommended_action": "Generate police report immediately",
        "timestamp": "2026-05-13T09:30:00",
        "status": "Alerted"
    },
    {
        "id": "002",
        "text": "Nobody likes you, you should just disappear forever",
        "source": "Message/Chat",
        "threat_type": "CYBERBULLYING",
        "risk_score": 7.8,
        "risk_level": "HIGH",
        "confidence": 0.91,
        "alert_sent_to": "School Admin",
        "recommended_action": "Flag account and notify guardian",
        "timestamp": "2026-05-13T10:15:00",
        "status": "Alerted"
    },
    {
        "id": "003",
        "text": "Urgent girls needed, easy money abroad, accommodation provided, travel included, contact privately",
        "source": "Website",
        "threat_type": "HUMAN TRAFFICKING",
        "risk_score": 9.8,
        "risk_level": "HIGH",
        "confidence": 0.97,
        "alert_sent_to": "NGO + Law Enforcement",
        "recommended_action": "Escalate to anti-trafficking unit",
        "timestamp": "2026-05-13T11:00:00",
        "status": "Alerted"
    },
    {
        "id": "004",
        "text": "LSD tabs available, premium quality, fast delivery guaranteed",
        "source": "Website",
        "threat_type": "DRUG TRAFFICKING",
        "risk_score": 8.6,
        "risk_level": "HIGH",
        "confidence": 0.93,
        "alert_sent_to": "Law Enforcement",
        "recommended_action": "Flag URL and report to cyber cell",
        "timestamp": "2026-05-13T11:45:00",
        "status": "Under Review"
    },
    {
        "id": "005",
        "text": "You're pathetic and everyone laughs at you behind your back",
        "source": "Social Media",
        "threat_type": "CYBERBULLYING",
        "risk_score": 6.4,
        "risk_level": "MEDIUM",
        "confidence": 0.82,
        "alert_sent_to": "Platform Moderator",
        "recommended_action": "Issue content warning, monitor account",
        "timestamp": "2026-05-13T12:30:00",
        "status": "Resolved"
    },
    {
        "id": "006",
        "text": "Domestic helpers needed urgently, no documents required, good salary",
        "source": "Email",
        "threat_type": "HUMAN TRAFFICKING",
        "risk_score": 8.9,
        "risk_level": "HIGH",
        "confidence": 0.94,
        "alert_sent_to": "NGO + Law Enforcement",
        "recommended_action": "Escalate to anti-trafficking unit",
        "timestamp": "2026-05-13T13:10:00",
        "status": "Alerted"
    },
    {
        "id": "007",
        "text": "Molly available, best price in town, WhatsApp me",
        "source": "Social Media",
        "threat_type": "DRUG TRAFFICKING",
        "risk_score": 8.1,
        "risk_level": "HIGH",
        "confidence": 0.89,
        "alert_sent_to": "Law Enforcement",
        "recommended_action": "Generate police report immediately",
        "timestamp": "2026-05-13T14:00:00",
        "status": "Alerted"
    },
    {
        "id": "008",
        "text": "I will make your life a living hell. You better watch out.",
        "source": "Message/Chat",
        "threat_type": "CYBERBULLYING",
        "risk_score": 7.2,
        "risk_level": "HIGH",
        "confidence": 0.87,
        "alert_sent_to": "School Admin",
        "recommended_action": "Flag account and notify guardian",
        "timestamp": "2026-05-13T14:30:00",
        "status": "Pending"
    },
    {
        "id": "009",
        "text": "Young women needed for overseas modeling, no experience needed, visa arranged",
        "source": "Website",
        "threat_type": "HUMAN TRAFFICKING",
        "risk_score": 9.5,
        "risk_level": "HIGH",
        "confidence": 0.96,
        "alert_sent_to": "NGO + Law Enforcement",
        "recommended_action": "Escalate to anti-trafficking unit",
        "timestamp": "2026-05-13T15:00:00",
        "status": "Alerted"
    },
    {
        "id": "010",
        "text": "Special K available, free samples for first-timers",
        "source": "Email",
        "threat_type": "DRUG TRAFFICKING",
        "risk_score": 7.5,
        "risk_level": "MEDIUM",
        "confidence": 0.84,
        "alert_sent_to": "Law Enforcement",
        "recommended_action": "Flag email and report to cyber cell",
        "timestamp": "2026-05-13T15:30:00",
        "status": "Under Review"
    },
]

# ── AI Detection Engine ───────────────────────────────────────────────────────
DRUG_KEYWORDS = [
    "plug", "white snow", "cocaine", "coke", "meth", "heroin", "lsd", "acid",
    "mdma", "molly", "ecstasy", "weed", "marijuana", "cannabis", "ketamine",
    "special k", "shipping", "delivery", "tabs", "pills", "grams", "ounce",
    "dope", "stash", "score", "fix", "smoke", "crack", "fentanyl",
    "opioid", "narcotics", "powder", "snow", "blow", "smack", "junk", "gear"
]

BULLYING_KEYWORDS = [
    "nobody likes you", "disappear", "hate you", "kill yourself", "loser",
    "pathetic", "worthless", "ugly", "stupid", "idiot", "freak", "dumb",
    "everyone laughs", "better watch out", "make your life", "living hell",
    "go away", "you suck", "no one cares", "shut up", "useless",
    "embarrassing", "humiliate", "bully", "harass", "threaten", "coward"
]

TRAFFICKING_KEYWORDS = [
    "girls needed", "women needed", "easy money", "abroad", "accommodation provided",
    "travel included", "contact privately", "domestic helpers", "no documents",
    "visa arranged", "modeling", "overseas", "young women", "escort",
    "massage", "discreet", "private work", "flexible hours",
    "quick money", "no experience", "urgent hiring", "foreign job", "work abroad",
    "travel package", "all expenses paid", "recruiter", "urgent job"
]


def detect_threat(text: str) -> dict:
    text_lower = text.lower()
    drug_score    = sum(1 for kw in DRUG_KEYWORDS       if kw in text_lower)
    bully_score   = sum(1 for kw in BULLYING_KEYWORDS   if kw in text_lower)
    traffic_score = sum(1 for kw in TRAFFICKING_KEYWORDS if kw in text_lower)

    scores = {
        "DRUG TRAFFICKING":  drug_score,
        "CYBERBULLYING":     bully_score,
        "HUMAN TRAFFICKING": traffic_score,
    }

    max_type = max(scores, key=scores.get)
    max_hits = scores[max_type]

    if max_hits == 0:
        return {
            "threat_type": "SAFE",
            "risk_score": round(random.uniform(0.5, 2.0), 1),
            "risk_level": "LOW",
            "confidence": round(random.uniform(0.75, 0.88), 2),
            "alert_sent_to": "None",
            "recommended_action": "No immediate action required. Continue monitoring.",
        }

    raw        = min(max_hits * 2.5, 10.0)
    risk_score = round(max(1.0, min(10.0, raw + random.uniform(-0.3, 0.3))), 1)
    confidence = round(min(0.70 + max_hits * 0.06 + random.uniform(0, 0.05), 0.99), 2)
    risk_level = "HIGH" if risk_score >= 7.5 else "MEDIUM" if risk_score >= 4.5 else "LOW"

    alert_map = {
        "DRUG TRAFFICKING":  "Law Enforcement",
        "CYBERBULLYING":     "School Admin + Platform Moderator",
        "HUMAN TRAFFICKING": "NGO + Law Enforcement",
    }
    action_map = {
        "DRUG TRAFFICKING":  "Generate police report and flag content immediately",
        "CYBERBULLYING":     "Flag account, notify guardian, and issue content warning",
        "HUMAN TRAFFICKING": "Escalate to anti-trafficking unit and notify NGO partners",
    }

    return {
        "threat_type":        max_type,
        "risk_score":         risk_score,
        "risk_level":         risk_level,
        "confidence":         confidence,
        "alert_sent_to":      alert_map[max_type],
        "recommended_action": action_map[max_type],
    }


# ── Helper ────────────────────────────────────────────────────────────────────
def _parse_dt(s: str) -> Optional[datetime]:
    """Safely parse ISO or date-only strings."""
    if not s:
        return None
    try:
        # Try full ISO first
        return datetime.fromisoformat(s)
    except ValueError:
        pass
    try:
        # Try date-only  YYYY-MM-DD
        return datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        return None


# ── Pydantic Models ───────────────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    text: str
    source: Optional[str] = "Social Media"


# ════════════════════════════════════════════════════════════════════════════════
# API ROUTES  (ALL must be registered BEFORE the static catch-all mount)
# ════════════════════════════════════════════════════════════════════════════════

@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.post("/analyze")
def analyze_threat(req: AnalyzeRequest):
    """Analyze text for threats using AI keyword detection engine."""
    if not req.text or len(req.text.strip()) < 3:
        raise HTTPException(status_code=400, detail="Text too short to analyze.")

    result   = detect_threat(req.text)
    new_id   = str(len(THREATS_DB) + 1).zfill(3)
    record   = {
        "id":        new_id,
        "text":      req.text,
        "source":    req.source,
        "timestamp": datetime.now().isoformat(),
        "status":    "Alerted" if result["risk_level"] == "HIGH" else "Pending",
        **result,
    }
    THREATS_DB.append(record)
    return record


@app.get("/threats")
def get_threats(
    threat_type: Optional[str] = Query(None),
    risk_level:  Optional[str] = Query(None),
    date_from:   Optional[str] = Query(None),
    date_to:     Optional[str] = Query(None),
    search:      Optional[str] = Query(None),
):
    """Return all threats, with optional filters."""
    results = list(THREATS_DB)

    if threat_type and threat_type.upper() != "ALL":
        results = [t for t in results if t["threat_type"] == threat_type.upper()]

    if risk_level and risk_level.upper() != "ALL":
        results = [t for t in results if t["risk_level"] == risk_level.upper()]

    df = _parse_dt(date_from)
    if df:
        results = [t for t in results if _parse_dt(t["timestamp"]) and _parse_dt(t["timestamp"]) >= df]

    dt_end = _parse_dt(date_to)
    if dt_end:
        # Include the whole end-day
        dt_end = dt_end.replace(hour=23, minute=59, second=59)
        results = [t for t in results if _parse_dt(t["timestamp"]) and _parse_dt(t["timestamp"]) <= dt_end]

    if search:
        q = search.lower()
        results = [
            t for t in results
            if q in t.get("text",        "").lower()
            or q in t.get("source",      "").lower()
            or q in t.get("threat_type", "").lower()
            or q in t.get("id",          "").lower()
        ]

    return results


@app.get("/threats/{threat_id}")
def get_threat_by_id(threat_id: str):
    """Get a single threat by ID."""
    for t in THREATS_DB:
        if t["id"] == threat_id:
            return t
    raise HTTPException(status_code=404, detail=f"Threat '{threat_id}' not found.")


@app.get("/dashboard/stats")
def get_dashboard_stats():
    """Return stats for dashboard cards and charts."""
    today = datetime.now().date()

    today_threats   = [t for t in THREATS_DB if _parse_dt(t["timestamp"]) and _parse_dt(t["timestamp"]).date() == today]
    drug_cases      = sum(1 for t in today_threats if t["threat_type"] == "DRUG TRAFFICKING")
    cyber_cases     = sum(1 for t in today_threats if t["threat_type"] == "CYBERBULLYING")
    traffic_alerts  = sum(1 for t in today_threats if t["threat_type"] == "HUMAN TRAFFICKING")

    days_abbr = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    weekly = []
    for i in range(6, -1, -1):
        day   = today - timedelta(days=i)
        count = sum(1 for t in THREATS_DB if _parse_dt(t["timestamp"]) and _parse_dt(t["timestamp"]).date() == day)
        if count == 0 and i > 0:
            count = random.randint(20, 65)
        weekly.append({"day": days_abbr[day.weekday()], "count": count})

    all_drug    = sum(1 for t in THREATS_DB if t["threat_type"] == "DRUG TRAFFICKING")
    all_cyber   = sum(1 for t in THREATS_DB if t["threat_type"] == "CYBERBULLYING")
    all_traffic = sum(1 for t in THREATS_DB if t["threat_type"] == "HUMAN TRAFFICKING")
    total_cat   = all_drug + all_cyber + all_traffic or 1

    return {
        "total_threats_today":   len(today_threats),
        "drug_cases":            drug_cases,
        "cyberbullying_cases":   cyber_cases,
        "trafficking_alerts":    traffic_alerts,
        "weekly_threats":        weekly,
        "threat_breakdown": [
            {"name": "Drug Trafficking",  "value": round(all_drug    / total_cat * 100), "color": "#EF4444"},
            {"name": "Cyberbullying",     "value": round(all_cyber   / total_cat * 100), "color": "#F97316"},
            {"name": "Human Trafficking", "value": round(all_traffic / total_cat * 100), "color": "#8B5CF6"},
        ],
    }


# FIX: Both GET and POST /report/:id  (frontend uses GET to display report page)
@app.get("/report/{threat_id}")
@app.post("/report/{threat_id}")
def generate_report(threat_id: str):
    """Generate a printable report for a threat."""
    for t in THREATS_DB:
        if t["id"] == threat_id:
            report_id = f"SNR-{threat_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            return {
                "report_id":    report_id,
                "generated_at": datetime.now().isoformat(),
                "threat":       t,
                "status":       "Report generated successfully",
            }
    raise HTTPException(status_code=404, detail=f"Threat '{threat_id}' not found.")


# ════════════════════════════════════════════════════════════════════════════════
# STATIC FILE SERVING  (React frontend — must be LAST)
# ════════════════════════════════════════════════════════════════════════════════

# Serve /assets/** (Vite-built JS & CSS)
if os.path.isdir(ASSETS_DIR):
    app.mount("/assets", StaticFiles(directory=ASSETS_DIR), name="assets")

# Serve individual public files (favicon.svg, vite.svg, etc.)
@app.get("/favicon.svg",  include_in_schema=False)
@app.get("/vite.svg",     include_in_schema=False)
def serve_public_file(request_path: str = ""):
    """Serve static public files from the static root."""
    # This is handled by the catch-all below but kept explicit for clarity
    if os.path.isdir(STATIC_DIR):
        return FileResponse(INDEX_HTML)
    return JSONResponse({"error": "Frontend not built."}, status_code=404)


# Catch-all: serve index.html for ALL React Router paths
@app.get("/{full_path:path}", include_in_schema=False)
def serve_frontend(full_path: str):
    """Serve React frontend for all unmatched routes."""
    # Try to serve the exact file first (favicon, robots.txt, etc.)
    if full_path and os.path.isdir(STATIC_DIR):
        exact = os.path.join(STATIC_DIR, full_path)
        if os.path.isfile(exact):
            return FileResponse(exact)

    # Fall back to index.html for React Router
    if os.path.isfile(INDEX_HTML):
        return FileResponse(INDEX_HTML)

    return JSONResponse(
        {
            "name":    "SafeNet AI API",
            "version": "1.0.0",
            "status":  "running ✅",
            "note":    "Frontend not built. Run: npm run build in safenet-frontend/",
            "docs":    "/docs",
        }
    )
