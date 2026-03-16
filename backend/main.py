"""
FraudGuard Backend — FastAPI
Run: uvicorn backend.main:app --reload --port 8000
"""
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.requests import Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import numpy as np
import uuid
import os
import json
import datetime

app = FastAPI(title="FraudShield API", version="1.0.0")

# ── Static files & templates ──────────────
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app.mount("/static", StaticFiles(directory=os.path.join(BASE,"static")), name="static")
templates = Jinja2Templates(directory=os.path.join(BASE,"templates"))

# ── In-memory SIEM store ──────────────────
siem_store = {"json_events": [], "cef_logs": []}

# ── Load ML model (lazy) ─────────────────
_model = None

def get_model():
    global _model
    if _model is not None:
        return _model
    try:
        import joblib
        model_path = os.path.join(BASE, "model", "xgb_model.pkl")
        if os.path.exists(model_path):
            _model = joblib.load(model_path)
            print("✅ ML model loaded from disk")
        else:
            print("⚠️  No model file found, using rule-based scoring")
    except Exception as e:
        print(f"⚠️  Model load error: {e}, using rule-based scoring")
    return _model

# ── Request schema ────────────────────────
class TransactionIn(BaseModel):
    sender_upi:   str   = "user@okaxis"
    receiver_upi: str   = "merchant@ybl"
    amount:       float = 1000.0
    hour:         int   = 12
    velocity:     int   = 2
    pin_fails:    int   = 0
    new_payee:    int   = 0
    vpn:          int   = 0
    payment_type: str   = "P2P"
    dow:          int   = 1
    response_ms:  int   = 200

# ── Feature engineering ───────────────────
def engineer_features(d: TransactionIn) -> dict:
    is_odd_hour  = 1 if d.hour in [0,1,2,3,4,23] else 0
    is_weekend   = 1 if d.dow >= 5 else 0
    amount_log   = float(np.log1p(d.amount))
    high_vel     = 1 if d.velocity > 6 else 0
    high_amount  = 1 if d.amount > 50000 else 0
    micro_txn    = 1 if d.amount < 10 else 0
    just_below   = 1 if 9000 <= d.amount <= 9999 else 0
    risk_score   = (d.pin_fails*2 + d.velocity*1.5 + d.new_payee*3 +
                    d.vpn*4 + is_odd_hour*2 + high_amount*3 + micro_txn*2)
    return dict(
        amount=d.amount, amount_log=amount_log, hour_of_day=d.hour, day_of_week=d.dow,
        failed_pin_attempts=d.pin_fails, txn_velocity_1hr=d.velocity, is_new_payee=d.new_payee,
        vpn_detected=d.vpn, bank_response_time_ms=d.response_ms,
        city_encoded=0, payment_type_encoded=["P2P","P2M","Recharge","Bill"].index(d.payment_type) if d.payment_type in ["P2P","P2M","Recharge","Bill"] else 0,
        is_odd_hour=is_odd_hour, is_weekend=is_weekend, high_velocity_flag=high_vel,
        high_amount_flag=high_amount, micro_txn_flag=micro_txn, just_below_limit=just_below,
        risk_score=risk_score
    )

FEATURE_ORDER = [
    'amount','amount_log','hour_of_day','day_of_week','failed_pin_attempts',
    'txn_velocity_1hr','is_new_payee','vpn_detected','bank_response_time_ms',
    'city_encoded','payment_type_encoded','is_odd_hour','is_weekend',
    'high_velocity_flag','high_amount_flag','micro_txn_flag','just_below_limit','risk_score'
]

# ── Rule-based fallback scorer ────────────
def rule_score(f: dict) -> float:
    prob = 0.02
    if f['vpn_detected']:       prob += 0.25
    if f['is_odd_hour']:        prob += 0.15
    if f['high_amount_flag']:   prob += 0.22
    if f['micro_txn_flag']:     prob += 0.18
    if f['just_below_limit']:   prob += 0.12
    if f['high_velocity_flag']: prob += 0.15
    if f['failed_pin_attempts'] > 1: prob += f['failed_pin_attempts'] * 0.06
    if f['is_new_payee']:       prob += 0.10
    return float(np.clip(prob + np.random.uniform(-0.02, 0.02), 0.01, 0.99))

def get_severity(prob: float, risk: float) -> str:
    if prob >= 0.85 or risk >= 20: return "CRITICAL"
    if prob >= 0.65 or risk >= 14: return "HIGH"
    if prob >= 0.45 or risk >= 8:  return "MEDIUM"
    return "LOW"

def get_reason(d: TransactionIn, f: dict) -> str:
    reasons = []
    if d.vpn:                  reasons.append("VPN/proxy detected")
    if f['is_odd_hour']:       reasons.append(f"Odd hour ({d.hour}:00)")
    if d.velocity > 6:         reasons.append(f"High velocity ({d.velocity}/hr)")
    if d.pin_fails > 1:        reasons.append(f"{d.pin_fails} failed PIN attempts")
    if d.new_payee:            reasons.append("First-time payee")
    if d.amount > 50000:       reasons.append(f"Large amount (₹{d.amount:,.0f})")
    if d.amount < 10:          reasons.append("Micro test transaction")
    if 9000 <= d.amount <= 9999: reasons.append("Just-below-limit pattern")
    return "; ".join(reasons) if reasons else "ML anomaly detection"

# ── SIEM log builder ──────────────────────
def build_siem_logs(txn_id: str, result: dict, d: TransactionIn):
    ts  = datetime.datetime.utcnow().isoformat() + "Z"
    sev = result["severity"]
    sev_num = {"CRITICAL":10,"HIGH":7,"MEDIUM":5,"LOW":3}.get(sev, 5)

    json_event = {
        "@timestamp": ts,
        "event": {"type": "fraud_alert", "severity": sev},
        "transaction": {"id": txn_id, "amount": d.amount, "sender": d.sender_upi,
                        "receiver": d.receiver_upi, "payment_type": d.payment_type},
        "threat": {"fraud_probability": round(result["fraud_probability"], 4),
                   "risk_score": result["risk_score"], "reason": result["reason"]},
        "source": {"vpn": bool(d.vpn), "hour": d.hour},
        "behavioral": {"velocity": d.velocity, "pin_fails": d.pin_fails},
        "alert_id": str(uuid.uuid4()),
        "model": "UPI-FraudGuard-v1.0"
    }
    cef_line = (
        f"CEF:0|UPI-FraudGuard|AIDetector|1.0|UPI_FRAUD_ALERT|"
        f"Fraudulent UPI Transaction|{sev_num}|"
        f"suser={d.sender_upi} duser={d.receiver_upi} "
        f"amt={d.amount} txnId={txn_id} "
        f"fraudProb={result['fraud_probability']:.4f} "
        f"riskScore={result['risk_score']:.1f} "
        f"reason={result['reason']}"
    )
    siem_store["json_events"].insert(0, json_event)
    siem_store["cef_logs"].insert(0, cef_line)

# ═══════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════

@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/api/score")
async def score_transaction(txn: TransactionIn):
    """Score a UPI transaction for fraud"""
    features = engineer_features(txn)
    model    = get_model()

    if model is not None:
        import pandas as pd
        X = pd.DataFrame([features])[FEATURE_ORDER]
        prob = float(model.predict_proba(X)[0][1])
    else:
        prob = rule_score(features)

    severity = get_severity(prob, features['risk_score'])
    reason   = get_reason(txn, features)
    action   = "BLOCK" if severity == "CRITICAL" else ("REVIEW" if severity in ["HIGH","MEDIUM"] else "ALLOW")
    txn_id   = "TXN" + uuid.uuid4().hex[:8].upper()
    is_fraud = prob >= 0.5

    result = {
        "txn_id":            txn_id,
        "fraud_probability": round(prob, 4),
        "is_fraud":          is_fraud,
        "severity":          severity,
        "risk_score":        round(features['risk_score'], 1),
        "action":            action,
        "reason":            reason,
        "features":          {k: features[k] for k in ['is_odd_hour','high_amount_flag','micro_txn_flag','risk_score']},
    }
    build_siem_logs(txn_id, result, txn)
    return result

@app.get("/api/alerts")
async def get_alerts(limit: int = 50, severity: str = None):
    """Get recent fraud alerts"""
    events = siem_store["json_events"]
    if severity:
        events = [e for e in events if e["event"]["severity"] == severity.upper()]
    return {"alerts": events[:limit], "total": len(events)}

@app.get("/api/siem/events")
async def get_siem_events(fmt: str = "json"):
    """Get SIEM events in JSON or CEF format"""
    if fmt == "cef":
        return {"format": "cef", "logs": siem_store["cef_logs"], "count": len(siem_store["cef_logs"])}
    return {"format": "json", "events": siem_store["json_events"], "count": len(siem_store["json_events"])}

@app.get("/api/metrics")
async def get_metrics():
    """Get aggregated fraud metrics"""
    events = siem_store["json_events"]
    counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    probs  = []
    for e in events:
        sev = e["event"]["severity"]
        if sev in counts: counts[sev] += 1
        probs.append(float(e["threat"]["fraud_probability"]))
    total   = len(events)
    flagged = sum(1 for e in events if float(e["threat"]["fraud_probability"]) >= 0.5)
    return {
        "total": total,
        "flagged": flagged,
        "alert_rate": round(flagged/total*100, 1) if total > 0 else 0,
        "avg_fraud_prob": round(sum(probs)/len(probs)*100, 2) if probs else 0,
        "severity_counts": counts,
    }

@app.get("/api/health")
async def health():
    return {"status": "ok", "model_loaded": _model is not None, "events_count": len(siem_store["json_events"])}
