# FraudShield — UPI Fraud Detection Web App

## Project Structure
```
upi_fraud_app/
├── backend/
│   └── main.py              ← FastAPI backend (all API routes)
├── static/
│   ├── css/style.css        ← Dark terminal UI styles
│   └── js/app.js            ← Frontend logic, scoring, charts
├── templates/
│   └── index.html           ← Main HTML (4 tabs)
├── model/
│   └── xgb_model.pkl        ← (place your trained model here)
├── requirements.txt
└── README.md
```

## Setup & Run

### Option A — With FastAPI backend (full)
```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. (Optional) Train and save model from your Colab notebook:
#    import joblib
#    joblib.dump(xgb_model, 'model/xgb_model.pkl')

# 3. Run the server
uvicorn backend.main:app --reload --port 8000

# 4. Open browser: http://localhost:8000
```

### Option B — Without backend (static HTML, Colab-friendly)
Just open templates/index.html directly in a browser.
The app includes a full local JavaScript scoring engine — no server needed.
All fraud scoring, alerts, metrics, and SIEM logs work offline.

## API Endpoints
| Method | Route              | Description                        |
|--------|--------------------|------------------------------------|
| GET    | /                  | Web UI                             |
| POST   | /api/score         | Score a UPI transaction            |
| GET    | /api/alerts        | Get recent fraud alerts            |
| GET    | /api/siem/events   | Get SIEM logs (json or cef format) |
| GET    | /api/metrics       | Get aggregated fraud metrics       |
| GET    | /api/health        | Health check                       |

## Tabs
- **Score** — Submit a transaction, get fraud probability + severity
- **Alerts** — Live feed of all flagged transactions, filterable by severity  
- **Metrics** — KPI cards + severity chart + probability distribution + timeline
- **SIEM** — CEF/JSON log viewer, copy to clipboard, export as file

## SIEM Formats
- **JSON** — Compatible with Elastic SIEM, Microsoft Sentinel
- **CEF** — Compatible with Splunk, IBM QRadar, ArcSight
