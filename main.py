from fastapi import FastAPI, Request
from pymongo import MongoClient
from rfc3161ng import get_timestamp



import datetime, hashlib, os, joblib, numpy as np

# Final fix to trigger redeploy
app = FastAPI()

# Configuration (Replace if need

import datetime, hashlib, os, joblib, numpy as np

# Final fix to trigger redeploy
app = FastAPI()

# Configuration (Replace if needed, but هذا هو URI الحالي)
MONGO_URI = "mongodb+srv://h59146083_db_user:ky0of5mh6hVXglIL@cluster0.jztcrtp.mongodb.net/?appName=Cluster0"
client = MongoClient(MONGO_URI)
db = client["mini_xdr"]
events = db["events"]

# Load AI Model (Isolation Forest)
MODEL_PATH = "iso_model.joblib"
model = None
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)

# =================================================================
# يجب أن تكون مسارات FastAPI هنا
# =================================================================
    print("✅ AI Model Loaded Successfully.")
else:
    print("⚠️ Warning: AI Model not found. Scoring will be set to 0.0.")

@app.get("/")
def home():
    return {"status":"mini XDR running"}

# --- Utility Functions ---

def compute_sha256(obj):
    # Component: Chain of Custody (SHA256)
    raw = str(obj).encode()
    return hashlib.sha256(raw).hexdigest()

def get_rfc3161_timestamp(data_hash):
    # Component: RFC 3161 Time Stamping Authority (TSA)
    # ملاحظة: TSA هذا موثوق وعام لكنه قد يتأخر أو يفشل أحياناً
    tsa_url = "http://tsa.pki.gov.cn/cms"
    try:
        # طلب الختم الزمني لـ SHA256
        tsr = get_timestamp(data_hash.encode('utf-8'), hash_algo='sha256', url=tsa_url, timeout=7)
        # نعود بالختم كـ Base64 (هو الإثبات الموثوق)
        return tsr.timestamp_token.decode('utf-8')
    except (RFC3161Error, HTTPError) as e:
        print(f"RFC3161 Error: Failed to get timestamp token. {e}")
        return "RFC_ERROR"
    except Exception as e:
        print(f"TSA Connection Error: {e}")
        return "TSA_UNREACHABLE"

def score_event(ev):    
    # Component: Isolation Forest (AI)
    proc = ev.get("process","")
    length = len(proc)
    severity = 1 if ev.get("severity","low")=="high" else 0
    X = np.array([[length, severity]])
    if model is None:
        return 0.0
    return float(model.decision_function(X)[0])

# --- Main Ingest Route (SIEM/XDR Core) ---
@app.post("/ingest")
async def ingest(request: Request):
    # 1. Prepare Payload
    payload = await request.json()
    payload["_received_at"] = datetime.datetime.utcnow().isoformat()
    
    # 2. Chain of Custody & RFC 3161
    payload["_sha256"] = compute_sha256(payload)
    payload["_rfc3161_token"] = get_rfc3161_timestamp(payload["_sha256"]) # إضافة الختم
    
    # 3. AI Scoring
    payload["_iso_score"] = score_event(payload)
    
    # 4. SOAR Rule (Using the threshold that successfully triggered the action: -0.05)
    payload["_action"] = False
    if payload["_iso_score"] < -0.05 and payload.get("severity")=="high":
        payload["_action"] = True
        # In a real system: Trigger isolation API call here
        print("🚨 SOAR: action triggered for suspicious event:", payload)
        
    # 5. Store the event (SIEM Storage)
    res = events.insert_one(payload)
    
    # 6. Return Response
    return {
        "status":"stored", 
        "id": str(res.inserted_id), 
        "sha256": payload["_sha256"], 
        "rfc3161_token": payload["_rfc3161_token"], # إضافة الختم في الرد
        "iso_score": payload["_iso_score"], 
        "action": payload["_action"]
    }
