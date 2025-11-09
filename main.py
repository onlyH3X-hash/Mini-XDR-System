from fastapi import FastAPI, Request
from pydantic import BaseModel, Field
from pymongo import MongoClient
from rfc3161ng import get_timestamp # هذا الاستيراد هو الوحيد الذي يعمل

# ⚠️ تم حذف محاولات استيراد RFC3161Error و HTTPError التي كانت تسبب التعطّل.

import datetime, hashlib, os, joblib, numpy as np

# 1. تعريف نموذج Pydantic لبيانات الحدث
class EventData(BaseModel):
    """النموذج المتوقع لحدث أمني يتم تسجيله."""
    timestamp: datetime.datetime = Field(default_factory=datetime.datetime.now, description="وقت وقوع الحدث.")
    source_ip: str = Field(..., description="عنوان IP المصدر.")
    destination_ip: str = Field(..., description="عنوان IP الوجهة.")
    event_type: str = Field(..., description="نوع الحدث (مثل: login, file_access, network_alert).")
    details: dict = Field(default_factory=dict, description="تفاصيل إضافية للحدث.")

# Final fix to trigger redeploy
app = FastAPI()

# Configuration
MONGO_URI = "mongodb+srv://h59146083_db_user:ky0of5mh6hVXglIL@cluster0.jztcrtp.mongodb.net/?appName=Cluster0"
client = MongoClient(MONGO_URI)
db = client["mini_xdr"]
events = db["events"]

# Load AI Model (Isolation Forest)
MODEL_PATH = "iso_model.joblib"
model = None
if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)
    print("✅ AI Model Loaded Successfully.")
else:
    print("⚠️ Warning: AI Model not found. Scoring will be set to 0.0.")

# =================================================================
# مسارات FastAPI هنا
# =================================================================

@app.get("/")
def home():
    return {"status":"mini XDR running"}

# --- Utility Functions ---

def compute_sha256(obj):
    # Component: Chain of Custody (SHA256)
    raw = str(obj).encode()
    return hashlib.sha256(raw).hexdigest()

def score_event(event_data: EventData) -> float:
    """يحسب درجة الخطر باستخدام نموذج AI أو درجة صفرية إذا لم يتم العثور على النموذج."""
    if model:
        # مثال مبسط لترميز البيانات لنموذج Isolation Forest (يجب تعديله لبيانات حقيقية)
        features = np.array([
            hash(event_data.source_ip) % 1000,
            hash(event_data.event_type) % 1000,
            len(event_data.details)
        ]).reshape(1, -1)
        
        # نموذج Isolation Forest يعطي -1 للحالات الشاذة و 1 للحالات الطبيعية
        prediction = model.predict(features)[0]
        # نحول النتيجة إلى درجة خطر (1.0 لخطر عالي، 0.0 لخطر منخفض)
        return 1.0 if prediction == -1 else 0.0
    
    return 0.0 # درجة الخطر الافتراضية إذا لم يتم تحميل النموذج

def get_rfc3161_timestamp(data_hash):
    # هذه الدالة تتطلب المزيد من التنفيذ
    return None

# --- Main Endpoints ---

@app.post("/log")
async def log_event(event: EventData):
    """يسجل حدث أمن جديد ويقوم بحساب درجة خطورته."""
    
    event_dict = event.model_dump()
    
    # 1. تحليل وحساب درجة الخطر
    risk_score = score_event(event)
    event_dict['risk_score'] = risk_score
    
    # 2. إنشاء سلسلة الحراسة (Chain of Custody) - SHA256
    event_hash = compute_sha256(event_dict)
    event_dict['event_hash'] = event_hash
    
    # 3. محاولة الحصول على ختم زمني موثوق (RFC 3161)
    # timestamp_proof = get_rfc3161_timestamp(event_hash) # معطل مؤقتاً لحين التنفيذ
    # if timestamp_proof:
    #     event_dict['timestamp_proof'] = timestamp_proof
    
    # 4. تخزين الحدث في MongoDB (بدلاً من Firestore مؤقتاً)
    try:
        events.insert_one(event_dict)
        return {
            "status": "Event logged successfully",
            "risk_score": risk_score,
            "event_hash": event_hash,
            "db_status": "Logged to MongoDB"
        }
    except Exception as e:
        return {
            "status": "Failed to log event",
            "error": str(e)
        }


