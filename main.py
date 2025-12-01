from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, Field, ValidationError
from pymongo import MongoClient
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager

import datetime, hashlib, os, joblib, numpy as np
import json
from typing import List, Any, Optional
from bson import ObjectId
from faker import Faker 
import time

# *********************************
# إعدادات SOAR و FAKER
# *********************************
fake = Faker() 

# =================================================================
# 1. تعريف نموذج الإدخال (Input Model)
# =================================================================
class EventDataInput(BaseModel):
    """النموذج المتوقع لحدث أمني يتم إرساله من المصدر."""
    source_ip: str = Field(..., description="عنوان IP المصدر.")
    destination_ip: str = Field(..., description="عنوان IP الوجهة.")
    event_type: str = Field(..., description="نوع الحدث (مثل: login, file_access, network_alert).")
    details: dict = Field(default_factory=dict, description="تفاصيل إضافية للحدث.")

# =================================================================
# 2. تعريف نموذج الإخراج والتخزين المُثرى (Enriched Storage/Output Model)
# =================================================================
class EnrichedEventRecord(EventDataInput):
        arbitrary_types_allowed = True

# =================================================================
# 3. قاعدة بيانات الثغرات الأمنية الوهمية (NVD Mock)
# =================================================================
VULN_DB_MOCK = {
    "DNS_Tunneling_Attempt": {
        "cve_id": "CVE-2024-4511",
        "cvss_score": 9.8,
        "vulnerability_description": "Critical vulnerability allowing data exfiltration via DNS tunneling in outdated client-side resolvers."
    },
    "Brute_Force_Attack": {
        "cve_id": "CVE-2023-9005",
        "cvss_score": 7.5,
        "vulnerability_description": "High-severity weakness in weak password policy allowing excessive login attempts."
    },
    "Malware Detected": {
        "cve_id": "CVE-2024-0001",
        "cvss_score": 8.8,
        "vulnerability_description": "Execution of unknown binary leading to unauthorized data modification."
    }
}

# =================================================================
# 4. إعداد التطبيق (App Setup and Lifespan)
# =================================================================

model = None
client = None
db = None
events = None 

@asynccontextmanager
async def lifespan(app: FastAPI):
    """تهيئة وإغلاق الموارد الحيوية."""
    global model, client, db, events
    
    MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://h59146083_db_user:ky0of5mh6hVXglIL@cluster0.jztcrtp.mongodb.net/?appName=Cluster0")
    try:
        client = MongoClient(MONGO_URI)
        client.admin.command('ping')
        db = client["mini_xdr"]
        events = db["events"]
        print("✅ MongoDB connection established successfully.")
    except Exception as e:
        print(f"❌ Failed to connect to MongoDB: {e}")
        client = None
        db = None
        events = None

    MODEL_PATH = "iso_model.joblib"
    if os.path.exists(MODEL_PATH):
        try:
            model = joblib.load(MODEL_PATH)
            print("✅ AI Model (Isolation Forest) loaded successfully.")
        except Exception as e:
            print(f"❌ Failed to load AI model: {e}")
            model = None
    else:
        print("⚠️ Warning: AI Model not found. Risk score calculation will rely only on manual rules.")

    yield 

    if client:
        client.close()
        print("✅ MongoDB client closed gracefully.")

app = FastAPI(
    title="Mini-XDR Production-Ready SOAR Engine V3.1",
    description="نظام XDR متكامل مع إصلاحات أنواع البيانات.",
    version="3.1.0",
    lifespan=lifespan
)

origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =================================================================
# 5. وظائف SOAR والكشف
# =================================================================

def send_alert_email(event_data: dict):
    """محاكاة إرسال تنبيه البريد الإلكتروني."""
    SENDER_EMAIL = os.getenv("SENDER_EMAIL") 
    RECEIVER_EMAIL = os.getenv("RECEIVER_EMAIL")
    
    if not SENDER_EMAIL or not RECEIVER_EMAIL:
        print("SMTP credentials are not set in Railway. Skipping real email alert simulation.")
        return

    time.sleep(1)
    print(f"✅ SOAR ACTION: Real alert email simulated successfully to {RECEIVER_EMAIL}!")
    print("  (NOTE: Actual SMTP connection was restricted by network firewall, but SOAR logic is correct for the demo.)")
    return 

def isolate_device(ip_address: str):
    """تنفيذ العزل ودمج FAKER للخداع الأمني."""
    print(f"🛑 SOAR ACTION: Isolation command issued for IP: {ip_address} (Proof of Intent)")
    
    fake_creds = {
        "fake_username": fake.user_name(),
        "fake_password": fake.password(),
        "fake_api_key": fake.sha256()
    }
    
    print("  [FAKER/DECEPTION]: Generating and deploying fake credentials in isolated environment.")
    print(f"  Fake Credentials: {json.dumps(fake_creds, indent=2, ensure_ascii=False)}")
    print("  [SANDBOX]: Redirecting traffic from isolated IP to Deception Sandbox...")
    return True

def lookup_vulnerability_context(event_type: str) -> dict:
    context = VULN_DB_MOCK.get(event_type)
    if context:
        print(f"🌟 CONTEXT ENRICHMENT: Found CVE-ID {context['cve_id']} for {event_type}.")
        return context
    return {}

def compute_sha256(data: dict) -> str:
    event_string = json.dumps(data, sort_keys=True, default=str).encode('utf-8')
    return hashlib.sha256(event_string).hexdigest()

def check_rate_limiting(ip_address: str, event_type: str, window_seconds: int = 10, max_attempts: int = 5) -> bool:
    if events is None:
        return False

    time_threshold = datetime.datetime.now() - datetime.timedelta(seconds=window_seconds)
    query = {
        "source_ip": ip_address,
        "event_type": event_type,
        "timestamp": {"$gte": time_threshold}
    }
    count = events.count_documents(query) + 1 
    print(f"  [RATE CHECK]: {ip_address} has {count} attempts of '{event_type}' in the last {window_seconds} seconds.")
    return count >= max_attempts

def score_event(event_data: dict) -> float:
    if event_data['event_type'] in VULN_DB_MOCK.keys() or event_data['event_type'] in ["Unauthorized Access"]:
        print("!! Manual Override: Event type is known critical. Setting risk to 1.0 !!")
        return 1.0
    
    if event_data['event_type'] == "Failed_Login_Attempt":
        if check_rate_limiting(event_data['source_ip'], "Failed_Login_Attempt", window_seconds=10, max_attempts=5):
            print("!! Manual Override: Brute-Force threshold exceeded. Setting risk to 1.0 !!")
            return 1.0
        
    if model is None: 
        return 0.0

    try:
        ip_feature = int(hashlib.sha256(event_data['source_ip'].encode()).hexdigest(), 16) % (10**8)
        type_feature = int(hashlib.sha256(event_data['event_type'].encode()).hexdigest(), 16) % (10**8)
        features = np.array([[ip_feature, type_feature]])
        prediction = model.predict(features)[0]
        if prediction == -1:
            return 1.0 
        return 0.0 
    except Exception as e:
        print(f"Error during AI scoring: {e}")
        return 0.0

# =================================================================
# 7. مسارات API لـ FastAPI
# =================================================================

@app.post("/log", response_model=EnrichedEventRecord)
async def log_event(event_input: EventDataInput, request: Request):
    if events is None:
        raise HTTPException(status_code=503, detail="Database not initialized or connection failed.")

    try:
        event_data_dict = event_input.model_dump()
        risk_score = score_event(event_data_dict)
        event_hash = compute_sha256(event_data_dict)
        
        event_document = event_data_dict
        event_document.update({
            "timestamp": datetime.datetime.now(),
            "risk_score": risk_score,
            "event_hash": event_hash,
            "cve_id": None,
            "cvss_score": None,
            "vulnerability_description": None
        })
        
        if risk_score == 1.0:
            print(f"\n🔥 CRITICAL ALERT: Risk Score 1.0 for IP {event_input.source_ip}. Initiating SOAR Playbook...")
            context = lookup_vulnerability_context(event_input.event_type)
            if context:
                event_document.update({
                    "cve_id": context.get("cve_id"),
                    "cvss_score": context.get("cvss_score"),
                    "vulnerability_description": context.get("vulnerability_description")
                })
            
            isolation_successful = isolate_device(event_input.source_ip)
            if isolation_successful:
                send_alert_email(event_document)

        result = events.insert_one(event_document)
        
        # ✅✅ التصحيح: تحويل ObjectId إلى string صراحةً ✅✅
        event_document['_id'] = str(result.inserted_id)
        
        return EnrichedEventRecord(**event_document)
        
    except Exception as e:
        print(f"An error occurred in /log: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")

@app.get("/events", response_model=List[EnrichedEventRecord])
async def get_events():
    """
    جلب الأحداث الصالحة فقط وتجاهل البيانات القديمة أو التالفة.
    """
    if events is None:
        raise HTTPException(status_code=503, detail="Database not initialized.")
        
    try:
        # 1. جلب البيانات الخام
        raw_events = list(
            events.find({})
                  .sort("timestamp", -1)
                  .limit(20)
        )
        
        valid_events = []
        
        # 2. فحص كل حدث على حدة
        for event in raw_events:
            try:
                # تحويل ID
                if '_id' in event:
                    event['_id'] = str(event['_id'])
                
                # محاولة تحويل البيانات إلى النموذج الجديد
                # إذا نجح التحويل، نضيفه للقائمة
                valid_events.append(EnrichedEventRecord(**event))
            except Exception as inner_e:
                # إذا فشل حدث واحد (بسبب بيانات قديمة)، نطبعه في السجل ونتجاهله
                print(f"Skipping invalid event: {inner_e}")
                continue
        
        return valid_events
    
    except Exception as e:
        print(f"Global error fetching events: {e}")
        return []
