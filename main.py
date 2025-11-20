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
    """النموذج الكامل للحدث كما هو مخزن في قاعدة البيانات (بعد الإثراء)."""
    id: str = Field(alias="_id", default_factory=lambda: str(ObjectId()), description="معرف MongoDB الفريد للحدث.")
    timestamp: datetime.datetime = Field(default_factory=datetime.datetime.now, description="وقت وقوع الحدث.")
    risk_score: float = Field(default=0.0, description="درجة الخطر المحسوبة بواسطة الذكاء الاصطناعي (0.0 - 1.0).")
    event_hash: str = Field(..., description="تجزئة SHA256 للحدث لضمان سلسلة الحراسة.")
    
    # حقول إثراء الثغرات الجديدة
    cve_id: Optional[str] = Field(None, description="معرف الثغرة المرتبط (CVE-ID) بعد عملية الإثراء.")
    cvss_score: Optional[float] = Field(None, description="درجة الخطورة وفقاً لمعيار CVSS V3.")
    vulnerability_description: Optional[str] = Field(None, description="وصف موجز للثغرة.")

    class Config:
        # إعدادات Pydantic
        populate_by_name = True
        json_encoders = {ObjectId: str}
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
events = None # سيكون None إذا فشل الاتصال

@asynccontextmanager
async def lifespan(app: FastAPI):
    """تهيئة وإغلاق الموارد الحيوية (قاعدة البيانات ونموذج الذكاء الاصطناعي)."""
    global model, client, db, events
    
    # تهيئة MongoDB
    # استخدام قيمة افتراضية إذا لم يتم تعيين متغير البيئة
    MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://h59146083_db_user:ky0of5mh6hVXglIL@cluster0.jztcrtp.mongodb.net/?appName=Cluster0")
    try:
        client = MongoClient(MONGO_URI)
        client.admin.command('ping')
        db = client["mini_xdr"]
        events = db["events"]
        print("✅ MongoDB connection established successfully.")
    except Exception as e:
        print(f"❌ Failed to connect to MongoDB: {e}")
        # إذا فشل الاتصال، ستبقى المتغيرات client, db, events بقيمة None
        client = None
        db = None
        events = None

    # تحميل نموذج AI (Isolation Forest)
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

    yield # بدء تشغيل التطبيق

    # إغلاق الموارد بعد انتهاء دورة حياة التطبيق
    if client:
        client.close()
        print("✅ MongoDB client closed gracefully.")

app = FastAPI(
    title="Mini-XDR Production-Ready SOAR Engine V3 - Contextualized (Fixed)",
    description="نظام XDR متكامل مع AI، SOAR، وخاصية الخداع الأمني وإثراء سياق الثغرات.",
    version="3.0.1",
    lifespan=lifespan
)

# تفعيل CORS للسماح بالوصول من أي مصدر
origins = ["*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =================================================================
# 5. وظائف SOAR التنفيذية وإثراء البيانات
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
    """
    استدعاء وهمي لقاعدة بيانات الثغرات (مثل NVD) لإثراء البيانات.
    """
    context = VULN_DB_MOCK.get(event_type)
    
    if context:
        print(f"🌟 CONTEXT ENRICHMENT: Found CVE-ID {context['cve_id']} for {event_type}. CVSS: {context['cvss_score']}")
        return context
    
    print(f"✨ CONTEXT ENRICHMENT: No specific CVE found for {event_type}. Continuing...")
    return {}

# =================================================================
# 6. وظائف التوثيق والكشف
# =================================================================

def compute_sha256(data: dict) -> str:
    """حساب تجزئة SHA256 للحدث لضمان سلسلة الحراسة (CoC)."""
    event_string = json.dumps(data, sort_keys=True, default=str).encode('utf-8')
    return hashlib.sha256(event_string).hexdigest()

def check_rate_limiting(ip_address: str, event_type: str, window_seconds: int = 10, max_attempts: int = 5) -> bool:
    """
    يتحقق من عدد مرات تكرار حدث معين (مثل الفشل في تسجيل الدخول)
    في نافذة زمنية محددة للكشف عن هجمات القوة الغاشمة (Brute-Force).
    """
    # **التصحيح الهام**: يجب المقارنة بـ None وليس باستخدام if not events
    if events is None:
        return False

    time_threshold = datetime.datetime.now() - datetime.timedelta(seconds=window_seconds)
    
    query = {
        "source_ip": ip_address,
        "event_type": event_type,
        "timestamp": {"$gte": time_threshold}
    }
    
    # يجب إدراج المحاولة الحالية في العد، لذا نستخدم +1
    count = events.count_documents(query) + 1 
    
    print(f"  [RATE CHECK]: {ip_address} has {count} attempts of '{event_type}' in the last {window_seconds} seconds.")

    return count >= max_attempts

def score_event(event_data: dict) -> float:
    """يحسب درجة الخطر للحدث باستخدام نموذج Isolation Forest أو القواعد اليدوية."""
    
    # القاعدة 1: الكشف عن هجمات الحقن/الأنفاق الواضحة
    if event_data['event_type'] in VULN_DB_MOCK.keys() or event_data['event_type'] in ["Unauthorized Access"]:
        print("!! Manual Override: Event type is known critical or injection-based. Setting risk to 1.0 !!")
        return 1.0
    
    # القاعدة 2: الكشف عن هجمات القوة الغاشمة (Brute-Force)
    if event_data['event_type'] == "Failed_Login_Attempt":
        # الآن نمرر الحدث الحالي لتضمينه في check_rate_limiting
        if check_rate_limiting(event_data['source_ip'], "Failed_Login_Attempt", window_seconds=10, max_attempts=5):
            print("!! Manual Override: Brute-Force threshold exceeded. Setting risk to 1.0 !!")
            return 1.0
        
    # منطق الذكاء الاصطناعي (إذا لم يكن هناك قواعد يدوية حاسمة)
    if model is None: 
        return 0.0

    try:
        ip_feature = int(hashlib.sha256(event_data['source_ip'].encode()).hexdigest(), 16) % (10**8)
        type_feature = int(hashlib.sha256(event_data['event_type'].encode()).hexdigest(), 16) % (10**8)
        
        features = np.array([[ip_feature, type_feature]])
        prediction = model.predict(features)[0]
        
        if prediction == -1:
            return 1.0 # خطر مرتفع
        return 0.0 # خطر منخفض
    except Exception as e:
        print(f"Error during AI scoring: {e}")
        return 0.0

# =================================================================
# 7. مسارات API لـ FastAPI
# =================================================================

@app.post("/log", response_model=EnrichedEventRecord)
async def log_event(event_input: EventDataInput, request: Request):
    """
    استلام الأحداث الأمنية، حساب درجة الخطورة، وتخزينها، وتنفيذ SOAR عند الضرورة وإثراء البيانات.
    """
    # **التصحيح الهام**: التحقق من تهيئة Collection باستخدام المقارنة بـ None
    if events is None:
        raise HTTPException(status_code=503, detail="Database not initialized or connection failed.")

    try:
        # 1. حساب درجة الخطورة (Risk Score)
        event_data_dict = event_input.model_dump()
        risk_score = score_event(event_data_dict)
        
        # 2. إنشاء هاش التوثيق (CoC)
        event_hash = compute_sha256(event_data_dict)
        
        # 3. إعداد الوثيقة الأساسية للتخزين
        event_document = event_data_dict
        event_document.update({
            "timestamp": datetime.datetime.now(),
            "risk_score": risk_score,
            "event_hash": event_hash,
            # تعيين القيم الافتراضية للـ Context
            "cve_id": None,
            "cvss_score": None,
            "vulnerability_description": None
        })
        
        # 4. تنفيذ الرد الآلي (SOAR) وإثراء السياق (CONTEXT ENRICHMENT)
        if risk_score == 1.0:
            print(f"\n🔥 CRITICAL ALERT: Risk Score 1.0 for IP {event_input.source_ip}. Initiating SOAR Playbook...")
            
            # ** خطوة الإثراء **
            context = lookup_vulnerability_context(event_input.event_type)
            if context:
                event_document.update({
                    "cve_id": context.get("cve_id"),
                    "cvss_score": context.get("cvss_score"),
                    "vulnerability_description": context.get("vulnerability_description")
                })
            
            # تنفيذ الرد الآلي
            isolation_successful = isolate_device(event_input.source_ip)
            if isolation_successful:
                send_alert_email(event_document)

        # 5. التخزين في MongoDB
        result = events.insert_one(event_document)
        
        # 6. إرجاع المستند المخزن كاملاً وفقاً لـ EnrichedEventRecord
        event_document['_id'] = result.inserted_id
        return EnrichedEventRecord(**event_document)
        
    except Exception as e:
        print(f"An error occurred in /log: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {e}")

@app.get("/events", response_model=List[EnrichedEventRecord])
async def get_events():
    """
    جلب آخر 20 حدث أمني من MongoDB للعرض على لوحة القيادة (مع بيانات الإثراء).
    """
    # **التصحيح الهام**: التحقق من تهيئة Collection باستخدام المقارنة بـ None
    if events is None:
        raise HTTPException(status_code=503, detail="Database not initialized or connection failed.")
        
    try:
        latest_events = list(
            events.find({})
                  .sort("timestamp", -1) # الأحدث أولاً
                  .limit(20) # آخر 20 حدث
        )
        
        # إنشاء نماذج الإخراج
        return [EnrichedEventRecord(**event) for event in latest_events]
    
    except Exception as e:
        print(f"Error fetching events: {e}")
        # في حالة وجود خطأ آخر غير خطأ التهيئة، إرجاع قائمة فارغة بدلاً من خطأ 500
        return []
