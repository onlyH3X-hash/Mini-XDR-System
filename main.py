from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from pymongo import MongoClient
from rfc3161ng import get_timestamp 
from contextlib import asynccontextmanager

import datetime, hashlib, os, joblib, numpy as np
from typing import List, Any
from bson import ObjectId 

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
# 2. تعريف نموذج الإخراج والتخزين (Storage/Output Model)
# =================================================================
class EventRecord(EventDataInput):
    """النموذج الكامل للحدث كما هو مخزن في قاعدة البيانات (الإخراج)."""
    # نستخدم alias="_id" لربط الحقل 'id' بـ '_id' في MongoDB
    id: str = Field(alias="_id", default_factory=lambda: str(ObjectId()), description="معرف MongoDB الفريد للحدث.")
    timestamp: datetime.datetime = Field(default_factory=datetime.datetime.now, description="وقت وقوع الحدث.")
    risk_score: float = Field(default=0.0, description="درجة الخطر المحسوبة بواسطة الذكاء الاصطناعي (0.0 - 1.0).")
    event_hash: str = Field(..., description="تجزئة SHA256 للحدث لضمان سلسلة الحراسة.")

    class Config:
        populate_by_name = True
        json_encoders = {ObjectId: str}
        arbitrary_types_allowed = True

# =================================================================
# تهيئة التطبيق وإدارة الموارد (MongoDB)
# =================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """تهيئة الموارد عند بدء التشغيل وإغلاقها عند الإغلاق."""
    
    # --- 1. إعداد MongoDB ---
    MONGO_URI = os.getenv("MONGO_URI") 
    if not MONGO_URI:
        raise ValueError("MONGO_URI environment variable is not set!")
    
    app.mongodb_client = MongoClient(MONGO_URI)
    app.mongodb = app.mongodb_client["mini_xdr"]
    app.events_collection = app.mongodb["events"]
    print("✅ MongoDB Client and Database Initialized.")

    # --- 2. تحميل نموذج AI ---
    MODEL_PATH = "iso_model.joblib"
    app.model = None
    if os.path.exists(MODEL_PATH):
        try:
            app.model = joblib.load(MODEL_PATH)
            print("✅ AI Model Loaded Successfully.")
        except Exception as e:
             print(f"⚠️ Warning: Failed to load AI Model: {e}")
    else:
        print("⚠️ Warning: AI Model not found. Scoring will be set to 0.0.")

    yield 

    # --- 3. إغلاق اتصال MongoDB عند إيقاف التشغيل ---
    if hasattr(app, 'mongodb_client'):
        app.mongodb_client.close()
        print("🛑 MongoDB Client closed.")

app = FastAPI(lifespan=lifespan)

# =================================================================
# وظائف مساعدة
# =================================================================

@app.get("/")
def home():
    return {"status":"mini XDR running"}

def compute_sha256(obj):
    # Component: Chain of Custody (SHA256)
    raw = str(obj).encode()
    return hashlib.sha256(raw).hexdigest()

def score_event(event_data: EventDataInput, model) -> float:
    """يحسب درجة الخطر باستخدام نموذج AI."""
    if model is not None:
        features = np.array([
            hash(event_data.source_ip) % 1000,
            hash(event_data.event_type) % 1000
        ]).reshape(1, -1)
        
        prediction = model.predict(features)[0]
        return 1.0 if prediction == -1 else 0.0
    
    return 0.0 

# =================================================================
# مسارات FastAPI الرئيسية
# =================================================================

# =================================================================
# مسارات FastAPI الرئيسية
# =================================================================

@app.get("/events", response_model=List[EventRecord], summary="جلب جميع الأحداث الأمنية المسجلة")
async def list_events():
    """يجلب جميع الوثائق من مجموعة 'events' ويعرضها كقائمة."""
    try:
        events_list = []
        for event in app.events_collection.find():
            
            # 1. تحويل ObjectId إلى str
            event['_id'] = str(event['_id'])
            
            # 2. **التعديل الحاسم:** التحقق من وجود 'timestamp' قبل التحويل
            if 'timestamp' in event:
                # 3. التحويل الآمن
                if isinstance(event['timestamp'], datetime.datetime):
                    event['timestamp'] = event['timestamp'].isoformat()
            
            events_list.append(event)
        
        return events_list
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Internal Server Error during data retrieval: {e}" 
        )

@app.post("/log", response_model=EventRecord, summary="تسجيل حدث أمني جديد وتحليل الخطر")
async def log_event(event_input: EventDataInput):
    """يسجل حدث أمن جديد ويقوم بحساب درجة خطورته."""
    
    # 1. تحويل نموذج الإدخال إلى قاموس وتحديد الوقت
    event_dict = event_input.model_dump()
    event_dict['timestamp'] = datetime.datetime.now()
    
    # 2. تحليل وحساب درجة الخطر
    risk_score = score_event(event_input, app.model)
    event_dict['risk_score'] = risk_score
    
    # 3. إنشاء سلسلة الحراسة (Chain of Custody) - SHA256
    event_hash = compute_sha256(event_dict)
    event_dict['event_hash'] = event_hash
    
    # 4. تخزين الحدث في MongoDB
    try:
        result = app.events_collection.insert_one(event_dict)
        
        # 5. بناء كائن الاستجابة الصحيح:
        # نخصص ID الذي تم إنشاؤه من MongoDB في القاموس
        event_dict['_id'] = str(result.inserted_id)
        
        # نستخدم القاموس النهائي event_dict لإنشاء كائن EventRecord
        # هذا يحل مشكلة 'multiple values for _id' (الخطأ 400)
        return EventRecord(**event_dict)

    except Exception as e:
        raise HTTPException(
            status_code=400, 
            detail={"status": "Failed to log event to MongoDB", "error": str(e)}
        )
