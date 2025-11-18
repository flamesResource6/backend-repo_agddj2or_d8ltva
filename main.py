import os
from datetime import datetime
from typing import List, Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr
from bson import ObjectId

from database import db, create_document, get_documents
from schemas import User, Doctorprofile, Service, Appointment, Message, Rating, Report

# Environment & security setup
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")

app = FastAPI(title="MediCare Plus API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utility helpers
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    user_id: Optional[str] = None
    role: Optional[str] = None

class AuthUser(BaseModel):
    id: str
    name: str
    email: EmailStr
    role: str


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow().timestamp() + ACCESS_TOKEN_EXPIRE_MINUTES * 60})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def get_user_by_email(email: str) -> Optional[dict]:
    return db["user"].find_one({"email": email}) if db else None


def get_user_by_id(user_id: str) -> Optional[dict]:
    try:
        return db["user"].find_one({"_id": ObjectId(user_id)}) if db else None
    except Exception:
        return None


async def get_current_user(token: str = Depends(oauth2_scheme)) -> AuthUser:
    credentials_exception = HTTPException(status_code=401, detail="Could not validate credentials")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        role: str = payload.get("role")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user_doc = get_user_by_id(user_id)
    if not user_doc:
        raise credentials_exception
    return AuthUser(id=str(user_doc["_id"]), name=user_doc["name"], email=user_doc["email"], role=user_doc.get("role", "patient"))


def require_role(allowed: List[str]):
    def role_dependency(user: AuthUser = Depends(get_current_user)) -> AuthUser:
        if user.role not in allowed:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return role_dependency


@app.get("/")
def root():
    return {"message": "MediCare Plus API running"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Set"
            response["database_name"] = db.name
            response["connection_status"] = "Connected"
            response["collections"] = db.list_collection_names()
            response["database"] = "✅ Connected & Working"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:80]}"
    return response


# ============ AUTH ============
@app.post("/auth/register", response_model=AuthUser)
def register(user: User):
    if get_user_by_email(user.email):
        raise HTTPException(status_code=400, detail="Email already registered")
    doc = user.model_dump()
    doc["password_hash"] = get_password_hash(doc["password_hash"])  # store hash
    inserted_id = create_document("user", doc)
    created = db["user"].find_one({"_id": ObjectId(inserted_id)})
    return AuthUser(id=str(created["_id"]), name=created["name"], email=created["email"], role=created.get("role", "patient"))


@app.post("/auth/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_doc = get_user_by_email(form_data.username)
    if not user_doc or not verify_password(form_data.password, user_doc.get("password_hash", "")):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    token = create_access_token({"sub": str(user_doc["_id"]), "role": user_doc.get("role", "patient")})
    return Token(access_token=token)


# ============ DOCTOR PROFILES ============
@app.post("/doctors", dependencies=[Depends(require_role(["admin"]))])
def create_doctor_profile(profile: Doctorprofile):
    if not get_user_by_id(profile.user_id):
        raise HTTPException(status_code=404, detail="User not found")
    inserted_id = create_document("doctorprofile", profile)
    return {"id": inserted_id}


@app.get("/doctors")
def list_doctors(specialization: Optional[str] = None, location: Optional[str] = None):
    q = {}
    if specialization:
        q["specialization"] = specialization
    if location:
        q["location"] = location
    docs = get_documents("doctorprofile", q)
    return [{**{k: v for k, v in d.items() if k != "_id"}, "id": str(d["_id"])} for d in docs]


# ============ SERVICES ============
@app.post("/services", dependencies=[Depends(require_role(["admin"]))])
def create_service(service: Service):
    inserted_id = create_document("service", service)
    return {"id": inserted_id}


@app.get("/services")
def list_services(category: Optional[str] = None):
    q = {"category": category} if category else {}
    docs = get_documents("service", q)
    return [{**{k: v for k, v in d.items() if k != "_id"}, "id": str(d["_id"])} for d in docs]


# ============ APPOINTMENTS ============
@app.post("/appointments", dependencies=[Depends(require_role(["patient"]))])
def book_appointment(appt: Appointment, user: AuthUser = Depends(get_current_user)):
    if user.id != appt.patient_id:
        raise HTTPException(status_code=403, detail="You can only book for yourself")
    if not get_user_by_id(appt.doctor_id):
        raise HTTPException(status_code=404, detail="Doctor not found")
    inserted_id = create_document("appointment", appt)
    return {"id": inserted_id}


@app.get("/appointments", dependencies=[Depends(get_current_user)])
def list_appointments(role: Optional[str] = None, user: AuthUser = Depends(get_current_user)):
    q = {}
    if role == "patient" or user.role == "patient":
        q["patient_id"] = user.id
    elif role == "doctor" or user.role == "doctor":
        q["doctor_id"] = user.id
    docs = get_documents("appointment", q)
    return [{**{k: v for k, v in d.items() if k != "_id"}, "id": str(d["_id"])} for d in docs]


# ============ MESSAGES ============
@app.post("/messages", dependencies=[Depends(get_current_user)])
def send_message(msg: Message, user: AuthUser = Depends(get_current_user)):
    if user.id != msg.from_user_id:
        raise HTTPException(status_code=403, detail="Sender mismatch")
    inserted_id = create_document("message", msg)
    return {"id": inserted_id}


@app.get("/messages", dependencies=[Depends(get_current_user)])
def get_messages(peer_id: Optional[str] = None, user: AuthUser = Depends(get_current_user)):
    q = {"$or": [{"from_user_id": user.id}, {"to_user_id": user.id}]}
    if peer_id:
        q = {"$or": [
            {"from_user_id": user.id, "to_user_id": peer_id},
            {"from_user_id": peer_id, "to_user_id": user.id},
        ]}
    docs = list(db["message"].find(q))
    return [{**{k: v for k, v in d.items() if k != "_id"}, "id": str(d["_id"])} for d in docs]


# ============ RATINGS ============
@app.post("/ratings", dependencies=[Depends(require_role(["patient"]))])
def add_rating(r: Rating, user: AuthUser = Depends(get_current_user)):
    if user.id != r.patient_id:
        raise HTTPException(status_code=403, detail="You can only rate as yourself")
    inserted_id = create_document("rating", r)
    # Update doctor's average rating
    ratings = list(db["rating"].find({"doctor_id": r.doctor_id}))
    if ratings:
        avg = sum(rt.get("rating", 0) for rt in ratings) / len(ratings)
        db["doctorprofile"].update_many({"user_id": r.doctor_id}, {"$set": {"average_rating": avg}})
    return {"id": inserted_id}


@app.get("/ratings")
def list_ratings(doctor_id: Optional[str] = None):
    q = {"doctor_id": doctor_id} if doctor_id else {}
    docs = get_documents("rating", q)
    return [{**{k: v for k, v in d.items() if k != "_id"}, "id": str(d["_id"])} for d in docs]


# ============ REPORTS ============
@app.post("/reports", dependencies=[Depends(require_role(["doctor"]))])
def create_report(rep: Report, user: AuthUser = Depends(get_current_user)):
    if user.id != rep.doctor_id:
        raise HTTPException(status_code=403, detail="Doctor mismatch")
    inserted_id = create_document("report", rep)
    return {"id": inserted_id}


@app.get("/reports", dependencies=[Depends(get_current_user)])
def list_reports(patient_id: Optional[str] = None, user: AuthUser = Depends(get_current_user)):
    q = {}
    if user.role == "patient":
        q["patient_id"] = user.id
    elif user.role == "doctor" and patient_id:
        q["patient_id"] = patient_id
    docs = get_documents("report", q)
    return [{**{k: v for k, v in d.items() if k != "_id"}, "id": str(d["_id"])} for d in docs]


# ============ SEARCH ============
@app.get("/search/doctors")
def search_doctors(q: Optional[str] = None, specialization: Optional[str] = None, location: Optional[str] = None):
    query: dict = {}
    if specialization:
        query["specialization"] = {"$regex": specialization, "$options": "i"}
    if location:
        query["location"] = {"$regex": location, "$options": "i"}
    if q:
        query["$or"] = [
            {"specialization": {"$regex": q, "$options": "i"}},
            {"qualifications": {"$regex": q, "$options": "i"}},
            {"availability": {"$regex": q, "$options": "i"}},
        ]
    docs = list(db["doctorprofile"].find(query))
    return [{**{k: v for k, v in d.items() if k != "_id"}, "id": str(d["_id"])} for d in docs]


@app.get("/search/services")
def search_services(q: Optional[str] = None, category: Optional[str] = None):
    query: dict = {}
    if category:
        query["category"] = {"$regex": category, "$options": "i"}
    if q:
        query["$or"] = [
            {"name": {"$regex": q, "$options": "i"}},
            {"description": {"$regex": q, "$options": "i"}},
            {"category": {"$regex": q, "$options": "i"}},
        ]
    docs = list(db["service"].find(query))
    return [{**{k: v for k, v in d.items() if k != "_id"}, "id": str(d["_id"])} for d in docs]


# ============ SIMPLE ADMIN STATS ============
@app.get("/admin/stats", dependencies=[Depends(require_role(["admin"]))])
def admin_stats():
    return {
        "users": db["user"].count_documents({}),
        "doctors": db["doctorprofile"].count_documents({}),
        "services": db["service"].count_documents({}),
        "appointments": db["appointment"].count_documents({}),
        "messages": db["message"].count_documents({}),
        "ratings": db["rating"].count_documents({}),
        "reports": db["report"].count_documents({}),
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
