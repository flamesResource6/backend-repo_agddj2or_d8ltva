"""
Database Schemas for MediCare Plus

Each Pydantic model represents a MongoDB collection. The collection name is the
lowercase of the class name (e.g., User -> "user").

These schemas are used for request/response validation and for the Flames DB viewer.
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Literal
from datetime import datetime

# Core users
class User(BaseModel):
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Unique email address")
    password_hash: str = Field(..., description="BCrypt password hash")
    role: Literal["admin", "doctor", "patient"] = Field("patient", description="User role")
    is_active: bool = Field(True, description="Whether user is active")

class Doctorprofile(BaseModel):
    user_id: str = Field(..., description="Reference to user (_id) who is a doctor")
    specialization: str = Field(..., description="Medical specialization, e.g., Cardiology")
    experience_years: int = Field(..., ge=0, le=60, description="Years of experience")
    availability: str = Field(..., description="Availability description or schedule text")
    qualifications: List[str] = Field(default_factory=list, description="List of qualifications")
    consultation_fee: float = Field(..., ge=0, description="Consultation charge")
    location: str = Field(..., description="Hospital/clinic location")
    average_rating: float = Field(0, ge=0, le=5, description="Computed average rating")

# Hospital services
class Service(BaseModel):
    category: str = Field(..., description="E.g., Cardiology, Pediatrics, Radiology")
    name: str = Field(..., description="Service name")
    description: Optional[str] = Field(None, description="Detailed description")

# Appointments
class Appointment(BaseModel):
    patient_id: str = Field(..., description="Reference to patient user _id")
    doctor_id: str = Field(..., description="Reference to doctor user _id")
    service_id: Optional[str] = Field(None, description="Reference to service _id")
    starts_at: datetime = Field(..., description="Appointment start datetime (ISO)")
    status: Literal["pending", "confirmed", "completed", "cancelled"] = Field("pending")
    notes: Optional[str] = Field(None, description="Optional patient notes")

# Secure messages
class Message(BaseModel):
    from_user_id: str = Field(..., description="Sender user _id")
    to_user_id: str = Field(..., description="Recipient user _id")
    content: str = Field(..., description="Message content")
    appointment_id: Optional[str] = Field(None, description="Related appointment _id")

# Ratings & feedback
class Rating(BaseModel):
    patient_id: str = Field(..., description="Patient user _id")
    doctor_id: str = Field(..., description="Doctor user _id")
    appointment_id: Optional[str] = Field(None, description="Related appointment _id")
    rating: int = Field(..., ge=1, le=5, description="Star rating (1-5)")
    review: Optional[str] = Field(None, description="Textual feedback")

# Medical reports metadata (files would be stored externally; we keep links)
class Report(BaseModel):
    patient_id: str = Field(..., description="Patient user _id")
    doctor_id: str = Field(..., description="Doctor user _id")
    report_type: str = Field(..., description="e.g., Lab Test, Prescription, Visit Summary")
    title: str = Field(..., description="Human-friendly title")
    url: Optional[str] = Field(None, description="Public or signed URL to file")
    content: Optional[str] = Field(None, description="Optional embedded text content if no URL")
