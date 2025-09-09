# models.py
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime, date
import uuid

db = SQLAlchemy()


# =========================
# Users
# =========================
class UserHR(UserMixin, db.Model):
    __tablename__ = "users_hr"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), default="EMP", index=True)  # ADMIN, MANAGER, BDE, FPC, EMP
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    profile = db.relationship(
        "EmployeeProfile",
        backref="user",
        uselist=False,
        cascade="all, delete-orphan"
    )

    def get_id(self):
        return self.id


# =========================
# Employee Profile
# (Extended to match admin form)
# =========================
class EmployeeProfile(db.Model):
    __tablename__ = "employee_profiles"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey("users_hr.id"), nullable=False, index=True)

    # Essentials
    name = db.Column(db.String(120), nullable=False, index=True)
    designation = db.Column(db.String(80))
    department = db.Column(db.String(80))

    # From Create Employee form
    phone = db.Column(db.String(32))
    country = db.Column(db.String(80))
    joining_date = db.Column(db.Date)             # <input type="date" name="joining_date">
    dob = db.Column(db.Date)                      # <input type="date" name="dob">
    blood_group = db.Column(db.String(8))         # A+, O-, etc.
    salary = db.Column(db.Numeric(12, 2))         # store as decimal
    branch = db.Column(db.String(80))             # Assam/Guwahati (HO), etc.
    aadhar = db.Column(db.String(32))
    uan = db.Column(db.String(32))

    emp_type = db.Column(db.String(32))           # Full-time / Part-time / Contract
    skill_level = db.Column(db.String(32))        # Fresher / Intermediate / Senior

    parents_senior = db.Column(db.Boolean)        # Yes / No -> boolean
    children = db.Column(db.Integer)

    payment_mode = db.Column(db.String(32))       # Cash / Bank Transfer / UPI
    prev_designation = db.Column(db.String(80))
    prev_tenure_end = db.Column(db.Date)

    shift = db.Column(db.String(32))              # General / Morning / Night
    gender = db.Column(db.String(16))

    address = db.Column(db.Text)
    religion = db.Column(db.String(32))
    marital = db.Column(db.String(16))            # Single / Married / Divorced
    language = db.Column(db.String(120))
    pan = db.Column(db.String(20))

    disability = db.Column(db.String(32))         # No Disability / Low / Moderate / High
    esic = db.Column(db.String(32))
    emp_status = db.Column(db.String(32))         # Active / On Leave / Resigned

    father = db.Column(db.String(120))
    dep_disability = db.Column(db.String(32))     # No Disability / Low / Moderate / High
    hostel_children = db.Column(db.Integer)

    prev_employer = db.Column(db.String(120))
    prev_tenure_from = db.Column(db.Date)
    prev_tenure_to = db.Column(db.Date)

    emp_code = db.Column(db.String(64), index=True)  # Employee ID
    avatar_path = db.Column(db.String(255))          # optional path to uploaded avatar

    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, index=True)

    def __repr__(self):
        return f"<EmployeeProfile {self.name} ({self.emp_code or self.user_id})>"


# =========================
# Attendance Log
# =========================
class AttendanceLog(db.Model):
    __tablename__ = "attendance_logs"

    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.String(36), db.ForeignKey("users_hr.id"), nullable=False, index=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    type = db.Column(db.String(10))               # "IN" or "OUT"
    confidence = db.Column(db.Float)
    device = db.Column(db.String(64))
    liveness_passed = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"<AttendanceLog {self.user_id} {self.type} {self.timestamp:%Y-%m-%d %H:%M:%S}>"
