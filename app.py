
from flask import (
    Flask, render_template, request, abort,
    redirect, url_for, flash, jsonify
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_bcrypt import Bcrypt
from flask_login import (
    LoginManager, login_user, logout_user,
    login_required, current_user
)
import re
from datetime import datetime, timezone, timedelta, date
import os
from collections import defaultdict

# ⬇️ Import the shared db + models (prefer models.py, fallback to models_hr.py)
try:
    from models_hr import db, UserHR, EmployeeProfile, AttendanceLog
except ModuleNotFoundError:
    from models_hr import db, UserHR, EmployeeProfile, AttendanceLog


# -----------------------------
# App & Security
# -----------------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-me-please")

# Database config
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///site.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize shared extensions
db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Rate Limiter
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# Blocked IPs (example)
BLOCKED_IPS = ["123.456.789.0"]


# -----------------------------
# Firewall Middleware
# -----------------------------
@app.before_request
def firewall():
    if request.remote_addr in BLOCKED_IPS:
        abort(403)
    user_agent = request.headers.get("User-Agent", "")
    if re.search(r"sqlmap|nikto|acunetix|fuzz", user_agent, re.I):
        abort(403)
    # very rough URL filter
    if re.search(r"(\%27)|(\')|(\-\-)|(\%23)|(#)|(<|>)", request.url):
        abort(403)


# Flask-Login loader
@login_manager.user_loader
def load_user(user_id):
    # SQLAlchemy >=2.0 style
    return db.session.get(UserHR, user_id)


# Role guard helper
def require_role(*roles):
    def deco(f):
        from functools import wraps
        @wraps(f)
        def w(*a, **k):
            if not current_user.is_authenticated:
                return login_manager.unauthorized()
            if current_user.role not in roles:
                abort(403)
            return f(*a, **k)
        return w
    return deco


# -----------------------------
# Helpers for Admin Dashboard
# -----------------------------
def _start_of_today_naive():
    """Compute start of 'today' in UTC, then make naive (match typical DB naive timestamps)."""
    start_today_utc = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    return start_today_utc.replace(tzinfo=None)

def _attendance_logs_for_ui(target_date: date | None = None):
    """
    Build a list of dicts for the UI CSV export widget:
      [{date, name, email, check_in, check_out, status, location}]
    - If target_date is None, return logs for today & yesterday (nice demo)
    - Pairs first IN and last OUT per user per day
    """
    rows = []
    try:
        # Determine date range
        if target_date is None:
            d2 = datetime.now().date()           # today
            d1 = d2 - timedelta(days=1)          # yesterday (so the UI has at least something)
            day_list = [d1, d2]
        else:
            day_list = [target_date]

        # Pull recent logs (last 3 days)
        since = datetime.now() - timedelta(days=3)
        q = (
            db.session.query(AttendanceLog, UserHR, EmployeeProfile)
            .join(UserHR, AttendanceLog.user_id == UserHR.id)
            .outerjoin(EmployeeProfile, EmployeeProfile.user_id == UserHR.id)
            .filter(AttendanceLog.timestamp >= since)
            .order_by(AttendanceLog.timestamp.asc())
        )
        logs = q.all()

        # Group by (user_id, YYYY-MM-DD)
        grouped = defaultdict(list)
        for log, user, prof in logs:
            ts = log.timestamp
            if ts is None:
                continue
            day_key = ts.date()
            if day_key not in day_list:
                continue
            grouped[(log.user_id, str(day_key))].append((ts, log, user, prof))

        for (uid, day_str), items in grouped.items():
            items.sort(key=lambda x: x[0])

            # compute first IN and last OUT
            check_in_time = None
            check_out_time = None
            for _, l, _, _ in items:
                typ = (l.type or "").upper()
                if typ == "IN" and check_in_time is None:
                    check_in_time = l.timestamp.strftime("%H:%M")
                if typ == "OUT":
                    check_out_time = l.timestamp.strftime("%H:%M")

            # Choose representative user/profile
            _, _, user, prof = items[0]
            name = (getattr(prof, "name", None) or user.email.split("@")[0].replace(".", " ").title())
            email = user.email

            status = "Present"
            if not check_in_time and not check_out_time:
                status = "Absent"
            elif check_in_time and not check_out_time:
                status = "Open"

            rows.append({
                "date": f"{day_str} 00:00",
                "name": name,
                "email": email,
                "check_in": check_in_time or "",
                "check_out": check_out_time or "",
                "status": status,
                "location": getattr(items[-1][1], "device", "") or "—"
            })
    except Exception as e:
        app.logger.warning(f"attendance_logs_for_ui failed: {e}")
        rows = []

    return rows


# -----------------------------
# Public/site routes
# -----------------------------
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about_us.html")

@app.route("/getintouch")
def getintouch():
    return render_template("getintouch.html")

@app.route("/career")
def career():
    return render_template("career.html")

@app.route("/fpo")
def fpo():
    return render_template("fpo.html")

@app.route("/research")
def research():
    return render_template("Research.html")

@app.route("/agri")
def agri():
    return render_template("agri.html")

@app.route("/value")
def value():
    return render_template("value.html")

@app.route("/mark")
def mark():
    return render_template("marketing.html")

@app.route("/ibcb")
def ibcb():
    return render_template("IBCB.html")

@app.route("/mon")
def mon():
    return render_template("Monitoring.html")

@app.route("/org")
def org():
    return render_template("organi.html")

@app.route("/com")
def com():
    return render_template("comunication.html")

@app.route("/agricul")
def agricul():
    return render_template("Agriculture.html")

@app.route("/fish")
def fish():
    return render_template("fishery.html")

@app.route("/poul")
def poul():
    return render_template("poultry.html")

@app.route("/pig")
def pig():
    return render_template("piggery.html")


@app.route("/rfp")
def rfp():
    return render_template("rfp.html")

@app.route("/ingfpo")
def ingfpo():
    return render_template("insightsfpo.html")

@app.route("/ling")
def ling():
    return render_template("lingos.html")

@app.route("/loc")
def loc():
    return render_template("localmarket.html")

@app.route("/pub")
def pub():
    return render_template("publication.html")

@app.route("/ing")
def ing():
    return render_template("insights.html")


# -----------------------------
# Auth
# -----------------------------
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "GET":
        return render_template("login.html")

    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    user = UserHR.query.filter_by(email=email).first()

    if not user or not bcrypt.check_password_hash(user.password_hash, password):
        flash("Invalid email or password", "error")
        return redirect(url_for("login"))

    login_user(user, remember=True)
    return redirect(url_for("admin_dashboard" if user.role == "ADMIN" else "employee_dashboard"))


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# -----------------------------
# Admin & Employee
# -----------------------------
@app.route("/admin/dashboard")
@login_required
@require_role("ADMIN")
def admin_dashboard():
    start_today_naive = _start_of_today_naive()

    stats = {
        "employees": EmployeeProfile.query.count(),
        "today_logs": AttendanceLog.query.filter(AttendanceLog.timestamp >= start_today_naive).count(),
    }

    # employees for the table [(profile, user), ...]
    employees = (
        db.session.query(EmployeeProfile, UserHR)
        .join(UserHR, EmployeeProfile.user_id == UserHR.id)
        .order_by(UserHR.created_at.desc() if hasattr(UserHR, "created_at") else UserHR.id.desc())
        .all()
    )

    # Provide logs for Attendance Export widget
    attendance_logs = _attendance_logs_for_ui()

    # Provide company domain for email auto-suggest in Create Sheet
    company_domain = os.getenv("COMPANY_DOMAIN", "company.com")

    return render_template(
        "admin_dashboard.html",
        stats=stats,
        employees=employees,
        attendance_logs=attendance_logs,
        company_domain=company_domain,
    )


@app.route("/admin/user/create", methods=["POST"])
@login_required
@require_role("ADMIN")
def admin_create_user():
    f = request.form
    email = (f.get("email") or "").strip().lower()
    name = (f.get("name") or "").strip()
    role = (f.get("role") or "EMP").strip().upper()

    # Client decides password mode; we accept what's provided
    password = (f.get("password") or "").strip()
    if not password:
        password = "12345678"

    if not email or not name:
        flash("Name and Email are required.", "error")
        return redirect(url_for("admin_dashboard"))

    if UserHR.query.filter_by(email=email).first():
        flash("Email already exists.", "error")
        return redirect(url_for("admin_dashboard"))

    allowed_roles = {"ADMIN", "MANAGER", "BDE", "FPC", "EMP"}
    if role not in allowed_roles:
        role = "EMP"

    user = UserHR(
        email=email,
        password_hash=bcrypt.generate_password_hash(password).decode("utf-8"),
        role=role
    )
    db.session.add(user)
    db.session.flush()  # to get user.id

    # ✅ Only use fields that exist on your current EmployeeProfile model
    profile = EmployeeProfile(
        user_id=user.id,
        name=name,
        designation=(f.get("designation") or "").strip() or "-",
        department=(f.get("department") or "").strip() or "-",
    )
    db.session.add(profile)
    db.session.commit()

    # Optional: email credentials if checkbox was ON (client sends email_creds=on)
    if (f.get("email_creds") or "").lower() in ("on", "true", "1"):
        app.logger.info(f"[STUB] Would email credentials to {email}")

    flash("Employee created successfully.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/delete-user", methods=["POST"])
@login_required
@require_role("ADMIN")
def admin_delete_user():
    """Used by the table's Delete button in admin_dashboard.html"""
    user_id = request.form.get("user_id")
    if not user_id:
        flash("Missing user_id.", "error")
        return redirect(url_for("admin_dashboard"))

    # IDs are UUID strings; do NOT cast to int
    user = db.session.get(UserHR, user_id)
    if not user:
        flash("User not found.", "error")
        return redirect(url_for("admin_dashboard"))

    db.session.delete(user)  # Profile has cascade; if not, delete it too.
    db.session.commit()
    flash("User deleted.", "success")
    return redirect(url_for("admin_dashboard"))


@app.route("/employee/dashboard")
@login_required
def employee_dashboard():
    return render_template("employee_dashboard.html", role=current_user.role)


# -----------------------------
# Attendance (supports both image and simple IN/OUT forms)
# -----------------------------
@app.route("/attendance")
@login_required
def attendance_page():
    return render_template("attendance.html")


@app.route("/attendance/mark", methods=["POST"])
@login_required
def attendance_mark():
    """
    Marks attendance. Accepts either:
      - form field 'type' => 'IN' or 'OUT' (no image required)
      - or an image file (stubbed), alternating IN/OUT
    """
    # 1) Prefer explicit type from a simple form/button
    typ = (request.form.get("type") or "").strip().upper()
    if typ in ("IN", "OUT"):
        log = AttendanceLog(
            user_id=current_user.id,
            type=typ,
            confidence=1.0,
            device="web",
            liveness_passed=True,
            timestamp=datetime.now()
        )
        db.session.add(log)
        db.session.commit()
        flash(f"Attendance {typ} marked.", "success")
        # If the request expects JSON (e.g., fetch), return JSON
        if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
            return jsonify({"ok": True, "type": typ})
        return redirect(url_for("employee_dashboard"))

    # 2) Otherwise, try image path (stubbed)
    file = request.files.get("image")
    if not file:
        # Nothing provided
        flash("No attendance input provided.", "error")
        return redirect(url_for("attendance_page"))

    # Alternate IN/OUT for demo when using image
    count = AttendanceLog.query.filter_by(user_id=current_user.id).count()
    typ = "IN" if count % 2 == 0 else "OUT"

    log = AttendanceLog(
        user_id=current_user.id,
        type=typ,
        confidence=0.99,
        device="web",
        liveness_passed=True,
        timestamp=datetime.now()
    )
    db.session.add(log)
    db.session.commit()

    flash(f"Attendance {typ} marked (image).", "success")
    if request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.is_json:
        return jsonify({"ok": True, "type": typ, "confidence": 0.99})
    return redirect(url_for("employee_dashboard"))


# -----------------------------
# Startup: create tables + **UPSERT** ADMIN
# -----------------------------
with app.app_context():
    db.create_all()

    # Read desired admin creds from env or defaults
    admin_email_env = os.getenv("ADMIN_EMAIL", "admin@12345local.sds")
    admin_pass_env  = os.getenv("ADMIN_PASSWORD", "Admin@123")

    # If a user with that email exists -> ensure role/admin + password
    admin_by_email = UserHR.query.filter_by(email=admin_email_env).first()
    any_admin = UserHR.query.filter_by(role="ADMIN").first()

    if admin_by_email:
        # make sure they are ADMIN and set password
        admin_by_email.role = "ADMIN"
        admin_by_email.password_hash = bcrypt.generate_password_hash(admin_pass_env).decode("utf-8")
        db.session.commit()
        print(f"[UPSERT] Admin set (by email) → {admin_email_env}")
    elif any_admin:
        # update the first existing admin to the desired email/pass
        any_admin.email = admin_email_env
        any_admin.password_hash = bcrypt.generate_password_hash(admin_pass_env).decode("utf-8")
        db.session.commit()
        print(f"[UPSERT] Admin updated → {admin_email_env}")
    else:
        # no admin exists -> create one
        admin = UserHR(
            email=admin_email_env,
            password_hash=bcrypt.generate_password_hash(admin_pass_env).decode("utf-8"),
            role="ADMIN"
        )
        db.session.add(admin)
        db.session.flush()
        db.session.add(EmployeeProfile(
            user_id=admin.id,
            name="System Admin",
            designation="Admin",
            department="IT"
        ))
        db.session.commit()
        print(f"[UPSERT] Admin created → {admin_email_env}")


if __name__ == "__main__":
    app.run(debug=True)
