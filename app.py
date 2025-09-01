from flask import Flask, render_template, request, abort
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import re

app = Flask(__name__)

# === Rate Limiter ===
limiter = Limiter(
    get_remote_address,  # key function
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# === Blocked IPs ===
BLOCKED_IPS = ["123.456.789.0"]  # Add IPs you want to block

# === Firewall Middleware ===
@app.before_request
def firewall():
    # 1. Block specific IPs
    if request.remote_addr in BLOCKED_IPS:
        abort(403)  # Forbidden

    # 2. Block suspicious User-Agents
    user_agent = request.headers.get("User-Agent", "")
    if re.search(r"sqlmap|nikto|acunetix|fuzz", user_agent, re.I):
        abort(403)

    # 3. Simple SQLi/XSS pattern detection in URL
    if re.search(r"(\%27)|(\')|(\-\-)|(\%23)|(#)|(<|>)", request.url):
        abort(403)

# === Routes ===
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

@app.route("/login")
@limiter.limit("5 per minute")  # Extra protection for login
def login():
    return render_template("login.html")

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


if __name__ == "__main__":
    app.run(debug=True)
