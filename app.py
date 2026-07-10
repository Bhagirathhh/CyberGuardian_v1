import os
import re
import platform
import socket
import shutil
import ipaddress
import hashlib
import time
import json
import joblib
from ml.feature_extraction import extract_features
from datetime import datetime
from urllib.parse import urlparse

import psutil
from flask import Flask, render_template, request, jsonify, Response, send_file, redirect, url_for, flash, session
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False


app = Flask(__name__)

# --- Database Setup ---
import sqlite3

DATABASE = os.path.join(os.path.dirname(__file__), "cyber_guardian.db")

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS audit_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            score INTEGER,
            grade TEXT,
            os_name TEXT,
            hostname TEXT,
            local_ip TEXT,
            cpu_usage REAL,
            ram_percent REAL,
            disk_percent REAL,
            recommendations TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS url_scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            url TEXT,
            result TEXT,
            score INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ''')
    conn.commit()
    conn.close()

init_db()

# --- Login Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please login first!", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

model = joblib.load("phishing_model.pkl")
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "change-this-in-production")
app.config["UPLOAD_FOLDER"] = os.path.join(os.path.dirname(__file__), "uploads")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

COMMON_PASSWORDS = {
    "password", "123456", "123456789", "qwerty", "admin", "welcome",
    "iloveyou", "password1", "abc123", "letmein", "monkey"
}

SUSPICIOUS_WORDS = {
    "login", "verify", "secure", "update", "free", "bonus", "gift",
    "account", "password", "confirm", "signin", "bank", "wallet"
}

RISKY_TLDS = {".xyz", ".top", ".click", ".info", ".buzz", ".loan", ".work", ".zip"}


def password_score(pwd: str):
    checks = []
    score = 0

    if len(pwd) >= 12:
        score += 2
        checks.append("✅ 12+ characters")
    elif len(pwd) >= 8:
        score += 1
        checks.append("✅ 8+ characters")
    else:
        checks.append("❌ Too short")

    if any(c.isupper() for c in pwd):
        score += 1
        checks.append("✅ Uppercase letter")
    else:
        checks.append("❌ Uppercase letter missing")

    if any(c.islower() for c in pwd):
        score += 1
        checks.append("✅ Lowercase letter")
    else:
        checks.append("❌ Lowercase letter missing")

    if any(c.isdigit() for c in pwd):
        score += 1
        checks.append("✅ Number included")
    else:
        checks.append("❌ Number missing")

    if any(not c.isalnum() for c in pwd):
        score += 1
        checks.append("✅ Special character included")
    else:
        checks.append("❌ Special character missing")

    if pwd.lower() in COMMON_PASSWORDS:
        score = max(score - 3, 0)
        checks.append("❌ Common password detected")

    if re.search(r"(.)\1\1", pwd):
        score = max(score - 1, 0)
        checks.append("⚠ Repeated characters detected")

    percent = int((score / 6) * 100)

    if percent < 40:
        result, color = "Weak Password", "#ef4444"
    elif percent < 75:
        result, color = "Medium Password", "#f59e0b"
    else:
        result, color = "Strong Password", "#22c55e"

    return result, color, percent, checks


def generate_password(length=16, use_upper=True, use_lower=True, use_digits=True, use_symbols=True):
    import secrets
    import string

    pools = []
    if use_upper:
        pools.append(string.ascii_uppercase)
    if use_lower:
        pools.append(string.ascii_lowercase)
    if use_digits:
        pools.append(string.digits)
    if use_symbols:
        pools.append("!@#$%^&*()-_=+[]{};:,.?/<>")

    if not pools:
        pools = [string.ascii_lowercase]

    all_chars = "".join(pools)
    pwd = [secrets.choice(pool) for pool in pools]

    while len(pwd) < length:
        pwd.append(secrets.choice(all_chars))

    secrets.SystemRandom().shuffle(pwd)
    return "".join(pwd[:length])


def analyze_url(raw_url: str):
    reasons = []
    risk = 0

    url = raw_url.strip()
    if not url:
        return "Invalid URL", "#ef4444", 100, ["❌ Empty URL"]

    if not re.match(r"^https?://", url, re.I):
        risk += 20
        reasons.append("⚠ URL scheme missing")
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.hostname or ""

    if parsed.scheme != "https":
        risk += 25
        reasons.append("❌ HTTPS not detected")
    else:
        reasons.append("✅ HTTPS detected")

    if not host:
        return "Invalid URL", "#ef4444", 100, ["❌ Invalid host"]

    try:
        ip = ipaddress.ip_address(host)
        reasons.append(f"⚠ Direct IP address used: {ip}")
        risk += 15
    except ValueError:
        pass

    host_lower = host.lower()
    path_lower = (parsed.path or "").lower()

    for word in SUSPICIOUS_WORDS:
        if word in host_lower or word in path_lower:
            risk += 10
            reasons.append(f"⚠ Suspicious keyword: {word}")

    if "@" in url:
        risk += 20
        reasons.append("⚠ Contains @ symbol")

    if host_lower.count(".") >= 3:
        risk += 10
        reasons.append("⚠ Too many subdomain levels")

    if len(url) > 80:
        risk += 10
        reasons.append("⚠ URL unusually long")

    if any(host_lower.endswith(tld) or tld in host_lower for tld in RISKY_TLDS):
        risk += 10
        reasons.append("⚠ Risky-looking domain extension")

    score = min(risk, 100)

    if score < 30:
        result, color = "Looks Safe", "#22c55e"
    elif score < 70:
        result, color = "Potentially Suspicious", "#f59e0b"
    else:
        result, color = "High Risk URL", "#ef4444"

    return result, color, score, reasons

def analyze_url_ai(url):
    features = [extract_features(url)]
    prediction = model.predict(features)[0]
    probability = model.predict_proba(features)[0]
    confidence = round(max(probability) * 100)

    reasons = []

    if features[0][4]:
        reasons.append("✅ HTTPS detected")
    else:
        reasons.append("⚠ HTTPS not detected")

    if features[0][6]:
        reasons.append("⚠ Direct IP Address used")

    if features[0][7]:
        reasons.append(f"⚠ {features[0][7]} suspicious keyword(s) detected")

    if features[0][8] > 3:
        reasons.append("⚠ Multiple subdomains detected")

    if prediction == 1:
        return ("🚨 Phishing Website", "#ef4444", confidence, reasons)

    return ("✅ Safe Website", "#22c55e", 100 - confidence, reasons)


def system_audit():
    os_name = f"{platform.system()} {platform.release()}"
    hostname = socket.gethostname()

    try:
        local_ip = socket.gethostbyname(hostname)
    except Exception:
        local_ip = "Unknown"

    python_version = platform.python_version()
    architecture = platform.architecture()[0]
    machine = platform.machine()

    disk = shutil.disk_usage("/")
    cpu_usage = psutil.cpu_percent(interval=0.5)
    cpu_cores = psutil.cpu_count(logical=True)
    ram = psutil.virtual_memory()

    total_gb = round(disk.total / (1024 ** 3), 2)
    free_gb = round(disk.free / (1024 ** 3), 2)
    used_gb = round(disk.used / (1024 ** 3), 2)

    total_ram = round(ram.total / (1024 ** 3), 2)
    used_ram = round(ram.used / (1024 ** 3), 2)
    available_ram = round(ram.available / (1024 ** 3), 2)
    ram_percent = round(ram.percent, 1)
    disk_percent = round((disk.used / disk.total) * 100, 1)

    score = 100
    recommendations = []

    if free_gb < 20:
        score -= 10
        recommendations.append("⚠ Low disk space detected")
        disk_status = "warning"
    else:
        recommendations.append("✅ Disk space healthy")
        disk_status = "good"

    if not python_version.startswith("3"):
        score -= 10
        recommendations.append("⚠ Old Python version")
        python_status = "warning"
    else:
        recommendations.append("✅ Modern Python version")
        python_status = "good"

    if cpu_usage > 85:
        score -= 10
        recommendations.append("⚠ High CPU usage")
        cpu_status = "warning"
    else:
        recommendations.append("✅ CPU usage normal")
        cpu_status = "good"

    if available_ram < 2:
        score -= 10
        recommendations.append("⚠ Low available RAM")
        ram_status = "warning"
    else:
        recommendations.append("✅ RAM availability healthy")
        ram_status = "good"

    if score >= 90:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 70:
        grade = "B"
    else:
        grade = "C"

    status_items = [
        {"label": "CPU", "value": f"{cpu_usage}%", "status": cpu_status},
        {"label": "RAM", "value": f"{ram_percent}%", "status": ram_status},
        {"label": "Disk", "value": f"{disk_percent}%", "status": disk_status},
        {"label": "Python", "value": python_version, "status": python_status},
    ]

    return {
        "os_name": os_name,
        "hostname": hostname,
        "local_ip": local_ip,
        "python_version": python_version,
        "total_gb": total_gb,
        "free_gb": free_gb,
        "used_gb": used_gb,
        "score": score,
        "grade": grade,
        "recommendations": recommendations,
        "cpu_usage": cpu_usage,
        "cpu_cores": cpu_cores,
        "total_ram": total_ram,
        "used_ram": used_ram,
        "available_ram": available_ram,
        "ram_percent": ram_percent,
        "disk_percent": disk_percent,
        "architecture": architecture,
        "machine": machine,
        "status_items": status_items,
    }


def sha256_text(text: str):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def hash_file(file_path: str, algorithm="sha256"):
    h = hashlib.new(algorithm)
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def make_pdf_report(data, out_path):
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("reportlab not installed")

    c = canvas.Canvas(out_path, pagesize=A4)
    width, height = A4
    y = height - 50

    c.setFont("Helvetica-Bold", 18)
    c.drawString(50, y, "Cyber Guardian Security Report")
    y -= 30

    c.setFont("Helvetica", 11)
    lines = [
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Host: {data.get('hostname', '-')}",
        f"OS: {data.get('os_name', '-')}",
        f"Python: {data.get('python_version', '-')}",
        f"Security Score: {data.get('score', '-')}/100",
        f"Grade: {data.get('grade', '-')}",
        "",
        "Recommendations:",
    ]

    for line in lines:
        c.drawString(50, y, line)
        y -= 18

    for item in data.get("recommendations", []):
        c.drawString(65, y, f"- {item}")
        y -= 16
        if y < 80:
            c.showPage()
            y = height - 50
            c.setFont("Helvetica", 11)

    c.save()
    return out_path


# ===================== AUTH ROUTES =====================

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not username or not email or not password:
            flash("All fields are required!", "danger")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match!", "danger")
            return render_template("register.html")

        if len(password) < 6:
            flash("Password must be at least 6 characters!", "danger")
            return render_template("register.html")

        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                (username, email, generate_password_hash(password))
            )
            conn.commit()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or email already exists!", "danger")
        finally:
            conn.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid username or password!", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# ===================== MAIN ROUTES =====================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/password", methods=["GET", "POST"])
def password():
    result = None
    color = "#ffffff"
    score_percent = 0
    checks = []

    if request.method == "POST":
        pwd = request.form.get("password", "")
        result, color, score_percent, checks = password_score(pwd)

    return render_template("password.html", result=result, color=color, score_percent=score_percent, checks=checks)


@app.route("/generate-password", methods=["GET", "POST"])
def generate_password_page():
    generated_password = None
    if request.method == "POST":
        length = int(request.form.get("length", 16))
        use_upper = request.form.get("upper") == "on"
        use_lower = request.form.get("lower") == "on"
        use_digits = request.form.get("digits") == "on"
        use_symbols = request.form.get("symbols") == "on"
        generated_password = generate_password(length, use_upper, use_lower, use_digits, use_symbols)

    return render_template("password_generator.html", generated_password=generated_password)


@app.route("/hash-generator", methods=["GET", "POST"])
def hash_generator():
    result = None
    if request.method == "POST":
        text = request.form.get("text", "")
        algo = request.form.get("algo", "sha256")
        result = hashlib.new(algo, text.encode("utf-8")).hexdigest()
    return render_template("hash_generator.html", result=result)


@app.route("/url-scanner", methods=["GET", "POST"])
def url_scanner():
    result = None
    color = "#ffffff"
    score = 0
    reasons = []

    if request.method == "POST":
        raw_url = request.form.get("url", "")
        result, color, score, reasons = analyze_url_ai(raw_url)

        # Save scan history if logged in
        if "user_id" in session and result:
            conn = get_db()
            conn.execute(
                "INSERT INTO url_scan_history (user_id, url, result, score) VALUES (?, ?, ?, ?)",
                (session["user_id"], raw_url, result, score)
            )
            conn.commit()
            conn.close()

    return render_template("url_scanner.html", result=result, color=color, score=score, reasons=reasons)


@app.route("/audit")
@login_required
def audit():
    data = system_audit()
    # Save to history
    conn = get_db()
    conn.execute(
        """INSERT INTO audit_history 
           (user_id, score, grade, os_name, hostname, local_ip, cpu_usage, ram_percent, disk_percent, recommendations)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (session["user_id"], data["score"], data["grade"], data["os_name"],
         data["hostname"], data["local_ip"], data["cpu_usage"],
         data["ram_percent"], data["disk_percent"], json.dumps(data["recommendations"]))
    )
    conn.commit()
    conn.close()
    return render_template("audit.html", **data)


@app.route("/history")
@login_required
def history():
    conn = get_db()
    audits = conn.execute(
        "SELECT * FROM audit_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 50",
        (session["user_id"],)
    ).fetchall()
    scans = conn.execute(
        "SELECT * FROM url_scan_history WHERE user_id = ? ORDER BY created_at DESC LIMIT 50",
        (session["user_id"],)
    ).fetchall()
    conn.close()
    return render_template("history.html", audits=audits, scans=scans)


@app.route("/live-monitor")
def live_monitor():
    return render_template("live_monitor.html")


@app.route("/stream")
def stream():
    def generate():
        while True:
            cpu = psutil.cpu_percent(interval=1)
            ram = psutil.virtual_memory().percent
            disk = psutil.disk_usage("/").percent
            payload = json.dumps({
                "cpu": cpu,
                "ram": ram,
                "disk": disk,
                "time": datetime.now().strftime("%H:%M:%S")
            })
            yield f"data: {payload}\n\n"
            time.sleep(0.2)

    return Response(generate(), mimetype="text/event-stream")


@app.route("/file-integrity", methods=["GET", "POST"])
def file_integrity():
    result = None
    file_hash = None
    stored_hash = request.form.get("stored_hash", "") if request.method == "POST" else ""
    uploaded_name = None

    if request.method == "POST" and "file" in request.files:
        file = request.files["file"]
        if file and file.filename:
            filename = secure_filename(file.filename)
            path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
            file.save(path)
            uploaded_name = filename
            file_hash = hash_file(path, "sha256")
            result = "MATCH" if stored_hash and stored_hash.lower() == file_hash.lower() else "NO MATCH"

    return render_template(
        "file_integrity.html",
        result=result,
        file_hash=file_hash,
        uploaded_name=uploaded_name,
        stored_hash=stored_hash
    )


@app.route("/pdf-report")
@login_required
def pdf_report():
    data = system_audit()
    pdf_path = os.path.join(app.config["UPLOAD_FOLDER"], f"audit_report_{int(time.time())}.pdf")
    make_pdf_report(data, pdf_path)
    return send_file(pdf_path, as_attachment=True, download_name="cyber_guardian_report.pdf")


# ===================== API ROUTES =====================

@app.route("/api/password", methods=["POST"])
def api_password():
    data = request.get_json(silent=True) or {}
    pwd = data.get("password", "")
    result, color, score_percent, checks = password_score(pwd)
    return jsonify({"result": result, "color": color, "score_percent": score_percent, "checks": checks})


@app.route("/api/url", methods=["POST"])
def api_url():
    data = request.get_json(silent=True) or {}
    raw_url = data.get("url", "")
    result, color, score, reasons = analyze_url(raw_url)
    return jsonify({"result": result, "color": color, "score": score, "reasons": reasons})


@app.route("/api/audit")
def api_audit():
    return jsonify(system_audit())


@app.route("/api/delete-history", methods=["POST"])
@login_required
def delete_history():
    data = request.get_json(silent=True) or {}
    record_id = data.get("id")
    record_type = data.get("type")  # "audit" or "scan"
    conn = get_db()
    if record_type == "audit":
        conn.execute("DELETE FROM audit_history WHERE id = ? AND user_id = ?", (record_id, session["user_id"]))
    elif record_type == "scan":
        conn.execute("DELETE FROM url_scan_history WHERE id = ? AND user_id = ?", (record_id, session["user_id"]))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=False)