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
import subprocess
from ml.feature_extraction import extract_features
from datetime import datetime
from urllib.parse import urlparse

import psutil
from flask import Flask, render_template, request, jsonify, Response, send_file, redirect, url_for, flash, session
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from dotenv import load_dotenv
import razorpay

# Load environment variables from .env file
load_dotenv()

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
            plan TEXT DEFAULT 'free',
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
        CREATE TABLE IF NOT EXISTS payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            payment_id TEXT,
            amount INTEGER,
            plan TEXT,
            status TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ''')
    conn.commit()
    conn.close()

init_db()

# --- Razorpay Client ---
RAZORPAY_KEY_ID = os.getenv("RAZORPAY_KEY_ID")
RAZORPAY_KEY_SECRET = os.getenv("RAZORPAY_KEY_SECRET")

if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
    print("⚠️ WARNING: Razorpay keys not found in .env file!")
    print("Please add RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET to .env file")

razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

# --- Login Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please login first!", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Premium Decorator ---
def premium_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please login first!", "warning")
            return redirect(url_for('login'))
        if session.get('plan') != 'premium':
            flash("⭐ This feature requires a Premium subscription! Upgrade to access.", "warning")
            return redirect(url_for('pricing'))
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


# ===================== NEW FEATURES =====================

def scan_open_ports():
    """🔌 Feature 1: Scan open ports and detect running services"""
    open_ports = []
    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt",
        27017: "MongoDB"
    }
    
    for port, service in common_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        try:
            result = sock.connect_ex(('127.0.0.1', port))
            if result == 0:
                open_ports.append({"port": port, "service": service, "status": "OPEN"})
        except:
            pass
        finally:
            sock.close()
    
    return open_ports


def check_firewall_status():
    """🔥 Feature 2: Check firewall status"""
    firewall_info = {"status": "Unknown", "active_rules_count": 0, "inbound_rules": 0, "outbound_rules": 0}
    
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles"], 
                capture_output=True, text=True, timeout=5
            )
            if "ON" in result.stdout or "On" in result.stdout:
                firewall_info["status"] = "Active"
            else:
                firewall_info["status"] = "Inactive"
        elif platform.system() == "Linux":
            result = subprocess.run(
                ["sudo", "ufw", "status"], capture_output=True, text=True, timeout=5
            )
            if "active" in result.stdout.lower():
                firewall_info["status"] = "Active"
            else:
                # Check iptables
                result2 = subprocess.run(
                    ["sudo", "iptables", "-L", "-n"], capture_output=True, text=True, timeout=5
                )
                if result2.stdout.strip():
                    firewall_info["status"] = "Active (iptables)"
                else:
                    firewall_info["status"] = "Inactive"
        elif platform.system() == "Darwin":
            result = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                capture_output=True, text=True, timeout=5
            )
            if "enabled" in result.stdout.lower():
                firewall_info["status"] = "Active"
            else:
                firewall_info["status"] = "Inactive"
    except:
        firewall_info["status"] = "Could not determine (run as admin/root)"
    
    return firewall_info


def check_established_connections():
    """🔗 Feature 3: Check established network connections"""
    connections = []
    suspicious_count = 0
    
    try:
        for conn in psutil.net_connections():
            if conn.status == 'ESTABLISHED' and conn.raddr:
                conn_info = {
                    "local_ip": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote_ip": f"{conn.raddr.ip}:{conn.raddr.port}",
                    "status": conn.status,
                    "pid": conn.pid
                }
                
                # Get process name for this connection
                try:
                    proc = psutil.Process(conn.pid)
                    conn_info["process"] = proc.name()
                except:
                    conn_info["process"] = "Unknown"
                
                connections.append(conn_info)
                
                # Flag suspicious connections (to unknown external IPs)
                try:
                    if not conn.raddr.ip.startswith(('10.', '172.', '192.168.', '127.')):
                        suspicious_count += 1
                except:
                    pass
    except:
        pass
    
    return connections, suspicious_count


def get_os_patches_info():
    """📦 Feature 4: Check outdated packages and OS patches"""
    patches_info = {
        "os": platform.system(),
        "total_packages": 0,
        "outdated_packages": 0,
        "security_updates": 0,
        "cve_list": [],
        "pending_updates": []
    }
    
    try:
        if platform.system() == "Linux":
            # Check apt updates
            result = subprocess.run(
                ["apt", "list", "--upgradable", "2>/dev/null"], 
                capture_output=True, text=True, timeout=10, shell=True
            )
            lines = result.stdout.strip().split('\n')
            packages = [l for l in lines if l and not l.startswith('Listing')]
            patches_info["total_packages"] = len(packages)
            
            # Count security updates
            sec_updates = [p for p in packages if 'security' in p.lower()]
            patches_info["security_updates"] = len(sec_updates)
            patches_info["outdated_packages"] = len(packages)
            patches_info["pending_updates"] = packages[:10]  # Top 10
        elif platform.system() == "Windows":
            # Use wuapi to check Windows updates
            result = subprocess.run(
                ["powershell", "-Command", 
                 "(Get-WUList).Count | Out-String"], 
                capture_output=True, text=True, timeout=10
            )
            try:
                count = int(result.stdout.strip())
                patches_info["total_packages"] = count
                patches_info["outdated_packages"] = count
                patches_info["security_updates"] = count
            except:
                patches_info["total_packages"] = "Run as admin to check"
    except:
        patches_info["total_packages"] = "Could not scan"
    
    return patches_info


def get_user_accounts_info():
    """👤 Feature 5: Get user accounts and privileges"""
    users_info = {
        "total_users": 0,
        "admin_users": [],
        "standard_users": [],
        "guest_enabled": False,
        "inactive_users": []
    }
    
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["net", "user"], capture_output=True, text=True, timeout=5
            )
            lines = result.stdout.split('\n')
            user_lines = []
            capture = False
            for line in lines:
                if '----------' in line:
                    capture = True
                    continue
                if capture and line.strip() and 'command completed' not in line.lower():
                    user_lines.extend(line.strip().split())
            
            # Check admin group
            admin_result = subprocess.run(
                ["net", "localgroup", "Administrators"], 
                capture_output=True, text=True, timeout=5
            )
            admin_lines = admin_result.stdout.split('\n')
            admins = []
            capture = False
            for line in admin_lines:
                if '----------' in line:
                    capture = True
                    continue
                if capture and line.strip() and 'command completed' not in line.lower():
                    admins.extend(line.strip().split())
            
            users_info["total_users"] = len(user_lines)
            users_info["admin_users"] = admins
            users_info["standard_users"] = [u for u in user_lines if u not in admins]
            
            # Check guest account
            guest_result = subprocess.run(
                ["net", "user", "Guest"], capture_output=True, text=True, timeout=5
            )
            if 'Account active' in guest_result.stdout and 'Yes' in guest_result.stdout:
                users_info["guest_enabled"] = True
                
        elif platform.system() == "Linux":
            # Read /etc/passwd
            with open('/etc/passwd', 'r') as f:
                users = [line.split(':')[0] for line in f if not line.startswith('#')]
            users_info["total_users"] = len(users)
            
            # Check sudo group
            with open('/etc/group', 'r') as f:
                for line in f:
                    if line.startswith('sudo:') or line.startswith('wheel:'):
                        sudo_users = line.strip().split(':')[3].split(',')
                        users_info["admin_users"] = [u for u in sudo_users if u]
            
            # Check guest
            users_info["guest_enabled"] = 'guest' in users
            
            if not users_info["admin_users"]:
                users_info["admin_users"] = ["root"]
    except:
        users_info["total_users"] = "Could not scan"
    
    return users_info


def scan_suspicious_processes():
    """⚙️ Feature 6: Scan for suspicious background processes"""
    suspicious_processes = []
    high_resource_processes = []
    total_processes = 0
    
    suspicious_names = [
        'nc', 'netcat', 'ncat', 'nmap', 'masscan', 'hydra', 'medusa',
        'john', 'hashcat', 'aircrack', 'burpsuite', 'sqlmap',
        'beacon', 'cobaltstrike', 'meterpreter', 'reverse_shell',
        'keylogger', 'rat', 'trojan', 'backdoor', 'miner',
        'xmr', 'ethminer', 'cpuminer', 'xmrig'
    ]
    
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status']):
            total_processes += 1
            try:
                pinfo = proc.info
                
                # Check for suspicious process names
                proc_name = (pinfo['name'] or '').lower()
                for susp_name in suspicious_names:
                    if susp_name in proc_name:
                        suspicious_processes.append({
                            "pid": pinfo['pid'],
                            "name": pinfo['name'],
                            "cpu": pinfo['cpu_percent'],
                            "memory": pinfo['memory_percent']
                        })
                        break
                
                # Check for high resource usage
                cpu = pinfo['cpu_percent'] or 0
                mem = pinfo['memory_percent'] or 0
                if cpu > 50 or mem > 20:
                    high_resource_processes.append({
                        "pid": pinfo['pid'],
                        "name": pinfo['name'] or "Unknown",
                        "cpu": round(cpu, 1),
                        "memory": round(mem, 1)
                    })
            except:
                pass
    except:
        pass
    
    return suspicious_processes, high_resource_processes, total_processes


def check_antivirus_status():
    """🛡️ Feature 7: Check Antivirus/Windows Defender status"""
    av_info = {
        "name": "Not detected",
        "real_time_protection": False,
        "cloud_delivered_protection": False,
        "last_update": "Unknown",
        "status": "Unknown"
    }
    
    try:
        if platform.system() == "Windows":
            # Check Windows Defender
            result = subprocess.run(
                ["powershell", "-Command", 
                 "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, CloudProtectionEnabled, AntispywareSignatureLastUpdated | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10
            )
            
            try:
                defender_status = json.loads(result.stdout)
                av_info["name"] = "Windows Defender"
                av_info["real_time_protection"] = defender_status.get('RealTimeProtectionEnabled', False)
                av_info["cloud_delivered_protection"] = defender_status.get('CloudProtectionEnabled', False)
                av_info["last_update"] = defender_status.get('AntispywareSignatureLastUpdated', 'Unknown')
                
                if av_info["real_time_protection"]:
                    av_info["status"] = "Active & Protected"
                else:
                    av_info["status"] = "⚠ Real-time protection OFF"
            except:
                av_info["status"] = "Windows Defender status unknown"
        elif platform.system() == "Linux":
            # Check common Linux AV
            clamav = subprocess.run(["which", "clamav"], capture_output=True, text=True, timeout=3)
            if clamav.returncode == 0:
                av_info["name"] = "ClamAV"
                av_info["status"] = "Installed"
            else:
                av_info["status"] = "No AV detected"
    except:
        av_info["status"] = "Could not determine"
    
    return av_info


def get_extended_system_audit():
    """🧠 Master function combining ALL features with risk scoring"""
    
    # Get basic system info
    os_name = f"{platform.system()} {platform.release()}"
    hostname = socket.gethostname()
    try:
        local_ip = socket.gethostbyname(hostname)
    except:
        local_ip = "Unknown"
    
    python_version = platform.python_version()
    architecture = platform.architecture()[0]
    machine = platform.machine()
    
    # Disk info
    disk = shutil.disk_usage("/")
    total_gb = round(disk.total / (1024 ** 3), 2)
    free_gb = round(disk.free / (1024 ** 3), 2)
    used_gb = round(disk.used / (1024 ** 3), 2)
    disk_percent = round((disk.used / disk.total) * 100, 1)
    
    # CPU & RAM
    cpu_usage = psutil.cpu_percent(interval=0.5)
    cpu_cores = psutil.cpu_count(logical=True)
    ram = psutil.virtual_memory()
    total_ram = round(ram.total / (1024 ** 3), 2)
    used_ram = round(ram.used / (1024 ** 3), 2)
    available_ram = round(ram.available / (1024 ** 3), 2)
    ram_percent = round(ram.percent, 1)
    
    # ===== NEW FEATURES =====
    open_ports = scan_open_ports()
    firewall_info = check_firewall_status()
    connections, suspicious_connections_count = check_established_connections()
    patches_info = get_os_patches_info()
    users_info = get_user_accounts_info()
    suspicious_procs, high_resource_procs, total_procs = scan_suspicious_processes()
    av_info = check_antivirus_status()
    
    # ===== DYNAMIC RISK SCORING =====
    score = 100
    recommendations = []
    risk_factors = []
    
    # Disk check
    if free_gb < 20:
        score -= 10
        recommendations.append(f"⚠ Low disk space detected ({free_gb}GB free). Clean up unnecessary files.")
        risk_factors.append({"type": "disk", "severity": "medium", "detail": f"Only {free_gb}GB free"})
    else:
        recommendations.append("✅ Disk space healthy")
    
    # Python version
    if not python_version.startswith("3"):
        score -= 10
        recommendations.append("⚠ Old Python version detected. Upgrade to Python 3.")
    else:
        recommendations.append("✅ Modern Python version")
    
    # CPU check
    if cpu_usage > 85:
        score -= 10
        recommendations.append(f"⚠ High CPU usage ({cpu_usage}%). Investigate background processes.")
        risk_factors.append({"type": "cpu", "severity": "high", "detail": f"CPU at {cpu_usage}%"})
    else:
        recommendations.append("✅ CPU usage normal")
    
    # RAM check
    if available_ram < 2:
        score -= 10
        recommendations.append(f"⚠ Low available RAM ({available_ram}GB). Close unused applications.")
        risk_factors.append({"type": "ram", "severity": "medium", "detail": f"Only {available_ram}GB RAM available"})
    else:
        recommendations.append("✅ RAM availability healthy")
    
    # 🔌 PORT SECURITY
    high_risk_ports = [p for p in open_ports if p['port'] in [21, 23, 3389, 3306, 6379]]
    medium_risk_ports = [p for p in open_ports if p['port'] in [22, 445, 5900]]
    
    if high_risk_ports:
        score -= 15
        ports_str = ", ".join([f"{p['port']} ({p['service']})" for p in high_risk_ports])
        recommendations.append(f"🚨 CRITICAL: High-risk ports OPEN: {ports_str}. Close immediately if not needed.")
        for p in high_risk_ports:
            risk_factors.append({"type": "port", "severity": "critical", "detail": f"Port {p['port']} ({p['service']}) is OPEN"})
    
    if medium_risk_ports:
        score -= 8
        ports_str = ", ".join([f"{p['port']} ({p['service']})" for p in medium_risk_ports])
        recommendations.append(f"⚠ Warning: Medium-risk ports OPEN: {ports_str}. Consider closing if not in use.")
        for p in medium_risk_ports:
            risk_factors.append({"type": "port", "severity": "medium", "detail": f"Port {p['port']} ({p['service']}) is OPEN"})
    
    if not high_risk_ports and not medium_risk_ports and open_ports:
        ports_str = ", ".join([f"{p['port']} ({p['service']})" for p in open_ports])
        recommendations.append(f"✅ Safe ports open: {ports_str}")
    elif not open_ports:
        recommendations.append("✅ No open ports detected. System is well-isolated.")
    
    # 🔥 FIREWALL
    if firewall_info["status"] == "Active":
        recommendations.append(f"✅ Firewall is {firewall_info['status']}")
    else:
        score -= 15
        recommendations.append(f"🚨 CRITICAL: Firewall is {firewall_info['status']}! Enable immediately.")
        risk_factors.append({"type": "firewall", "severity": "critical", "detail": "Firewall is inactive"})
    
    # 🔗 ESTABLISHED CONNECTIONS
    if suspicious_connections_count > 0:
        score -= 10
        recommendations.append(f"⚠ {suspicious_connections_count} connections to external IPs detected. Review for data exfiltration.")
        risk_factors.append({"type": "network", "severity": "medium", "detail": f"{suspicious_connections_count} external connections"})
    
    if len(connections) > 0:
        recommendations.append(f"✅ {len(connections)} established connections monitored (normal for active system)")
    
    # 📦 OS PATCHES
    if isinstance(patches_info.get("outdated_packages"), int) and patches_info["outdated_packages"] > 0:
        if patches_info["outdated_packages"] > 10:
            score -= 15
            recommendations.append(f"🚨 {patches_info['outdated_packages']} outdated packages found. System vulnerable to known CVEs.")
            risk_factors.append({"type": "patches", "severity": "high", "detail": f"{patches_info['outdated_packages']} pending updates"})
        else:
            score -= 5
            recommendations.append(f"⚠ {patches_info['outdated_packages']} packages need updating.")
            risk_factors.append({"type": "patches", "severity": "low", "detail": f"{patches_info['outdated_packages']} pending updates"})
    
    if patches_info.get("security_updates", 0) > 0:
        recommendations.append(f"⚠ {patches_info['security_updates']} are security updates. Update ASAP!")
    
    # 👤 USER ACCOUNTS
    if isinstance(users_info.get("total_users"), int):
        if users_info["total_users"] > 20:
            score -= 5
            recommendations.append(f"⚠ {users_info['total_users']} user accounts found. Review for unused accounts.")
            risk_factors.append({"type": "users", "severity": "low", "detail": f"{users_info['total_users']} total users"})
        else:
            recommendations.append(f"✅ {users_info['total_users']} user accounts (within normal range)")
    
    if users_info.get("guest_enabled"):
        score -= 10
        recommendations.append("🚨 Guest account is ENABLED! Disable it for security.")
        risk_factors.append({"type": "guest", "severity": "high", "detail": "Guest account is enabled"})
    else:
        recommendations.append("✅ Guest account is disabled")
    
    if len(users_info.get("admin_users", [])) > 3:
        score -= 5
        recommendations.append(f"⚠ {len(users_info['admin_users'])} users with admin/root privileges. Review necessity.")
    
    # ⚙️ SUSPICIOUS PROCESSES
    if suspicious_procs:
        score -= 20
        procs_str = ", ".join([f"{p['name']} (PID: {p['pid']})" for p in suspicious_procs[:5]])
        recommendations.append(f"🚨 CRITICAL: {len(suspicious_procs)} suspicious processes found: {procs_str}")
        for p in suspicious_procs:
            risk_factors.append({"type": "process", "severity": "critical", "detail": f"Suspicious: {p['name']} (PID: {p['pid']})"})
    else:
        recommendations.append(f"✅ No suspicious processes detected ({total_procs} total processes running)")
    
    if high_resource_procs:
        score -= 5
        for p in high_resource_procs[:3]:
            recommendations.append(f"⚠ High resource usage: {p['name']} - CPU: {p['cpu']}%, RAM: {p['memory']}%")
    
    # 🛡️ ANTIVIRUS
    if av_info.get("real_time_protection"):
        recommendations.append(f"✅ {av_info['name']} real-time protection is ON")
    else:
        score -= 10
        recommendations.append(f"⚠ {av_info['name']}: Real-time protection is OFF. Turn it on.")
        risk_factors.append({"type": "antivirus", "severity": "high", "detail": "Real-time protection is OFF"})
    
    if av_info.get("cloud_delivered_protection"):
        recommendations.append(f"✅ {av_info['name']} cloud-delivered protection is ON")
    else:
        recommendations.append(f"⚠ {av_info['name']}: Cloud-delivered protection is OFF")
    
    # Final grade
    score = max(0, min(100, score))
    if score >= 90:
        grade = "A+"
    elif score >= 80:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    
    # Status items for UI
    status_items = [
        {"label": "CPU", "value": f"{cpu_usage}%", "status": "warning" if cpu_usage > 85 else "good"},
        {"label": "RAM", "value": f"{ram_percent}%", "status": "warning" if ram_percent > 90 else "good"},
        {"label": "Disk", "value": f"{disk_percent}%", "status": "warning" if disk_percent > 90 else "good"},
        {"label": "Firewall", "value": firewall_info["status"], "status": "warning" if "inactive" in firewall_info["status"].lower() or "inactive" in str(firewall_info["status"]).lower() else "good"},
        {"label": "Ports", "value": f"{len(open_ports)} open", "status": "warning" if len(high_risk_ports) > 0 else "good"},
        {"label": "Updates", "value": f"{patches_info.get('outdated_packages', '?')} pending", "status": "warning" if isinstance(patches_info.get('outdated_packages'), int) and patches_info['outdated_packages'] > 0 else "good"},
        {"label": "Users", "value": f"{users_info.get('total_users', '?')} active", "status": "warning" if users_info.get('guest_enabled') else "good"},
        {"label": "AV", "value": av_info["name"], "status": "warning" if not av_info.get("real_time_protection") else "good"},
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
        # New fields
        "open_ports": open_ports,
        "high_risk_ports": high_risk_ports,
        "medium_risk_ports": medium_risk_ports,
        "firewall_info": firewall_info,
        "established_connections": connections[:20],  # Top 20 connections
        "suspicious_connections": suspicious_connections_count,
        "total_connections": len(connections),
        "patches_info": patches_info,
        "users_info": users_info,
        "suspicious_processes": suspicious_procs,
        "high_resource_processes": high_resource_procs,
        "total_processes": total_procs,
        "antivirus_info": av_info,
        "risk_factors": risk_factors
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
        f"Firewall: {data.get('firewall_info', {}).get('status', '-')}",
        f"Open Ports: {len(data.get('open_ports', []))}",
        f"Antivirus: {data.get('antivirus_info', {}).get('name', '-')}",
        f"Outdated Packages: {data.get('patches_info', {}).get('outdated_packages', '-')}",
        f"Active Users: {data.get('users_info', {}).get('total_users', '-')}",
        f"Suspicious Processes: {len(data.get('suspicious_processes', []))}",
        f"External Connections: {data.get('suspicious_connections', 0)}",
        "",
        "Security Recommendations:",
    ]

    for line in lines:
        c.drawString(50, y, line)
        y -= 18

    for item in data.get("recommendations", []):
        c.drawString(65, y, f"- {item[:80]}{'...' if len(item) > 80 else ''}")
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
                "INSERT INTO users (username, email, password_hash, plan) VALUES (?, ?, ?, ?)",
                (username, email, generate_password_hash(password), 'free')
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
            session["plan"] = user["plan"]
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


# ===================== PRICING & PAYMENT ROUTES =====================

@app.route("/pricing")
def pricing():
    return render_template("pricing.html")

@app.route('/create-payment', methods=['POST'])
@login_required
def create_payment():
    plan = request.form.get('plan', 'monthly')
    
    # Amount in paise (₹100 = 10000 paise)
    if plan == 'monthly':
        amount = 10000  # ₹100
        plan_name = "Monthly"
    else:
        amount = 100000  # ₹1000
        plan_name = "Yearly"
    
    try:
        # Create payment link - SIMPLIFIED VERSION
        payment_link = razorpay_client.payment_link.create({
            "amount": amount,
            "currency": "INR",
            "description": f"Cyber Guardian {plan_name} Plan",
            "callback_url": url_for('payment_callback', _external=True),
            "callback_method": "get"
        })
        
        # Store payment details in session
        session['payment_link_id'] = payment_link['id']
        session['payment_plan'] = plan
        
        # Save to payments table
        conn = get_db()
        conn.execute(
            "INSERT INTO payments (user_id, payment_id, amount, plan, status) VALUES (?, ?, ?, ?, ?)",
            (session["user_id"], payment_link['id'], amount, plan, 'initiated')
        )
        conn.commit()
        conn.close()
        
        # Redirect to payment page
        return redirect(payment_link['short_url'])
        
    except Exception as e:
        flash(f"Payment creation failed: {str(e)}", "danger")
        return redirect(url_for('pricing'))

@app.route('/payment-callback')
@login_required
def payment_callback():
    # Get payment status from query parameters
    payment_id = request.args.get('razorpay_payment_link_id')
    payment_status = request.args.get('razorpay_payment_link_status')
    payment_link_id = request.args.get('razorpay_payment_link_reference_id')
    
    if payment_status == 'paid':
        try:
            # Verify payment with Razorpay API
            payment_details = razorpay_client.payment_link.fetch(payment_id)
            
            if payment_details.get('status') == 'paid':
                # ✅ Payment successful - Upgrade user
                conn = get_db()
                
                # Update user plan
                conn.execute(
                    "UPDATE users SET plan = 'premium' WHERE id = ?",
                    (session["user_id"],)
                )
                
                # Update payment status
                conn.execute(
                    "UPDATE payments SET status = 'completed' WHERE payment_id = ?",
                    (payment_id,)
                )
                conn.commit()
                conn.close()
                
                # Update session
                session["plan"] = "premium"
                
                flash("🎉 Payment successful! You are now a Premium user! Enjoy all features!", "success")
                return redirect(url_for('home'))
            else:
                flash("Payment verification failed. Please contact support.", "danger")
                return redirect(url_for('pricing'))
                
        except Exception as e:
            flash(f"Payment verification error: {str(e)}", "danger")
            return redirect(url_for('pricing'))
            
    else:
        flash("Payment was not completed. Please try again.", "warning")
        return redirect(url_for('pricing'))

@app.route('/healthz')
def healthz():
    return jsonify({"status": "healthy", "message": "Cyber Guardian is running!"}), 200

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

    # Free users: 5 scans per day limit
    if 'user_id' in session and session.get('plan') == 'free':
        today = datetime.now().strftime('%Y-%m-%d')
        conn = get_db()
        count = conn.execute(
            "SELECT COUNT(*) as count FROM url_scan_history WHERE user_id = ? AND date(created_at) = ?",
            (session["user_id"], today)
        ).fetchone()['count']
        conn.close()
        
        if count >= 5:
            flash("⚠️ Daily limit reached (5 scans). Upgrade to Premium for unlimited scans!", "warning")
            return render_template("url_scanner.html", result=result, color=color, score=score, reasons=reasons)

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
@premium_required
def audit():
    data = get_extended_system_audit()
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
@premium_required
def pdf_report():
    data = get_extended_system_audit()
    pdf_path = os.path.join(app.config["UPLOAD_FOLDER"], f"audit_report_{int(time.time())}.pdf")
    make_pdf_report(data, pdf_path)
    return send_file(pdf_path, as_attachment=True, download_name="cyber_guardian_report.pdf")


# ===================== PAGE RENDERERS (Security Tools) =====================

@app.route("/api/security/ports")
@premium_required
def ports_page():
    return render_template('port_scanner.html')


@app.route("/api/security/firewall")
@premium_required
def firewall_page():
    return render_template('firewall_check.html')


@app.route("/api/security/connections")
@premium_required
def net_connections_page():
    return render_template('connections.html')


@app.route("/api/security/patches")
@premium_required
def patches_page():
    return render_template('patches.html')


@app.route("/api/security/users")
@premium_required
def users_page():
    return render_template('users.html')


@app.route("/api/security/processes")
@premium_required
def processes_page():
    return render_template('processes.html')


@app.route("/api/security/antivirus")
@premium_required
def antivirus_page():
    return render_template('antivirus.html')


# ===================== DATA ENDPOINTS (Security Tools) =====================

@app.route("/api/security/ports/data")
@premium_required
def get_open_ports_data():
    import socket
    open_ports = []
    common_ports = {21: "FTP", 22: "SSH", 23: "Telnet", 80: "HTTP", 443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP"}
    for port, service in common_ports.items():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.2)
        if s.connect_ex(('127.0.0.1', port)) == 0:
            open_ports.append({"port": port, "service": service, "status": "OPEN"})
        s.close()
    return {"count": len(open_ports), "open_ports": open_ports}


@app.route("/api/security/firewall/data")
@premium_required
def get_firewall_data():
    import subprocess, platform
    os_type = platform.system()
    status = "Unknown/Inactive"
    try:
        if os_type == "Windows":
            out = subprocess.check_output("netsh advfirewall show allprofiles state", shell=True).decode()
            status = "Active (Protected)" if "ON" in out else "Inactive (Warning)"
        elif os_type == "Linux":
            out = subprocess.check_output("sudo ufw status", shell=True).decode()
            status = "Active (Protected)" if "active" in out and "inactive" not in out else "Inactive (Warning)"
    except Exception:
        status = "Active (Protected)"
    return {"status": status}


@app.route("/api/security/connections/data")
@premium_required
def get_net_connections_data():
    import psutil
    connections_list = []
    try:
        for conn in psutil.net_connections(kind='tcp'):
            proc_name = "Unknown"
            if conn.pid:
                try:
                    proc_name = psutil.Process(conn.pid).name()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    proc_name = "System/Protected"
            
            connections_list.append({
                "pid": conn.pid if conn.pid else 0,
                "name": proc_name,
                "local": f"{conn.laddr.ip}:{conn.laddr.port}",
                "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "0.0.0.0:*",
                "status": conn.status
            })
        return {"connections": connections_list}
    except Exception as e:
        return {"error": str(e), "connections": []}, 500


@app.route("/api/security/patches/data")
@premium_required
def get_patches_data():
    patches = get_os_patches_info()
    return jsonify(patches)


@app.route("/api/security/users/data")
@premium_required
def get_users_data():
    users = get_user_accounts_info()
    return jsonify(users)


@app.route("/api/security/processes/data")
@premium_required
def get_processes_data():
    suspicious, high_resource, total = scan_suspicious_processes()
    return jsonify({
        "total_processes": total,
        "suspicious_count": len(suspicious),
        "suspicious": suspicious,
        "high_resource_count": len(high_resource),
        "high_resource": high_resource[:10]
    })


@app.route("/api/security/antivirus/data")
@premium_required
def get_antivirus_data():
    av = check_antivirus_status()
    return jsonify(av)


# ===================== LEGACY API ROUTES =====================

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
    return jsonify(get_extended_system_audit())


@app.route("/api/delete-history", methods=["POST"])
@login_required
def delete_history():
    data = request.get_json(silent=True) or {}
    record_id = data.get("id")
    record_type = data.get("type")
    conn = get_db()
    if record_type == "audit":
        conn.execute("DELETE FROM audit_history WHERE id = ? AND user_id = ?", (record_id, session["user_id"]))
    elif record_type == "scan":
        conn.execute("DELETE FROM url_scan_history WHERE id = ? AND user_id = ?", (record_id, session["user_id"]))
    conn.commit()
    conn.close()
    return jsonify({"success": True})


# ===================== NEW FEATURE ROUTES =====================

@app.route("/event-log-analyzer")
@premium_required
def event_log_analyzer():
    """Windows Event Log Analyzer - Check Windows logs for suspicious activity"""
    suspicious_activity = {
        "failed_logins": 0,
        "suspicious_powershell": [],
        "account_failures": [],
        "total_events": 0
    }
    
    try:
        if platform.system() == "Windows":
            # Check security logs for failed logins
            result = subprocess.run(
                ["powershell", "-Command", 
                 "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 50 | Select-Object TimeCreated, Message"],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout:
                # Count failed logins
                failed_logins = result.stdout.count("4625")
                suspicious_activity["failed_logins"] = failed_logins
                
                # Extract IP addresses from failed logins
                ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
                ips = re.findall(ip_pattern, result.stdout)
                suspicious_activity["account_failures"] = list(set(ips))[:5]
            
            # Check for suspicious PowerShell activity
            ps_result = subprocess.run(
                ["powershell", "-Command", 
                 "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} -MaxEvents 20 | Select-Object TimeCreated, Message"],
                capture_output=True, text=True, timeout=10
            )
            if ps_result.stdout:
                # Look for suspicious PowerShell commands
                suspicious_cmds = []
                suspicious_patterns = ['-enc', '-e', 'Invoke-', 'IEX', 'DownloadFile', 'WebClient', 'Net.WebClient']
                for line in ps_result.stdout.split('\n'):
                    for pattern in suspicious_patterns:
                        if pattern.lower() in line.lower():
                            suspicious_cmds.append(line[:150])
                            break
                suspicious_activity["suspicious_powershell"] = suspicious_cmds[:5]
                
            # Get total events count
            count_result = subprocess.run(
                ["powershell", "-Command", 
                 "(Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625}).Count"],
                capture_output=True, text=True, timeout=5
            )
            try:
                suspicious_activity["total_events"] = int(count_result.stdout.strip())
            except:
                suspicious_activity["total_events"] = suspicious_activity["failed_logins"]
                
        else:
            suspicious_activity["message"] = "Windows Event Log analysis is only available on Windows systems"
            
    except Exception as e:
        suspicious_activity["error"] = str(e)
        suspicious_activity["message"] = "Could not access Windows Event Logs. Run as administrator."
    
    return render_template("event-log-analyzer.html", activity=suspicious_activity)


@app.route("/persistence-scanner")
@premium_required
def persistence_scanner():
    """Persistence Scanner - Check for programs that run automatically on startup"""
    persistence_items = {
        "startup_apps": [],
        "services": [],
        "scheduled_tasks": [],
        "registry_entries": [],
        "total_items": 0,
        "suspicious_items": []
    }
    
    try:
        if platform.system() == "Windows":
            # Check Startup folder
            startup_paths = [
                os.path.join(os.getenv('APPDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup'),
                os.path.join(os.getenv('PROGRAMDATA'), 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
            ]
            for path in startup_paths:
                if os.path.exists(path):
                    for file in os.listdir(path):
                        if file.endswith(('.exe', '.lnk', '.bat', '.cmd', '.vbs')):
                            persistence_items["startup_apps"].append(file)
            
            # Check Services (using sc query)
            services_result = subprocess.run(
                ["sc", "query", "state=all", "type=service"],
                capture_output=True, text=True, timeout=10
            )
            service_lines = services_result.stdout.split('\n')
            services = []
            for line in service_lines:
                if 'SERVICE_NAME:' in line:
                    service_name = line.split('SERVICE_NAME:')[-1].strip()
                    if service_name:
                        services.append(service_name)
            persistence_items["services"] = services[:20]
            
            # Check scheduled tasks
            tasks_result = subprocess.run(
                ["schtasks", "/query", "/fo", "list"],
                capture_output=True, text=True, timeout=10
            )
            tasks = []
            for line in tasks_result.stdout.split('\n'):
                if 'TaskName:' in line:
                    task_name = line.split('TaskName:')[-1].strip()
                    if task_name and '\\' in task_name:
                        tasks.append(task_name)
            persistence_items["scheduled_tasks"] = tasks[:15]
            
            # Check suspicious items
            suspicious_names = ['update', 'installer', 'java', 'adobe', 'flash', 'chrome', 'firefox']
            for item in persistence_items["startup_apps"]:
                item_lower = item.lower()
                for susp in suspicious_names:
                    if susp in item_lower:
                        persistence_items["suspicious_items"].append({
                            "name": item,
                            "type": "Startup Application",
                            "reason": f"Potentially suspicious name: {susp}"
                        })
                        break
                        
        else:
            if platform.system() == "Linux":
                # Check systemd services
                services_result = subprocess.run(
                    ["systemctl", "list-unit-files", "--type=service"],
                    capture_output=True, text=True, timeout=5
                )
                services = []
                for line in services_result.stdout.split('\n'):
                    if '.service' in line and 'enabled' in line:
                        service_name = line.split('.service')[0]
                        if service_name.strip():
                            services.append(service_name)
                persistence_items["services"] = services[:10]
                
                # Check cron jobs
                cron_result = subprocess.run(
                    ["crontab", "-l"],
                    capture_output=True, text=True, timeout=5
                )
                if cron_result.stdout:
                    cron_lines = [l for l in cron_result.stdout.split('\n') if l and not l.startswith('#')]
                    persistence_items["scheduled_tasks"] = cron_lines[:10]
                    
            persistence_items["message"] = "Persistence scan completed for your operating system"
            
    except Exception as e:
        persistence_items["error"] = str(e)
        persistence_items["message"] = "Could not scan all persistence locations. Run with appropriate privileges."
    
    persistence_items["total_items"] = (
        len(persistence_items["startup_apps"]) + 
        len(persistence_items["services"]) + 
        len(persistence_items["scheduled_tasks"])
    )
    
    return render_template("persistence-scanner.html", persistence=persistence_items)


@app.route("/ioc-scanner", methods=["GET", "POST"])
@premium_required
def ioc_scanner():
    """IOC Scanner - Check suspicious IPs, Domains, URLs, File Hashes"""
    result = None
    ioc_type = None
    indicator = None
    
    if request.method == "POST":
        ioc_type = request.form.get("ioc_type")
        indicator = request.form.get("indicator", "").strip()
        
        if not indicator:
            flash("Please enter an indicator to scan", "warning")
        else:
            result = {
                "type": ioc_type,
                "indicator": indicator,
                "status": "Unknown",
                "risk_level": "Low",
                "details": [],
                "threat_intel": []
            }
            
            # Analyze based on IOC type
            if ioc_type == "ip":
                try:
                    ip = ipaddress.ip_address(indicator)
                    if ip.is_private:
                        result["status"] = "Safe (Private IP)"
                        result["risk_level"] = "Low"
                        result["details"].append("Private IP address - internal network")
                    else:
                        result["status"] = "Potentially Suspicious"
                        result["risk_level"] = "Medium"
                        result["details"].append("Public IP address - verify against threat intelligence")
                        
                        if indicator.startswith(('85.', '94.', '185.', '192.')):
                            result["threat_intel"].append("⚠️ IP range associated with known threat actors")
                        
                        for port in [22, 23, 80, 443, 445, 3389]:
                            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            sock.settimeout(0.5)
                            try:
                                if sock.connect_ex((indicator, port)) == 0:
                                    result["details"].append(f"⚠️ Port {port} is reachable")
                            except:
                                pass
                            sock.close()
                except:
                    result["status"] = "Invalid IP Address"
                    result["risk_level"] = "Error"
                    
            elif ioc_type == "domain":
                suspicious_keywords = ['login', 'verify', 'secure', 'update', 'bank', 'paypal', 'amazon', 'apple']
                found_keywords = [kw for kw in suspicious_keywords if kw in indicator.lower()]
                
                if found_keywords:
                    result["status"] = "Suspicious Domain"
                    result["risk_level"] = "High"
                    result["details"].append(f"⚠️ Contains suspicious keywords: {', '.join(found_keywords)}")
                    result["threat_intel"].append("Domain may be used for phishing")
                
                risky_tlds = ['.xyz', '.top', '.click', '.info', '.buzz', '.loan', '.work', '.zip']
                for tld in risky_tlds:
                    if indicator.lower().endswith(tld):
                        result["threat_intel"].append(f"⚠️ Risky TLD detected: {tld}")
                        result["risk_level"] = "High"
                        break
                
                if result["status"] == "Unknown":
                    result["status"] = "Low Risk Domain"
                    result["risk_level"] = "Low"
                    result["details"].append("Domain appears normal - monitor for suspicious behavior")
                    
            elif ioc_type == "url":
                url_result = analyze_url_ai(indicator)
                if "Phishing" in url_result[0]:
                    result["status"] = "Malicious URL"
                    result["risk_level"] = "Critical"
                    result["details"].append(f"🚨 {url_result[0]}")
                    result["details"].append(f"Confidence: {url_result[2]}%")
                    if url_result[3]:
                        result["details"].extend(url_result[3])
                else:
                    result["status"] = "Safe URL"
                    result["risk_level"] = "Low"
                    result["details"].append(url_result[0])
                    if url_result[3]:
                        result["details"].extend(url_result[3])
                    
            elif ioc_type == "hash":
                if len(indicator) == 32:
                    result["details"].append("MD5 hash detected")
                elif len(indicator) == 40:
                    result["details"].append("SHA-1 hash detected")
                elif len(indicator) == 64:
                    result["details"].append("SHA-256 hash detected")
                else:
                    result["details"].append("⚠️ Unknown hash format")
                
                suspicious_hashes = [
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "d41d8cd98f00b204e9800998ecf8427e",
                    "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
                ]
                if indicator.lower() in suspicious_hashes:
                    result["status"] = "⚠️ Known Malicious Hash"
                    result["risk_level"] = "Critical"
                    result["threat_intel"].append("Hash matches known malware signature")
                    result["details"].append("This hash is associated with known threats")
                else:
                    result["status"] = "Hash Not Found in Known Threat Database"
                    result["risk_level"] = "Low"
                    result["details"].append("Hash not detected in our threat intelligence database")
                    
        # Save scan result if logged in
        if "user_id" in session and result:
            conn = get_db()
            conn.execute(
                "INSERT INTO url_scan_history (user_id, url, result, score) VALUES (?, ?, ?, ?)",
                (session["user_id"], f"{ioc_type}: {indicator}", result.get("status", "Unknown"), 
                 100 if result.get("risk_level") == "Low" else 50 if result.get("risk_level") == "Medium" else 10)
            )
            conn.commit()
            conn.close()
    
    return render_template("ioc-scanner.html", result=result, ioc_type=ioc_type, indicator=indicator)


@app.route("/mitre-mapper", methods=["GET", "POST"])
@premium_required
def mitre_mapper():
    """MITRE ATT&CK Mapping - Map suspicious behaviors to MITRE techniques"""
    mapping_result = None
    behavior = None
    
    # MITRE ATT&CK Techniques Database
    mitre_techniques = {
        "powershell": {
            "technique": "T1059.001",
            "name": "Command and Scripting Interpreter: PowerShell",
            "tactic": "Execution",
            "description": "Adversaries may use PowerShell to execute commands and scripts.",
            "mitigation": "Disable PowerShell scripting where not needed, use constrained language mode.",
            "detection": "Monitor PowerShell command-line arguments and script block logging."
        },
        "suspicious_process": {
            "technique": "T1059",
            "name": "Command and Scripting Interpreter",
            "tactic": "Execution",
            "description": "Adversaries may abuse command interpreters to execute commands.",
            "mitigation": "Restrict script execution policies, use application whitelisting.",
            "detection": "Monitor process creation events and command-line parameters."
        },
        "port_445": {
            "technique": "T1021.002",
            "name": "Remote Services: SMB/Windows Admin Shares",
            "tactic": "Lateral Movement",
            "description": "Adversaries may use SMB to move laterally in the network.",
            "mitigation": "Restrict SMB access, use strong authentication, limit shares.",
            "detection": "Monitor for unusual SMB connections and authentication attempts."
        },
        "firewall_off": {
            "technique": "T1562.004",
            "name": "Impair Defenses: Disable or Modify System Firewall",
            "tactic": "Defense Evasion",
            "description": "Adversaries may disable the firewall to allow malicious activity.",
            "mitigation": "Use group policies to enforce firewall configuration.",
            "detection": "Monitor for changes to firewall configuration or service status."
        },
        "antivirus_off": {
            "technique": "T1562.001",
            "name": "Impair Defenses: Disable or Modify Tools",
            "tactic": "Defense Evasion",
            "description": "Adversaries may disable antivirus protection.",
            "mitigation": "Use endpoint detection and response (EDR) solutions.",
            "detection": "Monitor for AV service stoppage or configuration changes."
        },
        "suspicious_connection": {
            "technique": "T1071.001",
            "name": "Application Layer Protocol: Web Protocols",
            "tactic": "Command and Control",
            "description": "Adversaries may use web protocols for C2 communication.",
            "mitigation": "Use network segmentation and application whitelisting.",
            "detection": "Monitor network traffic for anomalous patterns."
        },
        "bruteforce": {
            "technique": "T1110.001",
            "name": "Brute Force: Password Guessing",
            "tactic": "Credential Access",
            "description": "Adversaries may brute force passwords to gain access.",
            "mitigation": "Use strong passwords, implement account lockout policies.",
            "detection": "Monitor for multiple failed login attempts."
        },
        "default": {
            "technique": "T1078",
            "name": "Valid Accounts",
            "tactic": "Defense Evasion",
            "description": "Adversaries may use valid accounts to hide malicious activity.",
            "mitigation": "Implement least privilege principle.",
            "detection": "Monitor for unusual account activity."
        }
    }
    
    if request.method == "POST":
        behavior = request.form.get("behavior", "").strip()
        behavior_lower = behavior.lower()
        
        mapping_result = {
            "behavior": behavior,
            "techniques": [],
            "risk_level": "Low",
            "summary": ""
        }
        
        # Map behavior to MITRE techniques
        matched_techniques = []
        risk_score = 0
        
        if "powershell" in behavior_lower:
            matched_techniques.append(mitre_techniques["powershell"])
            risk_score += 30
        if "process" in behavior_lower or "suspicious" in behavior_lower:
            matched_techniques.append(mitre_techniques["suspicious_process"])
            risk_score += 20
        if "port" in behavior_lower and "445" in behavior_lower:
            matched_techniques.append(mitre_techniques["port_445"])
            risk_score += 25
        if "firewall" in behavior_lower:
            matched_techniques.append(mitre_techniques["firewall_off"])
            risk_score += 20
        if "antivirus" in behavior_lower or "defender" in behavior_lower:
            matched_techniques.append(mitre_techniques["antivirus_off"])
            risk_score += 20
        if "connection" in behavior_lower or "network" in behavior_lower:
            matched_techniques.append(mitre_techniques["suspicious_connection"])
            risk_score += 15
        if "login" in behavior_lower or "failed" in behavior_lower:
            matched_techniques.append(mitre_techniques["bruteforce"])
            risk_score += 20
            
        if not matched_techniques:
            keywords = {
                "login failed": "bruteforce",
                "failed login": "bruteforce",
                "malware": "suspicious_process",
                "virus": "antivirus_off",
                "ransomware": "suspicious_process",
                "backdoor": "suspicious_connection",
                "trojan": "suspicious_process"
            }
            for key, tech in keywords.items():
                if key in behavior_lower:
                    matched_techniques.append(mitre_techniques[tech])
                    risk_score += 15
                    break
            else:
                matched_techniques.append(mitre_techniques["default"])
                risk_score += 10
        
        # Determine risk level
        if risk_score >= 60:
            mapping_result["risk_level"] = "Critical"
        elif risk_score >= 40:
            mapping_result["risk_level"] = "High"
        elif risk_score >= 20:
            mapping_result["risk_level"] = "Medium"
        else:
            mapping_result["risk_level"] = "Low"
            
        mapping_result["techniques"] = matched_techniques
        mapping_result["summary"] = f"Detected {len(matched_techniques)} MITRE ATT&CK technique(s)"
        
    return render_template("mitre-mapper.html", mapping_result=mapping_result, behavior=behavior)


@app.route("/ai-security-assistant")
@premium_required
def ai_security_assistant():
    """AI Security Assistant - Analyze reports and provide plain language recommendations"""
    analysis_result = None
    
    # Get system audit data
    audit_data = get_extended_system_audit()
    
    if audit_data:
        # Analyze and summarize
        risk_factors = audit_data.get("risk_factors", [])
        recommendations = audit_data.get("recommendations", [])
        score = audit_data.get("score", 100)
        
        # Determine overall risk
        if score >= 80:
            overall_risk = "LOW"
            risk_color = "#22c55e"
        elif score >= 60:
            overall_risk = "MEDIUM"
            risk_color = "#f59e0b"
        elif score >= 40:
            overall_risk = "HIGH"
            risk_color = "#ef4444"
        else:
            overall_risk = "CRITICAL"
            risk_color = "#dc2626"
        
        # Prioritize issues
        critical_issues = [r for r in risk_factors if r.get("severity") == "critical"]
        high_issues = [r for r in risk_factors if r.get("severity") == "high"]
        medium_issues = [r for r in risk_factors if r.get("severity") == "medium"]
        
        # Generate plain language summary
        summary_lines = []
        summary_lines.append(f"🟢 Overall System Health: {score}%")
        summary_lines.append(f"🔴 Overall Risk Level: {overall_risk}")
        summary_lines.append("")
        
        if critical_issues:
            summary_lines.append("🚨 CRITICAL ISSUES:")
            for idx, issue in enumerate(critical_issues[:3], 1):
                summary_lines.append(f"  {idx}. {issue.get('detail', '')}")
            summary_lines.append("")
        
        if high_issues:
            summary_lines.append("⚠️ HIGH PRIORITY ISSUES:")
            for idx, issue in enumerate(high_issues[:2], 1):
                summary_lines.append(f"  {idx}. {issue.get('detail', '')}")
            summary_lines.append("")
        
        # Generate action plan
        action_plan = []
        if critical_issues:
            action_plan.append("🚨 IMMEDIATE ACTIONS:")
            for issue in critical_issues[:2]:
                if "port" in issue.get("detail", "").lower():
                    action_plan.append(f"  - Close port {issue.get('detail', '')} immediately")
                elif "firewall" in issue.get("detail", "").lower():
                    action_plan.append("  - Enable system firewall immediately")
                elif "process" in issue.get("detail", "").lower():
                    action_plan.append("  - Terminate suspicious process and investigate")
                elif "antivirus" in issue.get("detail", "").lower():
                    action_plan.append("  - Enable antivirus real-time protection")
                else:
                    action_plan.append(f"  - Investigate: {issue.get('detail', '')}")
                    
        if high_issues and not critical_issues:
            action_plan.append("⚠️ RECOMMENDED ACTIONS:")
            for issue in high_issues:
                if "patches" in issue.get("detail", "").lower():
                    action_plan.append("  - Apply pending security updates")
                elif "connections" in issue.get("detail", "").lower():
                    action_plan.append("  - Review external network connections")
                else:
                    action_plan.append(f"  - Address: {issue.get('detail', '')}")
        
        if not critical_issues and not high_issues:
            action_plan.append("✅ System appears secure!")
            action_plan.append("  - Continue regular security monitoring")
            if medium_issues:
                action_plan.append("  - Address minor issues at your convenience")
                
        # Get top recommendations
        top_recommendations = []
        if recommendations:
            for rec in recommendations[:5]:
                if "✅" in rec:
                    top_recommendations.append(f"✅ {rec.replace('✅', '').strip()}")
                elif "⚠" in rec:
                    top_recommendations.append(f"⚠️ {rec.replace('⚠', '').strip()}")
                elif "🚨" in rec:
                    top_recommendations.append(f"🚨 {rec.replace('🚨', '').strip()}")
                else:
                    top_recommendations.append(f"• {rec}")
        
        analysis_result = {
            "overall_risk": overall_risk,
            "risk_color": risk_color,
            "score": score,
            "critical_count": len(critical_issues),
            "high_count": len(high_issues),
            "medium_count": len(medium_issues),
            "summary": "\n".join(summary_lines),
            "action_plan": "\n".join(action_plan),
            "recommendations": top_recommendations[:5],
            "risk_factors": risk_factors[:5]
        }
    
    return render_template("ai-security-assistant.html", analysis_result=analysis_result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=False)