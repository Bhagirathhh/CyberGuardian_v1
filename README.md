# 🛡️ Cyber Guardian v2.0

**Cyber Guardian v2.0** is an advanced, all-in-one cybersecurity toolkit built with Python and Flask. It provides a comprehensive web-based dashboard for system vulnerability assessment, network security monitoring, password analysis, phishing detection, file integrity verification, and professional security reporting — all accessible from your browser.

---

## 🚀 Features

### 🖥️ System & Vulnerability Audit

- **Complete Security Audit** — Full system scan covering 8+ security factors with AI-powered risk scoring (0–100)
- **🔌 Port Scanner** — Detects open ports (FTP, SSH, HTTP, RDP, MySQL, etc.) with service identification and risk classification
- **🔥 Firewall Check** — Verifies firewall status across Windows, Linux, and macOS with configuration recommendations
- **🔗 Network Connections** — Inspects all established TCP connections with process mapping and external IP detection
- **📦 Patch Manager** — Audits outdated packages, security updates, and pending updates
- **👤 User Audit** — Lists all user accounts, admin/root privileges, and checks if guest account is enabled
- **⚙️ Process Scanner** — Detects suspicious processes (reverse shells, miners, keyloggers) and high resource usage
- **🛡️ Antivirus Status** — Checks Windows Defender / ClamAV real-time protection, cloud protection, and signature age

### 🔐 Password Tools

- **Password Analyzer** — Strength scoring with detailed feedback on length, character variety, and common-password detection
- **Password Generator** — Configurable length, uppercase, lowercase, digits, and symbols with cryptographically secure randomness

### 🌐 URL & Phishing Detection

- **AI URL Scanner** — Machine learning-based phishing detection analyzing 9+ URL features with confidence scoring
- **Legacy URL Analyzer** — Rule-based assessment checking HTTPS, suspicious keywords, IP addresses, TLDs, and URL length

### 🔑 Hash & Integrity Tools

- **Hash Generator** — MD5, SHA1, SHA256 hashing for text with copy-to-clipboard
- **File Integrity Checker** — Upload files and verify SHA-256 integrity against known checksums

### 📊 Live System Monitoring

- Real-time CPU, RAM, and disk usage via Server-Sent Events (SSE) streaming dashboard
- Dynamic visual updates every 200ms

### 📄 PDF Reporting

- Download professional security audit reports with all findings, risk factors, and recommendations in PDF format

### 📋 Audit History

- Stores last 50 audit reports and URL scans per user with timestamps, scores, and full results

---

## 🛠️ Technologies Used

- **Backend:** Python 3, Flask, Werkzeug
- **Database:** SQLite 3
- **ML/AI:** scikit-learn, joblib
- **System Info:** psutil, platform, socket
- **PDF:** ReportLab
- **Frontend:** HTML5, CSS3, JavaScript (vanilla)
- **Security:** Werkzeug password hashing, session-based auth
- **Auth:** Custom login_required decorator with flash messaging

---


---

## 🎯 Project Objective

The objective of Cyber Guardian is to provide a lightweight, self-hosted cybersecurity toolkit that combines system vulnerability assessment, network security monitoring, phishing detection, and security auditing into a single easy-to-use platform. It helps security enthusiasts understand real-world attack surfaces, system administrators quickly audit machines for misconfigurations, developers learn about common vulnerabilities (open ports, weak passwords, outdated packages), and students explore practical cybersecurity concepts hands-on.

---

## ⚙️ Installation

### Prerequisites

- Python 3.8+
- pip
- Git

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/Bhagirathhh/CyberGuardian.git
cd CyberGuardian

# 2. Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate      # Linux/Mac
# .\venv\Scripts\activate     # Windows

# 3. Install system dependencies (Linux only)
sudo apt install python3-dev  # Required for psutil on some systems

# 4. Install Python packages
pip install --upgrade pip
pip install -r requirements.txt

# 5. Train/download ML model (if not already present)
# The phishing_model.pkl file should be in the project root

# 6. Run the application
python app.py
```

### Access

Open your browser and navigate to:

```
http://127.0.0.1:5000
```

---

## 📦 Dependencies

Create a `requirements.txt` file with:

```
Flask==3.0.0
Werkzeug==3.0.1
psutil==5.9.6
joblib==1.3.2
scikit-learn==1.3.2
reportlab==4.0.8
```

Install all at once:

```bash
pip install -r requirements.txt
```

---

## 🔮 Future Enhancements

- Two-Factor Authentication
- Network Scan (scan remote hosts, not just localhost)
- AI-Based Threat Prediction — predictive risk scoring using historical audit data
- Advanced Dashboard Analytics — charts, trends, and vulnerability timelines
- CVE Database Integration — real-time CVE lookup for installed packages
- Docker Deployment — one-command deployment with Docker Compose
- Multi-Language Support — English, Hindi, Gujarati, and more
- Real-Time Alerts — email/desktop notifications for critical vulnerabilities
- Auto-Remediation — one-click fix suggestions for common misconfigurations
- Mobile-Responsive UI — full mobile dashboard experience

---

## 🧪 Tested On

- **Windows 10/11** — Fully tested
- **Kali Linux** — Fully tested
- **Ubuntu 22.04/24.04** — Fully tested
- **macOS Ventura** — Firewall check only

---

## 👨‍💻 Developer

**Bhagirathsinh Zala**

- GitHub: @Bhagirathhh (https://github.com/Bhagirathhh)
- Cybersecurity Enthusiast | Python Developer | Open Source Contributor

---

## 📄 License

This project is open source and available under the MIT License.

---

## ⭐ Support

If you found this project useful, consider giving it a star on GitHub — it motivates further development and helps others discover the project!

---

**Cyber Guardian v2.0 — Advanced Cybersecurity Toolkit**  
*Securing systems, one audit at a time.*
