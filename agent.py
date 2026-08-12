#!/usr/bin/env python3
"""
🛡️ Cyber Guardian Agent v1.0
Run this on your system to scan it and send results to the cloud.
"""

import os
import sys
import json
import platform
import socket
import shutil
import hashlib
import subprocess
import time
import uuid
from datetime import datetime

# Try to import psutil, if not available, install it
try:
    import psutil
except ImportError:
    print("📦 Installing required package: psutil...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "psutil"])
    import psutil

try:
    import requests
except ImportError:
    print("📦 Installing required package: requests...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests"])
    import requests


# ===================== CONFIGURATION =====================
# ⚠️ CHANGE THESE VALUES ACCORDING TO YOUR DEPLOYMENT ⚠️
API_URL = "https://cyberguardian-v1.onrender.com/api/agent/scan"
API_KEY = "cyber-guardian-agent-secret-key-2026"  # Match with app.py

# Generate a unique agent ID for this machine
AGENT_ID = str(uuid.uuid4())[:8]


# ===================== SCAN FUNCTIONS =====================

def get_system_info():
    """Get all system information"""
    print("🔍 Scanning system...")
    
    # Basic Info
    os_name = f"{platform.system()} {platform.release()}"
    hostname = socket.gethostname()
    
    try:
        local_ip = socket.gethostbyname(hostname)
    except:
        local_ip = "Unknown"
    
    python_version = platform.python_version()
    architecture = platform.architecture()[0]
    machine = platform.machine()
    cpu_cores = psutil.cpu_count(logical=True)
    
    # Disk Info
    disk = shutil.disk_usage("/")
    total_gb = round(disk.total / (1024 ** 3), 2)
    free_gb = round(disk.free / (1024 ** 3), 2)
    used_gb = round(disk.used / (1024 ** 3), 2)
    disk_percent = round((disk.used / disk.total) * 100, 1)
    
    # CPU & RAM
    cpu_usage = psutil.cpu_percent(interval=0.5)
    ram = psutil.virtual_memory()
    total_ram = round(ram.total / (1024 ** 3), 2)
    used_ram = round(ram.used / (1024 ** 3), 2)
    available_ram = round(ram.available / (1024 ** 3), 2)
    ram_percent = round(ram.percent, 1)
    
    # Open Ports
    open_ports = scan_open_ports()
    
    # Firewall Status
    firewall_status = check_firewall_status()
    
    # Suspicious Processes
    suspicious_procs, total_procs = scan_suspicious_processes()
    
    # User Accounts
    users_info = get_user_accounts_info()
    
    # Antivirus Status
    av_info = check_antivirus_status()
    
    # ===== CALCULATE SCORE =====
    score = 100
    recommendations = []
    
    # Disk check
    if free_gb < 20:
        score -= 10
        recommendations.append(f"⚠️ Low disk space ({free_gb}GB free)")
    
    # RAM check
    if available_ram < 2:
        score -= 10
        recommendations.append(f"⚠️ Low available RAM ({available_ram}GB)")
    
    # CPU check
    if cpu_usage > 85:
        score -= 10
        recommendations.append(f"⚠️ High CPU usage ({cpu_usage}%)")
    
    # Port check
    high_risk_ports = [p for p in open_ports if p['port'] in [21, 23, 3389, 3306, 6379]]
    if high_risk_ports:
        score -= 15
        for p in high_risk_ports:
            recommendations.append(f"🚨 Port {p['port']} ({p['service']}) is OPEN")
    
    medium_risk_ports = [p for p in open_ports if p['port'] in [22, 445, 5900]]
    if medium_risk_ports:
        score -= 8
        for p in medium_risk_ports:
            recommendations.append(f"⚠️ Port {p['port']} ({p['service']}) is OPEN")
    
    # Firewall check
    if "Inactive" in firewall_status or "inactive" in firewall_status.lower():
        score -= 15
        recommendations.append("🚨 Firewall is INACTIVE! Enable it immediately.")
    elif firewall_status == "Active":
        recommendations.append("✅ Firewall is ACTIVE")
    
    # Suspicious processes
    if suspicious_procs:
        score -= 20
        for p in suspicious_procs[:3]:
            recommendations.append(f"⚠️ Suspicious process: {p['name']} (PID: {p['pid']})")
    else:
        recommendations.append(f"✅ No suspicious processes detected ({total_procs} total)")
    
    # Guest account
    if users_info.get('guest_enabled'):
        score -= 10
        recommendations.append("🚨 Guest account is ENABLED! Disable it.")
    else:
        recommendations.append("✅ Guest account is disabled")
    
    # Antivirus
    if av_info.get('real_time_protection'):
        recommendations.append(f"✅ {av_info['name']} real-time protection is ON")
    else:
        score -= 10
        recommendations.append(f"⚠️ {av_info['name']}: Real-time protection is OFF")
    
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
    
    return {
        "agent_id": AGENT_ID,
        "os_name": os_name,
        "hostname": hostname,
        "local_ip": local_ip,
        "python_version": python_version,
        "architecture": architecture,
        "machine": machine,
        "cpu_cores": cpu_cores,
        "total_processes": total_procs,
        "total_gb": total_gb,
        "free_gb": free_gb,
        "used_gb": used_gb,
        "cpu_usage": cpu_usage,
        "total_ram": total_ram,
        "used_ram": used_ram,
        "available_ram": available_ram,
        "ram_percent": ram_percent,
        "disk_percent": disk_percent,
        "open_ports": open_ports,
        "firewall_status": firewall_status,
        "suspicious_processes": suspicious_procs,
        "users_info": users_info,
        "antivirus_info": av_info,
        "score": score,
        "grade": grade,
        "recommendations": recommendations
    }


def scan_open_ports():
    """Scan common ports for open connections"""
    open_ports = []
    common_ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
        443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
        5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy"
    }
    
    for port, service in common_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        try:
            result = sock.connect_ex(('127.0.0.1', port))
            if result == 0:
                open_ports.append({"port": port, "service": service})
        except:
            pass
        finally:
            sock.close()
    
    return open_ports


def check_firewall_status():
    """Check firewall status on the system"""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles"],
                capture_output=True, text=True, timeout=5
            )
            if "ON" in result.stdout or "On" in result.stdout:
                return "Active"
            else:
                return "Inactive"
        elif platform.system() == "Linux":
            # Check ufw
            result = subprocess.run(
                ["sudo", "ufw", "status"],
                capture_output=True, text=True, timeout=5
            )
            if "active" in result.stdout.lower():
                return "Active (UFW)"
            
            # Check iptables
            result2 = subprocess.run(
                ["sudo", "iptables", "-L", "-n"],
                capture_output=True, text=True, timeout=5
            )
            if result2.stdout.strip():
                return "Active (iptables)"
            else:
                return "Inactive"
        elif platform.system() == "Darwin":
            result = subprocess.run(
                ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
                capture_output=True, text=True, timeout=5
            )
            if "enabled" in result.stdout.lower():
                return "Active"
            else:
                return "Inactive"
    except:
        return "Unknown (run as admin/root)"
    
    return "Unknown"


def scan_suspicious_processes():
    """Scan for suspicious processes"""
    suspicious_names = [
        'nc', 'netcat', 'nmap', 'masscan', 'hydra', 'john',
        'hashcat', 'aircrack', 'sqlmap', 'beacon', 'cobaltstrike',
        'meterpreter', 'keylogger', 'miner', 'xmrig', 'burpsuite',
        'metasploit', 'msfconsole', 'reverse_shell', 'trojan'
    ]
    
    suspicious = []
    total = 0
    
    try:
        for proc in psutil.process_iter(['pid', 'name']):
            total += 1
            try:
                proc_name = (proc.info['name'] or '').lower()
                for susp in suspicious_names:
                    if susp in proc_name:
                        suspicious.append({
                            "pid": proc.info['pid'],
                            "name": proc.info['name']
                        })
                        break
            except:
                pass
    except:
        pass
    
    return suspicious, total


def get_user_accounts_info():
    """Get user accounts information"""
    users_info = {
        "total_users": 0,
        "admin_users": [],
        "guest_enabled": False
    }
    
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["net", "user"],
                capture_output=True, text=True, timeout=5
            )
            lines = result.stdout.split('\n')
            users = []
            capture = False
            for line in lines:
                if '----------' in line:
                    capture = True
                    continue
                if capture and line.strip():
                    users.extend(line.strip().split())
            
            users_info["total_users"] = len(users)
            
            # Check guest
            guest_result = subprocess.run(
                ["net", "user", "Guest"],
                capture_output=True, text=True, timeout=5
            )
            if 'Account active' in guest_result.stdout and 'Yes' in guest_result.stdout:
                users_info["guest_enabled"] = True
                
        elif platform.system() == "Linux":
            with open('/etc/passwd', 'r') as f:
                users = [line.split(':')[0] for line in f if not line.startswith('#')]
            users_info["total_users"] = len(users)
            users_info["guest_enabled"] = 'guest' in users
            
        elif platform.system() == "Darwin":
            result = subprocess.run(
                ["dscl", ".", "list", "/Users"],
                capture_output=True, text=True, timeout=5
            )
            users = [u for u in result.stdout.split('\n') if u and not u.startswith('_')]
            users_info["total_users"] = len(users)
            
    except:
        pass
    
    return users_info


def check_antivirus_status():
    """Check antivirus status"""
    av_info = {
        "name": "Not detected",
        "real_time_protection": False
    }
    
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["powershell", "-Command", 
                 "Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusName | ConvertTo-Json"],
                capture_output=True, text=True, timeout=10
            )
            
            try:
                status = json.loads(result.stdout)
                av_info["name"] = status.get('AntivirusName', 'Windows Defender')
                av_info["real_time_protection"] = status.get('RealTimeProtectionEnabled', False)
            except:
                av_info["name"] = "Windows Defender"
                av_info["real_time_protection"] = False
                
        elif platform.system() == "Linux":
            # Check for common Linux antivirus
            avs = ['clamav', 'clamd', 'rkhunter', 'chkrootkit']
            for av in avs:
                if subprocess.run(["which", av], capture_output=True).returncode == 0:
                    av_info["name"] = av.capitalize()
                    av_info["real_time_protection"] = True
                    break
                    
    except:
        pass
    
    return av_info


def get_machine_id():
    """Get a unique identifier for this machine"""
    try:
        if platform.system() == "Windows":
            result = subprocess.run(
                ["wmic", "csproduct", "get", "uuid"],
                capture_output=True, text=True, timeout=5
            )
            lines = result.stdout.strip().split('\n')
            if len(lines) > 1:
                return lines[1].strip()
        elif platform.system() == "Linux":
            with open('/etc/machine-id', 'r') as f:
                return f.read().strip()
        elif platform.system() == "Darwin":
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.split('\n'):
                if 'Hardware UUID' in line:
                    return line.split(':')[-1].strip()
    except:
        pass
    
    return AGENT_ID


# ===================== MAIN =====================

def main():
    print("=" * 60)
    print("🛡️  Cyber Guardian Agent v1.0")
    print("=" * 60)
    print(f"💻 System: {platform.system()} {platform.release()}")
    print(f"🖥️  Hostname: {socket.gethostname()}")
    print(f"🔑 Agent ID: {AGENT_ID}")
    print("=" * 60)
    print()
    
    # Scan system
    data = get_system_info()
    
    # Display results
    print("\n" + "=" * 60)
    print("📊 SCAN RESULTS")
    print("=" * 60)
    print(f"🏆 Security Score: {data['score']}/100")
    print(f"📈 Grade: {data['grade']}")
    print(f"💻 OS: {data['os_name']}")
    print(f"🖥️  Host: {data['hostname']}")
    print(f"📡 IP: {data['local_ip']}")
    print(f"🔢 CPU Cores: {data['cpu_cores']}")
    print(f"💾 RAM: {data['ram_percent']}% used ({data['available_ram']}GB free)")
    print(f"💿 Disk: {data['disk_percent']}% used ({data['free_gb']}GB free)")
    print(f"🔌 Open Ports: {len(data['open_ports'])}")
    print(f"🔥 Firewall: {data['firewall_status']}")
    print(f"⚙️  Total Processes: {data['total_processes']}")
    print(f"🚨 Suspicious Processes: {len(data['suspicious_processes'])}")
    print(f"👤 User Accounts: {data['users_info'].get('total_users', 0)}")
    print(f"🛡️  Antivirus: {data['antivirus_info'].get('name', 'Not detected')}")
    
    if data['open_ports']:
        print("\n🔌 Open Ports:")
        for p in data['open_ports']:
            print(f"   - Port {p['port']}: {p['service']}")
    
    print("\n📝 RECOMMENDATIONS:")
    if data['recommendations']:
        for rec in data['recommendations']:
            print(f"   {rec}")
    else:
        print("   ✅ System looks secure!")
    
    # Send to cloud
    print("\n" + "=" * 60)
    print("📤 Sending data to Cyber Guardian Cloud...")
    print("=" * 60)
    
    try:
        response = requests.post(
            API_URL,
            json=data,
            headers={
                'Content-Type': 'application/json',
                'X-API-Key': API_KEY
            },
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            print("✅ Data sent successfully!")
            if result.get('scan_id'):
                print(f"📋 Scan ID: {result['scan_id']}")
            print(f"🔗 View results at: https://cyberguardian-v1.onrender.com/history")
        else:
            print(f"❌ Error: {response.status_code}")
            print(f"   {response.text}")
            print("\n💾 Saving local report...")
            save_local_report(data)
            
    except requests.exceptions.ConnectionError:
        print("❌ Failed to connect to cloud. Saving local report...")
        save_local_report(data)
    except Exception as e:
        print(f"❌ Error: {e}")
        print("💾 Saving local report...")
        save_local_report(data)
    
    print("\n" + "=" * 60)
    print("✅ Scan complete!")
    print("=" * 60)


def save_local_report(data):
    """Save scan results to local file"""
    filename = f"cyber_guardian_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)
    print(f"📄 Report saved to: {filename}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)