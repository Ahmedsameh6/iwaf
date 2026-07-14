from flask import Flask, request, jsonify, g, send_file, render_template, redirect, url_for, flash, session
from time import time
import os
import csv
import subprocess
import platform
from datetime import datetime
import logging
from collections import defaultdict
import threading
from functools import wraps
import requests
import re
import socket
import joblib
import sqlite3
import urllib.parse as _up
from werkzeug.security import generate_password_hash, check_password_hash

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler("security.log"), logging.StreamHandler()]
)
logger = logging.getLogger("security")

app = Flask(__name__)
app.secret_key = os.environ.get('IWAF_SECRET_KEY', 'iwaf_fixed_secret_key_2024')

def hash_password(pw):
    return generate_password_hash(pw)

def verify_password(pw, hashed):
    # Support legacy SHA-256 hashes during migration
    import hashlib
    legacy = hashlib.sha256(pw.encode()).hexdigest()
    if hashed == legacy:
        return True
    return check_password_hash(hashed, pw)

def init_db():
    try:
        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL CHECK(role IN ('admin', 'user'))
            )''')
            # Check if admin exists
            c.execute("SELECT id, password_hash FROM users WHERE username = 'admin'")
            row = c.fetchone()
            if row is None:
                # No admin — create one
                c.execute("INSERT INTO users (username, email, password_hash, role) VALUES (?,?,?,?)",
                          ('admin', 'admin@iwaf.local', hash_password('admin123'), 'admin'))
                logger.info("Admin user created")
            conn.commit()
        logger.info("Database initialized")
    except Exception as e:
        logger.error(f"DB init error: {e}")

init_db()

def get_current_user():
    uid = session.get('user_id')
    if not uid:
        return None
    try:
        with sqlite3.connect('users.db') as conn:
            c = conn.cursor()
            c.execute("SELECT id, username, email, role FROM users WHERE id=?", (uid,))
            row = c.fetchone()
            if row:
                return {'id': row[0], 'username': row[1], 'email': row[2], 'role': row[3]}
    except Exception as e:
        logger.error(f"get_current_user: {e}")
    return None

@app.context_processor
def inject_current_user():
    user = get_current_user()
    if user:
        # Add is_authenticated and role compatible with flask-login style
        user['is_authenticated'] = True
    else:
        user = {'id': None, 'username': None, 'email': None, 'role': None, 'is_authenticated': False}
    return {'current_user': type('User', (), user)()}

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not get_current_user():
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user or user['role'] != 'admin':
            return jsonify({"status": "error", "message": "Admin privileges required"}), 403
        return f(*args, **kwargs)
    return decorated

try:
    loaded_model = joblib.load('waf_model.sav')
    logger.info("ML model loaded OK")
except Exception as e:
    logger.warning(f"ML joblib load failed, trying legacy: {e}")
    try:
        import pickle
        loaded_model = pickle.load(open('waf_model.sav', 'rb'))
        logger.info("ML model loaded via legacy pickle")
    except Exception as e2:
        logger.error(f"ML model load failed: {e2}")
        loaded_model = None


VT_API_KEY = os.environ.get("VT_API_KEY", "dd42652e45a2a9d368eff2e38949172bca1ac5e1fc652d0e337cb0d1eac7c9cd")
VT_CACHE_DURATION = 86400

visits = defaultdict(list)
blacklist = set()
trusted_ips = set()
ip_to_mac = {}
concurrent_requests = defaultdict(int)
slow_request_counter = defaultdict(int)
vt_cache = {}
data_lock = threading.RLock()

class Config:
    BLACKLIST_FILE = "blacklist.txt"
    LOG_FILE = "attacker_log.csv"
    TRUSTED_IPS_FILE = "trusted_ips.txt"
    RATE_LIMIT = 50
    WINDOW_SIZE = 60
    ATTACK_LOG_FILE = "attack_log.csv"
    ATTACK_LOG_FIELDS = [
        "timestamp","event_name","violation_type","signature_name","source_ip",
        "destination_ip","source_port","destination_port","device_action",
        "requested_url","response_code","referer","user_agent"
    ]
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024
    MAX_REQUEST_HEADERS = 50
    MAX_HEADER_SIZE = 8192
    MAX_TOTAL_HEADER_SIZE = 100 * 1024
    MAX_REQUEST_PROCESSING_TIME = 30
    REQUEST_TIMEOUT = 10
    MAX_CONCURRENT_REQUESTS_PER_IP = 10
    TELEGRAM_BOT_TOKEN = "8799872924:AAE6zQJh-qOQqVKrwgWr96aUZCo-U315x3E"
    TELEGRAM_CHAT_ID = "1780974079"

config = Config()
app.config['MAX_CONTENT_LENGTH'] = config.MAX_CONTENT_LENGTH

# ─── OWASP Top 10 + Extended Attack Patterns ────────────────────────────────
# Each entry: (compiled_regex, attack_type_label)
DETECTION_RULES = [
    # 1. SQL Injection — OWASP A03
    (re.compile(
        r"(\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?)"
        r"|(\bUNION\b.{0,30}\bSELECT\b)"
        r"|(\bSELECT\b.{0,80}\bFROM\b)"
        r"|(\bINSERT\b.{0,30}\bINTO\b)"
        r"|(\bDROP\b.{0,30}\bTABLE\b)"
        r"|(\bDELETE\b.{0,30}\bFROM\b)"
        r"|(\bALTER\b.{0,20}\bTABLE\b)"
        r"|(\bCREATE\b.{0,20}\bTABLE\b)"
        r"|(\bTRUNCATE\b.{0,20}\bTABLE\b)"
        r"|(\bEXEC(UTE)?\b\s*[\(\s])"
        r"|(\bSLEEP\s*\(\d+\))"
        r"|(\bBENCHMARK\s*\()"
        r"|(--\s*(\n|$))"
        r"|(\bINFORMATION_SCHEMA\b)"
        r"|(\bSYSDATABASES\b|\bSYSOBJECTS\b)"
        r"|('\s*(OR|AND)\s*'?\s*\d)",
        re.IGNORECASE
    ), "sql_injection"),

    # 2. XSS — Cross-Site Scripting — OWASP A03
    (re.compile(
        r"(<script\b[^>]*>)"
        r"|(<[a-z:]+[\s][^>]*\bon\w+\s*=\s*['\"]?[^>]{0,200})"
        r"|(javascript\s*:)"
        r"|(vbscript\s*:)"
        r"|(<iframe\b)"
        r"|(<svg\b[^>]*\bon)"
        r"|(<img\b[^>]*\bonerror\s*=)"
        r"|(expression\s*\([^)]{0,100}\))"
        r"|(&#x?[0-9a-f]+;.*script)"
        r"|(<embed\b|<object\b|<applet\b|<form\b[^>]*action\s*=)",
        re.IGNORECASE | re.DOTALL
    ), "xss"),

    # 3. Command Injection — OWASP A03
    (re.compile(
        r";\s*(cat|rm|ls|whoami|id|wget|curl|bash|sh|python|python3|perl|nc|ncat|netcat|dd|chmod|chown|mkfifo|mknod|nmap)\b"
        r"|(\|\|?\s*(cat|ls|whoami|id|bash|sh|wget|curl|nc)\b)"
        r"|(&&\s*(cat|ls|whoami|id|rm|wget|curl)\b)"
        r"|(`.{0,80}`)"
        r"|(\$\([^)]{0,80}\))"
        r"|(>&?\s*/dev/(tcp|udp)/)"
        r"|(\beval\s*\()",
        re.IGNORECASE
    ), "command_injection"),

    # 4. LFI / Path Traversal — OWASP A01
    (re.compile(
        r"(\.\.[/\\]){2,}"
        r"|(php://\w+)"
        r"|(data://text)"
        r"|(expect://)"
        r"|(zip://)"
        r"|(glob://)"
        r"|(file://)"
        r"|(%2e%2e(%2f|%5c)){2,}"
        r"|(\.\.%2f){2,}"
        r"|(\.\.%5c){2,}"
        r"|(/(etc/passwd|etc/shadow|proc/self|windows/system32|boot\.ini))",
        re.IGNORECASE
    ), "lfi_path_traversal"),

    # 5. CRLF / Header Injection — OWASP A03
    (re.compile(
        r"(\r\n[A-Za-z\-]+:)"
        r"|(\n[A-Za-z\-]+:\s)"
        r"|(%0[dD]%0[aA])"
        r"|(%0[aA][A-Za-z])"
        r"|(\\r\\n[A-Za-z])",
        re.IGNORECASE
    ), "crlf_injection"),

    # 6. SSTI — Server-Side Template Injection — OWASP A03
    (re.compile(
        r"(\{\{[^}]{0,100}\}\})"
        r"|(\$\{[^}]{0,100}\})"
        r"|(#\{[^}]{0,100}\})"
        r"|(<%=[^%]{0,100}%>)"
        r"|(\{%[-\s]*(for|if|set|macro|block|include|import|extends)\b)"
        r"|(\[\[.{0,80}\]\])"
        r"|(@\{[^}]{0,80}\})"
        r"|(<#\s*(assign|list|if|include|import|macro|function|call|attempt|ftl|setting)\b)"
        r"|(\?new\s*\(\s*\))"
        r"|(freemarker\.template\.utility)",
        re.IGNORECASE | re.DOTALL
    ), "ssti"),

    # 7. XXE — XML External Entity — OWASP A05
    (re.compile(
        r"(<!\s*ENTITY[^>]{0,200})"
        r"|(SYSTEM\s+['\"]\s*(file|http|ftp|expect|php|data)://)"
        r"|(<!DOCTYPE[^>]{0,300}\[)"
        r"|(<!\[CDATA\[)"
        r"|(\&[a-z_][a-z0-9_]{0,20};)"
        r"|(xmlns\s*:\s*\w+\s*=\s*['\"][^'\"]{0,200}['\"])",
        re.IGNORECASE | re.DOTALL
    ), "xxe"),

    # 8. SSRF — Server-Side Request Forgery — OWASP A10
    (re.compile(
        r"(https?://(?:localhost|127\.0\.0\.\d+|0\.0\.0\.0|\[::1\]|169\.254\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+))"
        r"|(https?://[^/\s]{0,100}@)"
        r"|(file://[/\\])"
        r"|(gopher://|dict://|sftp://|ldap://|tftp://)"
        r"|(https?://[^\s]{0,200}/(admin|internal|metadata|latest|v1|api))",
        re.IGNORECASE
    ), "ssrf"),

    # 9. Open Redirect — OWASP A01
    (re.compile(
        r"(//[a-z0-9\-\.]{3,50}\.[a-z]{2,10})"
        r"|(https?://[a-z0-9\-]{2,50}\.[a-z]{2,10}[/?])"
        r"|(url=https?://)"
        r"|(redirect=https?://)"
        r"|(next=https?://)"
        r"|(return=https?://)"
        r"|(goto=https?://)",
        re.IGNORECASE
    ), "open_redirect"),

    # 10. NoSQL Injection — OWASP A03
    (re.compile(
        r"(\$where\s*:)"
        r"|(\$gt|\$lt|\$gte|\$lte|\$ne|\$in|\$nin|\$exists|\$regex|\$or|\$and|\$not|\$nor)\s*:"
        r"|(\{\s*['\"]\$)"
        r"|(\bdb\.(\w+\.)?find\s*\()"
        r"|(mapreduce|group\s*:\s*\{)",
        re.IGNORECASE
    ), "nosql_injection"),

    # 11. LDAP Injection — OWASP A03
    (re.compile(
        r"(\*\)\s*\()"
        r"|(\)\s*\(\s*\|)"
        r"|(\(objectClass=\*\))"
        r"|(\|\s*\(uid=\*\))"
        r"|(\(cn=\*\))"
        r"|(\bLDAP\b.{0,30}\bfilter\b)",
        re.IGNORECASE
    ), "ldap_injection"),

    # 12. HTTP Request Smuggling — OWASP A05
    (re.compile(
        r"(Transfer-Encoding\s*:\s*chunked.{0,50}Content-Length\s*:)"
        r"|(Content-Length\s*:\s*\d+.{0,50}Transfer-Encoding\s*:)"
        r"|(0\s*\r?\n\s*\r?\n.{0,100}(?:GET|POST|PUT).{0,100}HTTP/1)"
        r"|(\bHTTP/1\.[01]\s+\d{3}[^\n]{0,200}\bHTTP/1\.[01]\b)",
        re.IGNORECASE | re.DOTALL
    ), "http_request_smuggling"),

    # 13. Log4Shell / Log4j — CVE-2021-44228
    (re.compile(
        r"(\$\{jndi\s*:)"
        r"|(\$\{\s*::-[jJ]\s*\})"
        r"|(jndi:(ldap|rmi|dns|iiop|corba|nds|nis|ldaps)://)"
        r"|(\$\{lower:\s*j\})"
        r"|(\$\{upper:\s*j\})"
        r"|(\$\{env:[A-Z_]{2,30}\})",
        re.IGNORECASE
    ), "log4shell"),

    # 14. Insecure Deserialization — OWASP A08
    (re.compile(
        r"(O:[0-9]+:\"[a-z][^\"]*\")"
        r"|(rO0AB[A-Za-z0-9+/]{1,})"
        r"|(\\xac\\xed\\x00\\x05)"
        r"|(\xac\xed\x00\x05)"
        r"|(YToyOi|YTo[0-9]O)"
        r"|(gASV[A-Za-z0-9+/]{4,})"
        r"|(java\.lang\.(Runtime|ProcessBuilder|Thread))"
        r"|(java\.io\.ObjectInputStream)"
        r"|(sun\.reflect\.annotation)",
        re.IGNORECASE | re.DOTALL
    ), "deserialization"),

    # 15. XML / XPath Injection — OWASP A03
    (re.compile(
        r"(\bOR\b\s+['\"]?\w+['\"]?\s*=\s*['\"]?\w+['\"]?\s*(\bOR\b|\bAND\b))"
        r"|(\]\s*\[\s*@)"
        r"|(//\*\[)"
        r"|(\bcount\s*\(\s*//)"
        r"|(\bstring-length\s*\()"
        r"|(\bsubstring\s*\([^)]{0,80},\s*\d+)",
        re.IGNORECASE
    ), "xml_xpath_injection"),
]

# Backward-compat alias (used in /waf-test and before_request)
MALICIOUS_PATTERNS = [r for r, _ in DETECTION_RULES]

def is_valid_ip(ip):
    try:
        parts = str(ip).strip().split(".")
        return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
    except:
        return False

def is_ip_malicious(ip_address):
    now = time()
    with data_lock:
        if ip_address in vt_cache:
            ts, is_mal, details = vt_cache[ip_address]
            if now - ts < VT_CACHE_DURATION:
                return is_mal, details
    if not is_valid_ip(ip_address):
        return False, {"status": "ERROR", "reason": "Invalid IP"}
    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
        resp = requests.get(url, headers={"x-apikey": VT_API_KEY}, timeout=5)
        resp.raise_for_status()
        data = resp.json()
        attrs = data.get("data", {}).get("attributes", {})
        mal = attrs.get("last_analysis_stats", {}).get("malicious", 0)
        sus = attrs.get("last_analysis_stats", {}).get("suspicious", 0)
        details = {"malicious_count": mal, "suspicious_count": sus,
                   "country": attrs.get("country", "Unknown")}
        if mal >= 2:
            details["status"] = "MALICIOUS"
            is_mal = True
        elif mal == 1 or sus >= 2:
            details["status"] = "SUSPICIOUS"
            is_mal = False
        else:
            details["status"] = "SAFE"
            is_mal = False
        with data_lock:
            vt_cache[ip_address] = (now, is_mal, details)
        return is_mal, details
    except Exception as e:
        return False, {"status": "ERROR", "reason": str(e)}

def load_trusted_ips():
    ips = set()
    if os.path.exists(config.TRUSTED_IPS_FILE):
        with open(config.TRUSTED_IPS_FILE) as f:
            for line in f:
                ip = line.strip()
                if ip and is_valid_ip(ip):
                    ips.add(ip)
    return ips

def save_trusted_ips():
    with open(config.TRUSTED_IPS_FILE, 'w') as f:
        for ip in trusted_ips:
            f.write(ip + '\n')

def load_blacklist():
    bl = set()
    if os.path.exists(config.BLACKLIST_FILE):
        with open(config.BLACKLIST_FILE) as f:
            for line in f:
                ip = line.strip()
                if ip and is_valid_ip(ip):
                    bl.add(ip)
    return bl

def save_blacklist():
    with open(config.BLACKLIST_FILE, 'w') as f:
        for ip in blacklist:
            f.write(ip + '\n')

def _send_telegram_worker(token, chat_id, message):
    """Background Telegram notifier with better reliability"""
    try:
        token = str(token).strip()
        chat_id = str(chat_id).strip()

        if ":" not in token:
            logger.error("Invalid Telegram token format")
            return

        url = f"https://api.telegram.org/bot{token}/sendMessage"

        resp = requests.post(
            url,
            json={
                "chat_id": chat_id,
                "text": message
            },
            timeout=15
        )

        logger.info(f"Telegram status: {resp.status_code}")
        logger.info(f"Telegram response: {resp.text[:300]}")

        if not resp.ok:
            logger.warning(f"Telegram alert failed: {resp.text[:200]}")
        else:
            logger.info("Telegram alert sent successfully")

    except Exception as e:
        logger.exception(f"Telegram alert error: {e}")

def send_telegram_alert(source_ip, source_port, dest_ip, dest_port, attack_type, mac_address):
    token = config.TELEGRAM_BOT_TOKEN or os.environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = config.TELEGRAM_CHAT_ID or os.environ.get("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id:
        logger.warning("Telegram not configured: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is empty")
        return
    message = (
        f"🚨 *IWAF Security Alert*\n"
        f"━━━━━━━━━━━━━━━━━\n"
        f"🔴 *Attack Type:* `{attack_type}`\n"
        f"🌐 *Source IP:* `{source_ip}:{source_port}`\n"
        f"🎯 *Destination:* `{dest_ip}:{dest_port}`\n"
        f"💻 *MAC:* `{mac_address}`\n"
        f"🕐 *Time:* `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`"
    )
    
    t = threading.Thread(target=_send_telegram_worker, args=(token, chat_id, message), daemon=True)
    t.start()

def block_ip_fw(ip):
    try:
        if platform.system() == "Linux":
            subprocess.run(["iptables","-A","INPUT","-s",ip,"-j","DROP"],
                           capture_output=True, timeout=5)
    except:
        pass

def unblock_ip_fw(ip):
    try:
        if platform.system() == "Linux":
            subprocess.run(["iptables","-D","INPUT","-s",ip,"-j","DROP"],
                           capture_output=True, timeout=5)
    except:
        pass

def block_ip(ip, reason="rate_limit_exceeded"):
    with data_lock:
        if ip in blacklist:
            return False
        blacklist.add(ip)
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            with open(config.LOG_FILE, 'a', newline='') as f:
                csv.writer(f).writerow([ip, "N/A", len(visits.get(ip, [])), timestamp, reason])
        except:
            pass
    # save_blacklist خارج الـ lock عشان file I/O متوقّفش الـ threads
    save_blacklist()
    logger.warning(f"Blocked IP {ip}: {reason}")
    block_ip_fw(ip)
    try:
        send_telegram_alert(ip, "?", socket.gethostbyname(socket.gethostname()), "5000", reason, "N/A")
    except Exception as e:
        logger.debug(f"Telegram skip: {e}")
    return True

def unblock_ip(ip):
    with data_lock:
        if ip not in blacklist:
            return False
        blacklist.remove(ip)
        save_blacklist()
    unblock_ip_fw(ip)
    logger.info(f"Unblocked IP {ip}")
    return True

def log_attack(req, violation_type, signature_name):
    try:
        file_exists = os.path.exists(config.ATTACK_LOG_FILE) and os.path.getsize(config.ATTACK_LOG_FILE) > 0
        with open(config.ATTACK_LOG_FILE, 'a', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=config.ATTACK_LOG_FIELDS)
            if not file_exists:
                writer.writeheader()
            writer.writerow({
                "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "event_name": "WAF_BLOCK",
                "violation_type": violation_type,
                "signature_name": str(signature_name)[:200],
                "source_ip": req.remote_addr,
                "destination_ip": req.host,
                "source_port": req.environ.get('REMOTE_PORT', '?'),
                "destination_port": "5000",
                "device_action": "blocked",
                "requested_url": req.url[:500],
                "response_code": "403",
                "referer": req.referrer or "",
                "user_agent": req.headers.get('User-Agent', '')[:200]
            })
    except Exception as e:
        logger.error(f"log_attack error: {e}")

trusted_ips.update(load_trusted_ips())
trusted_ips.add('127.0.0.1')
trusted_ips.add('::1')
blacklist.update(load_blacklist())

for lf in [config.ATTACK_LOG_FILE, config.LOG_FILE]:
    if not os.path.exists(lf):
        with open(lf, 'w', newline='') as f:
            w = csv.writer(f)
            if lf == config.ATTACK_LOG_FILE:
                w.writerow(config.ATTACK_LOG_FIELDS)
            else:
                w.writerow(['IP Address','MAC Address','Request Count','Timestamp','Reason'])

@app.before_request
def check_security():
    ip = request.remote_addr
    g.client_ip = ip
    g.start_time = time()
    with data_lock:
        concurrent_requests[ip] += 1

    if ip in trusted_ips:
        return None
    if ip in blacklist:
        return jsonify({"error": "Access denied"}), 403

    if ip not in ('127.0.0.1', '::1'):
        
        with data_lock:
            cached = vt_cache.get(ip)
        if cached:
            ts, is_mal, details = cached
            if time() - ts < VT_CACHE_DURATION:
                if is_mal:
                    block_ip(ip, f"malicious_ip:{details.get('status','?')}")
                    return jsonify({"error": "Access denied - Malicious IP"}), 403
        else:
            
            def _vt_check_and_block(check_ip_addr):
                is_mal, details = is_ip_malicious(check_ip_addr)
                if is_mal:
                    block_ip(check_ip_addr, f"malicious_ip:{details.get('status','?')}")
            threading.Thread(target=_vt_check_and_block, args=(ip,), daemon=True).start()

    content_length = request.headers.get('Content-Length', type=int)
    if content_length and content_length > config.MAX_CONTENT_LENGTH:
        block_ip(ip, "oversized_payload")
        return jsonify({"error": "Payload too large"}), 413

    if len(request.headers) > config.MAX_REQUEST_HEADERS:
        block_ip(ip, "excessive_headers")
        return jsonify({"error": "Too many headers"}), 400

    for name, value in request.headers:
        if len(value) > config.MAX_HEADER_SIZE:
            block_ip(ip, "oversized_header")
            return jsonify({"error": "Header too large"}), 400

    if concurrent_requests[ip] > config.MAX_CONCURRENT_REQUESTS_PER_IP:
        block_ip(ip, "concurrent_request_limit")
        return jsonify({"error": "Too many concurrent requests"}), 429

    with data_lock:
        now = time()
        visits[ip] = [t for t in visits[ip] if t > (now - config.WINDOW_SIZE)]
        visits[ip].append(now)
        if len(visits[ip]) > config.RATE_LIMIT:
            block_ip(ip, "rate_limit_exceeded")
            return jsonify({"error": "Too many requests"}), 429

    parts = []
    for k, vs in request.args.lists():
        parts.extend(vs)
    for k, vs in request.form.lists():
        parts.extend(vs)
    if request.data:
        parts.append(request.data.decode('utf-8', errors='ignore'))

    decoded_parts = []

    for part in parts:
        try:
            decoded_parts.append(_up.unquote_plus(str(part)))
        except:
            decoded_parts.append(str(part))

    for part in decoded_parts:
        logger.debug(f"Scanning payload ({len(part)} chars)")

        if loaded_model:
            try:
                pred = loaded_model.predict([part])[0]
                if pred != "valid":
                    log_attack(request, pred, part)
                    block_ip(ip, f"malicious_payload:{pred}")
                    return jsonify({"error": f"Attack detected: {pred}"}), 403
            except Exception as e:
                logger.error(f"ML error: {e}")
        # Regex engine — iterate all OWASP rules
        for pattern, vtype in DETECTION_RULES:
            if pattern.search(part):
                log_attack(request, vtype, part)
                block_ip(ip, f"malicious_payload:{vtype}")
                return jsonify({"error": "Attack detected"}), 403
    return None

@app.after_request
def log_request(response):
    if hasattr(g, 'start_time') and hasattr(g, 'client_ip'):
        ip = g.client_ip
        duration = time() - g.start_time
        if response.status_code >= 400 or duration > 1.0:
            logger.info(f"[{ip}] {response.status_code} {duration:.2f}s")
    return response

@app.teardown_request
def cleanup_request(exception=None):
    if hasattr(g, 'client_ip'):
        ip = g.client_ip
        with data_lock:
            if concurrent_requests[ip] > 0:
                concurrent_requests[ip] -= 1

# ---- Routes ----
login_attempts = defaultdict(list)
LOGIN_MAX_ATTEMPTS = 10
LOGIN_WINDOW = 300  # 5 minutes

@app.route("/login", methods=["GET","POST"])
def login():
    if get_current_user():
        return redirect(url_for('dashboard'))
    if request.method == "POST":
        ip = request.remote_addr
        now = time()
        with data_lock:
            login_attempts[ip] = [t for t in login_attempts[ip] if t > now - LOGIN_WINDOW]
            if len(login_attempts[ip]) >= LOGIN_MAX_ATTEMPTS:
                flash('Too many login attempts. Please wait 5 minutes.', 'danger')
                return render_template('login.html')
            login_attempts[ip].append(now)
        username = request.form.get('username','')
        password = request.form.get('password','')
        try:
            with sqlite3.connect('users.db') as conn:
                c = conn.cursor()
                c.execute("SELECT id, password_hash FROM users WHERE username=?", (username,))
                row = c.fetchone()
            if row and verify_password(password, row[1]):
                with data_lock:
                    login_attempts[ip] = []
                session['user_id'] = row[0]
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password.', 'danger')
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash('An error occurred.', 'danger')
    return render_template('login.html')

@app.route("/logout")
def logout():
    session.pop('user_id', None)
    flash('Logged out.', 'success')
    return redirect(url_for('login'))

@app.route("/")
def home():
    if not get_current_user():
        return redirect(url_for('login'))
    return redirect(url_for('dashboard'))

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route("/waf-test-page")
@login_required
def waf_test_page():
    return render_template('waf_test.html')

@app.route("/blacklist-page")
@login_required
def blacklist_page():
    return render_template('blacklist.html')

@app.route("/trusted-page")
@login_required
def trusted_page():
    return render_template('trusted.html')

@app.route("/check-ip-page")
@login_required
def check_ip_page():
    return render_template('check_ip.html')

@app.route("/settings")
@login_required
def settings():
    return render_template('settings.html', config=config.__dict__)

@app.route("/manage-users", methods=["GET","POST"])
@login_required
@require_admin
def manage_users():
    cur = get_current_user()
    if request.method == "POST":
        action = request.form.get('action')
        try:
            with sqlite3.connect('users.db') as conn:
                c = conn.cursor()
                if action == "add":
                    un = request.form.get('username')
                    em = request.form.get('email')
                    pw = request.form.get('password')
                    role = request.form.get('role')
                    c.execute("SELECT id FROM users WHERE username=?", (un,))
                    if c.fetchone():
                        flash('Username already exists.', 'danger')
                    else:
                        c.execute("INSERT INTO users (username,email,password_hash,role) VALUES (?,?,?,?)",
                                  (un, em, hash_password(pw), role))
                        conn.commit()
                        flash('User added.', 'success')
                elif action == "edit":
                    uid = request.form.get('user_id')
                    un = request.form.get('username')
                    em = request.form.get('email')
                    role = request.form.get('role')
                    c.execute("UPDATE users SET username=?,email=?,role=? WHERE id=?", (un,em,role,uid))
                    conn.commit()
                    flash('User updated.', 'success')
                elif action == "delete":
                    uid = request.form.get('user_id')
                    if str(uid) == str(cur['id']):
                        flash('Cannot delete own account.', 'danger')
                    else:
                        c.execute("DELETE FROM users WHERE id=?", (uid,))
                        conn.commit()
                        flash('User deleted.', 'success')
        except Exception as e:
            logger.error(f"manage_users: {e}")
            flash('Error occurred.', 'danger')
    with sqlite3.connect('users.db') as conn:
        c = conn.cursor()
        c.execute("SELECT id,username,email,role FROM users")
        users = c.fetchall()
    return render_template('manage_users.html', users=users)

@app.route("/block/<ip_address>", methods=["POST"])
@login_required
@require_admin
def manual_block(ip_address):
    if ip_address in trusted_ips:
        return jsonify({"status":"error","message":"Cannot block trusted IP"}), 400
    success = block_ip(ip_address, "manual_block")
    if success:
        return jsonify({"status":"success","message":f"IP {ip_address} blocked"})
    return jsonify({"status":"info","message":f"IP {ip_address} already blocked"})

@app.route("/unblock/<ip_address>", methods=["POST"])
@login_required
@require_admin
def manual_unblock(ip_address):
    success = unblock_ip(ip_address)
    if success:
        return jsonify({"status":"success","message":f"IP {ip_address} unblocked"})
    return jsonify({"status":"info","message":f"IP {ip_address} not in blacklist"})

@app.route("/blacklist", methods=["GET"])
@login_required
def get_blacklist():
    with data_lock:
        return jsonify({"blacklist": list(blacklist)})

@app.route("/trusted", methods=["GET"])
@login_required
def get_trusted_ips_route():
    with data_lock:
        return jsonify({"trusted_ips": list(trusted_ips)})

@app.route("/trusted/add/<ip_address>", methods=["POST"])
@login_required
@require_admin
def add_trusted_ip(ip_address):
    should_unblock = False
    with data_lock:
        if ip_address in trusted_ips:
            return jsonify({"status":"info","message":"Already trusted"})
        trusted_ips.add(ip_address)
        save_trusted_ips()
        if ip_address in blacklist:
            should_unblock = True
    if should_unblock:
        unblock_ip(ip_address)
    return jsonify({"status":"success","message":f"IP {ip_address} trusted"})

@app.route("/trusted/remove/<ip_address>", methods=["POST"])
@login_required
@require_admin
def remove_trusted_ip(ip_address):
    if ip_address == request.remote_addr:
        return jsonify({"status":"error","message":"Cannot remove own IP"}), 400
    with data_lock:
        if ip_address not in trusted_ips:
            return jsonify({"status":"info","message":"Not in trusted list"})
        trusted_ips.discard(ip_address)
        save_trusted_ips()
        return jsonify({"status":"success","message":f"IP {ip_address} removed"})

@app.route("/stats", methods=["GET"])
@login_required
def get_stats():
    with data_lock:
        now = time()
        active_ips = {ip: len(ts) for ip, ts in visits.items() if ts and ts[-1] > (now-300)}
        return jsonify({
            "blacklist_size": len(blacklist),
            "trusted_ips_count": len(trusted_ips),
            "active_ips": len(active_ips),
            "high_rate_ips": {ip: c for ip, c in active_ips.items() if c > config.RATE_LIMIT // 2},
            "slow_request_offenders": {ip: c for ip, c in slow_request_counter.items() if c > 0},
            "concurrent_requests": {ip: c for ip, c in concurrent_requests.items() if c > 0},
            "ml_model_loaded": loaded_model is not None
        })

@app.route("/reset-slow-counter/<ip_address>", methods=["POST"])
@login_required
@require_admin
def reset_slow_counter(ip_address):
    with data_lock:
        count = slow_request_counter.pop(ip_address, 0)
        return jsonify({"status":"success","message":f"Reset counter (was {count})"})

@app.route("/check-ip/<ip_address>", methods=["GET"])
@login_required
def check_ip(ip_address):
    is_mal, details = is_ip_malicious(ip_address)
    return jsonify({"ip": ip_address, "is_malicious": is_mal, "status": details.get("status"), "details": details})

@app.route("/clear-vt-cache", methods=["POST"])
@login_required
@require_admin
def clear_vt_cache():
    with data_lock:
        n = len(vt_cache)
        vt_cache.clear()
        return jsonify({"status":"success","message":f"Cleared {n} entries"})

@app.route("/attack-log", methods=["GET"])
@login_required
def get_attack_log():
    logs = []
    try:
        if os.path.exists(config.ATTACK_LOG_FILE):
            with open(config.ATTACK_LOG_FILE, newline='') as f:
                reader = csv.DictReader(f)
                if reader.fieldnames:
                    logs = list(reader)
    except Exception as e:
        logger.error(f"attack-log: {e}")
    return jsonify({"logs": logs})

@app.route("/attacker-log", methods=["GET"])
@login_required
def get_attacker_log():
    logs = []
    try:
        if os.path.exists(config.LOG_FILE):
            with open(config.LOG_FILE, newline='') as f:
                reader = csv.DictReader(f)
                if reader.fieldnames:
                    logs = list(reader)
    except Exception as e:
        logger.error(f"attacker-log: {e}")
    return jsonify({"logs": logs})

@app.route("/security-log", methods=["GET"])
@login_required
def get_security_log():
    logs = []
    try:
        if os.path.exists("security.log"):
            with open("security.log") as f:
                logs = f.readlines()[-100:]
    except Exception as e:
        logger.error(f"security-log: {e}")
    return jsonify({"logs": logs})

@app.route("/export-attack-log", methods=["GET"])
@login_required
def export_attack_log():
    if os.path.exists(config.ATTACK_LOG_FILE):
        return send_file(config.ATTACK_LOG_FILE, as_attachment=True, download_name="attack_log.csv")
    return jsonify({"error":"Not found"}), 404

@app.route("/export-attacker-log", methods=["GET"])
@login_required
def export_attacker_log():
    if os.path.exists(config.LOG_FILE):
        return send_file(config.LOG_FILE, as_attachment=True, download_name="attacker_log.csv")
    return jsonify({"error":"Not found"}), 404

@app.route("/delete-log/<log_type>", methods=["POST"])
@login_required
@require_admin
def delete_log(log_type):
    file_map = {"attack": config.ATTACK_LOG_FILE, "attacker": config.LOG_FILE, "security": "security.log"}
    fp = file_map.get(log_type)
    if not fp:
        return jsonify({"status":"error","message":"Invalid log type"}), 400
    try:
        if os.path.exists(fp):
            os.remove(fp)
        if log_type in ["attack","attacker"]:
            with open(fp, 'w', newline='') as f:
                w = csv.writer(f)
                if log_type == "attack":
                    w.writerow(config.ATTACK_LOG_FIELDS)
                else:
                    w.writerow(['IP Address','MAC Address','Request Count','Timestamp','Reason'])
        return jsonify({"status":"success","message":f"Deleted {log_type} log"})
    except Exception as e:
        return jsonify({"status":"error","message":str(e)}), 500

@app.route("/update-settings", methods=["POST"])
@login_required
@require_admin
def update_settings():
    try:
        data = request.json or {}
        int_fields = ["RATE_LIMIT","WINDOW_SIZE","MAX_CONTENT_LENGTH","MAX_REQUEST_HEADERS",
                      "MAX_HEADER_SIZE","MAX_REQUEST_PROCESSING_TIME","REQUEST_TIMEOUT",
                      "MAX_CONCURRENT_REQUESTS_PER_IP"]
        for key, value in data.items():
            if hasattr(config, key):
                setattr(config, key, int(value) if key in int_fields else str(value))
        return jsonify({"status":"success","message":"Settings updated"})
    except Exception as e:
        return jsonify({"status":"error","message":str(e)}), 500

@app.route("/waf-test", methods=["POST"])
@login_required
def waf_test():
    payload = (request.json or {}).get("payload","")
    if not payload:
        return jsonify({"error":"No payload"}), 400
    result = {"payload": payload, "prediction": "unknown", "method": "none", "is_attack": False,
              "matched_rules": []}
    # Step 1: ML model
    if loaded_model:
        try:
            pred = loaded_model.predict([payload])[0]
            result["prediction"] = pred
            result["method"] = "ml_model"
            result["is_attack"] = pred != "valid"
        except Exception as e:
            result["ml_error"] = str(e)
    # Step 2: All 15 OWASP rules — scan all, collect ALL matches
    for pattern, vtype in DETECTION_RULES:
        if pattern.search(payload):
            result["matched_rules"].append(vtype)
            if not result["is_attack"]:
                result["prediction"] = vtype
                result["method"] = "regex"
                result["is_attack"] = True
    # Step 3: Sanity check — plain key=value form data with no attack chars
    ATTACK_CHARS = re.compile(
        r"('|--|;|<|>|\{|\}|\||&\s*(cat|ls|id|whoami)|%0[aAdD]|php://|data://|\$\{jndi|objectClass)",
        re.IGNORECASE
    )
    if result["is_attack"] and result["method"] == "ml_model" and not result["matched_rules"]:
        if not ATTACK_CHARS.search(payload):
            try:
                parsed = _up.parse_qs(payload, strict_parsing=True)
                all_clean = all(
                    re.match(r"^[\w\s.\-@+,\/]+$", v)
                    for vals in parsed.values() for v in vals
                )
                if parsed and all_clean:
                    result["prediction"] = "valid"
                    result["is_attack"] = False
                    result["method"] = "sanity_check"
            except Exception:
                pass
    if result["prediction"] == "unknown":
        result["prediction"] = "valid"
    return jsonify(result)

if __name__ == "__main__":
    logger.info("Starting IWAF server...")
    app.run(host="0.0.0.0", port=5000, debug=False)
