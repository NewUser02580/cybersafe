# app.py
import os
import ipaddress
import socket
import hashlib
from urllib.parse import urlparse

import requests
from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = "super_secret_key"  # replace in prod

# API KEYS
GOOGLE_API_KEY = "AIzaSyA285IeHgxVy9trbZsHNZPUfovvNMoxXp4"
VT_API_KEY = "YOUR_VIRUSTOTAL_API_KEY"

SAFE_BROWSING_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}" if GOOGLE_API_KEY else None
VT_FILE_REPORT_URL = "https://www.virustotal.com/api/v3/files/"


# ---------- Helpers for URL checks ----------
def is_private_or_loopback(hostname):
    if not hostname:
        return False
    if hostname.lower() == "localhost":
        return True
    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        try:
            ip_str = socket.gethostbyname(hostname)
            ip = ipaddress.ip_address(ip_str)
        except Exception:
            return False
    return ip.is_private or ip.is_loopback or ip.is_reserved


def simple_heuristics(parsed):
    warnings = []
    if parsed.scheme == "http":
        warnings.append("Uses HTTP (not HTTPS)")
    host = parsed.hostname or ""
    try:
        ipaddress.ip_address(host)
        warnings.append("URL uses a raw IP address instead of a domain")
    except ValueError:
        pass
    if parsed.port and parsed.port not in (80, 443):
        warnings.append(f"Non-standard port: {parsed.port}")
    suspicious_keywords = ["login", "secure", "verify", "bank", "update", "confirm"]
    combined = (parsed.netloc + parsed.path).lower()
    for kw in suspicious_keywords:
        if kw in combined and len(parsed.netloc) > 0:
            warnings.append(f"Contains suspicious keyword: '{kw}'")
            break
    return warnings


def call_safe_browsing_api(url):
    if not SAFE_BROWSING_URL:
        return {"error": "Google Safe Browsing API key not provided."}
    body = {
        "client": {"clientId": "cybersafe", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE",
                "SOCIAL_ENGINEERING",
                "POTENTIALLY_HARMFUL_APPLICATION",
                "UNWANTED_SOFTWARE"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        resp = requests.post(SAFE_BROWSING_URL, json=body, timeout=10)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        return {"error": str(e)}


def check_url(url_input):
    url = url_input.strip()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    parsed = urlparse(url)
    host = parsed.hostname

    details = {
        "url": url,
        "heuristics": [],
        "safe_browsing": None,
        "final_decision": None,
        "notes": []
    }

    h = simple_heuristics(parsed)
    details["heuristics"] = h

    if host and is_private_or_loopback(host):
        details["notes"].append("Host resolves to loopback/private/reserved IP.")
        details["final_decision"] = "suspicious_local"
        return details

    sb_resp = call_safe_browsing_api(url)
    details["safe_browsing"] = sb_resp

    if "error" in sb_resp:
        details["notes"].append(f"Safe Browsing error: {sb_resp['error']}")
        details["final_decision"] = "unknown" if not h else "suspicious_heuristics"
        return details

    if "matches" in sb_resp and sb_resp["matches"]:
        details["final_decision"] = "malicious_public"
        return details

    details["final_decision"] = "publicly_safe" if not h else "suspicious_heuristics"
    return details


# ---------- Password Check ----------
def pwned_password_check(password_plain):
    if not password_plain:
        return {"error": "Empty password"}

    sha1 = hashlib.sha1(password_plain.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    try:
        resp = requests.get(url, timeout=8)
        resp.raise_for_status()
        lines = resp.text.splitlines()
        for line in lines:
            parts = line.split(":")
            if len(parts) != 2:
                continue
            ret_suffix, count = parts[0].strip(), parts[1].strip()
            if ret_suffix == suffix:
                return {"pwned": True, "count": int(count)}
        return {"pwned": False, "count": 0}
    except Exception as e:
        return {"error": str(e)}


# ---------- NEW: File Hash Scanner ----------
def compute_sha256(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


def check_file_with_virustotal(file_path):
    if not VT_API_KEY:
        return {"error": "VirusTotal API key not provided."}

    file_hash = compute_sha256(file_path)
    url = VT_FILE_REPORT_URL + file_hash
    headers = {"x-apikey": VT_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            return {"hash": file_hash, "stats": stats}
        elif resp.status_code == 404:
            return {"hash": file_hash, "message": "File not found in VirusTotal database."}
        else:
            return {"error": f"Unexpected response {resp.status_code}"}
    except Exception as e:
        return {"error": str(e)}


# ---------- Routes ----------
@app.route("/", methods=["GET", "POST"])
def home():
    result = None
    result_type = "info"
    details = None

    if request.method == "POST":
        if "url" in request.form:
            url_val = request.form.get("url", "").strip()
            if not url_val:
                flash("Enter a URL to check.", "danger")
                return redirect(url_for("home"))
            details = check_url(url_val)
            fd = details.get("final_decision")
            if fd == "malicious_public":
                result = "⚠️ This link is malicious."
                result_type = "danger"
            elif fd == "suspicious_local":
                result = "⚠️ Local/private address. Treat with caution."
                result_type = "warn"
            elif fd == "suspicious_heuristics":
                result = "⚠️ Suspicious heuristics detected."
                result_type = "warn"
            elif fd == "unknown":
                result = "⚠️ Could not verify (API error)."
                result_type = "warn"
            elif fd == "publicly_safe":
                result = "✅ No threats found."
                result_type = "safe"

        elif "password" in request.form:
            pw = request.form.get("password", "")
            if not pw:
                flash("Enter a password.", "danger")
                return redirect(url_for("home"))

            pw_resp = pwned_password_check(pw)
            details = {"password_check": pw_resp}
            if "error" in pw_resp:
                result = "⚠️ Error: " + pw_resp["error"]
                result_type = "warn"
            elif pw_resp.get("pwned"):
                count = pw_resp.get("count", 0)
                result = f"❌ This password was found {count} times in breaches!"
                result_type = "danger"
            else:
                result = "✅ This password was NOT found in breaches."
                result_type = "safe"

        elif "file" in request.files:
            file = request.files["file"]
            if file.filename == "":
                flash("No file selected.", "danger")
                return redirect(url_for("home"))

            upload_path = os.path.join("uploads", file.filename)
            os.makedirs("uploads", exist_ok=True)
            file.save(upload_path)

            file_result = check_file_with_virustotal(upload_path)
            details = {"file_result": file_result}
            if "error" in file_result:
                result = "⚠️ Error: " + file_result["error"]
                result_type = "warn"
            elif "stats" in file_result:
                stats = file_result["stats"]
                if stats["malicious"] > 0:
                    result = f"❌ File flagged malicious by {stats['malicious']} engines!"
                    result_type = "danger"
                else:
                    result = "✅ File not flagged as malicious."
                    result_type = "safe"
            else:
                result = file_result.get("message", "ℹ️ File check complete.")
                result_type = "info"

    return render_template("index.html", result=result, result_type=result_type, details=details)


if __name__ == "__main__":
    print("Starting CyberSafe app...")
    app.run(debug=True)
