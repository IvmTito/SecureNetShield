from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import joblib
import re
import urllib.parse
import warnings
import sys
import requests
import base64
import socket
from datetime import datetime
import os
warnings.filterwarnings('ignore')

OTX_API_KEY = "89623557ae9771cc5cf15d7e5c75a9acd5b0cebc8664f9893c02e4fbe7beefb3"
VT_API_KEY = "8af304e70ee969955b34b4df768da145e1798080375f58d5865ef31cdc94cd58"
ABUSE_API_KEY = "172bd62f509569e6a5495f4221077c3dc5fba7de5b918594c4227bcff357a006275538ad0ced90b4"

app = Flask(__name__)
CORS(app)

# --- إعدادات النظام ---
print("🛡️ [System] Starting Secure AI Server...")

# 1. تحميل النموذج
try:
    model = joblib.load('phishing_model.pkl')
    print("✅ [System] AI Model Loaded Successfully.")
except:
    print("❌ [System] Error: phishing_model.pkl not found.")
    sys.exit(1)


# 3. تحميل أسماء الأعمدة
try:
    df_train = pd.read_csv('PhishingData.csv')
    df_train.columns = df_train.columns.str.strip()
    feature_names = df_train.columns[1:-1]
    # للتأكد، هنعرف العدد هنا
    total_features_needed = len(feature_names)
    print(f"✅ [System] Feature Mapping Loaded: {total_features_needed} features.")
except Exception as e:
    print(f"❌ [System] Error: {e}")
    sys.exit(1)


def check_otx(domain):

    print(f"🔍 Checking OTX for: {domain}")

    try:
        headers = {
            "X-OTX-API-KEY": OTX_API_KEY
        }

        response = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
            headers=headers,
            timeout=3
        )

        if response.status_code != 200:
            return False, 0

        data = response.json()

        pulse_count = data.get("pulse_info", {}).get("count", 0)

        print(f"OTX Pulse Count = {pulse_count}")

        if pulse_count >= 100:
            return True, pulse_count

        return False, 0

    except Exception as e:
        print(f"OTX Error: {e}")
        return False, 0

def check_virustotal(url):

    print(f"🔍 VirusTotal Checking: {url}")

    try:

        url_id = base64.urlsafe_b64encode(
            url.encode()
        ).decode().strip("=")

        headers = {
            "x-apikey": VT_API_KEY
        }

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=5
        )

        if response.status_code != 200:
            return False, 0

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        total_hits = malicious + suspicious

        print(f"VT Hits = {total_hits}")

        if total_hits >= 5:
            return True, total_hits

        return False, 0

    except Exception as e:
        print(f"VirusTotal Error: {e}")
        return False, 0

def check_abuseipdb(domain):
    try:

        ip = socket.gethostbyname(domain)

        headers = {
            "Key": ABUSE_API_KEY,
            "Accept": "application/json"
        }

        response = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers=headers,
            params={
                "ipAddress": ip,
                "maxAgeInDays": 90
            },
            timeout=5
        )

        if response.status_code != 200:
            return False, 0

        data = response.json()

        score = data["data"]["abuseConfidenceScore"]
        reports = data["data"]["totalReports"]

        print(f"AbuseIPDB IP: {ip}")
        print(f"AbuseIPDB Score: {score}")
        print(f"AbuseIPDB Reports: {reports}")

        if score >= 90 and reports >= 10:
            return True, score

        return False, score

    except Exception as e:
        print(f"AbuseIPDB Error: {e}")
        return False, 0
    
def save_training_sample(
    url,
    domain,
    url_length,
    has_ip,
    has_at,
    has_double_slash,
    has_hyphen,
    subdomain_count,
    otx_hits,
    vt_hits,
    abuse_score,
    source,
    label
):
    try:

        row = pd.DataFrame([{
            "url": url,
            "domain": domain,
            "url_length": url_length,
            "has_ip": has_ip,
            "has_at": has_at,
            "has_double_slash": has_double_slash,
            "has_hyphen": has_hyphen,
            "subdomain_count": subdomain_count,
            "otx_hits": otx_hits,
            "virustotal_hits": vt_hits,
            "abuse_score": abuse_score,
            "source": source,
            "label": label,
            "timestamp": datetime.now()
        }])
        if os.path.exists("SecureNetShield_Dataset_v1.csv"):

            row.to_csv(
                "SecureNetShield_Dataset_v1.csv",
                mode="a",
                header=False,
                index=False
            )

        else:

            row.to_csv(
                "SecureNetShield_Dataset_v1.csv",
                index=False
            )

    except Exception as e:
        print(f"Dataset Save Error: {e}")    
@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    url = data.get('url', '')
    
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        clean_domain = domain.replace('www.', '')

        if url.startswith("chrome-extension://"):
            return jsonify({
                "status": "safe",
                "score": 100,
                "reason": "Internal Extension Page"
            })
# Dataset Cache Lookup

        try:

            dataset_df = pd.read_csv(
                "SecureNetShield_Dataset_v1.csv"
            )

            dataset_df = dataset_df.sort_values("timestamp")
        
            cached = dataset_df[
                dataset_df["domain"].str.lower() == clean_domain
            ]

            if not cached.empty:

                latest = cached.iloc[-1]

                print(f"📚 Dataset Cache Hit: {clean_domain}")

                if latest["label"] == "malicious":

                    return jsonify({
                        "status": "malicious",
                        "score": 100,
                        "reason": "Dataset Cached Malicious"
                    })

                return jsonify({
                    "status": "safe",
                    "score": 100,
                    "reason": "Dataset Cached Safe"
                })

        except Exception as e:
            print(f"Dataset Lookup Error: {e}")

        url_length = len(url)

        has_ip = 1 if re.search(
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',
            domain
        ) else 0

        has_at = 1 if '@' in url else 0

        has_double_slash = 1 if '//' in url[7:] else 0

        has_hyphen = 1 if '-' in domain else 0

        subdomain_count = domain.count('.')

        otx_hits = 0
        vt_hits = 0
        abuse_score = 0
    except:
        return jsonify({"status": "safe", "score": 100, "reason": "Invalid URL"})

    # --- Layer 4: Rules ---
    if '@' in url:
        print("AT RULE TRIGGERED")
        save_training_sample(
            url,
            clean_domain,
            url_length,
            has_ip,
            has_at,
            has_double_slash,
            has_hyphen,
            subdomain_count,
            otx_hits,
            vt_hits,
            abuse_score,
            "rule_at_symbol",
            "malicious"
        )
        print("AT RULE SAVED")
        return jsonify({
            "status": "malicious",
            "score": 100.0,
            "reason": "Critical: '@' Symbol Detected"
        })

    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    if re.search(ip_pattern, domain):

        save_training_sample(
            url,
            clean_domain,
            url_length,
            has_ip,
            has_at,
            has_double_slash,
            has_hyphen,
            subdomain_count,
            otx_hits,
            vt_hits,
            abuse_score,
            "rule_ip",
            "malicious"
        )

        return jsonify({
            "status": "malicious",
            "score": 95.0,
            "reason": "Direct IP Address Detected"
        })
    
    # --- Layer 2: OTX ---

    otx_found, pulse_count = check_otx(clean_domain)

    otx_hits = pulse_count

    print(f"OTX Hits: {otx_hits}")

    # --- Layer 3.5: VirusTotal ---
    vt_found, vt_hits = check_virustotal(url)

    # OTX + VirusTotal 

    if pulse_count >= 200 and vt_hits >= 5:

        return jsonify({
            "status": "malicious",
            "score": 99.0,
            "reason": f"OTX ({pulse_count}) + VirusTotal ({vt_hits})"
        })
    
    if vt_found:

        save_training_sample(
            url,
            clean_domain,
            url_length,
            has_ip,
            has_at,
            has_double_slash,
            has_hyphen,
            subdomain_count,
            otx_hits,
            vt_hits,
            abuse_score,
            "virustotal",
            "malicious"
        )

        return jsonify({
            "status": "malicious",
            "score": 95.0,
            "reason": f"VirusTotal Match ({vt_hits} detections)"
        })
        # --- Layer 3.7: AbuseIPDB ---

    abuse_found, abuse_score = check_abuseipdb(clean_domain)

    if abuse_found:

        save_training_sample(
            url,
            clean_domain,
            url_length,
            has_ip,
            has_at,
            has_double_slash,
            has_hyphen,
            subdomain_count,
            0,
            0,
            abuse_score,
            "abuseipdb",
            "malicious"
        )

        return jsonify({
            "status": "malicious",
            "score": float(abuse_score),
            "reason": f"AbuseIPDB Reputation Score ({abuse_score})"
        })


    # --- Layer 5: AI ---
    print("ENTERING AI")
    try:
        features = []
        # استخراج 7 خصائص يدوياً
        features.append(-1 if re.search(ip_pattern, domain) else 1) # 1. IP
        
        length = len(url)
        if length < 54: features.append(1) # 2. Length
        elif 54 <= length <= 75: features.append(0)
        else: features.append(-1)
        
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 't.co']
        features.append(-1 if any(s in url for s in shorteners) else 1) # 3. Shortener
        features.append(-1 if '@' in url else 1) # 4. @
        features.append(-1 if '//' in url[7:] else 1) # 5. //
        features.append(-1 if '-' in domain else 1) # 6. -
        
        dots = domain.count('.')
        if dots == 1: features.append(1) # 7. Subdomain
        elif dots == 2: features.append(0)
        else: features.append(-1)
        
        # --- التصحيح الجوهري ---
        # المحتاجين 30 عامود، معانا 7. فلازم نضيف 23 (مش 22)
        remaining_features_needed = total_features_needed - 7
        for _ in range(remaining_features_needed):
            features.append(0) 

        input_data = pd.DataFrame([features], columns=feature_names)
        print("RUNNING MODEL")
        prediction = model.predict(input_data.values)
        proba = model.predict_proba(input_data.values)
        print("FEATURES:", features)
        print("PREDICTION:", prediction[0])
        print("PROBA:", proba)
        if prediction[0] == -1:
            save_training_sample(
                url,
                clean_domain,
                url_length,
                has_ip,
                has_at,
                has_double_slash,
                has_hyphen,
                subdomain_count,
                0,
                0,
                abuse_score,
                "ai",
                "malicious"
            )
            return jsonify({"status": "malicious", "score": proba[0][0]*100, "reason": "AI Detected Phishing Pattern"})
        else:
            save_training_sample(
                url,
                clean_domain,
                url_length,
                has_ip,
                has_at,
                has_double_slash,
                has_hyphen,
                subdomain_count,
                0,
                0,
                abuse_score,
                "ai",
                "safe"
            )
            return jsonify({"status": "safe", "score": proba[0][1]*100, "reason": "AI Detected Safe Pattern"})
            
    except Exception as e:
        print(f"⚠️ AI Error: {e}")
        return jsonify({"status": "safe", "score": 50.0, "reason": "AI Analysis Failed (Safe Default)"})

if __name__ == '__main__':
    print("🚀 Server is LIVE on http://127.0.0.1:5000")
    app.run(port=5000, debug=True)