# file 4 - flask web dashboard with llm integration

from flask import Flask, render_template, jsonify
import pickle
import pandas as pd
import numpy as np
import os
import requests
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

app = Flask(__name__)

# your huggingface token - paste yours here
HF_TOKEN = os.getenv("HF_TOKEN", "")
API_URL  = ("https://api-inference.huggingface.co/"
            "models/mistralai/Mistral-7B-Instruct-v0.2")

# load saved model
print("loading model...")
with open('models/model.pkl', 'rb') as f:
    model = pickle.load(f)
with open('models/encoder.pkl', 'rb') as f:
    encoder = pickle.load(f)
with open('models/scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)
print("model loaded")

# load dataset
print("loading dataset...")
data = pd.read_csv('data/cicids2017_cleaned.csv')
target_col = 'Attack Type'
x = data.drop(target_col, axis=1)
y = data[target_col]
x_scaled = scaler.transform(x)
print("dataset ready")

# severity mapping
severity_map = {
    'Normal Traffic' : 'NONE',
    'DDoS'           : 'CRITICAL',
    'DoS'            : 'CRITICAL',
    'Brute Force'    : 'HIGH',
    'Port Scanning'  : 'MEDIUM',
    'Web Attacks'    : 'HIGH',
    'Bots'           : 'HIGH',
}

# store detections in memory
detections = []

def generate_llm_report(attack_type, confidence,
                         severity, source_ip, blocked):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ref = datetime.now().strftime("INC-%Y%m%d-%H%M%S")

    action = (f"Source IP {source_ip} automatically blocked."
              if blocked else
              "Traffic flagged for manual review.")

    # send to llm
    prompt = (f"[INST] You are a cybersecurity analyst. "
              f"Write a short professional incident report for: "
              f"Attack: {attack_type}, Severity: {severity}, "
              f"Source IP: {source_ip}, "
              f"Confidence: {confidence}%, "
              f"Time: {now}, Action: {action}. "
              f"Include these sections: "
              f"1.Executive Summary "
              f"2.Attack Details "
              f"3.Severity Assessment "
              f"4.Action Taken "
              f"5.Recommended Steps "
              f"6.Status. "
              f"Keep under 200 words. [/INST]")

    headers = {
        "Authorization": f"Bearer {HF_TOKEN}",
        "Content-Type" : "application/json"
    }
    payload = {
        "inputs": prompt,
        "parameters": {
            "max_new_tokens"  : 350,
            "temperature"     : 0.3,
            "return_full_text": False
        }
    }

    try:
        response = requests.post(
            API_URL,
            headers=headers,
            json=payload,
            timeout=30
        )
        if response.status_code == 200:
            result = response.json()
            report = result[0].get('generated_text', '')
            if len(report) > 50:
                print(f"llm report generated for {attack_type}")
                return report
        else:
            print(f"llm api status: {response.status_code}")
    except Exception as e:
        print(f"llm error: {e}")

    # fallback template if llm fails
    print("using template report...")
    return f"""CYBERSECURITY INCIDENT REPORT (AI-Generated)
=============================================
Report ID : {ref}
Time      : {now}
Severity  : {severity}

1. EXECUTIVE SUMMARY
A {attack_type} attack was detected from source
IP {source_ip} with {confidence}% confidence.
{"Immediate automated response was triggered."
 if blocked else
 "The incident has been flagged for review."}

2. ATTACK DETAILS
Attack Type : {attack_type}
Source IP   : {source_ip}
Confidence  : {confidence}%
Severity    : {severity}
Detected At : {now}

3. SEVERITY ASSESSMENT
This is a {severity} severity incident.
{"Immediate action was required and taken."
 if severity in ["CRITICAL", "HIGH"] else
 "Situation is under monitoring."}

4. ACTION TAKEN
{action}

5. RECOMMENDED STEPS
- Review all firewall logs for related activity
- Check for coordinated attacks from other IPs
- Update threat intelligence with this indicator
- Brief management on incident status

6. STATUS
{"RESOLVED - IP Blocked Automatically"
 if blocked else
 "OPEN - Awaiting Human Review"}
============================================="""

def analyze_traffic(index, source_ip):
    sample = x_scaled[index].reshape(1, -1)
    pred   = model.predict(sample)[0]
    proba  = model.predict_proba(sample)[0]
    confidence  = round(float(max(proba)) * 100, 2)
    attack_type = encoder.inverse_transform([pred])[0]
    severity    = severity_map.get(attack_type, 'MEDIUM')

    blocked = False
    if attack_type != 'Normal Traffic' and confidence >= 90:
        blocked = True
        with open('reports/blocked_ips.txt', 'a',
                  encoding='utf-8') as f:
            f.write(f"BLOCKED {source_ip} - "
                    f"{attack_type} - {datetime.now()}\n")

    # generate report using llm
    report = generate_llm_report(
        attack_type, confidence,
        severity, source_ip, blocked
    )

    # save report to file
    filename = (f"reports/incident_"
                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                f".txt")
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(report)

    result = {
        'id'        : datetime.now().strftime("INC-%Y%m%d-%H%M%S"),
        'time'      : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'ip'        : source_ip,
        'attack'    : attack_type,
        'confidence': confidence,
        'severity'  : severity,
        'blocked'   : blocked,
        'report'    : report
    }
    detections.append(result)
    return result

# routes
@app.route('/')
def home():
    return render_template('dashboard.html')

@app.route('/api/simulate')
def simulate():
    global detections
    detections = []  # reset on each simulation

    ddos_idx = data[data[target_col]=='DDoS'].index[0]
    dos_idx  = data[data[target_col]=='DoS'].index[0]
    bf_idx   = data[data[target_col]=='Brute Force'].index[0]
    ps_idx   = data[data[target_col]=='Port Scanning'].index[0]
    web_idx  = data[data[target_col]=='Web Attacks'].index[0]
    norm_idx = data[data[target_col]=='Normal Traffic'].index[0]

    test_cases = [
        (ddos_idx, "192.168.1.101"),
        (dos_idx,  "10.0.0.25"),
        (bf_idx,   "172.16.5.88"),
        (ps_idx,   "192.168.2.200"),
        (web_idx,  "10.10.1.45"),
        (norm_idx, "192.168.0.1"),
    ]

    results = []
    for idx, ip in test_cases:
        r = analyze_traffic(idx, ip)
        results.append(r)

    return jsonify(results)

@app.route('/api/detections')
def get_detections():
    return jsonify(detections)

@app.route('/api/stats')
def get_stats():
    total   = len(detections)
    blocked = sum(1 for d in detections if d['blocked'])
    attacks = sum(1 for d in detections
                  if d['attack'] != 'Normal Traffic')
    normal  = total - attacks

    attack_types = {}
    for d in detections:
        t = d['attack']
        attack_types[t] = attack_types.get(t, 0) + 1

    return jsonify({
        'total'       : total,
        'blocked'     : blocked,
        'attacks'     : attacks,
        'normal'      : normal,
        'attack_types': attack_types
    })

if __name__ == '__main__':
    os.makedirs('reports', exist_ok=True)
    print("\ndashboard running!")
    print("open browser: http://127.0.0.1:5000")
    app.run(debug=True)