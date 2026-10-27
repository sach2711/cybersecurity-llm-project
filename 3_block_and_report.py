# step 3 - detect attack, block ip, generate report
# this uses our saved model to predict and take action

import pickle
import numpy as np
import pandas as pd
from datetime import datetime
import os
import warnings
warnings.filterwarnings('ignore')

# load saved model files
print("loading saved model...")
with open('models/model.pkl', 'rb') as f:
    model = pickle.load(f)

with open('models/encoder.pkl', 'rb') as f:
    encoder = pickle.load(f)

with open('models/scaler.pkl', 'rb') as f:
    scaler = pickle.load(f)

print("model loaded successfully")

# load dataset to get test samples
print("loading dataset for testing...")
data = pd.read_csv('data/cicids2017_cleaned.csv')
target_col = 'Attack Type'
x = data.drop(target_col, axis=1)
y = data[target_col]

# scale features
x_scaled = scaler.transform(x)

# severity levels for each attack
severity_map = {
    'Normal Traffic' : 'NONE',
    'DDoS'           : 'CRITICAL',
    'DoS'            : 'CRITICAL',
    'Brute Force'    : 'HIGH',
    'Port Scanning'  : 'MEDIUM',
    'Web Attacks'    : 'HIGH',
    'Bots'           : 'HIGH',
}

def block_ip(ip):
    # simulate blocking ip address
    print(f"blocking ip : {ip}")
    log = f"BLOCKED {ip} at {datetime.now()}"
    with open('reports/blocked_ips.txt', 'a') as f:
        f.write(log + '\n')
    return True

def generate_report(attack, confidence, severity, ip, blocked):
    # create incident report text
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ref = datetime.now().strftime("INC-%Y%m%d-%H%M%S")

    if blocked:
        action = f"source ip {ip} was automatically blocked"
        status = "RESOLVED - IP Blocked Automatically"
    else:
        action = "flagged for manual review by security team"
        status = "OPEN - Awaiting Manual Review"

    report = f"""
============================================
CYBERSECURITY INCIDENT REPORT
============================================
report id  : {ref}
date time  : {now}
severity   : {severity}

1. INCIDENT SUMMARY
a {attack} attack was detected from ip {ip}
with {confidence}% confidence at {now}

2. ATTACK DETAILS
attack type  : {attack}
source ip    : {ip}
confidence   : {confidence}%
severity     : {severity}

3. IMPACT ASSESSMENT
this is a {severity} severity incident
{'immediate action required' if severity == 'CRITICAL'
 else 'prompt attention needed'}

4. ACTION TAKEN
{action}

5. RECOMMENDED STEPS
- check firewall logs for more suspicious activity
- verify no other ips involved in attack
- update threat intelligence with this ip
- inform management team about incident

6. STATUS
{status}
============================================
"""
    return report

def analyze_sample(index, source_ip):
    print(f"\n{'='*45}")
    print(f"analyzing traffic sample {index}")
    print(f"source ip : {source_ip}")
    print(f"{'='*45}")

    # get one sample
    sample = x_scaled[index].reshape(1, -1)

    # predict
    pred = model.predict(sample)[0]
    proba = model.predict_proba(sample)[0]
    confidence = round(float(max(proba)) * 100, 2)
    attack_type = encoder.inverse_transform([pred])[0]
    severity = severity_map.get(attack_type, 'MEDIUM')

    print(f"attack detected : {attack_type}")
    print(f"confidence      : {confidence}%")
    print(f"severity        : {severity}")

    # decide action
    blocked = False
    if attack_type == 'Normal Traffic':
        print("traffic is normal - no action needed")
    elif confidence >= 90 and severity in ['CRITICAL', 'HIGH']:
        print("high confidence threat - auto blocking...")
        blocked = block_ip(source_ip)
        print(f"ip {source_ip} blocked successfully")
    elif confidence >= 70:
        print("medium confidence - flagging for review")
    else:
        print("low confidence - logging only")

    # generate report
    report = generate_report(
        attack_type, confidence,
        severity, source_ip, blocked
    )

    # save report
    filename = f"reports/incident_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    with open(filename, 'w') as f:
        f.write(report)

    print(f"\nreport saved : {filename}")
    print(report)

    return attack_type, confidence, severity, blocked

# test with different samples
# find actual attack rows for testing
print("finding attack samples...")
attack_rows = data[data[target_col] != 'Normal Traffic']
ddos_idx = data[data[target_col] == 'DDoS'].index[0]
dos_idx = data[data[target_col] == 'DoS'].index[0]
bf_idx = data[data[target_col] == 'Brute Force'].index[0]
ps_idx = data[data[target_col] == 'Port Scanning'].index[0]
normal_idx = data[data[target_col] == 'Normal Traffic'].index[0]

test_cases = [
    (ddos_idx, "192.168.1.101"),
    (dos_idx,  "10.0.0.25"),
    (bf_idx,   "172.16.5.88"),
    (ps_idx,   "192.168.2.200"),
    (normal_idx,"10.10.1.45"),
]

results = []
for idx, ip in test_cases:
    attack, conf, sev, blocked = analyze_sample(idx, ip)
    results.append({
        'ip'        : ip,
        'attack'    : attack,
        'confidence': conf,
        'severity'  : sev,
        'blocked'   : blocked
    })

# show summary
print("\n===== SUMMARY OF ALL DETECTIONS =====")
for r in results:
    status = "BLOCKED" if r['blocked'] else "FLAGGED/NORMAL"
    print(f"{r['ip']:18} | {r['attack']:15} | "
          f"{r['confidence']:5}% | {status}")

print("\ndone with step 3!")
print("check reports folder for generated reports")