# file 5 - llm report generator
# uses huggingface api to write professional reports

import requests
import json
import os
from datetime import datetime
# paste your huggingface token here
HF_TOKEN = os.getenv("HF_TOKEN", "")

# api url - using mistral model
API_URL = ("https://api-inference.huggingface.co/"
           "models/mistralai/Mistral-7B-Instruct-v0.2")

def generate_llm_report(attack_type, confidence,
                         severity, source_ip, blocked):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ref = datetime.now().strftime("INC-%Y%m%d-%H%M%S")

    action = (f"Source IP {source_ip} was automatically "
              f"blocked by the system."
              if blocked else
              f"Traffic from {source_ip} flagged "
              f"for manual review.")

    # prompt we send to llm
    prompt = f"""[INST] You are a professional cybersecurity analyst working in a Security Operations Center.

Write a formal cybersecurity incident report based on this data:
- Attack Type: {attack_type}
- Confidence: {confidence}%
- Severity: {severity}
- Source IP: {source_ip}
- Detection Time: {now}
- Action Taken: {action}

Write the report with exactly these sections:
1. EXECUTIVE SUMMARY (2 sentences)
2. ATTACK DETAILS (technical description)
3. SEVERITY ASSESSMENT (business impact)
4. ACTION TAKEN (what system did automatically)
5. RECOMMENDED NEXT STEPS (3 bullet points)
6. STATUS (resolved or open)

Keep it professional, under 250 words. [/INST]"""

    headers = {
        "Authorization": f"Bearer {HF_TOKEN}",
        "Content-Type": "application/json"
    }

    payload = {
        "inputs": prompt,
        "parameters": {
            "max_new_tokens": 400,
            "temperature"   : 0.3,
            "return_full_text": False
        }
    }

    print(f"sending to llm api...")
    print(f"attack: {attack_type} | severity: {severity}")

    try:
        response = requests.post(
            API_URL,
            headers=headers,
            json=payload,
            timeout=60
        )

        if response.status_code == 200:
            result = response.json()
            if isinstance(result, list):
                report_text = result[0].get(
                    'generated_text', '')
            else:
                report_text = result.get(
                    'generated_text', '')

            print("llm report generated successfully!")
            return report_text

        elif response.status_code == 503:
            print("model loading, using template report...")
            return generate_template(
                attack_type, confidence,
                severity, source_ip,
                blocked, now, ref)

        else:
            print(f"api error {response.status_code}")
            print(f"response: {response.text[:200]}")
            return generate_template(
                attack_type, confidence,
                severity, source_ip,
                blocked, now, ref)

    except Exception as e:
        print(f"error: {e}")
        return generate_template(
            attack_type, confidence,
            severity, source_ip,
            blocked, now, ref)

def generate_template(attack_type, confidence,
                       severity, source_ip,
                       blocked, now, ref):
    # backup template if api fails
    return f"""
CYBERSECURITY INCIDENT REPORT (AI-Generated)
=============================================
Report ID  : {ref}
Date/Time  : {now}
Severity   : {severity}

1. EXECUTIVE SUMMARY
A {attack_type} attack was detected from source IP
{source_ip} with {confidence}% confidence level.
{'Immediate automated response was triggered.' 
 if blocked else 
 'The incident has been flagged for review.'}

2. ATTACK DETAILS
Attack Type  : {attack_type}
Source IP    : {source_ip}
Confidence   : {confidence}%
Severity     : {severity}
Detected At  : {now}

3. SEVERITY ASSESSMENT
This is a {severity} severity incident.
{'Immediate action was required and taken.' 
 if severity in ['CRITICAL','HIGH'] else 
 'Situation is under monitoring.'}

4. ACTION TAKEN
{'Source IP ' + source_ip + ' was automatically '
 'blocked by the defense system.' 
 if blocked else 
 'Traffic flagged for manual security review.'}

5. RECOMMENDED NEXT STEPS
• Review all firewall logs for related activity
• Check for coordinated attacks from other IPs
• Update threat intelligence with this indicator
• Brief management on incident status

6. STATUS
{'✅ RESOLVED — IP Blocked Automatically' 
 if blocked else 
 '🔴 OPEN — Awaiting Human Review'}
=============================================
"""

# test it
if __name__ == "__main__":
    print("="*50)
    print("testing llm report generation...")
    print("="*50)

    # test with ddos attack
    report = generate_llm_report(
        attack_type = "DDoS",
        confidence  = 99.99,
        severity    = "CRITICAL",
        source_ip   = "192.168.1.101",
        blocked     = True
    )

    print("\n" + "="*50)
    print("GENERATED REPORT:")
    print("="*50)
    print(report)

    # save report
    filename = (f"reports/llm_report_"
                f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(report)
    print(f"\nreport saved: {filename}")
    print("\ndone with file 5!")
