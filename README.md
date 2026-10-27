# LLM-Integrated ML Framework for Automated Cyber Threat Detection, Response and Incident Report Generation

Final year project, Sathyabama Institute of Science and Technology (B.Tech - I.T)

**Team:** Sachin S (43120295) and Niresh Kumar S (43120282)
**Guide:** Ms. P. Gopika, M.E., (Ph.D)

---

## What is this project?

When a company gets attacked, a security analyst has to read through a lot of logs, work out what kind of attack it was, and then write a report. This takes hours. We wanted to see if we could automate most of that.

So we built a small pipeline that:

1. takes a network traffic sample,
2. predicts whether it is normal traffic or an attack (and which type) using XGBoost,
3. decides whether to block the source IP based on how confident the model is,
4. asks an LLM (Mistral 7B through the HuggingFace API) to write an incident report,
5. shows everything on a simple Flask dashboard.

## Dataset

We used the **CICIDS2017 (Cleaned & Preprocessed)** version from Kaggle (uploaded by Eric Anacleto Ribeiro).

- 2,520,751 rows and 53 columns
- 7 classes: Normal Traffic, DoS, DDoS, Port Scanning, Brute Force, Web Attacks, Bots
- The file is about 684 MB, so it is **not uploaded here**. Download it from Kaggle and put it in the `data/` folder as `cicids2017_cleaned.csv`.

## How it works

```
Traffic sample -> StandardScaler -> XGBoost -> Decision step -> LLM report -> Dashboard
```

**Decision step (our rule):**
- confidence >= 90% and the attack is not normal traffic -> block the IP
- otherwise -> flag it for manual review

**Severity we assigned:** DDoS and DoS = CRITICAL, Brute Force / Web Attacks / Bots = HIGH, Port Scanning = MEDIUM.

## Results

Trained on 2,016,600 rows and tested on 504,151 rows (80:20 split).

| Metric | Value |
|---|---|
| Accuracy | 99.9% |
| Macro F1 | 0.97 |

The weakest class was **Bots** (recall 0.71), probably because there are only about 1,900 bot samples compared to over 2 million normal ones. Other classes were between 0.97 and 1.00 recall.

## Project structure

```
cybersecurity-project/
├── 1_preprocess.py        # loads the dataset and prints basic info
├── 2_train_model.py       # trains XGBoost and saves model/encoder/scaler
├── 3_block_and_report.py  # runs detection + blocking + report in the terminal
├── 4_app.py               # Flask dashboard (main demo)
├── 5_llm_report.py        # tests the LLM report generation alone
├── templates/
│   └── dashboard.html
├── data/                  # put the CSV here (not in repo)
├── models/                # created after training (not in repo)
└── reports/               # generated reports and blocked IP log
```

## How to run

1. Install the libraries:
   ```
   pip install pandas numpy scikit-learn xgboost flask requests
   ```
2. Download the dataset from Kaggle and place it at `data/cicids2017_cleaned.csv`.
3. Make sure the `models` and `reports` folders exist.
4. Train the model (takes a few minutes):
   ```
   python 2_train_model.py
   ```
5. (Optional) Add your HuggingFace token for LLM reports. In PowerShell:
   ```
   $env:HF_TOKEN="your_token_here"
   ```
   Without a token, the project still runs and uses a template report.
6. Start the dashboard:
   ```
   python 4_app.py
   ```
   Open http://127.0.0.1:5000 and click **Run Attack Simulation**.

Loading the dataset takes around 30 to 60 seconds when the app starts.

## Things to be aware of (limitations)

We want to be honest about what this is and is not:

- The demo uses **sample rows from the dataset**, not live network traffic. Clicking the button simulates traffic arriving.
- The dataset has no IP addresses, so the IPs on the dashboard are **made-up demo IPs**.
- "Blocking" is **simulated**. The IP is written to `reports/blocked_ips.txt`. It does not change the real firewall.
- If the HuggingFace API fails or is rate limited, the code falls back to a fixed template report.
- Our test numbers come from the same dataset the model was trained on (a held-out split), so real-world performance could be lower.

## Future work

- Capture real packets (for example with Scapy) so the system works on live traffic
- Real firewall integration for blocking
- Add SHAP to explain why the model flagged each sample
- Compare XGBoost with Random Forest and SVM properly
- Improve detection of the Bots class

## Base paper

M. A. M. Farzaan, M. C. Ghanem, A. El-Hajjar, D. N. Ratnayake, "AI-Powered System for an Efficient and Effective Cyber Incidents Detection and Response in Cloud Environments," IEEE Transactions on Machine Learning in Communications and Networking, vol. 3, 2025.

## Tech used

Python, Pandas, NumPy, scikit-learn, XGBoost, Flask, HuggingFace Inference API (Mistral 7B), HTML/CSS/JavaScript