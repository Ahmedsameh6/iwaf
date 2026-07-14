# IWAF — WAF Attack Detection & Prevention System

A full Web Application Firewall (WAF) that combines a machine learning classifier with a signature-based detection engine to identify and block malicious HTTP traffic in real time — including SQLi, XSS, SSTI, LFI, RCE/Command Injection, NoSQL Injection, CRLF Injection, XXE, SSRF, Log4Shell, and more — all managed through a custom admin dashboard.

## Overview

IWAF inspects every incoming request through two layers before it reaches the application:

1. **ML Classifier** — a character-level TF-IDF vectorizer combined with a Logistic Regression model, trained on a merged and cleaned dataset covering multiple attack types, classifies each payload in real time.
2. **Signature Engine** — 15 regex-based detection rules mapped to the OWASP Top 10 and related CVE-class attacks, scanning every request parameter, form field, and raw body.

An attack is blocked if it matches **either** layer, and the offending IP is automatically logged, rate-limited, and blacklisted, with optional VirusTotal reputation checks and Telegram alerts.

## My Role — Ahmed, Team Lead (Cyber Security Track)

I led the Cyber Security track and the integration of the whole team's work. My core responsibilities:

- **WAF Core Engine** — designed and built the central `before_request` pipeline: the single choke point every request passes through (size/header checks, rate limiting, IP trust/block checks, ML + signature scanning) before reaching any route.
- **15 OWASP Detection Rules** — authored and tuned the full signature set (regex rules) mapped to the OWASP Top 10 and beyond (see table below).
- **Team integration** — merged each track's independent module (AI, backend, frontend, cyber security) into one consistent Flask application with a shared data model and request flow.

## Detection Coverage

| # | Detection | OWASP / Reference |
|---|-----------|---------------------|
| 1 | SQL Injection | A03 |
| 2 | XSS (Cross-Site Scripting) | A03 |
| 3 | Command Injection | A03 |
| 4 | LFI / Path Traversal | A01 |
| 5 | CRLF / Header Injection | A03 |
| 6 | SSTI (Server-Side Template Injection) | A03 |
| 7 | XXE (XML External Entity) | A05 |
| 8 | SSRF (Server-Side Request Forgery) | A10 |
| 9 | Open Redirect | A01 |
| 10 | NoSQL Injection | A03 |
| 11 | LDAP Injection | A03 |
| 12 | HTTP Request Smuggling | A05 |
| 13 | Log4Shell (CVE-2021-44228) | — |
| 14 | Insecure Deserialization | A08 |
| 15 | XML / XPath Injection | A03 |

## Features

- Multi-class classification of common web attack payloads via ML
- Custom-built admin dashboard: live stats, blacklist/trusted IP management, attack/security logs
- Rate limiting, concurrent-request throttling, oversized payload/header protection
- VirusTotal integration for automatic reputation-based IP blocking
- Real-time Telegram alerts on every blocked attack
- User authentication with roles (`admin` / `user`), login-attempt throttling
- Built-in WAF test console (`/waf-test`) to try payloads and see which layer/rule caught them
- CSV export for attack/attacker/security logs
- Merged and cleaned training dataset pipeline (EDA + preprocessing scripts)

## Tech Stack

- **Backend:** Python, Flask
- **Machine Learning:** scikit-learn (TF-IDF + Logistic Regression), pandas, numpy, joblib
- **Database:** SQLite
- **Frontend:** Jinja2 templates, HTML/CSS/JS
- **Integrations:** VirusTotal API, Telegram Bot API
- **EDA/Visualization:** matplotlib, seaborn

## How It Works

1. Individual attack-type datasets (SQLi, XSS, SSTI, LFI, Shell, NoSQL, CRLF) are merged and cleaned.
2. Labels are normalized across sources.
3. A TF-IDF + Logistic Regression pipeline is trained on the merged dataset and evaluated (accuracy, precision, recall, F1-score, confusion matrix).
4. The trained model (`waf_model.sav`) is loaded by the Flask app and used for real-time payload classification alongside the signature engine.

## Team

This is a graduation project built by a multi-track team. Each member owned a self-contained module.

### 🔴 Cyber Security Track
| Name | Responsibility |
|------|-----------------|
| **Ahmed** *(Team Lead)* | WAF Core Engine + 15 OWASP Detection Rules |
| Tahseen | Rate Limiting + IP Firewall + Blacklist |
| Yousef | VirusTotal API + Telegram Alerts + Logs |

### 🤖 AI Track
| Name | Responsibility |
|------|-----------------|
| Menna Elzayat | ML Model Training (TF-IDF + Logistic Regression) |
| Noran | Dataset + Sanity Check + False Positive Reduction |

### ⚙️ Backend Track
| Name | Responsibility |
|------|-----------------|
| Sandy | Flask Routes + Auth + Session Management |
| Moaz | Database (SQLite) + Settings + Export Logs |

### 🎨 Frontend Track
| Name | Responsibility |
|------|-----------------|
| Shahd | Dashboard + WAF Test Page + Base Template |
| Malak | Login + All Pages + CSS + JS |

## Project Structure

```
IWAF/
├── app.py                 # Core Flask app: request pipeline, detection engine, routes
├── waf_model.sav          # Trained ML model (TF-IDF + Logistic Regression)
├── requirements.txt
├── users.db               # SQLite database (users/roles)
├── templates/             # Dashboard, login, settings, logs, user management pages
├── static/                # CSS/JS/assets
├── blacklist.txt          # Persisted blocked IPs
├── trusted_ips.txt        # Persisted trusted IPs
├── attack_log.csv         # Structured attack event log
├── attacker_log.csv       # Attacker/IP summary log
├── security.log           # Application security log
└── LICENSE
```

## Getting Started

### Prerequisites
- Python 3.10+

### Installation

```bash
git clone https://github.com/Ahmedsameh6/iwaf.git
cd iwaf
pip install -r requirements.txt
```

### Configuration

Before running in production, set the following as environment variables instead of relying on the defaults in `app.py`:

```bash
export IWAF_SECRET_KEY="your-secret-key"
export VT_API_KEY="your-virustotal-api-key"
export TELEGRAM_BOT_TOKEN="your-telegram-bot-token"
export TELEGRAM_CHAT_ID="your-telegram-chat-id"
```

### Run

```bash
python app.py
```

The app runs on `http://0.0.0.0:5000` by default. Log in with the default admin account (`admin` / `admin123`) and **change the password immediately** after first login.

## Security Note

> ⚠️ This repository currently has API keys/tokens hardcoded as default fallback values inside `app.py`, and a default admin password. Rotate those credentials, move all secrets to environment variables, and change the default admin password before any public/production deployment.

## Attribution

The ML classification approach (character n-gram TF-IDF + Logistic Regression pipeline) is based on and adapted from an existing WAF payload-classification approach. The team modified the training pipeline, retrained the model on its own merged/cleaned dataset, and built a completely custom UI from scratch. If you are the original author of the base approach this project was adapted from and would like explicit credit/linking here, please open an issue.

## Disclaimer

This project is intended for educational and defensive security research purposes only. Do not use it to attack systems you do not have explicit permission to test.

## License

This project is licensed under the MIT License — see the [LICENSE](./LICENSE) file for details.
