

### 🔴 Cyber Security Track
| الاسم | الفولدر | المسؤولية |
|---|---|---|
| أحمد | Ahmed_Cyber | WAF Core Engine + 15 OWASP Detection Rules |
| تحسين | Tahseen_Cyber | Rate Limiting + IP Firewall + Blacklist |
| يوسف | Yousef_Cyber | VirusTotal API + Telegram Alerts + Logs |

### 🤖 AI Track
| الاسم | الفولدر | المسؤولية |
|---|---|---|
| منه | Mona_AI | ML Model Training (TF-IDF + Logistic Regression) |
| نوران | Noran_AI | Dataset + Sanity Check + False Positive Reduction |

### ⚙️ Backend Track
| الاسم | الفولدر | المسؤولية |
|---|---|---|
| ساندي | Sandy_Backend | Flask Routes + Auth + Session Management |
| معاذ | Moaz_Backend | Database (SQLite) + Settings + Export Logs |

### 🎨 Frontend Track
| الاسم | الفولدر | المسؤولية |
|---|---|---|
| شهد | Shahd_Frontend | Dashboard + WAF Test Page + Base Template |
| ملك | Malak_Frontend | Login + All Pages + CSS + JS |

---

## 📁 هيكل الفولدرات

```
WAF_Team_Project/
│
├── Ahmed_Cyber/
│   ├── README.md
│   ├── app.py
│   └── my_code/
│       └── detection_engine.py     ← الـ 15 OWASP rules + before_request
│
├── Tahseen_Cyber/
│   ├── README.md
│   ├── blacklist.txt
│   ├── trusted_ips.txt
│   ├── attacker_log.csv
│   └── my_code/
│       └── rate_limit_firewall.py  ← Config + block/unblock + rate limit
│
├── Yousef_Cyber/
│   ├── README.md
│   ├── security.log
│   ├── attack_log.csv
│   └── my_code/
│       └── vt_telegram_logs.py     ← VirusTotal + Telegram + log routes
│
├── Mona_AI/
│   ├── README.md
│   ├── waf_model.sav
│   └── my_code/
│       └── model_training.py       ← Pipeline + TF-IDF + LR + evaluation
│
├── Noran_AI/
│   ├── README.md
│   ├── attack_log.csv
│   └── my_code/
│       └── dataset_sanity_check.py ← Training data + sanity check logic
│
├── Sandy_Backend/
│   ├── README.md
│   ├── app.py
│   ├── users.db
│   └── my_code/
│       └── auth_routes.py          ← login/logout/session/decorators
│
├── Moaz_Backend/
│   ├── README.md
│   ├── users.db
│   └── my_code/
│       └── db_settings_export.py   ← init_db + settings + export + delete
│
├── Shahd_Frontend/
│   ├── README.md
│   └── templates/
│       ├── base.html
│       ├── dashboard.html
│       └── waf_test.html
│
└── Malak_Frontend/
    ├── README.md
    ├── templates/
    │   ├── login.html
    │   ├── blacklist.html
    │   ├── trusted.html
    │   ├── check_ip.html
    │   ├── settings.html
    │   └── manage_users.html
    └── static/
        ├── style.css
        ├── main.js
        └── logo.png
```

---


