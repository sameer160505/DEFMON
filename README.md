# 🛡️ DEFMON – Website Security Monitoring & Automated Response Tool using SIEM & SOAR

A **real-time Security Information and Event Management (SIEM)** and **Security Orchestration, Automation and Response (SOAR)** platform designed to monitor web applications, detect cyber attacks, generate alerts, and automatically respond to security incidents.

---

# 🌐 Overview

DEFMON is a real-time website security monitoring platform developed to strengthen web application security through continuous log analysis, intelligent threat detection, and automated incident response.

The platform collects web server logs from Apache and Nginx, analyzes incoming requests using rule-based and behavioral detection techniques, identifies malicious activities, and automatically executes response playbooks such as IP blocking, alert generation, and incident creation.

Built using **FastAPI**, **React**, **PostgreSQL**, and **Docker**, DEFMON provides a centralized dashboard for Security Operations Center (SOC) analysts to monitor attacks and respond efficiently.

---

# 🚀 Key Features

- 🔍 Real-Time Website Log Monitoring
- 🛡️ SIEM-Based Threat Detection Engine
- 🤖 SOAR Automated Response Playbooks
- ⚡ FastAPI REST API Backend
- 📊 React Dashboard for SOC Monitoring
- 🔐 JWT Authentication & Role-Based Access
- 🚨 SQL Injection Detection
- 🚨 Cross-Site Scripting (XSS) Detection
- 🚨 Brute Force Attack Detection
- 🚨 Directory Traversal Detection
- 🌍 Threat Intelligence Integration
- 🚫 Automatic IP Blocking
- 📋 Incident Management
- 📈 Risk Scoring System
- 📝 Audit Logging
- 🐳 Dockerized Deployment

---

# 🧠 Tech Stack

| Layer | Technologies |
|--------|--------------|
| Frontend | React, Vite, HTML5, CSS3, JavaScript |
| Backend | Python, FastAPI, SQLAlchemy, Uvicorn |
| Database | PostgreSQL |
| Authentication | JWT |
| Containerization | Docker, Docker Compose |
| Migration | Alembic |
| Security | SIEM, SOAR, Threat Intelligence |

---

# 🏗️ System Architecture

```
Apache / Nginx Logs
            │
            ▼
      Log Collection
            │
            ▼
     Log Normalization
            │
            ▼
    SIEM Detection Engine
            │
 ┌──────────┼──────────┐
 │          │          │
 ▼          ▼          ▼
SQLi      XSS      Brute Force
Detection Detection Detection
            │
            ▼
      Threat Intelligence
            │
            ▼
      Alert Generation
            │
            ▼
      SOAR Playbooks
            │
 ┌──────────┼───────────┐
 ▼          ▼           ▼
Block IP  Incident   Notifications
            │
            ▼
      React Dashboard
```

---

# 📂 Project Structure

```
DEFMON
│
├── defmon/
│   ├── api/
│   ├── detection/
│   ├── soar/
│   ├── models/
│   ├── pipeline.py
│   ├── database.py
│   └── main.py
│
├── frontend/
│
├── scripts/
│
├── docker/
│
├── tests/
│
├── alembic/
│
├── data/
│
├── docker-compose.yml
├── requirements.txt
├── config.yaml
└── README.md
```

---

# 🔐 Threat Detection

DEFMON continuously monitors web traffic and detects multiple attack types, including:

- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Brute Force Login Attempts
- Directory Traversal
- High Request Rate
- Web Scanner Detection
- Suspicious User Agents
- Malicious IP Reputation

---

# 🤖 Automated Response (SOAR)

After detecting a malicious activity, DEFMON automatically performs predefined playbooks such as:

- 🚫 Block Malicious IP Address
- 📋 Create Security Incident
- 🚨 Generate Security Alert
- 🔔 Notify Administrator
- 📝 Maintain Audit Logs
- 🌍 Enrich Alerts with Threat Intelligence
- 📊 Assign Risk Score

---

# 📊 Dashboard Features

- 🔐 Secure Login
- 📈 Live Security Dashboard
- 🚨 Alert Monitoring
- 📋 Incident Management
- 🌍 Threat Intelligence Panel
- 📊 Attack Statistics
- 📉 Attack Timeline
- 📝 Log Viewer
- 🚫 Blocked IP Management
- 📄 Report Generation

---

# ⚙️ How It Works

## 📝 Log Collection

- Collects Apache and Nginx access logs
- Receives remote log ingestion through Sender APIs
- Normalizes raw logs into structured events

---

## 🔍 Threat Detection

Each request is analyzed using:

- Rule-Based Detection
- Pattern Matching
- Threshold Analysis
- Behavioral Analysis
- Threat Intelligence Lookup

Detected attacks are classified by severity and assigned a risk score.

---

## 🤖 Automated Response

Once an attack is confirmed, the SOAR engine automatically:

- Blocks attacker IP
- Generates alerts
- Creates incidents
- Records response actions
- Notifies administrators

---

# 🛠️ Installation & Setup

## 1️⃣ Clone Repository

```bash
git clone https://github.com/sameer160505/DEFMON.git

cd DEFMON
```

---

## 2️⃣ Configure Environment

```bash
cp .env.example .env
```

Update your environment variables.

---

## 3️⃣ Start Docker Services

```bash
docker compose up --build -d
```

---

## 4️⃣ Run Database Migration

```bash
docker compose exec defmon-api alembic upgrade head
```

---

## 5️⃣ Create Default Admin

```bash
docker compose exec defmon-api python -m defmon.seed
```

---

## 6️⃣ Access Application

### Frontend

```
http://localhost:13000
```

### Backend API

```
http://localhost:18000
```

### Swagger Documentation

```
http://localhost:18000/docs
```

---

# 📡 API Endpoints

| Method | Endpoint | Description |
|---------|----------|-------------|
| POST | /api/auth/login | User Login |
| GET | /api/alerts | View Alerts |
| GET | /api/incidents | View Incidents |
| GET | /api/logs | Search Logs |
| POST | /api/senders | Create Sender |
| POST | /api/senders/ingest | Remote Log Ingestion |
| GET | /health | Health Check |

---

# 🧪 Running Tests

```bash
pytest
```

or

```bash
make test
```
---

# 🔒 Security Highlights

- JWT Authentication
- Role-Based Access Control
- Real-Time Log Analysis
- Threat Intelligence Integration
- Automated Incident Response
- Risk Scoring
- Secure API Architecture
- Dockerized Deployment

---

# 🌱 Future Enhancements

- 🤖 AI/ML-Based Threat Detection
- 📧 Email & Slack Notifications
- 📱 Mobile Dashboard
- ☁️ Cloud Deployment
- 📊 Splunk & Elastic Stack Integration
- 🔗 MITRE ATT&CK Mapping
- 🌍 Multi-Tenant Support
- 📈 Advanced Threat Analytics

---

# 👨‍💻 Authors

- **K. Inzamam Al Sameer**
- Babakrishnan S
- Regis Theophilus A N
- Yogesh R

**Department of Computer Science and Engineering (Cyber Security)**

**Arunai Engineering College (Autonomous)**

**Anna University, Chennai**

---

# 📚 Academic Project

This project was developed as a **Bachelor of Engineering Final Year Project (B.E. Computer Science and Engineering – Cyber Security)**.

**Project Title:**  
**DEFMON – Website Security Monitoring and Automated Response Tool using SIEM & SOAR**

---

# ⭐ Support

If you found this project useful, consider giving it a ⭐ on GitHub!
