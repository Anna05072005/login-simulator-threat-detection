# Login Activity Simulator & Threat Detection System

## Overview
This project simulates authentication activity in a corporate environment and applies SQL-based detection rules to identify suspicious behavior such as brute-force attacks, password spraying, and potential account compromise.

A Python simulator generates dynamic users, devices, IP addresses, and login events, which are stored in a SQLite database. Detection logic is implemented entirely in SQL and executed by a separate detection runner, mimicking a simplified SIEM-style security analytics pipeline.

The objective is to demonstrate an end-to-end security analytics workflow including data simulation, storage, aggregation, and rule-based threat detection.

---

## Project Structure
login-simulator-siem/
├── data/
│ └── siem.db # generated locally (not committed)
├── src/
│ ├── simulate.py # generates auth events
│ └── detect.py # runs SQL detections and stores alerts
├── schema.sql # DB schema (tables + indexes)
├── detections.sql # SQL detection rules
├── requirements.txt
└── README.md


Note: `data/siem.db` is generated locally and ignored via `.gitignore`.

---

## Methodology

### Simulation
Authentication telemetry is generated using Python, including:
- Users with departments and roles
- Devices with operating systems and browsers
- IP addresses and geographic locations
- Successful and failed login attempts

Events are written to SQLite in the `auth_events` table. Suspicious behavior is injected probabilistically to simulate attack scenarios such as credential stuffing, brute force, and password spraying.

### Detection
Detection logic is implemented entirely in SQL (`detections.sql`) and executed by `detect.py`.

Current rules aggregate authentication failures over a rolling **10-minute window** and generate alerts for:
- Brute force from a single IP address
- Account under attack (multiple failed attempts for one user)
- Password spraying (one IP targeting many users)
- New device login (successful login from an unseen device for a user)

Each alert includes timestamp, severity, type, entity (user/IP), and a short explanation. Results are stored in the `alerts` table.

---

## Database Schema
Main tables:
- `users` — employee accounts and roles
- `devices` — registered devices (OS and browser)
- `auth_events` — authentication activity (timestamp, user, IP, device, location, success/failure)
- `alerts` — detection results with severity and investigation context

Indexes are applied to authentication timestamps and commonly filtered fields for efficient detection queries.

---

## How to Run

### 0) Setup
```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
1) Initialize schema (first run or after deleting DB)
python src/detect.py --db data/siem.db --init-schema
2) Start the simulator
Run for 60 seconds:

python src/simulate.py --duration 60
Or run indefinitely (stop with Ctrl+C):

python src/simulate.py
3) Run detections
python src/detect.py --db data/siem.db
Recent alerts will be printed to the terminal and stored in the alerts table.

Technologies
Python
SQLite
SQL
(Standard libraries commonly used: sqlite3, argparse, random, datetime)

Author
Anna Cherkashina
BSc Data Science, Simon Fraser University

