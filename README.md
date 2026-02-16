# Login Activity Simulator & Threat Detection System

## Overview

This project builds a security analytics pipeline that simulates corporate authentication activity and detects suspicious behavior using SQL-based detection rules.

The goal is to demonstrate an end-to-end cybersecurity data workflow including event simulation, database design, rule-based detection, and alert generation.

---

## Dataset

- Source: Synthetic authentication telemetry generated in Python  
- Database file: `data/siem.db` (generated locally)  
- Main table: `auth_events`

The simulator dynamically creates:

- Users with departments and roles
- Devices with operating systems and browsers
- IP addresses and geographic locations
- Successful and failed login attempts

Suspicious activity is probabilistically injected to simulate realistic attack scenarios.

---

## Project Structure

```

login-simulator-siem/
├── data/
│ └── siem.db
├── src/
│ ├── simulate.py
│ └── detect.py
├── schema.sql
├── detections.sql
├── requirements.txt
└── README.md


---

## Methodology

- Authentication telemetry simulation using Python  
- SQLite database schema with indexed tables  
- SQL-based threat detection rules  
- Aggregation over rolling 10-minute windows  
- Alert generation with severity levels  

Detection rules identify:

- Brute-force attacks from a single IP  
- Account under attack (multiple failed attempts)  
- Password spraying (one IP targeting many users)  
- New device login activity  

Alerts are stored in the `alerts` table with timestamp, severity, entity, and explanation.

---

## Results 

The system successfully generates realistic authentication telemetry and identifies anomalous patterns using rule-based SQL detection.

Alerts are printed to the terminal and persisted in the database for investigation and further analysis.

---

## How to Run

```bash
python -m venv .venv
pip install -r requirements.txt

python src/detect.py --db data/siem.db --init-schema
python src/simulate.py --duration 60
python src/detect.py --db data/siem.db
```

---

## Technologies
Python
SQLite
SQL
argparse
sqlite3
datetime

---

## Author
Anna Cherkashina
BSc Data Science, Simon Fraser University