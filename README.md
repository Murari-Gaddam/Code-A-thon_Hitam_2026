# Network Intrusion Detection Agent

A prototype Network Intrusion Detection dashboard built for Codeathon 2026.

The system uses a two-stage machine-learning pipeline to classify network traffic and presents the results through a web-based security dashboard.

## Overview

The project takes network-flow features as input and performs:

1. Anomaly / OOD detection using an Isolation Forest.
2. Traffic classification using a temperature-scaled LightGBM classifier.
3. Confidence-based filtering to mark uncertain predictions as suspicious.
4. Dashboard visualization of detected normal traffic, attacks, and suspicious events.

The current demo uses a sample of 2,000 CICIDS2017-processed records.

## Demo Results

| Metric | Value |
|---|---:|
| Total records | 2,000 |
| Normal | 1,674 |
| Attacks | 298 |
| Suspicious | 28 |
| Threats / errors found | 326 |
| Risk | 16.30% |

Note: The IP addresses and timestamps shown in the dashboard are simulated demo metadata. They are generated for visualization and are not the original CICIDS2017 network endpoints/timestamps.

---

## Project Structure
```text
Codethon_2026/
├── detector.py
├── frontend_data.csv
├── predictions.csv
├── cicids2017-soc-classifier-v2/
│   └── model/
│       ├── tier1_lgbm_temp_scaled.pkl
│       ├── stage1_isolation_forest.pkl
│       ├── scaler.pkl
│       ├── feature_selector.pkl
│       ├── selected_features.pkl
│       ├── feature_cols.pkl
│       ├── label_encoder.pkl
│       └── pipeline_thresholds.pkl
├── backend/
│   └── app.py
├── frontend/
│   ├── index.html
│   ├── script.js
│   ├── style.css
│   └── styles.css
├── uploads/
└── README.md
```
---

## Machine Learning Pipeline

The detector expects 71 model input features.

### Stage 1 — Anomaly Detection

An Isolation Forest is used as an initial gate.

- Inlier → passed to the classifier.
- Anomaly / out-of-distribution sample → marked as SUSPICIOUS.

### Stage 2 — Attack Classification

Samples that pass the anomaly gate are classified using a temperature-scaled LightGBM model.

The supported classes are:

- Bot
- Brute Force
- DoS
- Normal
- PortScan
- Web Attack

### Confidence Threshold

The classifier uses a confidence threshold of:

0.60

If the prediction confidence is below this threshold, the result is treated as:

SUSPICIOUS
Unknown

Otherwise:

- Normal → NORMAL
- Any attack class → ATTACK

---

## Model Files

The trained model artifacts are stored in:

cicids2017-soc-classifier-v2/model/

The model was obtained from the Hugging Face repository:

mehddii/cicids2017-soc-classifier-v2

The detector also preserves the expected 71-feature ordering before inference.

---

## Backend

The backend is implemented using Flask.

### Health Check

GET /api/health

Used to check whether the backend is running.

### Analyze CSV

POST /api/analyze

Accepts a CSV containing the required model features and returns prediction results as JSON.

The response includes:

- total rows
- normal count
- attack count
- suspicious count
- prediction results
- attack type
- confidence
- simulated timestamp
- simulated source IP
- simulated destination IP

---

## Frontend

The frontend is a standalone HTML/CSS/JavaScript dashboard.

Main files:

- index.html — dashboard structure
- styles.css — primary dashboard styling
- style.css — additional stylesheet
- script.js — dashboard interaction and data rendering

The dashboard includes:

- packet throughput
- active socket count
- threats found
- risk percentage
- event filtering
- event table
- UTC clock
- pause/resume feed control

The current demo header metrics are intentionally static:

PKTS/SEC        2,000
ACTIVE SOCKETS  1,842
THREATS FOUND   326
RISK            16.30%

---

## Running the Project

### 1. Create / activate the virtual environment

python3 -m venv .venv

source .venv/bin/activate

### 2. Install dependencies

pip install flask pandas numpy scikit-learn lightgbm

On macOS, LightGBM may also require OpenMP:

brew install libomp

### 3. Start the backend

From the project root:

python backend/app.py

The backend runs on:

http://127.0.0.1:5001

### 4. Open the dashboard

Open:

http://127.0.0.1:5001/

The Flask backend serves the frontend files as well.

---

## Data

The demo dataset is based on the processed CICIDS2017 dataset.

The sample used for the current demonstration contains:

- 2,000 records
- 71 model features
- 1 label column

Ground-truth distribution in the sample:

Normal        1667
DoS            251
PortScan        74
Brute Force      5
Web Attack       3

The model's predictions are stored in:

predictions.csv

Frontend-ready data is stored in:

frontend_data.csv

---

## Current Limitations

This is a prototype/demo rather than a production IDS.

- Dashboard IP addresses are simulated.
- Dashboard timestamps are simulated.
- Packet-per-second and active-socket metrics are currently demo values.
- Risk is currently displayed using the demo calculation.
- The current dashboard can operate independently from the ML inference pipeline.
- CICIDS2017 is an offline benchmark dataset, not a live enterprise network feed.
- Model performance depends on how closely real network traffic matches the training data.

---

## Future Improvements

Possible next steps include:

- Connect the frontend directly to backend inference results.
- Stream live network traffic instead of CSV records.
- Capture real packet/flow features using a network monitoring pipeline.
- Calculate live risk from backend predictions.
- Add temporal attack correlation.
- Add alert severity levels.
- Add persistent event history.
- Add explainability for individual predictions.
- Add model monitoring and drift detection.
- Deploy the detector on a real network gateway or monitoring node.

---

## Credits / Model

Machine-learning model:

mehddii/cicids2017-soc-classifier-v2

Dataset:

CICIDS2017 / processed CICIDS2017 data

Frameworks and libraries:

- Python
- Flask
- Pandas
- NumPy
- scikit-learn
- LightGBM
- HTML
- CSS
- JavaScript

---

## Disclaimer

This project is intended for educational, research, and demonstration purposes. It should not be treated as a production-grade network security system without additional validation, monitoring, security hardening, and testing on representative real-world traffic.
