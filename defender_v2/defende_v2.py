#!/usr/bin/env python3
"""
File name: defender_v2.py
Author: abhijithsuren

- Loads a CSV dataset (configurable path) and trains a DecisionTreeClassifier.
- Exposes a Flask web service:
    POST /check   -> {"verdict": "DGA"|"NOT_DGA"|"UNKNOWN", "confidence": float}
    GET  /dashboard -> HTML UI (shows recent queries and allows manual block/unblock)
    GET  /api/queries -> JSON list of recent queries
    POST /api/block  -> JSON {"domain": "..."} (manual block)
    POST /api/unblock-> JSON {"domain": "..."} (manual unblock)
- Persists logs and manual block list under /app/logs so volume mapping keeps them on the host.
"""

from flask import Flask, request, jsonify, render_template_string
import pandas as pd
import numpy as np
import os
import math
import json
import threading
import time
from datetime import datetime
from sklearn.tree import DecisionTreeClassifier
from sklearn.exceptions import NotFittedError

# ---------------- Configuration ----------------
CSV_PATH = os.environ.get("DEFENDER_CSV_PATH", "/app/datasets/domains_features_numeric_with_more_tables.csv")
# If CSV_PATH does not exist, the model will use a fallback that labels everything NOT_DGA by default.
MODEL_NAME = "decision_tree"

LOG_DIR = "/app/logs"
os.makedirs(LOG_DIR, exist_ok=True)
DEFENDER_LOG = os.path.join(LOG_DIR, "defender_v2.log")
QUERIES_FILE = os.path.join(LOG_DIR, "queries.json")
BLOCKED_FILE = os.path.join(LOG_DIR, "blocked.json")
MAX_RECENT = 200   # keep last 200 queries in memory for dashboard
# -----------------------------------------------

app = Flask(__name__)

# In-memory structures
recent_queries = []  # list of dicts: {domain, verdict, confidence, timestamp, source("auto"|"manual")}
recent_lock = threading.Lock()

# manual blocklist (domains that analyst manually blocks)
# persisted to BLOCKED_FILE
if os.path.exists(BLOCKED_FILE):
    try:
        with open(BLOCKED_FILE, "r") as f:
            manual_block = set(json.load(f))
    except Exception:
        manual_block = set()
else:
    manual_block = set()

# Simple logger
def log(msg: str):
    ts = datetime.utcnow().isoformat() + "Z"
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        with open(DEFENDER_LOG, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass

def persist_blocked():
    try:
        with open(BLOCKED_FILE, "w") as f:
            json.dump(sorted(list(manual_block)), f)
    except Exception as e:
        log(f"ERROR: cannot persist blocked list: {e}")

def persist_query(q):
    # append to queries file
    try:
        if os.path.exists(QUERIES_FILE):
            with open(QUERIES_FILE, "r+") as f:
                try:
                    data = json.load(f)
                except Exception:
                    data = []
                data.append(q)
                f.seek(0)
                json.dump(data[-1000:], f)  # keep last 1000
                f.truncate()
        else:
            with open(QUERIES_FILE, "w") as f:
                json.dump([q], f)
    except Exception as e:
        log(f"ERROR: cannot persist query: {e}")

# ---------------- Feature extraction helpers ----------------
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [c / len(s) for c in list(map(lambda x: s.count(x), set(s)))]
    return -sum(p * math.log2(p) for p in probs)

def extract_features_from_domain(domain: str):
    """
    Given a domain string like 'abc123.com' return the numeric feature vector in the
    same order as training:
    [length, digits, letters, unique_chars, vowels, consonants, digit_ratio, entropy]
    (NOTE: We intentionally do NOT require tld_id here to keep the pipeline simple. Maybe we can implement that on v3)
    """
    domain = domain.strip().lower()
    if "." in domain:
        name = domain.rsplit(".", 1)[0]
        tld = domain.rsplit(".", 1)[1]
    else:
        name = domain
        tld = ""
    length = len(name)
    digits = sum(c.isdigit() for c in name)
    letters = sum(c.isalpha() for c in name)
    vowels = sum(c in "aeiou" for c in name)
    consonants = letters - vowels
    unique_chars = len(set(name))
    digit_ratio = (digits / length) if length > 0 else 0.0
    entropy = shannon_entropy(name)
    return [length, digits, letters, unique_chars, vowels, consonants, digit_ratio, entropy]

# ---------------- Model loading / training ----------------
model = None
model_lock = threading.Lock()

def load_and_train(csv_path: str):
    global model
    if not os.path.exists(csv_path):
        log(f"Training CSV not found at {csv_path}. Defender_v2 will run with fallback classifier (NOT_DGA default).")
        model = None
        return
    try:
        log(f"Loading training CSV from {csv_path} ...")
        df = pd.read_csv(csv_path)
        # Expect columns similar to: length,digits,letters,unique_chars,vowels,consonants,digit_ratio,entropy,tld_id,label
        # We will drop 'label' to get X, and drop tld_id if present (to avoid needing original TLD encoder)
        if "label" not in df.columns:
            raise ValueError("CSV must contain a 'label' column with target labels (e.g., DGA/NOT_DGA).")
        X = df.drop(columns=["label"])
        # If tld_id present, drop it to keep features numeric and consistent
        if "tld_id" in X.columns:
            X = X.drop(columns=["tld_id"])
        y = df["label"]
        # Convert to numeric matrix if needed
        X_numeric = X.select_dtypes(include=[np.number]).fillna(0.0)
        # Train Decision Tree
        clf = DecisionTreeClassifier(random_state=42)
        clf.fit(X_numeric.values, y.values)
        with model_lock:
            model = (clf, X_numeric.columns.tolist())  # save columns order
        log("Model trained successfully.")
    except Exception as e:
        log(f"ERROR training model: {e}")
        model = None

# Load model at startup (non-blocking)
load_and_train(CSV_PATH)

# Optional separate thread to retrain periodically if you want (not active by default)
def retrain_periodically(interval_seconds=0):
    if interval_seconds <= 0:
        return
    while True:
        time.sleep(interval_seconds)
        load_and_train(CSV_PATH)

# ---------------- Decision / API logic ----------------
def classify_domain(domain: str):
    """
    Returns tuple (verdict, confidence, detail_source)
    - verdict: "DGA" or "NOT_DGA" or "UNKNOWN"
    - confidence: float between 0..1 (or 0.0 if not available)
    - detail_source: string (e.g., 'model','manual','fallback')
    """
    domain = domain.strip().lower()
    
    # Manual blocklist has highest priority
    if domain in manual_block:
        return ("DGA", 1.0, "manual_block")

    # Feature extraction
    feats = extract_features_from_domain(domain)
    X = np.array(feats).reshape(1, -1)

    # If model available, use it
    with model_lock:
        if model is None:
            # fallback behavior: treat as NOT_DGA (safe for lab), but mark as fallback
            return ("NOT_DGA", 0.0, "fallback_no_model")
        clf, feature_cols = model

    try:
        # Predict class
        pred = clf.predict(X)[0]

        # Map numeric labels to strings (0 -> NOT_DGA, 1 -> DGA)
        if isinstance(pred, (int, float, np.integer, np.floating)):
            verdict = "DGA" if int(pred) == 1 else "NOT_DGA"
        else:
            verdict = str(pred).upper()  # fallback if label is string

        # Calculate confidence if probability is available
        confidence = 0.0
        try:
            proba = clf.predict_proba(X)
            classes = clf.classes_
            class_index = list(classes).index(pred)
            confidence = float(proba[0][class_index])
        except Exception:
            confidence = 0.0

        return (verdict, confidence, "model")

    except Exception as e:
        # If prediction fails for any reason, fallback
        log(f"Model prediction error for domain {domain}: {e}")
        return ("UNKNOWN", 0.0, "error")

# ---------------- Flask endpoints ----------------
@app.route("/check", methods=["POST"])
def api_check():
    """
    Victim_v2 sends JSON: {"domain": "example.com"}
    Responds JSON: {"verdict":"DGA"|"NOT_DGA"|"UNKNOWN", "confidence": float, "source": "..."}
    """
    data = request.get_json(silent=True)
    if not data or "domain" not in data:
        return jsonify({"error": "missing 'domain' in JSON"}), 400
    domain = str(data["domain"]).strip()
    ts = datetime.utcnow().isoformat() + "Z"

    # classify
    verdict, confidence, source = classify_domain(domain)

    # If source == "fallback_no_model" treat as NOT_DGA by default; if manual_block handled earlier.
    record = {
        "domain": domain,
        "verdict": verdict,
        "confidence": round(float(confidence), 4),
        "source": source,
        "timestamp": ts
    }

    # save to recent list and persist
    with recent_lock:
        recent_queries.append(record)
        if len(recent_queries) > MAX_RECENT:
            recent_queries.pop(0)
    persist_query(record)
    log(f"CHECK: {domain} => {verdict} (conf={confidence:.3f}) src={source}")

    # Return verdict
    return jsonify({"verdict": verdict, "confidence": round(float(confidence), 4), "source": source})

@app.route("/api/queries", methods=["GET"])
def api_queries():
    with recent_lock:
        # return recent queries newest-first
        return jsonify(list(reversed(recent_queries)))

@app.route("/api/block", methods=["POST"])
def api_block():
    data = request.get_json(silent=True)
    if not data or "domain" not in data:
        return jsonify({"error": "missing 'domain' in JSON"}), 400
    domain = str(data["domain"]).strip().lower()
    manual_block.add(domain)
    persist_blocked()
    log(f"MANUAL BLOCK: {domain}")
    return jsonify({"status": "ok", "domain": domain})

@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    data = request.get_json(silent=True)
    if not data or "domain" not in data:
        return jsonify({"error": "missing 'domain' in JSON"}), 400
    domain = str(data["domain"]).strip().lower()
    if domain in manual_block:
        manual_block.remove(domain)
        persist_blocked()
        log(f"MANUAL UNBLOCK: {domain}")
        return jsonify({"status": "ok", "domain": domain})
    else:
        return jsonify({"status": "not_found", "domain": domain}), 404

# Simple health endpoint
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "model_loaded": model is not None})

# ---------------- Simple web dashboard (HTML + JS) ----------------
DASH_HTML = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Defender SOC Dashboard</title>
  <style>
    body {
      background: url("/static/bg.png") no-repeat center center fixed;
      background-size: cover;
      font-family: Arial, sans-serif;
      color: #fff;
    }

    /* Overlay to darken the background slightly */
    body::before {
      content: "";
      position: fixed;
      top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0, 0, 0, 0.034); /* 75% dark overlay */
      z-index: -1;
    }


    h1 {
      font-size: 20px;
      color: #fff;  /* bright white headings */
    }

    table {
      border-collapse: collapse;
      width: 100%;
      margin-top: 12px;
      background: rgba(197, 190, 190, 0);       /* dark gray table bg */
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 2px 8px rgba(0,0,0,0.6);
    }

    th, td {
      /*border: 0px solid #ffffff;    subtle borders */
      border: 4px solid #ffffff;
      padding: 10px;
      text-align: left;
    }

    th {
      background: #ffffff;
      color: #000000;
      font-weight: 600;
    }

    .dga {
      background-color:#8c29a0;  /* dark red background */
      color: #ffffff;             /* neon red text */
      
    }

    tr.notdga {
      background-color: #289198;  /* dark green background */
      color:   #ffffff;             /* neon green text */
    }

    .controls {
      margin-top: 12px;
      background: #ffffff;
      padding: 12px;
      border-radius: 8px;
      box-shadow: 0 1px 6px rgba(0,0,0,0.4);
    }

    input[type="text"] {
      padding: 8px;
      background: #ffffff;
      border: 2px solid #c433db;
      border-radius: 10px;
      color: #000000;
    }

    button {
      padding: 8px 14px;
      margin-right: 6px;
      background: #c433db;       /* purple? idk */
      border: none;
      border-radius: 7px;
      color: white;
      font-weight: 600;
      cursor: pointer;
      transition: background 0.3s;
    }

    button:hover {
      background: #ff0088;       /* lighter blue hover */
    }

    #status {
      margin-left: 8px;
      color: #000000;
    }

  </style>
</head>
<body>
  <h1>Defender SOC Dashboard</h1>
  <div>
    <button onclick="refresh()">Refresh</button>
    <span id="status">Loading...</span>
  </div>

  <div class="controls">
    <input type="text" id="manualDomain" placeholder="domain.to.block">
    <button onclick="manualBlock()">Block</button>
    <button onclick="manualUnblock()">Unblock</button>
  </div>

  <table id="queriesTable">
    <thead>
      <tr><th>Time (UTC)</th><th>Domain</th><th>Verdict</th><th>Confidence</th><th>Source</th><th>Action</th></tr>
    </thead>
    <tbody></tbody>
  </table>

<script>
async function api(path, method='GET', body=null){
  const res = await fetch(path, {
    method: method,
    headers: {'Content-Type': 'application/json'},
    body: body ? JSON.stringify(body) : null
  });
  return res.json();
}



async function refresh(){
  document.getElementById('status').innerText = "Refreshing..."
  try {
    const data = await api('/api/queries');
    const tbody = document.querySelector('#queriesTable tbody');
    tbody.innerHTML = '';

    for (let i = 0; i < data.length; i++) {
      const q = data[i];
      const tr = document.createElement('tr');
      tr.className = q.verdict === 'DGA' ? 'dga' : (q.verdict === 'NOT_DGA' ? 'notdga' : '');

      // Add the basic row cells
      tr.innerHTML = `
        <td>${q.timestamp}</td>
        <td>${q.domain}</td>
        <td>${q.verdict}</td>
        <td>${q.confidence}</td>
        <td>${q.source}</td>
      `;

      // Create Action button cell
      const actionTd = document.createElement('td');
      if (q.verdict.toUpperCase() === 'DGA') {
        actionTd.innerHTML = `<button onclick="unblockDomain('${q.domain}')">Unblock</button>`;
      } else {
        actionTd.innerHTML = `<button onclick="blockDomain('${q.domain}')">Block</button>`;
      }

      // Add the action button cell to the row
      tr.appendChild(actionTd);

      // Add the row to the table body
      tbody.appendChild(tr);
    }

    document.getElementById('status').innerText = "Updated " + new Date().toLocaleTimeString();
  } catch (e) {
    document.getElementById('status').innerText = "Error refreshing";
    console.error(e);
  }
}

async function blockDomain(domain){
  await api('/api/block','POST',{domain:domain});
  await refresh();
}

async function unblockDomain(domain){
  await api('/api/unblock','POST',{domain:domain});
  await refresh();
}

async function manualBlock(){
  const input = document.getElementById('manualDomain');
  const domain = input.value.trim();
  if (!domain) return alert('Enter a domain');
  await api('/api/block','POST',{domain:domain});
  input.value = '';   // ✅ clear input
  await refresh();
}

async function manualUnblock(){
  const input = document.getElementById('manualDomain');
  const domain = input.value.trim();
  if (!domain) return alert('Enter a domain');
  await api('/api/unblock','POST',{domain:domain});
  input.value = '';   // ✅ clear input
  await refresh();
}

// poll every 2 seconds
refresh();
setInterval(refresh, 2000);
</script>
</body>
</html>
"""

@app.route("/")
def dashboard():
    return render_template_string(DASH_HTML)

# ---------------- Startup ----------------
if __name__ == "__main__":
    log("Defender_v2 starting up...")
    # try to train model now if not already
    load_and_train(CSV_PATH)
    # Ensure persisted blocked file exists
    persist_blocked()
    # Ensure queries file exists
    if not os.path.exists(QUERIES_FILE):
        with open(QUERIES_FILE, "w") as f:
            json.dump([], f)
    # start Flask
    app.run(host="0.0.0.0", port=5000, debug=False)
