#!/usr/bin/env python3
"""
File name: attacker_v2.py
Author: abhijithsuren

- Generates DGA domain sets (10 labels per set) periodically.
- Chooses 5 random domains from each set as "active C2" (simulated).
- Runs a Flask HTTP server that handles incoming requests:
    * If Host == google.com|microsoft.com|facebook.com -> reply "hi from <domain>"
    * Else if Host in active C2 list -> reply "C2 server connected"
    * Else if Host in current generated set but not active -> drop / return 404 (logged)
    * Else -> return 404 (ignored)
- Logs all requests/decisions to /app/logs/attacker_v2.log
"""

import hashlib
import base64
import random
import time
import threading
import os
import sys
from datetime import datetime
from flask import Flask, request, make_response

# ---------------- Configuration ----------------
SEED = "spreadlove"         # same seed used by victim_v2 for DGA <3
SET_SIZE = 10               # number of labels per set
ACTIVE_PER_SET = 5          # how many of the set are active C2
DELAY_SECONDS = 50           # how often to generate a new set
LABEL_LENGTH = 12           # characters in generated label
LOG_DIR = "/app/logs"
LOG_FILE = os.path.join(LOG_DIR, "attacker_v2.log")
HTTP_HOST = "0.0.0.0"
HTTP_PORT = 8080
ALLOWED_DOMAINS = {"google.com", "microsoft.com", "facebook.com"}
# ------------------------------------------------

# ensure logging dir exists
os.makedirs(LOG_DIR, exist_ok=True)

def log(msg: str):
    ts = datetime.utcnow().isoformat() + "Z"
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass

# DGA label generator (same method as victim_v2 for compatibility)
def generate_domain_label(seed: str, timestamp_str: str, index: int, label_length: int = LABEL_LENGTH) -> str:
    input_bytes = f"{seed}:{timestamp_str}:{index}".encode("utf-8")
    digest = hashlib.sha256(input_bytes).digest()
    b32 = base64.b32encode(digest).decode("utf-8").lower().replace("=", "")
    label = "".join(ch for ch in b32 if ch.isalnum())[:label_length]
    if label and label[0].isdigit():
        label = "a" + label[1:]
    return label

def generate_set(seed: str, set_time: float) -> list:
    """
    Generate SET_SIZE unique labels for the given set_time.
    Returns list of domain strings (label + '.com' style TLD - here we will use .com by default).
    Note: victim_v2 used multiple TLDs in your modified victim_v2; attacker_v2 can match by creating the same
    labels, and since victim_v2 attaches actual TLDs from its TLD list, the attacker_v2 checks domain base too.
    We'll store full domain strings for matching (label + tld).
    """
    timestamp_str = datetime.utcfromtimestamp(set_time).strftime("%Y%m%d%H%M")
    labels = []
    i = 0
    while len(labels) < SET_SIZE:
        label = generate_domain_label(seed, timestamp_str, i)
        if label not in labels:
            labels.append(label)
        i += 1
    # For simplicity attacker_v2 tracks labels with common TLDs frequently used by victim_v2.
    # To match victim_v2's multi-TLD behavior the attacker_v2 will consider any TLD for a label when matching.
    # We'll store labels (no TLD) in current_labels. For quick matching, keep both label-only and full forms.
    # dga_lab_v3 will consider TLD
    return labels

# Global state (protected by lock when updated)
state_lock = threading.Lock()
current_labels = []     # list of 10 labels (no TLDs)
current_active = set()  # set of active labels (no TLDs)

def rotate_sets_loop(stop_event: threading.Event):
    """
    Periodically generate new DGA sets and randomly mark ACTIVE_PER_SET labels as active C2 endpoints.
    """
    set_index = 0
    while not stop_event.is_set():
        set_time = time.time()
        labels = generate_set(SEED, set_time)
        # pick random active labels
        active = set(random.sample(labels, min(ACTIVE_PER_SET, len(labels))))
        with state_lock:
            current_labels.clear()
            current_labels.extend(labels)
            current_active.clear()
            current_active.update(active)
        log(f"New DGA set #{set_index}: labels={labels}")
        log(f"Active C2 labels (sample): {sorted(list(active))}")
        set_index += 1
        # wait for DELAY_SECONDS (interruptible)
        slept = 0.0
        while slept < DELAY_SECONDS and not stop_event.is_set():
            time.sleep(0.5)
            slept += 0.5

# Helper to normalize a domain for checking: return the label (left-of-last-dot) in lowercase
def domain_label_from_domain(domain: str) -> str:
    domain = domain.strip().lower()
    if "." in domain:
        return domain.rsplit(".", 1)[0]
    return domain

# Flask app for HTTP handling
app = Flask(__name__)

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>", methods=["GET", "POST"])
def catch_all(path):
    # Determine requested domain: prefer Host header, fallback to path if given
    host = request.headers.get("Host", "").split(":")[0].lower()
    # sometimes victim_v2 might call attacker_v2:8080 with Host header set to domain, or directly call domain if DNS proxy used
    requested_domain = host if host else path.split("/")[0].lower()
    if not requested_domain:
        requested_domain = ""
    label = domain_label_from_domain(requested_domain)

    # Log incoming attempt
    src = request.remote_addr
    ts = datetime.utcnow().isoformat() + "Z"
    # Decision logic
    with state_lock:
        labels_snapshot = list(current_labels)
        active_snapshot = set(current_active)

    # Allowed domains (google/microsoft/facebook) check - exact full domain check
    if requested_domain in ALLOWED_DOMAINS:
        msg = f"Allowed domain request from {src} for {requested_domain} -> replying greeting"
        log(msg)
        resp = make_response(f"hi from {requested_domain}", 200)
        resp.headers["Content-Type"] = "text/plain"
        return resp

    # If label is one of our generated labels:
    if label in labels_snapshot:
        # If this label is one of active C2:
        if label in active_snapshot:
            # Accept connection -> simulate C2 reply
            log(f"C2 ACCEPT: {requested_domain} from {src} -> replying 'C2 server connected'")
            resp = make_response("C2 server connected", 200)
            resp.headers["Content-Type"] = "text/plain"
            return resp
        else:
            # Label belongs to current set but not active -> drop/ignore
            log(f"DROPPED (not active): {requested_domain} from {src} (label in set but not in active C2)")
            # return 404 to simulate no service running
            return ("", 404)
    else:
        # domain not recognized as attacker_v2 DGA label nor allowed -> ignore / 404
        log(f"IGNORED: {requested_domain} from {src} (not an attacker_v2 label)")
        return ("", 404)

# Health endpoint
@app.route("/health", methods=["GET"])
def health():
    with state_lock:
        active = list(current_active)
    return {"status": "ok", "active_sample": active[:5], "labels_count": len(current_labels)}

def main():
    # start DGA rotation thread
    stop_event = threading.Event()
    t = threading.Thread(target=rotate_sets_loop, args=(stop_event,), daemon=True)
    t.start()

    # Start Flask server
    try:
        log(f"Attacker_v2 HTTP server starting on {HTTP_HOST}:{HTTP_PORT}")
        app.run(host=HTTP_HOST, port=HTTP_PORT)
    except KeyboardInterrupt:
        log("Attacker_v2 shutting down (KeyboardInterrupt)")
    finally:
        stop_event.set()
        t.join(timeout=2.0)
        log("Attacker_v2 stopped.")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        log(f"UNCAUGHT ERROR in attacker_v2: {e}")
        sys.exit(1)
