#!/usr/bin/env python3
"""
File name: victim_v2.py
Author: abhijithsuren
Description: Beginner-friendly victim_v2 script for DGA lab.

Changes:
- Uses a tld_list of 10 TLDs and appends them one-to-one to each generated DGA label.
- Removed dga-lab.local usage.
- If user types a domain without a TLD, '.com' is appended.
"""

import hashlib
import base64
import time
import threading
import requests
import os
import sys
from datetime import datetime

# ----------------- Configuration -----------------
SEED = "spreadlove"        # the seed is clear as crystal #spreadlove #bekind <3
SET_SIZE = 10              # domains per set (must match length of TLD_LIST)
DELAY_SECONDS = 50          # wait between sets
DEFENDER_URL = "http://defender_v2:5000/check"   # Defender_v2 REST endpoint
ATTACKER_HOST = "attacker_v2" # hostname on Docker network; used when simulating a connection (Host header method)
ATTACKER_PORT = 8080
LOG_DIR = "/app/logs"
LOG_FILE = os.path.join(LOG_DIR, "victim_v2.log")

# new: list of TLDs to append, one-to-one for the 10 labels generated per set
TLD_LIST = [".com", ".net", ".xyz", ".top", ".site",
            ".online", ".club", ".tk", ".pw", ".cc"]
# -------------------------------------------------

# sanity check
if len(TLD_LIST) < SET_SIZE:
    raise ValueError("TLD_LIST must have at least SET_SIZE entries")

# ensure log directory exists
os.makedirs(LOG_DIR, exist_ok=True)

# simple logger (append)
def log(msg: str):
    ts = datetime.utcnow().isoformat() + "Z"
    line = f"[{ts}] {msg}"
    #print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")

# deterministic DGA generator:
# combine SEED + timestamp_str + index -> sha256 -> base32 -> domain label
def generate_domain_label(seed: str, timestamp_str: str, index: int, label_length: int = 12) -> str:
    """
    Create a deterministic domain label from (seed, timestamp_str, index).
    Returns a string of length `label_length` containing lowercase letters and digits.
    """
    input_bytes = f"{seed}:{timestamp_str}:{index}".encode("utf-8")
    digest = hashlib.sha256(input_bytes).digest()
    # base32 (A-Z2-7), then make lowercase and remove '=' padding
    b32 = base64.b32encode(digest).decode("utf-8").lower().replace("=", "")
    # keep only letters and digits, cut to requested length
    label = "".join(ch for ch in b32 if ch.isalnum())[:label_length]
    # ensure label starts with a letter (makes it more domain-like)
    if label and label[0].isdigit():
        # replace first char with 'a'
        label = "a" + label[1:]
    return label

def generate_set(seed: str, set_index: int, set_time: float) -> list:
    """
    Generate one set of domains (SET_SIZE) using timestamp-based period.
    set_time: epoch seconds used in timestamp (float)
    Returns list of fully qualified domains where each generated label is appended
    with the corresponding element from TLD_LIST (one-to-one).
    """
    timestamp_str = datetime.utcfromtimestamp(set_time).strftime("%Y%m%d%H%M")
    labels = []
    i = 0
    while len(labels) < SET_SIZE:
        label = generate_domain_label(seed, timestamp_str, i)
        if label not in labels:
            labels.append(label)
        i += 1

    # append TLDs one-to-one: label 0 -> TLD_LIST[0], label 1 -> TLD_LIST[1], ...
    domains = []
    for idx, label in enumerate(labels):
        tld = TLD_LIST[idx % len(TLD_LIST)]
        domain = f"{label}{tld}"
        domains.append(domain)
    return domains

def send_to_defender(domain: str, timeout=5) -> dict:
    """
    Send domain to defender_v2 and wait for response.
    Returns a dictionary with default structure {"verdict":"UNKNOWN", "detail": "..."} on error.
    Expected Defender_v2 response: {"verdict": "DGA"} or {"verdict":"NOT_DGA"}.
    """
    payload = {"domain": domain}
    try:
        resp = requests.post(DEFENDER_URL, json=payload, timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
        verdict = data.get("verdict", "UNKNOWN")
        return {"verdict": verdict, "detail": data}
    except requests.exceptions.RequestException as e:
        log(f"ERROR: cannot contact Defender_v2 ({e}) for domain {domain}")
        return {"verdict": "UNKNOWN", "detail": str(e)}
    except ValueError:
        log(f"ERROR: Defender_v2 returned non-JSON response for domain {domain}")
        return {"verdict": "UNKNOWN", "detail": "Non-JSON response"}

def simulate_connection(domain: str):
    """
    Simulate connecting to the domain if defender_v2 says NOT_DGA.
    For lab simplicity we connect to the attacker_v2 container and set the Host header to the domain.
    """
    url = f"http://{ATTACKER_HOST}:{ATTACKER_PORT}/"
    headers = {"Host": domain}
    try:
        r = requests.get(url, headers=headers, timeout=5)
        log(f"Connection attempt to {domain} (via attacker_v2) returned status {r.status_code}, body: {r.text!r}")
    except requests.exceptions.RequestException as e:
        log(f"Connection attempt to {domain} failed: {e}")

def handle_domain(domain: str):
    """
    Full victim_v2-side handling of one domain:
    - log generated/requested domain
    - send to defender_v2 and wait for verdict
    - if verdict == NOT_DGA -> attempt simulated connection
    - persist logs
    """
    log(f"Generated/Requested domain: {domain}")
    resp = send_to_defender(domain)
    verdict = resp.get("verdict", "UNKNOWN")
    log(f"Defender_v2 verdict for {domain}: {verdict}  details={resp.get('detail')}")
    # Act based on verdict
    if verdict == "NOT_DGA":
        log(f"VERDICT NOT_DGA: attempting connection to {domain}")
        simulate_connection(domain)
    elif verdict == "DGA":
        log(f"VERDICT DGA: blocking {domain} (no connection)")
    else:
        # Unknown verdict (defender_v2 down or error) -> safe action: block / or retry
        log(f"VERDICT UNKNOWN: default action = block {domain}")

# Background thread that continuously generates DGA sets
def dga_generation_loop(stop_event: threading.Event):
    set_index = 0
    while not stop_event.is_set():
        set_time = time.time()
        domains = generate_set(SEED, set_index, set_time)
        log(f"--- DGA SET {set_index} (time={datetime.utcfromtimestamp(set_time).isoformat()}Z) ---")
        for d in domains:
            if stop_event.is_set():
                break
            handle_domain(d)
        set_index += 1
        # wait for the configured delay between sets
        log(f"Set {set_index-1} complete. Sleeping for {DELAY_SECONDS} seconds before next set.")
        total_sleep = 0.0
        while total_sleep < DELAY_SECONDS and not stop_event.is_set():
            time.sleep(0.5)
            total_sleep += 0.5

# Terminal input loop (main thread) for interactive user queries
def interactive_input_loop(stop_event: threading.Event):
    log("Interactive input ready. Type domain names and press Enter. Type 'exit' to quit.")
    try:
        while not stop_event.is_set():
            user_input = input("Enter domain (or 'exit'): ").strip()
            if user_input.lower() == "exit":
                log("Exit requested by user.")
                stop_event.set()
                break
            if user_input == "":
                continue
            # If user did not provide a TLD, append .com for interactive queries
            domain = user_input if "." in user_input else f"{user_input}.com"
            handle_domain(domain)
    except (EOFError, KeyboardInterrupt):
        log("Interactive input terminated (CTRL-C or EOF). Stopping.")
        stop_event.set()

def main():
    log("Victim_v2 script starting.")
    stop_event = threading.Event()

    # start DGA generation in background thread
    t = threading.Thread(target=dga_generation_loop, args=(stop_event,), daemon=True)
    t.start()

    # main thread handles interactive input
    interactive_input_loop(stop_event)

    # when interactive loop ends, signal background thread to stop and wait
    stop_event.set()
    log("Waiting for background DGA thread to finish...")
    t.join(timeout=2.0)
    log("Victim_v2 script exiting.")

if __name__ == "__main__":
    log("Starting victim_v2 container process.")
    try:
        main()
    except Exception as e:
        log(f"UNCAUGHT ERROR in victim_v2 process: {e}")
        sys.exit(1)
