#!/usr/bin/env python3
import os
import subprocess
import sys
import requests
from datetime import datetime

# Configuration
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
CHAT_ID        = os.getenv("CHAT_ID")
GIST_URL       = "https://gist.githubusercontent.com/RedBullSecurity/3eb88debcb01759eccf65ec2b799b340/raw/redbull-bug-bounty-scope-rb-only.txt"

STATE_FILE   = "scope_state.txt"
NEW_FILE     = "new_host.txt"
PENDING_FILE = "pending_assets.txt"
LOCK_FILE    = "scan_lock.txt"
INIT_FLAG    = "initial_scan_done.flag"
FUZZ_FILE    = "fuzz_targets.txt"

# Keywords that trigger fuzzing
FUZZ_TRIGGERS = [
    "admin", "api", "dev", "staging", "internal", 
    "login", "dashboard", "portal", "manage", 
    "console", "panel", "test", "uat", "preprod"
]

# Ensure required files exist
for f in [NEW_FILE, PENDING_FILE, FUZZ_FILE]:
    if not os.path.exists(f):
        open(f, "w").close()

def log(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}")

def notify(msg):
    if not TELEGRAM_TOKEN or not CHAT_ID:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            data={"chat_id": CHAT_ID, "text": msg},
            timeout=10
        )
    except Exception as e:
        log(f"Telegram error: {e}")

def save_set(filename, data_set):
    with open(filename, "w") as f:
        f.write("\n".join(sorted(data_set)))

def probe_live(domains):
    if not domains:
        return {}
    try:
        result = subprocess.run(
            ['httpx', '-silent', '-ip', '-title', '-no-color'],
            input="\n".join(domains),
            capture_output=True,
            text=True,
            timeout=300
        )
        live = {}
        for line in result.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                domain = parts[0].replace('https://', '').replace('http://', '').split(':')[0].rstrip('/')
                ip = parts[1].strip('[]')
                title = " ".join(parts[2:]) if len(parts) > 2 else ""
                live[domain] = {"ip": ip, "title": title}
        return live
    except Exception as e:
        log(f"httpx error: {e}")
        return {}

def main():
    log("Fetching remote scope...")
    try:
        res = requests.get(GIST_URL, timeout=15)
        res.raise_for_status()
        current_scope = set(line.strip() for line in res.text.splitlines() if line.strip())
    except Exception as e:
        log(f"Failed to fetch scope: {e}")
        sys.exit(1)

    initial_mode = not os.path.exists(INIT_FLAG)
    
    if not os.path.exists(STATE_FILE):
        save_set(STATE_FILE, current_scope)
        old_scope = set()
    else:
        with open(STATE_FILE) as f:
            old_scope = set(line.strip() for line in f.read().splitlines() if line.strip())

    new_domains = current_scope - old_scope
    removed = old_scope - current_scope

    if removed:
        log(f"Removed {len(removed)} domains.")
        notify(f"🗑 Removed from RedBull scope ({len(removed)}):\n" + "\n".join(sorted(removed)[:20]))

    if not new_domains:
        log("No new assets — updating state and exiting.")
        save_set(STATE_FILE, current_scope)
        open(NEW_FILE, "w").close()
        open(FUZZ_FILE, "w").close()
        sys.exit(0)

    log(f"Found {len(new_domains)} new domains. Probing for live web servers...")
    live = probe_live(list(new_domains))

    if not live:
        log("No new live hosts found. Saving state and exiting.")
        save_set(STATE_FILE, current_scope)
        open(NEW_FILE, "w").close()
        open(FUZZ_FILE, "w").close()
        sys.exit(0)

    # Write live hosts
    with open(NEW_FILE, "w") as f:
        for d in live.keys():
            f.write(f"{d}\n")

    # Check for fuzzing targets
    fuzz_targets = [d for d in live.keys() if any(trig in d for trig in FUZZ_TRIGGERS)]
    with open(FUZZ_FILE, "w") as f:
        for d in fuzz_targets:
            f.write(f"{d}\n")

    mode_label = "INITIAL" if initial_mode else "NEW"
    sub_lines  = "\n".join(f"  {d} ({info['ip']})" for d, info in sorted(live.items())[:30])
    notify(f"🔍 RedBull {mode_label} ASSETS ({len(live)}):\n{sub_lines}" + ("\n...and more" if len(live) > 30 else ""))

    if fuzz_targets:
        notify(f"🎯 Fuzzing Targets Identified ({len(fuzz_targets)}):\n" + "\n".join(fuzz_targets[:10]))

    # Update state globally and handle initial flag
    save_set(STATE_FILE, current_scope)
    if initial_mode:
        open(INIT_FLAG, "w").close()
    log("State updated successfully.")

if __name__ == "__main__":
    main()
