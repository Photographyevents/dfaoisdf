#!/usr/bin/env python3
"""
RedBull Recon Monitor
- Fetches scope from RedBull's public gist
- Diffs against known scope
- Resolves live domains via httpx
- Triggers Nuclei + Naabu on new assets
- First run: full scan of everything
- Subsequent runs: diff only
"""

import os
import re
import subprocess
import sys
import requests
from datetime import datetime

# ── Config ────────────────────────────────────────────────────
TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
CHAT_ID        = os.getenv("CHAT_ID")

GIST_URL   = "https://gist.githubusercontent.com/RedBullSecurity/3eb88debcb01759eccf65ec2b799b340/raw/redbull-bug-bounty-scope-rb-only.txt"

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

# Ensure state files exist
for f in [STATE_FILE, NEW_FILE, PENDING_FILE, FUZZ_FILE]:
    if not os.path.exists(f):
        open(f, "a").close()

# ── Helpers ───────────────────────────────────────────────────
def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)

def notify(msg):
    if not TELEGRAM_TOKEN or not CHAT_ID:
        log(f"[NOTIFY] {msg}")
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            data={"chat_id": CHAT_ID, "text": msg},
            timeout=10,
        )
    except Exception as e:
        log(f"Telegram error: {e}")

def run(cmd, timeout=600, input_data=None):
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout, input=input_data
        )
        return [l.strip() for l in r.stdout.splitlines() if l.strip()]
    except subprocess.TimeoutExpired:
        log(f"⚠ Timeout: {cmd}")
        return []
    except Exception as e:
        log(f"⚠ Error: {e}")
        return []

def load_set(filepath):
    if not os.path.exists(filepath):
        return set()
    with open(filepath) as f:
        return set(l.strip() for l in f if l.strip())

def save_set(filepath, items):
    with open(filepath, "w") as f:
        f.write("\n".join(sorted(items)))

def is_scan_running():
    return os.path.exists(LOCK_FILE)

def is_initial_done():
    return os.path.exists(INIT_FLAG)

# ── Fetch scope ───────────────────────────────────────────────
def fetch_scope():
    log("Fetching RedBull scope from gist...")
    try:
        r = requests.get(GIST_URL, timeout=15)
        r.raise_for_status()
        scope = set(l.strip() for l in r.text.splitlines() if l.strip())
        log(f"Fetched {len(scope)} entries from gist")
        return scope
    except Exception as e:
        log(f"❌ Failed to fetch scope: {e}")
        sys.exit(1)

# ── httpx probe ───────────────────────────────────────────────
def probe_live(domains):
    """Probe domains with httpx, return dict of domain → {ip, url, title}"""
    if not domains:
        return {}
    log(f"Probing {len(domains)} domains with httpx...")
    input_data = "\n".join(domains)
    out = run(
        "httpx -silent -ip -title -status-code -no-color -timeout 10",
        timeout=600,
        input_data=input_data,
    )
    live = {}
    for line in out:
        parts = line.split()
        if not parts:
            continue
        url = parts[0]
        domain = url.replace("https://", "").replace("http://", "")
        domain = domain.split(":")[0].rstrip("/")
        ip = ""
        title = ""
        for p in parts[1:]:
            if re.match(r"\[\d+\.\d+\.\d+\.\d+\]", p):
                ip = p.strip("[]")
            elif p.startswith("[") and not re.match(r"\[\d+\]", p) and not re.match(r"\[\d+\.\d+", p):
                title = p.strip("[]")
        if domain:
            live[domain] = {"ip": ip, "url": url, "title": title}
    log(f"Live: {len(live)}")
    return live

# ── Fuzz target detection ─────────────────────────────────────
def detect_fuzz_targets(live):
    targets = []
    for domain, info in live.items():
        combined = domain.lower() + " " + info.get("title", "").lower()
        if any(kw in combined for kw in FUZZ_TRIGGERS):
            targets.append(info.get("url", domain))
    return targets

# ── Write scan input files ────────────────────────────────────
def write_scan_files(live):
    with open(NEW_FILE, "w") as f:
        for domain, info in live.items():
            f.write(f"{domain} {info['ip']}\n")
    log(f"✅ Written {len(live)} entries to {NEW_FILE}")

    fuzz = detect_fuzz_targets(live)
    with open(FUZZ_FILE, "w") as f:
        if fuzz:
            f.write("\n".join(fuzz))
    if fuzz:
        log(f"🎯 {len(fuzz)} fuzz targets → {FUZZ_FILE}")
    return fuzz

def append_pending(live):
    with open(PENDING_FILE, "a") as f:
        for domain, info in live.items():
            f.write(f"{domain} {info['ip']}\n")
    log(f"⏳ Queued {len(live)} assets to {PENDING_FILE}")

# ── Main ──────────────────────────────────────────────────────
def main():
    initial_mode = not is_initial_done()
    if initial_mode:
        log("🆕 Initial run — will scan everything")
        notify("🚀 RedBull Recon — initial run starting")

    # 1. Fetch current scope
    current_scope = fetch_scope()

    # 2. Load old scope
    old_scope = load_set(STATE_FILE)

    # 3. Diff
    if initial_mode:
        new_domains   = current_scope
        removed       = set()
    else:
        new_domains   = current_scope - old_scope
        removed       = old_scope - current_scope
        log(f"New: {len(new_domains)} | Removed: {len(removed)}")

        if removed:
            notify(
                f"🗑 Removed from RedBull scope ({len(removed)}):\n"
                + "\n".join(sorted(removed)[:20])
            )

    if not new_domains:
        log("No new assets — nothing to do")
        save_set(STATE_FILE, current_scope)
        open(NEW_FILE, "w").close()
        sys.exit(0)

    # 4. Probe live
    live = probe_live(new_domains)

    if not live:
        log("No live hosts found")
        save_set(STATE_FILE, current_scope)
        open(NEW_FILE, "w").close()
        sys.exit(0)

    # 5. Notify immediately before scans
    mode_label = "INITIAL" if initial_mode else "NEW"
    sub_lines  = "\n".join(
        f"  {d} ({info['ip']}) {info['title']}"
        for d, info in sorted(live.items())[:30]
    )
    notify(
        f"🔍 RedBull {mode_label} ASSETS ({len(live)}):\n{sub_lines}"
        + ("\n...and more" if len(live) > 30 else "")
    )

    # 6. Update state
    save_set(STATE_FILE, current_scope)

    # 7. Queue or trigger
    if is_scan_running():
        append_pending(live)
        notify(f"⏳ Scan running — queued {len(live)} RedBull assets")
    else:
        fuzz = write_scan_files(live)
        if fuzz:
            notify(f"🎯 Fuzz targets:\n" + "\n".join(fuzz[:10]))

    # 8. Mark initial done
    if initial_mode:
        open(INIT_FLAG, "w").close()
        log("✅ Initial scan flag set")

if __name__ == "__main__":
    main()
