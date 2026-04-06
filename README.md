# RedBull Recon Pipeline

Automated recon and vulnerability scanning for RedBull bug bounty (Intigriti).

## Repo structure

```
redbull-recon/
├── .github/
│   └── workflows/
│       ├── scope-monitor.yml   ← runs every 6h
│       ├── nuclei-scan.yml     ← triggered on new assets
│       └── naabu-scan.yml      ← triggered on new assets
├── custom-templates/           ← your handpicked Nuclei templates
│   ├── tomcat/
│   ├── jolokia-actuator/
│   ├── aws/
│   ├── cloudinary/
│   └── general/
├── monitor.py
├── scope_state.txt             ← auto-managed
├── new_host.txt                ← auto-managed
├── pending_assets.txt          ← auto-managed
├── fuzz_targets.txt            ← auto-managed
├── scan_lock.txt               ← auto-managed (deleted after scan)
└── initial_scan_done.flag      ← created after first full scan
```

## Setup

### 1. GitHub Secrets required
| Secret | Value |
|--------|-------|
| `TELEGRAM_TOKEN` | Your bot token |
| `CHAT_ID` | Your Telegram chat ID |
| `PAT_TOKEN` | GitHub PAT with `repo` + `workflow` scopes |

### 2. Add custom templates
Upload your handpicked templates to `custom-templates/`:
- Tomcat manager/status/RCE
- Jolokia + Spring actuator endpoints
- Java deserialization
- AWS credentials/bucket exposure
- Cloudinary key exposure
- General: `.env`, git-config, secrets, tokens, takeovers

### 3. Push and enable Actions
```bash
git add .
git commit -m "Initial setup"
git push
```
Go to Actions tab → enable workflows if prompted.

## How it works

| Run | Behaviour |
|-----|-----------|
| First run (no `initial_scan_done.flag`) | Fetch full scope → httpx all → scan everything |
| Every 6h after | Fetch scope → diff → httpx new only → scan new only |

## State files
| File | Purpose |
|------|---------|
| `scope_state.txt` | Full current scope snapshot |
| `new_host.txt` | Current run's new live hosts (domain + ip) |
| `pending_assets.txt` | Queued if scan was running during monitor |
| `fuzz_targets.txt` | Hosts flagged for fuzzing |
| `scan_lock.txt` | Present while scans are running |
| `initial_scan_done.flag` | Marks first full scan complete |
