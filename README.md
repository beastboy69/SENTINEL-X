# SENTINEL-X | Hackathon Prototype

A local-first defensive analysis prototype with a browser dashboard, SQLite persistence, explainable rules, synthetic fixtures, and an optional read-only Windows Event Log metadata collector.

## Requirements
- Python 3.10 or newer recommended
- No third-party Python packages
- A modern browser

## Run on Windows
1. Extract the ZIP.
2. Open PowerShell in the extracted `SENTINEL-X-Fullstack` folder.
3. Start the app:

```powershell
python backend/server.py
```

4. Open `http://127.0.0.1:8080` in your browser.
5. Keep the terminal open while using the app. Press `Ctrl+C` to stop it.

If port 8080 is occupied, run `python backend/server.py --port 8090` and open `http://127.0.0.1:8090`.

## Run tests
Open a second PowerShell window in the project folder:

```powershell
python -m unittest discover -s tests -v
```

The tests cover rule wiring, negative fixtures, duplicate-safe triage, API response behavior, and legal/static routes. They do not establish real-world detection accuracy.

## Personal Cybersecurity Analyst modules
- **Phishing URL analysis:** deterministic URL-structure heuristics plus DNS resolution; does not visit links or claim threat-intelligence reputation.
- **Phishing email analysis:** text/header heuristics for urgency, credential requests, payment pressure, links, OTP language and From/Reply-To mismatch. It does not verify SPF/DKIM/DMARC or attachment safety.
- **Local data exposure scan:** scans a user-selected folder, text-like extensions only, with per-file size and file-count limits. Reports relative path and match category only; does not display/store matched values or modify files.
- **Password breach lookup:** optional Have I Been Pwned Pwned Passwords range API using k-anonymity (only first five SHA-1 hex characters sent). Requires internet; the password is not stored or sent. The UI clears the field after a completed response.
- **Windows endpoint telemetry:** existing read-only System, Defender and PowerShell event metadata collector.

These are functional prototype tools, not full antivirus/EDR. Heuristic scores are not calibrated probabilities. A clean result does not prove safety. Email breach status for an email address is not included because reliable HIBP email lookups require an API key and user authorization; no account/passwords are scraped. Folder scanning does not monitor outbound network transfers or cloud storage activity.

## What it does
- Serves the frontend and local JSON API from one process.
- Stores synthetic event metadata and explainable rule findings in SQLite.
- Offers buttons to add fixtures, run rule tests, and re-run triage.
- On Windows, the live collection control reads recent metadata from System, Windows Defender Operational, and PowerShell Operational logs; it polls every 30 seconds while enabled and does not store event messages or script contents.
- The collection status area reports success/failure per log so inaccessible channels are not silently presented as collected.
- On Windows, the backend does not automatically seed synthetic events into a fresh database. Synthetic fixtures can still be added manually for a demo.
- Avoids duplicate findings when triage is run more than once.
- Includes a favicon, privacy policy, and terms page for prototype review.

## Honest limitations
- Live Windows collection requires the backend to run on Windows with access to the selected event logs. It is not active when the backend runs on Linux or another operating system.
- This is near-real-time polling, not a push subscription: it checks a recent 15-minute window every 30 seconds only while the browser tab is open. The database deduplicates repeated event metadata. It is not a durable streaming agent and is not guaranteed to capture every event under all conditions.
- Running `START_SENTINEL_X.bat` on Windows launches the local backend. Alternatively, run `python backend/server.py` from PowerShell in this folder. Open `http://127.0.0.1:8080` and press **Start live collection**. Leave the browser tab open while collecting.
- The backend is intentionally loopback-only. Do not change the host to `0.0.0.0` or expose this prototype to a network.
- Synthetic demo data is still available and is clearly marked.
- Rules are deterministic examples, not machine-learning detection or validated threat intelligence.
- No claim is made about precision, recall, protection, or production readiness.
- The server binds to `127.0.0.1` by default. Do not expose it to the public internet as-is.
- The legal pages describe the included local prototype and must be reviewed against the final deployment and operator details.

## Public launch gate
**Do not launch publicly until all are completed and verified:**
- Configure and verify the custom domain and HTTPS.
- Verify favicon on the deployed domain.
- Confirm any hosting-platform badge/branding is removed where permitted by that platform.
- Review and finalize privacy and terms pages, including real operator contact details and applicable jurisdiction.
- Add production-appropriate authentication/access controls and deployment security configuration.
- Test the deployed site, API error handling, mobile layout, and backup/data-deletion process.

This repository is a hackathon-ready local demonstration, not a production security service.
