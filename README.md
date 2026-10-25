# KEVShift: Explainable Vulnerability Change Tracking

KEVShift is a local application that imports vulnerability scan results you already have,
stores their history, compares the reported CVEs with the CISA Known Exploited Vulnerabilities
(KEV) catalog, and explains what changed between catalog snapshots and between comparable scans.

KEVShift is **not** a vulnerability scanner. It never scans a network, never tries to exploit
anything, never logs in anywhere, and never claims that an asset has been attacked.

**Central idea:** a CVE that was *not* in the KEV catalog when your scan ran can be *added* later.
Because KEVShift keeps every scan and every catalog snapshot, it can show that change even if you
never imported a new scan, and it explains each flag in plain English.

---

## 1. What is in the project

```
kevshift/
  app.py                 Streamlit dashboard (pages only, no business rules)
  requirements.txt       Python packages
  pytest.ini             Test settings
  src/
    validators.py        CVE-ID and date validation shared by all modules
    models.py            Plain data containers
    csv_importer.py      CSV validation, duplicate detection, rejection reports
    database.py          SQLite schema and history storage
    kev_client.py        KEV download, validation, snapshot saving, offline fallback
    change_detector.py   The comparison rules (pure functions)
    workflow.py          Glue: import a scan, run an analysis
    reporting.py         Findings table, filters, CSV export, text reports
    epss_client.py       Optional EPSS scores (supplementary)
    demo.py              Synthetic demonstration scenario
  tests/                 128 automated tests
  sample_data/           Synthetic scans and KEV snapshots (all invented)
  data/                  Created at run time: database, saved KEV snapshots, uploaded files
  docs/                  Architecture, schema, module guide, report, demo script, defense Q&A, glossary
```

Read in this order: `docs/ARCHITECTURE.md`, `docs/MODULE_GUIDE.md`, then the code.
Other documents: `docs/STAGES.md` (what was done, stage by stage), `docs/GITHUB_GUIDE.md`, `docs/DATABASE_SCHEMA.md`,
`docs/PROJECT_REPORT.md`, `docs/DEMO_SCRIPT.md`, `docs/DEFENSE_QUESTIONS.md`, `docs/GLOSSARY.md`.

---

## 2. Install on Windows (no administrator rights needed)

### 2.1 Install Python
1. Install Python 3.10 or newer from https://www.python.org/downloads/ (or the Microsoft Store).
2. In the installer, tick **"Add python.exe to PATH"**.
3. Open **Command Prompt** (a normal one, not "Run as administrator") and check:
   ```
   python --version
   ```
   If `python` is not recognized, try `py --version` and use `py` instead of `python` below.

### 2.2 Open a terminal INSIDE the project folder
Unzip the project, then go into the folder that contains `app.py` and `requirements.txt`.
Replace the path with your own:
```
cd /d C:\Users\YourName\Downloads\kevshift
dir
```
`dir` must list `app.py`, `requirements.txt`, `src` and `tests`. If it does not, you are in the wrong
folder (never work from `C:\Windows\system32`).

### 2.3 (Recommended) create a virtual environment
A virtual environment keeps this project's packages separate from the rest of your computer.
```
python -m venv .venv
.venv\Scripts\activate
```
Your prompt now starts with `(.venv)`. If PowerShell blocks activation, use Command Prompt, or run
`Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.

### 2.4 Install the packages (needs internet once)
```
python -m pip install -r requirements.txt
```

### 2.5 Run the tests
```
python -m pytest
```
Expected result: `128 passed`. (Run `python -m pytest -v` to see every test name.)

### 2.6 Start the dashboard
```
python -m streamlit run app.py
```
Your browser opens http://localhost:8501. Press `Ctrl+C` in the terminal to stop it.
(`streamlit run app.py` also works if the `streamlit` command is on your PATH.)

---

## 3. Using the dashboard

The sidebar has two choices:

* **Data set**: `My data` (your real data, stored in `data/`) or `Synthetic demo` (invented data in `data/demo/`).
* **Page**: Overview, Import scan CSV, KEV catalog, Findings, History, Help and limitations.

### First run with your own data
1. **KEV catalog** page -> *Refresh KEV catalog now*. This downloads the official CISA feed and saves a snapshot.
   No internet? Use *Load a KEV JSON file manually* (see Troubleshooting).
2. **Import scan CSV** page -> upload your CSV. Type a **comparable scan group** label (for example
   `internal-weekly`) and use the *same* label for scans made with the same scope and settings.
   Review the validation result, then press *Save accepted rows to the database*.
3. **Findings** page -> filter, read the explanations, download the CSV.
4. Come back later and press *Refresh KEV catalog now* again. If CISA added CVEs that match your
   stored findings, they appear as **Newly added to KEV** even though you imported no new scan.

### CSV format
```
asset_name,cve_id,scan_date,finding_status
web-server-01,CVE-2025-12345,2025-10-01,open
```
* `cve_id`: `CVE-YYYY-NNNN` (4 or more digits). Spaces and lower case are fixed automatically.
* `scan_date`: `YYYY-MM-DD`, not in the future.
* `finding_status`, one of:

| Status | Meaning |
|---|---|
| `open` | The scanner reports the vulnerability as present |
| `in_progress` | The finding is being worked on |
| `mitigated` | A mitigation is recorded, but the vulnerability may still exist |
| `accepted_risk` | The organization decided to accept the risk |
| `false_positive` | The finding was judged to be a scanner mistake |

Rows that are invalid are **never silently dropped**: they are listed with the reason and can be
downloaded as a validation report. Duplicate rows (same asset and CVE in one file) are ignored and counted.
Excel users: save as **CSV UTF-8 (Comma delimited)**.

### Change categories

| Category | Meaning (short) |
|---|---|
| Newly added to KEV | In the latest scan, listed in the selected snapshot, not in the one before |
| First observed KEV match | Listed in KEV, but no earlier snapshot exists to compare |
| Still present and listed in KEV | Listed in both snapshots |
| Not observed in latest scan | In an earlier scan of the same comparable group, missing from the latest. **Not** called fixed |
| Needs manual review | Listed in KEV but status is mitigated / accepted_risk / false_positive |
| No KEV match | Not listed in the selected snapshot |

---

## 4. The synthetic demonstration

All demo data is invented (CVE IDs use the unassigned year `2099`).

**In the dashboard:** choose *Synthetic demo*, press *Load demo up to step 1*, look at **Findings**; then
step 2, then step 3.

**On the command line:**
```
python -m src.demo
```
It prints the three reports and saves them in `data/demo_reports/`. Pre-generated copies are in
`docs/demo_reports/`. See `docs/DEMO_SCRIPT.md` for a 3-5 minute presentation script.

---

## 5. Safety and design rules

* Network access is limited to two public sources: the CISA KEV feed and (optionally) the FIRST EPSS API.
  Every request has a timeout and its HTTP status is checked.
* A downloaded catalog is validated **before** it is saved. An invalid or incomplete response never replaces a
  valid snapshot; the app falls back to the last valid snapshot and says clearly that the refresh failed.
* SQL is parameterized. Uploaded CSV content is only ever treated as text, never executed. Exported CSV files
  neutralize spreadsheet formulas.
* No credentials or secrets are stored. Timestamps are in UTC.
* Streamlit itself may try to look up your public IP address to print an "External URL" when it starts; that is
  Streamlit's behavior, not KEVShift's.

---

## 6. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `ERROR: Could not open requirements file ... 'requirements.txt'` | You are not in the project folder. `cd /d` into the folder that contains `requirements.txt` (check with `dir`). |
| `ProxyError('Cannot connect to proxy') ... WinError 10061` during `pip install` | Windows or pip is set to use a proxy (often a VPN/filter tool) that is not running. Check: `echo %HTTPS_PROXY%` and `echo %HTTP_PROXY%` and `pip config list`. Start the proxy/VPN program, or clear it for this window: `set HTTP_PROXY=` and `set HTTPS_PROXY=` then repeat `python -m pip install -r requirements.txt`. Also check Windows Settings -> Network -> Proxy and turn off "Use a proxy server" if you do not need it. If your internet needs a proxy, set it to the correct address and port: `python -m pip install -r requirements.txt --proxy http://HOST:PORT`. |
| `getaddrinfo failed` / `Failed to establish a new connection` during `pip install` | No internet, DNS, VPN or proxy problem. Check a browser can open https://pypi.org, try another network or DNS (8.8.8.8 / 1.1.1.1), turn a VPN on or off, then repeat the install. |
| `'python' is not recognized` | Python is not on PATH. Re-run the installer and tick *Add to PATH*, or use `py` instead of `python`. |
| `'streamlit' is not recognized` | Use `python -m streamlit run app.py`. |
| `ModuleNotFoundError: No module named 'src'` | Start the app or tests from the project folder (the one containing `app.py`). |
| `ModuleNotFoundError: No module named 'streamlit'` (or pandas, pytest) | Activate the virtual environment, then `python -m pip install -r requirements.txt`. |
| PowerShell: *running scripts is disabled* | Use Command Prompt, or `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`. |
| Port 8501 already in use | `python -m streamlit run app.py --server.port 8502`. |
| Refresh button shows an error and "cached" data | The download failed (no internet, firewall, CISA down). The last valid snapshot is still used and its age is shown. Try again later. |
| No internet at all, but you have a KEV JSON file | KEV catalog page -> *Load a KEV JSON file manually*. It is validated like a download; the load time is recorded as its retrieval time. |
| "The file is not UTF-8 text" | In Excel use *Save As -> CSV UTF-8 (Comma delimited)*. |
| "Missing required column(s)" | The header row must contain `asset_name,cve_id,scan_date,finding_status`. |
| "This exact file was already imported" | The same file content was saved before (history is never duplicated). |
| Findings page says "No findings" | Import a scan CSV and make sure a KEV snapshot exists. |
| No "Not observed" rows | Give both scans the same comparable group label, with a later scan date on the second. |
| `database is locked` | Another copy of the app is open. Close it and retry. |
| Start from scratch | Close the app and delete the `data` folder contents (not the folder itself). |

Python version note: the project was developed and its 128 tests were run on Python 3.13. Python 3.10 or newer
is required. If a package fails to install on a very new Python release, install Python 3.12 or 3.13 and repeat.

---

## 7. Optional EPSS

On the **Findings** page, the expander *Supplementary: EPSS* can fetch EPSS values for KEV-listed CVEs from
the official FIRST API and cache them. EPSS estimates the probability of exploitation in the wild soon; KEV
records documented exploitation. EPSS never replaces KEV change detection and is never used to rank rows.

## 8. Limitations and future work

* "Latest comparable scan" depends on the comparable-group label you assign; KEVShift cannot verify that two
  scans really used the same scope.
* Only the exact CVE ID is matched; there is no product or version analysis.
* A Nessus (or other scanner) CSV adapter and CVSS enrichment were intentionally left out; they are listed as
  future work in `docs/PROJECT_REPORT.md`.
