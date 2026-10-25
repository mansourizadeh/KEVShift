# Demonstration Script (3-5 minutes)

All data is **synthetic**. Before presenting: `python -m pytest` (expect 128 passed), then
`python -m streamlit run app.py`. In the sidebar choose **Data set: Synthetic demo** and press **Reset demo data**.

## 0:00-0:30 Introduction
"KEVShift is not a scanner. It stores scan results I already have and the CISA KEV catalog over time, and explains
what changed. Its key feature: a catalog update can change the meaning of an old scan."

## 0:30-1:30 Before: 1 October
Press **Load demo up to step 1**, open **Findings**.
* Scan of 1 October reports `CVE-2099-0001` on `web-server-01`. The stored KEV snapshot (1 Oct) does not list it.
* Row says **No KEV match**. Point out `CVE-2099-0002` is **First observed KEV match** because no earlier snapshot exists:
  "I cannot claim it is new, only first observed."

## 1:30-3:00 After: 15 October (the key moment)
Press **Load demo up to step 2**, reload **Findings**.
* **No new scan was imported** (open **History** and show one scan run, two snapshots).
* `CVE-2099-0001` is now **Newly added to KEV** (CISA date added 14 Oct), comparing snapshot 1 Oct and 15 Oct.
* Read the explanation and the verification action. Stress: "It does **not** say the asset was attacked; it says
  verify and prioritize."
* Show `CVE-2099-0002` on web-server-01 = **Still present and listed in KEV**, and the `mitigated` copy on app-server-03
  = **Needs manual review**.
* Mention the substring trap: the catalog also lists `CVE-2099-00011`; matching is exact, so it never matches `...0001`.

## 3:00-3:45 Not observed in latest scan: 22 October
Press **Load demo up to step 3**.
* `CVE-2099-0003` on `db-server-02` is **Not observed in latest scan**. Read: "absence is not evidence of a change; the
  asset may not have been covered." Note it does not say fixed.

## 3:45-4:30 Safety and reproducibility
* **KEV catalog** page: source, last successful check, version, cache age. Explain failed refresh = warning/error, never a
  green success, previous snapshot untouched.
* **Findings**: use a filter, press *Download filtered findings (CSV)*.
* "Every flag can be reproduced from the saved snapshots and scans."

## 4:30-5:00 Close
Show `python -m pytest` result and limitations (user-defined comparable group, CVE-ID-only matching).

## Before-and-after reports
Saved in `docs/demo_reports/`: `demo_step1_report.*` (before), `demo_step2_report.*` (after catalog change),
`demo_step3_report.*` (after comparable scan). Regenerate with `python -m src.demo`.
