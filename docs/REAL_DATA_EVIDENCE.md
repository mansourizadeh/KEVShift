# Evidence with Real CISA Catalog Data

## Why this exists
The synthetic demo (CVE-2099-xxxx) is repeatable but cannot show that the application handles a *real* catalog. This
document records what was checked against real data, how, and, just as important, what was **not** checked.

## The real data
`sample_data/real/` holds three snapshots of the CISA Known Exploited Vulnerabilities catalog, **unmodified**, extracted
byte-for-byte from the git history of CISA's own repository `https://github.com/cisagov/kev-data` (file
`known_exploited_vulnerabilities.json`). The data is licensed CC0 (`LICENSE_CC0_CISA_KEV.txt`).

| File | catalogVersion | dateReleased | Entries | Source commit (kev-data) |
|---|---|---|---|---|
| `cisa_kev_2026-10-01.json` | 2026.10.01 | 2026-10-01T19:54:04Z | 1,731 | a25b61fbc5e3125030a15e09adba33f427cc0e25 |
| `cisa_kev_2026-10-15.json` | 2026.10.15 | 2026-10-15T17:00:11Z | 1,746 | 7923b5f7040256ca9887d268b4c2a02453a2ff30 |
| `cisa_kev_2026-10-23.json` | 2026.10.23 | 2026-10-23T19:30:18Z | 1,756 | b9c486ef8f3ba0709bb662ae843ffee96953c400 |

`manifest.json` records each file's SHA-256, size and source commit; a test fails if any file is edited.
The dates 1 October and 15 October match the scenario in the project specification.

**What really changed in the catalog:** 1 Oct -> 15 Oct: 15 CVEs added, 0 removed. 15 Oct -> 23 Oct: 10 added, 0 removed.

## Where the files came from (honest provenance)
The official URL `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` could **not** be
reached from the environment where the project was built (its network proxy refused `www.cisa.gov`). CISA's own GitHub
repository, which publishes the same file and its history, was reachable, so the snapshots were taken from there. They
are real CISA data, but they were **not downloaded from the cisa.gov endpoint**.

## What was checked, and the result
Everything below uses real bytes and the application's own code.

| Check | Result |
|---|---|
| The validator accepts all three real files (structure, declared count equals actual count, valid IDs and dates) | pass |
| Real files contain fields the app does not use (`forensicTriage`, `cwes`, `notes`); they are ignored safely | pass |
| Each real snapshot is stored with every entry; saved file is byte-identical; every entry (including typographic characters such as curly quotes) round-trips through SQLite unchanged | pass |
| An unchanged real catalog does not create a second snapshot | pass |
| Every one of 1,756 real IDs matches itself and nothing longer, shorter or lower-case, through **both** matching functions | pass |
| Real substring traps: listed IDs that are a prefix of other listed IDs (`CVE-2020-1464`/`CVE-2020-14644`, `CVE-2022-2294`/`CVE-2022-22948`, `CVE-2022-4135`/`CVE-2022-41352`) each match only themselves; a scan that reports only the short ID is not flagged when only the long one is listed | pass |
| 1 Oct -> 15 Oct scenario with real catalogs and **no new scan**: a finding for a CVE really added on 8 Oct goes from "No KEV match" to "Newly added to KEV", with the real `dateAdded` and real vulnerability name read from the file | pass |
| A third real snapshot turns that finding into "Still present and listed in KEV", and a CVE added 15 -> 23 Oct is flagged "Newly added" | pass |
| Analysis of the stored real snapshots is identical before and after an application restart | pass |
| Offline fallback to a cached real snapshot; a half-downloaded real file is rejected and the previous real snapshot is untouched | pass |
| "Not observed in latest scan" with real CVEs makes no remediation claim | pass |

Run them: `python -m pytest tests/test_real_catalog.py -v` (22 tests). Per-snapshot reports produced by
`tools/verify_real_kev.py`: `docs/real_evidence/`.

**Do the tests actually test?** The tests were checked by deliberately breaking the code (a "mutation check"). With the
matching function changed to substring search, 5 of the real-data tests fail. This check also exposed a gap in the first
version of these tests (they exercised only one of the two matching functions); that was fixed and re-checked.

## What was NOT verified (do not claim it)
1. **The live download from cisa.gov.** Not possible in the build environment. Run
   `python tools/verify_real_kev.py` on a connected computer; it downloads the feed with the application's own client and
   writes `data/real_kev_evidence.md`. Until that is done, say: "verified against real catalog files from CISA's official
   repository; live endpoint check to be done on the target machine".
2. **Real scanner output.** The scans are synthetic, with real CVE IDs in invented assets. This shows the logic with
   real catalog entries; it says nothing about any real system. No Nessus adapter exists.
3. **Interpretation of CISA's wording.** KEVShift stores the catalog text as given and never rephrases it.
4. **Removal handling on real data:** the real snapshots contain no removals, so removal detection is covered only by
   synthetic tests.

## How to repeat the check on your own computer
```
python -m pytest tests/test_real_catalog.py -v
python tools/verify_real_kev.py            # live feed, needs internet
python tools/verify_real_kev.py --file sample_data/real/cisa_kev_2026-10-15.json   # offline
```
In the dashboard you can also open **KEV catalog -> Load a KEV JSON file manually** and load the three real files in date
order (oldest first); then import any CSV and open **Findings** and **History**.
