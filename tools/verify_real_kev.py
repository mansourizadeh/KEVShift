"""Check KEVShift against a REAL CISA catalog and write an evidence report.

Run from the project folder:

    python tools/verify_real_kev.py                 # download the live feed from cisa.gov (needs internet)
    python tools/verify_real_kev.py --file cisa.json   # use a file you saved (works offline)

It uses the application's own code (download, validation, storage, matching) in a throw-away database,
so nothing in your data/ folder is touched. Exit code 0 = every check passed, 1 = a check failed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src import change_detector, database, kev_client  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--file", help="KEV JSON file to check instead of downloading")
    parser.add_argument("--out", default="data/real_kev_evidence.md", help="where to write the evidence report")
    args = parser.parse_args()

    checks: list = []

    def check(name: str, ok: bool, detail: str = "") -> bool:
        checks.append((name, ok, detail))
        print(("PASS  " if ok else "FAIL  ") + name + (f" - {detail}" if detail else ""))
        return ok

    if args.file:
        raw = Path(args.file).read_bytes()
        source = f"file: {args.file}"
    else:
        print(f"Downloading {kev_client.KEV_FEED_URL} ...")
        try:
            raw = kev_client.download_kev_json()
        except kev_client.KevDownloadError as exc:
            print(f"FAIL  download - {exc}")
            print("Tip: open the URL in your browser, save the file, and run again with --file saved.json")
            return 1
        source = kev_client.KEV_FEED_URL
    check("obtained data", bool(raw), f"{len(raw)} bytes from {source}")

    try:
        snapshot = kev_client.parse_kev_json(raw)
    except kev_client.KevFormatError as exc:
        check("parse and validate", False, str(exc))
        return 1
    declared = json.loads(raw).get("count")
    check("parse and validate", True, f"version {snapshot.catalog_version}, released {snapshot.date_released}")
    check("entry count equals the count declared in the file", declared == len(snapshot.entries),
          f"{len(snapshot.entries)} entries, declared {declared}")

    index = {e.cve_id: e for e in snapshot.entries}
    check("every entry matches itself and no longer or lower-case variant does",
          all(change_detector.match_kev(c, index) is index[c] and change_detector.match_kev(c + "0", index) is None
              and change_detector.match_kev(c.lower(), index) is None for c in index))
    pairs = [(c[:-1], c) for c in index if c[:-1] in index]
    check("real prefix pairs (one listed ID inside another) match only themselves",
          all(change_detector.match_kev(a, index) is index[a] and change_detector.match_kev(b, index) is index[b]
              for a, b in pairs), f"{len(pairs)} pair(s) found: {pairs[:3]}")

    with tempfile.TemporaryDirectory() as folder:
        folder_path = Path(folder)
        conn = database.connect(folder_path / "check.db")
        database.init_schema(conn)
        stamp = database.utc_timestamp(datetime.now(timezone.utc))
        snapshot_id, created = kev_client.store_snapshot_bytes(conn, raw, folder_path, source_url=source, retrieved_at=stamp)
        info = database.get_snapshot(conn, snapshot_id)
        check("snapshot stored", created and info.entry_count == len(snapshot.entries), f"{info.entry_count} rows")
        check("saved file is byte-identical to the input", Path(info.stored_path).read_bytes() == raw)
        check("every entry round-trips through SQLite unchanged", database.get_kev_index(conn, snapshot_id) == index)
        _, created_again = kev_client.store_snapshot_bytes(conn, raw, folder_path, source_url=source, retrieved_at=stamp)
        check("unchanged content does not create a second snapshot", not created_again)
        conn.close()

    newest = sorted(snapshot.entries, key=lambda e: (e.date_added, e.cve_id), reverse=True)[:5]
    report = [
        "# KEVShift real-catalog evidence report", "",
        f"* Generated (UTC): {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}",
        f"* Source: {source}", f"* SHA-256: {hashlib.sha256(raw).hexdigest()}",
        f"* Catalog version: {snapshot.catalog_version}", f"* Date released: {snapshot.date_released}",
        f"* Entries: {len(snapshot.entries)}", "", "## Checks", "",
    ]
    report += [f"* {'PASS' if ok else 'FAIL'}: {name}" + (f" ({detail})" if detail else "") for name, ok, detail in checks]
    report += ["", "## Five most recently added entries (read from the file)", "",
               "| CVE | Date added | Vendor / product | Name |", "|---|---|---|---|"]
    report += [f"| {e.cve_id} | {e.date_added} | {e.vendor_project} / {e.product} | {e.vulnerability_name} |" for e in newest]
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(report) + "\n", encoding="utf-8")
    failed = [name for name, ok, _ in checks if not ok]
    print(f"\nEvidence report written to {out}")
    print("RESULT: ALL CHECKS PASSED" if not failed else f"RESULT: {len(failed)} CHECK(S) FAILED: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
