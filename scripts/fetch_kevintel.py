"""NOT USED since 2026-11-25 -- build.py no longer imports this module.
Previdian closed its free tier (terms rewritten 2026-11-19) and deleted
the account this project's key belonged to, so every request answered
401 and, because one failed source aborts the build, the whole site
stopped updating from 2026-11-20. Kept only in case access is ever
arranged again; re-adding it also needs the column back in docs/js/app.js.

Fetch Previdian's free KEV catalog (previdian.com, formerly
kevintel.com -- KEVIntel rebranded; the old domain still works but
redirects, so this uses the current one directly).

Requires KEVINTEL_API_KEY, sent as the X-API-Token header. The free tier
only exposes the paginated list endpoint (no single-CVE lookup), so we
page through the whole catalog every run.
"""
import os

from http_util import get_json

BASE_URL = "https://previdian.com/api/v2/kevs"
PER_PAGE = 100


def fetch():
    api_key = os.environ["KEVINTEL_API_KEY"]
    headers = {"X-API-Token": api_key}

    result = {}
    page = 1
    while True:
        resp = get_json(BASE_URL, headers=headers, params={"page": page, "per_page": PER_PAGE})
        for entry in resp.get("kevs", []):
            cve_id = entry.get("cve_id")
            date_added = entry.get("added_date")
            if not cve_id or not date_added:
                continue  # GHSA-only / pre-CVE (VULN-*) entries have no CVE ID
            date_added = date_added[:10]
            existing = result.get(cve_id)
            if existing is None or date_added < existing:
                result[cve_id] = date_added

        pagination = resp.get("pagination", {})
        if page >= pagination.get("total_pages", page):
            break
        page += 1
    return result


if __name__ == "__main__":
    rows = fetch()
    print(f"KEVIntel: {len(rows)} CVEs")
