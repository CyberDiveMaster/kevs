"""Fetch KEVIntel's free KEV catalog (kevintel.com).

Requires KEVINTEL_API_KEY, sent as the X-API-Token header. The free tier
only exposes the paginated list endpoint (no single-CVE lookup), so we
page through the whole catalog every run.
"""
import os

from http_util import get_json

BASE_URL = "https://kevintel.com/api/v2/kevs"
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
