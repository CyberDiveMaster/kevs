"""Fetch VulnCheck's Community KEV catalog.

Requires VULNCHECK_API_KEY (Bearer token). The /v3/backup/vulncheck-kev
endpoint returns a short-lived presigned S3 URL to a single JSON file
containing the FULL catalog -- much cheaper than paginating the live
/v3/index/vulncheck-kev endpoint one page at a time.
"""
import io
import json
import os
import re
import zipfile

import requests

from http_util import USER_AGENT, get_json

BACKUP_URL = "https://api.vulncheck.com/v3/backup/vulncheck-kev"
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")


def fetch():
    api_key = os.environ["VULNCHECK_API_KEY"]
    headers = {"Authorization": f"Bearer {api_key}"}

    backup_meta = get_json(BACKUP_URL, headers=headers)
    download_url = backup_meta["data"][0]["url"]

    resp = requests.get(download_url, headers={"User-Agent": USER_AGENT}, timeout=120)
    resp.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        json_name = next(n for n in zf.namelist() if n.endswith(".json"))
        entries = json.loads(zf.read(json_name))

    result = {}
    for entry in entries:
        date_added = entry.get("date_added")
        if not date_added:
            continue
        date_added = date_added[:10]
        for cve_id in entry.get("cve") or []:
            if not CVE_RE.match(cve_id):
                continue
            existing = result.get(cve_id)
            if existing is None or date_added < existing:
                result[cve_id] = date_added
    return result


if __name__ == "__main__":
    rows = fetch()
    print(f"VulnCheck KEV: {len(rows)} CVEs")
