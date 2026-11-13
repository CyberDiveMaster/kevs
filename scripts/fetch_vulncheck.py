"""Fetch VulnCheck's Community KEV catalog.

Requires VULNCHECK_API_KEY (Bearer token). The /v3/backup/vulncheck-kev
endpoint returns a short-lived presigned S3 URL to a single JSON file
containing the FULL catalog -- much cheaper than paginating the live
/v3/index/vulncheck-kev endpoint one page at a time.

Besides the listing date, each entry's vendorProject / product are kept.
VulnCheck fills them for practically every entry (5,896 of 5,899 measured
2026-11-13), including the ~4,100 CISA does not list, and writes each
vendor one way -- which makes it a better source for the viewer's Vendor /
Product columns than cve.org's free-text CNA records, about 40% of which
just say "n/a". build.py falls back to cve.org only where a name is
missing here.
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

# What VulnCheck puts in vendorProject / product when it has no real name.
_BLANK_NAMES = {"", "-", "n/a"}


def _clean_name(value):
    if value is None:
        return None
    value = str(value).strip()
    return None if value.lower() in _BLANK_NAMES else value


def fetch():
    """Returns {cve_id: {"date_added", "vendor", "product"}}; vendor and
    product are None where VulnCheck has no usable name."""
    api_key = os.environ["VULNCHECK_API_KEY"]
    headers = {"Authorization": f"Bearer {api_key}"}

    backup_meta = get_json(BACKUP_URL, headers=headers)
    download_url = backup_meta["data"][0]["url"]

    resp = requests.get(download_url, headers={"User-Agent": USER_AGENT}, timeout=120)
    resp.raise_for_status()

    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        json_name = next(n for n in zf.namelist() if n.endswith(".json"))
        entries = json.loads(zf.read(json_name))

    return parse(entries)


def parse(entries):
    result = {}
    for entry in entries:
        date_added = entry.get("date_added")
        if not date_added:
            continue
        date_added = date_added[:10]
        vendor = _clean_name(entry.get("vendorProject"))
        product = _clean_name(entry.get("product"))
        for cve_id in entry.get("cve") or []:
            if not CVE_RE.match(cve_id):
                continue
            existing = result.get(cve_id)
            if existing is None:
                result[cve_id] = {"date_added": date_added, "vendor": vendor, "product": product}
                continue
            # Same CVE under more than one entry: the earliest listing
            # wins, and a name one entry lacks is taken from the other.
            existing["date_added"] = min(existing["date_added"], date_added)
            existing["vendor"] = existing["vendor"] or vendor
            existing["product"] = existing["product"] or product
    return result


if __name__ == "__main__":
    rows = fetch()
    named = sum(1 for r in rows.values() if r["vendor"] and r["product"])
    print(f"VulnCheck KEV: {len(rows)} CVEs ({named} with vendor and product)")
