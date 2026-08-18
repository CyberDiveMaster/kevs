"""Fetch CIRCL's Known Exploited Vulnerabilities catalog (vulnerability-lookup).

No auth. CIRCL is a correlation platform, not an independent KEV source --
most entries are mirrored from an upstream (CISA, KEVIntel, Shadowserver,
ENISA). Genuinely CIRCL-original entries carry CIRCL's own "gcve" origin
UUID (1a89b78e-f703-45f3-bb86-59eb712668bd, "CIRCL Local" per
https://vulnerability.circl.lu/kev-catalogs) and -- unlike mirrored rows
-- have an EMPTY evidence list, since evidence[] exists to cite an
external corroborating source. The API supports filtering server-side by
this origin, so only CIRCL's own ~19 entries are fetched, not the whole
~2800-CVE mirror.

CIRCL is also not CVE-only -- vulnId can be a CNVD (China National
Vulnerability Database) or other non-CVE identifier; those are skipped
since this whole project is keyed by CVE ID.
"""
import re

from http_util import get_json

BASE_URL = "https://vulnerability.circl.lu/api/kev/"
PER_PAGE = 1000
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")

# "CIRCL Local" origin UUID, confirmed against the totals published at
# https://vulnerability.circl.lu/kev-catalogs (labels/totals/uuids
# embedded in that page's #kev-diagram-data script tag).
CIRCL_LOCAL_ORIGIN_UUID = "1a89b78e-f703-45f3-bb86-59eb712668bd"


def fetch():
    result = {}
    page = 1
    while True:
        resp = get_json(BASE_URL, params={
            "vulnerability_lookup_origin": CIRCL_LOCAL_ORIGIN_UUID,
            "page": page, "per_page": PER_PAGE,
        })
        meta = resp.get("metadata", {})
        rows = resp.get("data", [])
        if not rows:
            break
        for row in rows:
            cve_id = (row.get("vulnerability") or {}).get("vulnId")
            if not cve_id or not CVE_RE.match(cve_id):
                continue
            date_added = (row.get("timestamps") or {}).get("first_seen_at")
            if not date_added:
                continue
            date_added = date_added[:10]  # ISO datetime -> date
            existing = result.get(cve_id)
            if existing is None or date_added < existing:
                result[cve_id] = date_added
        count = meta.get("count", 0)
        if page * PER_PAGE >= count:
            break
        page += 1
    return result


if __name__ == "__main__":
    rows = fetch()
    print(f"CIRCL KEV (own curation only): {len(rows)} CVEs")
