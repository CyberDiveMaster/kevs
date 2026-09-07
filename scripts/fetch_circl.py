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
            # GCVE BCP-07 (the format CIRCL's KEV API implements) defines
            # asserted_at as "Date when an authority or source officially
            # declared exploitation", explicitly noting it "mirrors
            # fields such as 'date added' in KEV lists" -- so it, not
            # anything else here, is the counterpart of CISA's dateAdded
            # and friends that the other four columns show.
            #
            # About 5 of ~23 CIRCL-Local entries omit asserted_at, so
            # first_seen_at ("earliest known exploitation activity based
            # on technical observation") is the fallback -- earlier than
            # a declaration by definition, but the closest thing on hand.
            #
            # status.status_updated_at is deliberately NOT used: per spec
            # it is "the last change to the exploitation status", i.e.
            # record metadata, not a listing date. CVE-2021-44228 shows
            # why that matters -- its entry asserts 2026-09-03 while
            # status_updated_at says 2024-06-03, and reading the latter
            # as a listing date is simply wrong.
            timestamps = row.get("timestamps") or {}
            date_added = timestamps.get("asserted_at") or timestamps.get("first_seen_at")
            if not date_added:
                continue
            date_added = date_added[:10]  # ISO datetime -> date
            # Kept so the viewer can deep-link to CIRCL's own per-entry
            # page (/known-exploited-vulnerabilities-catalog/{uuid}),
            # which actually displays these dates -- the generic
            # /vuln/{CVE} page only shows a badge linking here, mixing
            # all four catalogs' entries together.
            entry_uuid = row.get("uuid")
            existing = result.get(cve_id)
            if existing is None or date_added < existing["date_added"]:
                result[cve_id] = {"date_added": date_added, "entry_uuid": entry_uuid}
        count = meta.get("count", 0)
        if page * PER_PAGE >= count:
            break
        page += 1
    return result


if __name__ == "__main__":
    rows = fetch()
    print(f"CIRCL KEV (own curation only): {len(rows)} CVEs")
