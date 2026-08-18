"""Fetch ENISA's EU Vulnerability Database (EUVD) known-exploited list.

No auth. /api/kev/dump returns the FULL catalog in one call (unlike
/api/exploitedvulnerabilities, which ignores its own page/size params and
always returns the same small fixed set -- not usable for a full export).

The dump mixes two very different things under one list: entries ENISA
mirrors wholesale from CISA KEV ("cisa_kev" tag -- the vast majority) and
entries from ENISA's own independent EU-specific findings ("eukev_kev"
tag -- a few dozen). Since the CISA column already covers the mirrored
entries, the ENISA column here is deliberately restricted to
"eukev_kev"-tagged entries only, so it reflects ENISA's own catalog
rather than double-counting CISA's.
"""
from http_util import get_json

DUMP_URL = "https://euvdservices.enisa.europa.eu/api/kev/dump"
OWN_SOURCE_TAG = "eukev_kev"


def fetch():
    entries = get_json(DUMP_URL)
    result = {}
    for entry in entries:
        cve_id = entry.get("cveId")
        date_added = entry.get("dateAdded")
        if not cve_id or not date_added:
            continue
        if OWN_SOURCE_TAG not in (entry.get("sources") or []):
            continue
        euvd_id = entry.get("euvdId")
        existing = result.get(cve_id)
        if existing is None or date_added < existing["date_added"]:
            result[cve_id] = {"date_added": date_added, "enisa_id": euvd_id}
    return result


if __name__ == "__main__":
    rows = fetch()
    print(f"ENISA EUVD (own eukev findings only): {len(rows)} CVEs")
