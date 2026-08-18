"""Fetch CISA's Known Exploited Vulnerabilities catalog.

Single static JSON file, no auth, no pagination -- refreshed by CISA
twice daily (per their own published schedule).
"""
from http_util import get_json

FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch():
    data = get_json(FEED_URL)
    result = {}
    for vuln in data.get("vulnerabilities", []):
        cve_id = vuln.get("cveID")
        date_added = vuln.get("dateAdded")
        if cve_id and date_added:
            result[cve_id] = date_added
    return result


if __name__ == "__main__":
    rows = fetch()
    print(f"CISA KEV: {len(rows)} CVEs")
