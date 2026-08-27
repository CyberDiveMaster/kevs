"""Orchestrator: fetch all 5 KEV catalogs, take their union, look up
Date Published / CVSS / Vendor / Product for every CVE from the official
CVE Program record, and export docs/data/kevs.json + meta.json for the
static Tabulator viewer.

Any single source failing raises and aborts the whole build (non-zero
exit) rather than silently exporting a partial dataset -- a transient
API outage should never make a CVE look like it "isn't listed" in a
catalog it's actually in. The next scheduled run retries from scratch.
"""
import datetime
import json
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

import fetch_cisa
import fetch_circl
import fetch_enisa
import fetch_kevintel
import fetch_vulncheck
from fetch_cve_metadata import ensure_metadata

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_PATH = os.path.join(REPO_ROOT, "data", "cve_metadata_cache.json")
DOCS_DATA_DIR = os.path.join(REPO_ROOT, "docs", "data")


def main():
    print("Fetching CISA KEV...")
    cisa = fetch_cisa.fetch()
    print(f"  {len(cisa)} CVEs")

    print("Fetching ENISA EUVD...")
    enisa = fetch_enisa.fetch()
    print(f"  {len(enisa)} CVEs")

    print("Fetching CIRCL KEV...")
    circl = fetch_circl.fetch()
    print(f"  {len(circl)} CVEs")

    print("Fetching VulnCheck KEV...")
    vulncheck = fetch_vulncheck.fetch()
    print(f"  {len(vulncheck)} CVEs")

    print("Fetching KEVIntel...")
    kevintel = fetch_kevintel.fetch()
    print(f"  {len(kevintel)} CVEs")

    all_cve_ids = sorted(set(cisa) | set(enisa) | set(circl) | set(vulncheck) | set(kevintel))
    print(f"Union: {len(all_cve_ids)} unique CVEs")

    print("Resolving CVE metadata (Date Published / CVSS / Vendor / Product)...")
    metadata, fetched = ensure_metadata(all_cve_ids, CACHE_PATH)
    print(f"  fetched {fetched} new record(s), {len(metadata)} cached total")

    rows = []
    for cve_id in all_cve_ids:
        enisa_entry = enisa.get(cve_id)
        catalog_dates = {
            "cisa_added": cisa.get(cve_id),
            "enisa_added": enisa_entry["date_added"] if enisa_entry else None,
            "circl_added": circl.get(cve_id),
            "kevintel_added": kevintel.get(cve_id),
            "vulncheck_added": vulncheck.get(cve_id),
        }
        present_dates = [d for d in catalog_dates.values() if d]
        active_since = min(present_dates) if present_dates else None

        meta = metadata.get(cve_id, {})
        vendor, product = meta.get("vendor"), meta.get("product")
        # cna_vendor/cna_product are only absent for cache entries from
        # before the NVD fallback existed -- treat "key genuinely missing"
        # as "unknown, not NVD" rather than mistaking every pre-migration
        # CNA-sourced value (the vast majority of the cache) for an NVD one.
        # Once such an entry is (re)fetched, the key always exists (as a
        # real value or explicit None), so this self-corrects over time.
        vendor_from_nvd = (
            vendor is not None and "cna_vendor" in meta
            and meta["cna_vendor"] in (None, "n/a")
        )
        product_from_nvd = (
            product is not None and "cna_product" in meta
            and meta["cna_product"] in (None, "n/a")
        )
        rows.append({
            "cve_id": cve_id,
            "date_published": meta.get("date_published"),
            "cvss_score": meta.get("cvss_score"),
            "cvss_version": meta.get("cvss_version"),
            "vendor": vendor,
            "vendor_from_nvd": vendor_from_nvd,
            "product": product,
            "product_from_nvd": product_from_nvd,
            "active_since": active_since,
            "enisa_id": enisa_entry["enisa_id"] if enisa_entry else None,
            **catalog_dates,
        })

    os.makedirs(DOCS_DATA_DIR, exist_ok=True)
    with open(os.path.join(DOCS_DATA_DIR, "kevs.json"), "w", encoding="utf-8") as f:
        json.dump(rows, f, separators=(",", ":"))

    meta_out = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat(),
        "cve_count": len(rows),
        "source_counts": {
            "cisa": len(cisa),
            "enisa": len(enisa),
            "circl": len(circl),
            "vulncheck": len(vulncheck),
            "kevintel": len(kevintel),
        },
    }
    with open(os.path.join(DOCS_DATA_DIR, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta_out, f, indent=1)

    print(f"Wrote {len(rows)} rows to docs/data/kevs.json")


if __name__ == "__main__":
    main()
