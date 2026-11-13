"""Orchestrator: fetch all 5 KEV catalogs, take their union, look up
Date Published / CVSS for every CVE from the official CVE Program record,
name its Vendor / Product from VulnCheck KEV (the CVE Program record only
where VulnCheck has none), and export docs/data/kevs.json + meta.json for
the static Tabulator viewer.

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
import fetch_epss
import fetch_kevintel
import fetch_vulncheck
from fetch_cve_metadata import ensure_metadata

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CACHE_PATH = os.path.join(REPO_ROOT, "data", "cve_metadata_cache.json")
EPSS_CACHE_PATH = os.path.join(REPO_ROOT, "data", "epss_cache.json")
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

    # Vendor / Product come from VulnCheck wherever it has both. cve.org's
    # own names only matter for the handful of CVEs where it doesn't, so
    # those are the only ones worth re-asking cve.org about while its
    # record still says "n/a".
    names_needed = {
        c for c in all_cve_ids
        if not (c in vulncheck and vulncheck[c]["vendor"] and vulncheck[c]["product"])
    }
    print(f"Vendor/Product: VulnCheck names {len(all_cve_ids) - len(names_needed)} CVEs, "
          f"{len(names_needed)} fall back to cve.org")

    print("Resolving CVE metadata (Date Published / CVSS / fallback Vendor / Product)...")
    metadata, fetched = ensure_metadata(all_cve_ids, CACHE_PATH, names_needed=names_needed)
    print(f"  fetched {fetched} new record(s), {len(metadata)} cached total")

    # EPSS only changes once/day (FIRST.org publishes ~13:30 UTC) -- only
    # re-download the bulk CSV on the workflow's dedicated daily schedule
    # (REFRESH_EPSS=true, 14:30 UTC); every other run just reuses whatever
    # was cached last, since re-fetching hourly would gain nothing.
    if os.environ.get("REFRESH_EPSS") == "true":
        print("Refreshing EPSS scores + trend from FIRST.org (current + 1d/7d/30d)...")
        epss_data = fetch_epss.fetch_with_trends(all_cve_ids)
        fetch_epss.save_cache(EPSS_CACHE_PATH, epss_data)
        print(f"  refreshed {len(epss_data)} CVEs")
    else:
        epss_data = fetch_epss.load_cache(EPSS_CACHE_PATH)
        print(f"Using cached EPSS scores ({len(epss_data)} CVEs, not refreshed this run)")

    rows = []
    for cve_id in all_cve_ids:
        enisa_entry = enisa.get(cve_id)
        circl_entry = circl.get(cve_id)
        vulncheck_entry = vulncheck.get(cve_id) or {}
        catalog_dates = {
            "cisa_added": cisa.get(cve_id),
            "enisa_added": enisa_entry["date_added"] if enisa_entry else None,
            "circl_added": circl_entry["date_added"] if circl_entry else None,
            "kevintel_added": kevintel.get(cve_id),
            "vulncheck_added": vulncheck_entry.get("date_added"),
        }
        present_dates = [d for d in catalog_dates.values() if d]
        active_since = min(present_dates) if present_dates else None

        meta = metadata.get(cve_id, {})
        date_published = meta.get("date_published")
        # Static baseline (all 5 catalogs included) for CSV export -- the
        # viewer recomputes this live from whichever catalogs are still
        # included when one is excluded via its header x button, same as
        # active_since itself. Can be negative: a catalog sometimes lists
        # a CVE as exploited before cve.org's own record is published.
        days_to_active = None
        if active_since and date_published:
            days_to_active = (
                datetime.date.fromisoformat(active_since)
                - datetime.date.fromisoformat(date_published[:10])
            ).days
        # Per field, not per row: VulnCheck occasionally has a vendor but
        # no product. The cve.org value is passed through as-is, so a CNA
        # that wrote a literal "n/a" still shows as "n/a".
        vendor = vulncheck_entry.get("vendor") or meta.get("cna_vendor")
        product = vulncheck_entry.get("product") or meta.get("cna_product")
        epss_entry = epss_data.get(cve_id) or {}
        rows.append({
            "cve_id": cve_id,
            "date_published": date_published,
            "cvss_score": meta.get("cvss_score"),
            "cvss_version": meta.get("cvss_version"),
            "epss": epss_entry.get("epss"),
            "epss_percentile": epss_entry.get("percentile"),
            # Change vs. the longest of 30d/7d/1d ago that actually has a
            # snapshot for this CVE -- None/{} when not even yesterday's
            # snapshot has it (e.g. published within the last day).
            "epss_trend_window": epss_entry.get("trend_window_days"),
            "epss_trend_delta": epss_entry.get("trend_delta"),
            "epss_deltas": epss_entry.get("deltas") or {},
            "vendor": vendor,
            "product": product,
            "active_since": active_since,
            "days_to_active": days_to_active,
            "enisa_id": enisa_entry["enisa_id"] if enisa_entry else None,
            # Both only exist to build per-entry deep links in the viewer.
            "circl_entry_uuid": circl_entry["entry_uuid"] if circl_entry else None,
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
