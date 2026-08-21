"""Look up Date Published / CVSS / Vendor / Product for a CVE from the
official CVE Services API (cve.org), via GET /api/cve/{id} on
cveawg.mitre.org. Read access needs no credentials, but is rate-limited
to 5 requests/30s; with a CVE Services API key (CNA-sponsored account,
not a self-serve signup) that rises to 50/30s -- set CVE_API_KEY,
CVE_API_ORG, and CVE_API_USER to use one once available (header names
are inferred from public CVE Services docs and unverified against a
real account; adjust if they turn out wrong).

Results are cached in data/cve_metadata_cache.json (committed to the
repo) so a run only has to fetch CVEs newly added to a KEV catalog since
the last run, not the whole union every time. A single run also caps how
many NEW lookups it performs (CVE_METADATA_MAX_PER_RUN) so an initial
backfill of several thousand CVEs spreads across a few scheduled runs
instead of blowing past GitHub Actions' 6-hour job limit.

A cache entry with a null field (most often a CVE that was still
"RESERVED" -- not yet published -- when first fetched) is NOT permanent:
entries missing date_published/cvss_score/vendor/product are retried
every RECHECK_INTERVAL, tracked via each entry's own "checked_at"
timestamp, so a since-published record eventually gets picked up. A
literal "n/a" string (some older CNA records genuinely say that) is real
data, not a gap, and is never retried.
"""
import datetime
import json
import os
import re
import time

import requests

from http_util import USER_AGENT

CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,7})$")
BASE_URL = "https://cveawg.mitre.org/api/cve"
DEFAULT_MAX_PER_RUN = 1500
RECHECK_INTERVAL = datetime.timedelta(days=7)

# v4.0 > v3.1 > v3.0 > v2.0, matching the convention already used by
# Vulnrichment Viewer (see cvss-version-hint in that project's app.js).
CVSS_KEYS_BY_VERSION = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]


def _auth_headers():
    key = os.environ.get("CVE_API_KEY")
    org = os.environ.get("CVE_API_ORG")
    user = os.environ.get("CVE_API_USER")
    if key and org and user:
        return {"CVE-API-KEY": key, "CVE-API-ORG": org, "CVE-API-USER": user}
    return {}


def _min_interval_seconds():
    # 5 req/30s unauthenticated, 50 req/30s with a CVE Services API key.
    return 30 / 50 if _auth_headers() else 30 / 5


def _pick_cvss(metrics_lists):
    """metrics_lists: list of (source, metrics-array) pairs, CNA first."""
    for key in CVSS_KEYS_BY_VERSION:
        for _source, metrics in metrics_lists:
            for metric in metrics:
                cvss = metric.get(key)
                if cvss and cvss.get("baseScore") is not None:
                    return cvss.get("baseScore"), cvss.get("version")
    return None, None


def _fetch_one(cve_id):
    if not CVE_RE.match(cve_id):
        return None
    headers = {"User-Agent": USER_AGENT, **_auth_headers()}
    try:
        resp = requests.get(f"{BASE_URL}/{cve_id}", headers=headers, timeout=30)
        if resp.status_code == 404:
            return {"date_published": None, "cvss_score": None, "cvss_version": None,
                    "vendor": None, "product": None}
        resp.raise_for_status()
        record = resp.json()
    except requests.RequestException:
        return None  # transient failure -- leave uncached, retry next run

    cna = record.get("containers", {}).get("cna", {})
    adp_list = record.get("containers", {}).get("adp", []) or []

    date_published = record.get("cveMetadata", {}).get("datePublished")

    metrics_lists = [("cna", cna.get("metrics", []))]
    for adp in adp_list:
        metrics_lists.append(("adp", adp.get("metrics", [])))
    cvss_score, cvss_version = _pick_cvss(metrics_lists)

    vendors, products = [], []
    for affected in cna.get("affected", []):
        v, p = affected.get("vendor"), affected.get("product")
        if v and v not in vendors:
            vendors.append(v)
        if p and p not in products:
            products.append(p)

    return {
        "date_published": date_published,
        "cvss_score": cvss_score,
        "cvss_version": cvss_version,
        "vendor": "; ".join(vendors) or None,
        "product": "; ".join(products) or None,
    }


def _is_incomplete(entry):
    return any(entry.get(k) is None for k in ("date_published", "cvss_score", "vendor", "product"))


def _needs_recheck(entry, now):
    if not _is_incomplete(entry):
        return False
    checked_at = entry.get("checked_at")
    if not checked_at:
        return True  # cached before this field existed -- due immediately
    try:
        checked_dt = datetime.datetime.fromisoformat(checked_at)
    except ValueError:
        return True
    return now - checked_dt >= RECHECK_INTERVAL


def load_cache(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_cache(path, cache):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(cache, f, indent=1, sort_keys=True)
        f.write("\n")


def ensure_metadata(cve_ids, cache_path, max_per_run=None):
    if max_per_run is None:
        max_per_run = int(os.environ.get("CVE_METADATA_MAX_PER_RUN", DEFAULT_MAX_PER_RUN))
    min_interval = _min_interval_seconds()
    now = datetime.datetime.now(datetime.timezone.utc)

    cache = load_cache(cache_path)
    due = [c for c in cve_ids if c not in cache or _needs_recheck(cache[c], now)]
    due = due[:max_per_run]

    fetched = 0
    last_request_at = 0.0
    for cve_id in due:
        elapsed = time.monotonic() - last_request_at
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        last_request_at = time.monotonic()

        meta = _fetch_one(cve_id)
        if meta is not None:
            meta["checked_at"] = now.isoformat()
            cache[cve_id] = meta
            fetched += 1
    if fetched:
        save_cache(cache_path, cache)
    return cache, fetched
