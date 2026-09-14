"""Look up Date Published / CVSS / Vendor / Product for a CVE from the
official CVE Services API (cve.org), via GET /api/cve/{id} on
cveawg.mitre.org. Read access needs no credentials, but is rate-limited
to 5 requests/30s; with a CVE Services API key (CNA-sponsored account,
not a self-serve signup) that rises to 50/30s -- set CVE_API_KEY,
CVE_API_ORG, and CVE_API_USER to use one once available (header names
are inferred from public CVE Services docs and unverified against a
real account; adjust if they turn out wrong).

Many CNA records (especially ones assigned by "mitre" itself as a
fallback for reporters without their own CNA) leave vendor/product as a
literal "n/a" placeholder rather than filling in structured `affected`
data -- roughly 40% of this project's dataset as of 2026-08. When that
happens, NVD's own curated CPE data is used as a fallback (the first
cpeMatch entry's vendor/product), via services.nvd.nist.gov -- also
rate-limited (5/30s unauthenticated; set NVD_API_KEY, a free instant
signup unlike CVE Services, for 50/30s).

Results are cached in data/cve_metadata_cache.json (committed to the
repo) so a run only has to fetch CVEs newly added to a KEV catalog since
the last run, not the whole union every time. A single run also caps how
many NEW lookups it performs (CVE_METADATA_MAX_PER_RUN) so an initial
backfill of several thousand CVEs spreads across a few scheduled runs
instead of blowing past GitHub Actions' 6-hour job limit.

A cache entry is NOT permanent as long as its CNA-provided vendor/product
is missing or "n/a": every RECHECK_INTERVAL it re-asks cve.org first (in
case the CNA has since filled in real data -- cna_vendor/cna_product
track what cve.org itself said, separately from the displayed
vendor/product, so a later real CNA value always wins over an older NVD
fallback), and only re-tries the NVD fallback if cve.org is still
lacking. date_published/cvss_score missing entirely (most often a CVE
still "RESERVED" and not yet published) is retried the same way.
"""
import datetime
import json
import os
import re
import time

import requests

from http_util import USER_AGENT

CVE_RE = re.compile(r"^CVE-(\d{4})-(\d{4,7})$")
CVE_BASE_URL = "https://cveawg.mitre.org/api/cve"
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_MAX_PER_RUN = 5000
RECHECK_INTERVAL = datetime.timedelta(days=7)

# A CVE that's still missing a date_published is usually one a KEV catalog
# listed *before* its CNA published the record -- precisely the case this
# viewer exists to surface (it's what makes Days negative). That gap is
# normally hours to a couple of days, so the 7-day interval above would
# leave the most interesting rows blank for a week after the record went
# live. CVE-2026-85706 is the worked example: CISA/Previdian/VulnCheck all
# listed it 2026-09-11, cve.org published it 2026-09-12 02:46Z, and the
# 09-11 13:10Z check had already stamped checked_at -- so it would have
# stayed blank (and Days empty instead of -1) until 09-18.
#
# Recent IDs therefore retry roughly every other run. An old CVE still
# missing a record is a different animal -- withdrawn, rejected, or never
# published -- and will most likely never fill in, so it keeps the long
# interval rather than burning a cve.org request every few hours forever.
# See _recheck_interval() for why this is scoped to date_published alone.
RECENT_RECHECK_INTERVAL = datetime.timedelta(hours=6)
RECENT_YEARS = 2

# v4.0 > v3.1 > v3.0 > v2.0, matching the convention already used by
# Vulnrichment Viewer (see cvss-version-hint in that project's app.js).
CVSS_KEYS_BY_VERSION = ["cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"]


def _cve_auth_headers():
    key = os.environ.get("CVE_API_KEY")
    org = os.environ.get("CVE_API_ORG")
    user = os.environ.get("CVE_API_USER")
    if key and org and user:
        return {"CVE-API-KEY": key, "CVE-API-ORG": org, "CVE-API-USER": user}
    return {}


def _cve_min_interval_seconds():
    # 5 req/30s unauthenticated, 50 req/30s with a CVE Services API key.
    return 30 / 50 if _cve_auth_headers() else 30 / 5


def _nvd_auth_headers():
    key = os.environ.get("NVD_API_KEY")
    return {"apiKey": key} if key else {}


def _nvd_min_interval_seconds():
    return 30 / 50 if os.environ.get("NVD_API_KEY") else 30 / 5


def _pick_cvss(metrics_lists):
    """metrics_lists: list of (source, metrics-array) pairs, CNA first."""
    for key in CVSS_KEYS_BY_VERSION:
        for _source, metrics in metrics_lists:
            for metric in metrics:
                cvss = metric.get(key)
                if cvss and cvss.get("baseScore") is not None:
                    return cvss.get("baseScore"), cvss.get("version")
    return None, None


def _fetch_cve_record(cve_id):
    """Returns (date_published, cvss_score, cvss_version, cna_vendor,
    cna_product), or None on a transient failure (leave uncached, retry
    next run). A 404 (not yet published) returns all-None, not None."""
    headers = {"User-Agent": USER_AGENT, **_cve_auth_headers()}
    try:
        resp = requests.get(f"{CVE_BASE_URL}/{cve_id}", headers=headers, timeout=30)
        if resp.status_code == 404:
            return None, None, None, None, None
        resp.raise_for_status()
        record = resp.json()
    except requests.RequestException:
        return None

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

    return date_published, cvss_score, cvss_version, "; ".join(vendors) or None, "; ".join(products) or None


def _fetch_nvd_vendor_product(cve_id):
    """First cpeMatch entry's vendor/product from NVD's own CPE data, or
    (None, None) if NVD has nothing usable (transient failure, no
    configurations, or a wildcard-only match)."""
    headers = {"User-Agent": USER_AGENT, **_nvd_auth_headers()}
    try:
        resp = requests.get(NVD_BASE_URL, params={"cveId": cve_id}, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except requests.RequestException:
        return None, None

    for vuln in data.get("vulnerabilities") or []:
        for config in vuln.get("cve", {}).get("configurations") or []:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    parts = match.get("criteria", "").split(":")
                    if len(parts) <= 4:
                        continue
                    vendor, product = parts[3], parts[4]
                    if vendor and vendor != "*":
                        return vendor, (product if product and product != "*" else None)
    return None, None


def _is_placeholder(value):
    return value is None or value == "n/a"


def _is_incomplete(entry):
    if entry.get("date_published") is None or entry.get("cvss_score") is None:
        return True
    return _is_placeholder(entry.get("cna_vendor")) or _is_placeholder(entry.get("cna_product"))


def _recheck_interval(cve_id, entry, now):
    """Short interval only for the narrow case it's meant for: a recent
    CVE with no date_published, i.e. a record that is very likely just
    not published yet and will fill itself in within days.

    Deliberately NOT applied to the other things _is_incomplete() covers
    (missing CVSS, "n/a" vendor/product). Those are mostly permanent --
    the CNA simply never supplied them -- so polling them every few hours
    forever would spend ~69 requests a run to change nothing, versus the
    handful this narrow test actually catches.
    """
    if entry.get("date_published") is not None:
        return RECHECK_INTERVAL
    match = CVE_RE.match(cve_id)
    if not match:
        return RECHECK_INTERVAL
    if int(match.group(1)) >= now.year - (RECENT_YEARS - 1):
        return RECENT_RECHECK_INTERVAL
    return RECHECK_INTERVAL


def _needs_recheck(cve_id, entry, now):
    # Entries cached before cna_vendor/cna_product existed (pre-NVD-fallback)
    # were never evaluated against the current logic at all -- force one
    # fresh check regardless of checked_at, rather than making them wait
    # out a RECHECK_INTERVAL they were never actually subject to.
    if "cna_vendor" not in entry or "cna_product" not in entry:
        return True
    if not _is_incomplete(entry):
        return False
    checked_at = entry.get("checked_at")
    if not checked_at:
        return True  # cached before this field existed -- due immediately
    try:
        checked_dt = datetime.datetime.fromisoformat(checked_at)
    except ValueError:
        return True
    return now - checked_dt >= _recheck_interval(cve_id, entry, now)


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
    cve_min_interval = _cve_min_interval_seconds()
    nvd_min_interval = _nvd_min_interval_seconds()
    now = datetime.datetime.now(datetime.timezone.utc)

    cache = load_cache(cache_path)
    due = [c for c in cve_ids if CVE_RE.match(c) and (c not in cache or _needs_recheck(c, cache[c], now))]
    due = due[:max_per_run]

    fetched = 0
    last_cve_request_at = 0.0
    last_nvd_request_at = 0.0
    for cve_id in due:
        elapsed = time.monotonic() - last_cve_request_at
        if elapsed < cve_min_interval:
            time.sleep(cve_min_interval - elapsed)
        last_cve_request_at = time.monotonic()

        result = _fetch_cve_record(cve_id)
        if result is None:
            continue  # transient failure -- leave uncached (or stale), retry next run
        date_published, cvss_score, cvss_version, cna_vendor, cna_product = result

        vendor, product = cna_vendor, cna_product
        if _is_placeholder(cna_vendor) or _is_placeholder(cna_product):
            elapsed = time.monotonic() - last_nvd_request_at
            if elapsed < nvd_min_interval:
                time.sleep(nvd_min_interval - elapsed)
            last_nvd_request_at = time.monotonic()

            nvd_vendor, nvd_product = _fetch_nvd_vendor_product(cve_id)
            if _is_placeholder(cna_vendor) and nvd_vendor:
                vendor = nvd_vendor
            if _is_placeholder(cna_product) and nvd_product:
                product = nvd_product

        cache[cve_id] = {
            "date_published": date_published,
            "cvss_score": cvss_score,
            "cvss_version": cvss_version,
            "vendor": vendor,
            "product": product,
            "cna_vendor": cna_vendor,
            "cna_product": cna_product,
            "checked_at": now.isoformat(),
        }
        fetched += 1
    if fetched:
        save_cache(cache_path, cache)
    return cache, fetched
