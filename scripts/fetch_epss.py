"""Fetch EPSS (Exploit Prediction Scoring System) scores from FIRST.org.

FIRST publishes a single bulk CSV covering every scored CVE, refreshed
once daily (~13:30 UTC) -- https://www.first.org/epss/data. No auth, no
per-CVE rate limit; one download covers the whole union. Historical
snapshots are available too, one gzip CSV per calendar day back to
2021-04-14, at a date-stamped URL -- used here to compute a trend
(change over the longest of 30d/7d/1d that actually has data for that
CVE, since KEV catalogs often flag a CVE within days of publication,
before 30 days of EPSS history even exists for it). These are fetched
fresh each time and never stored in the repo, so this doesn't grow
repo size over time -- only the small per-CVE result ends up cached.

Unlike the other fetchers here, this is NOT re-downloaded on every
3-hour KEV sync run: EPSS only changes once/day, so build.py only calls
fetch_with_trends() when REFRESH_EPSS is set (the workflow's dedicated
daily schedule, 14:30 UTC -- an hour after FIRST's own publish time) and
otherwise reuses the last result from data/epss_cache.json.
"""
import csv
import datetime
import gzip
import io
import json
import os

import requests

from http_util import USER_AGENT

CURRENT_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
DATED_URL = "https://epss.empiricalsecurity.com/epss_scores-{date}.csv.gz"

# Longest first -- fetch_with_trends() picks the first of these that
# actually has a historical snapshot for a given CVE, so the earliest
# possible history in the SPECIFICATION is more true a signal, but the
# 1d fallback is what makes freshly-published/freshly-KEV-listed CVEs
# (which VulnCheck in particular flags very quickly) show a trend at all
# instead of always "-".
TREND_WINDOWS_DAYS = [30, 7, 1]


def _parse_bulk_csv(content_bytes, wanted):
    result = {}
    with gzip.GzipFile(fileobj=io.BytesIO(content_bytes)) as gz:
        text = io.TextIOWrapper(gz, encoding="utf-8")
        next(text)  # "#model_version:...,score_date:..." comment line, not CSV
        for row in csv.DictReader(text):
            cve_id = row["cve"]
            if cve_id in wanted:
                result[cve_id] = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
    return result


def _fetch_url(url, wanted):
    resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=60)
    resp.raise_for_status()
    return _parse_bulk_csv(resp.content, wanted)


def fetch(cve_ids):
    """Current EPSS scores only -- {cve_id: {"epss": float, "percentile": float}}."""
    return _fetch_url(CURRENT_URL, set(cve_ids))


def fetch_with_trends(cve_ids):
    """Current scores plus a trend computed against whichever of
    30d/7d/1d ago actually has a snapshot for that CVE (FIRST's archive
    only goes back to 2021-04-14, and a CVE published more recently than
    the window obviously has no earlier snapshot either).

    Returns {cve_id: {"epss", "percentile", "trend_window_days",
    "trend_delta", "deltas"}}, where trend_window_days/trend_delta are
    the primary (longest-available) window and its epss delta, and
    "deltas" holds every window that had data (keyed by the window as a
    string, e.g. {"7": 0.123}), for a fuller tooltip. Both are None/{}
    when not even yesterday's snapshot has this CVE.
    """
    wanted = set(cve_ids)
    current = _fetch_url(CURRENT_URL, wanted)

    today = datetime.date.today()
    historical = {}
    for days in TREND_WINDOWS_DAYS:
        date_str = (today - datetime.timedelta(days=days)).isoformat()
        try:
            historical[days] = _fetch_url(DATED_URL.format(date=date_str), wanted)
        except requests.RequestException:
            historical[days] = {}

    result = {}
    for cve_id, cur in current.items():
        deltas = {}
        for days in TREND_WINDOWS_DAYS:
            past = historical.get(days, {}).get(cve_id)
            if past is not None:
                deltas[str(days)] = cur["epss"] - past["epss"]

        trend_window_days, trend_delta = None, None
        for days in TREND_WINDOWS_DAYS:  # longest first
            if str(days) in deltas:
                trend_window_days, trend_delta = days, deltas[str(days)]
                break

        result[cve_id] = {
            "epss": cur["epss"],
            "percentile": cur["percentile"],
            "trend_window_days": trend_window_days,
            "trend_delta": trend_delta,
            "deltas": deltas,
        }
    return result


def load_cache(path):
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def save_cache(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, separators=(",", ":"), sort_keys=True)
        f.write("\n")


if __name__ == "__main__":
    sample = fetch_with_trends(["CVE-2021-44228", "CVE-2014-0160"])
    print(json.dumps(sample, indent=1))
