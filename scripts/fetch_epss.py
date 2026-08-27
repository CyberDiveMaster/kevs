"""Fetch EPSS (Exploit Prediction Scoring System) scores from FIRST.org.

FIRST publishes a single bulk CSV covering every scored CVE, refreshed
once daily (~13:30 UTC) -- https://www.first.org/epss/data. No auth, no
per-CVE rate limit; one download covers the whole union.

Unlike the other fetchers here, this is NOT re-downloaded on every
3-hour KEV sync run: EPSS only changes once/day, so build.py only calls
fetch() when REFRESH_EPSS is set (the workflow's dedicated daily
schedule, 14:30 UTC -- an hour after FIRST's own publish time) and
otherwise reuses the last result from data/epss_cache.json.
"""
import csv
import gzip
import io
import json
import os

import requests

from http_util import USER_AGENT

BULK_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def fetch(cve_ids):
    """Downloads the full bulk CSV (every CVE ever scored -- several
    hundred thousand rows) and returns just the given CVE IDs as
    {cve_id: {"epss": float, "percentile": float}}."""
    wanted = set(cve_ids)
    resp = requests.get(BULK_URL, headers={"User-Agent": USER_AGENT}, timeout=60)
    resp.raise_for_status()

    result = {}
    with gzip.GzipFile(fileobj=io.BytesIO(resp.content)) as gz:
        text = io.TextIOWrapper(gz, encoding="utf-8")
        next(text)  # "#model_version:...,score_date:..." comment line, not CSV
        for row in csv.DictReader(text):
            cve_id = row["cve"]
            if cve_id in wanted:
                result[cve_id] = {"epss": float(row["epss"]), "percentile": float(row["percentile"])}
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
    sample = fetch(["CVE-2021-44228", "CVE-2014-0160"])
    print(sample)
