import time
import requests

USER_AGENT = "kevs-viewer/1.0 (+https://github.com/)"


def get_json(url, headers=None, params=None, retries=3, timeout=30):
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    last_err = None
    for attempt in range(retries):
        try:
            resp = requests.get(url, headers=hdrs, params=params, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            last_err = e
            if attempt < retries - 1:
                time.sleep(2 * (attempt + 1))
    raise last_err
