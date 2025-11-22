import json
from datetime import datetime, timedelta
from . import config


def load_last_timestamp():
    try:
        with open(config.LAST_TS_FILE, "r") as f:
            ts = f.read().strip()
            if ts:
                return ts
    except FileNotFoundError:
        pass
    return (datetime.utcnow() - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def save_last_timestamp(ts):
    try:
        with open(config.LAST_TS_FILE, "w") as f:
            f.write(ts)
    except Exception:
        pass


def load_ioc_cache():
    try:
        with open(config.IOC_CACHE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_ioc_cache(cache):
    try:
        with open(config.IOC_CACHE_FILE, "w") as f:
            json.dump(cache, f)
    except Exception:
        pass
