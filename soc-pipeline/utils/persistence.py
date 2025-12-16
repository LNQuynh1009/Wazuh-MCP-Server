#!/usr/bin/env python3

import json
from datetime import datetime, timedelta
from config import LAST_TS_FILE, IOC_CACHE_FILE


def load_last_timestamp():
    """Load the last processed timestamp from file."""
    try:
        with open(LAST_TS_FILE, "r") as f:
            ts = f.read().strip()
            if ts:
                return ts
    except FileNotFoundError:
        pass
    # default to very recent time to avoid large historical pulls
    return (datetime.utcnow() - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def save_last_timestamp(ts):
    """Save the last processed timestamp to file."""
    try:
        with open(LAST_TS_FILE, "w") as f:
            f.write(ts)
    except Exception:
        pass


def load_ioc_cache():
    """Load the IOC cache from file."""
    try:
        with open(IOC_CACHE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def save_ioc_cache(cache):
    """Save the IOC cache to file."""
    try:
        with open(IOC_CACHE_FILE, "w") as f:
            json.dump(cache, f)
    except Exception:
        pass
