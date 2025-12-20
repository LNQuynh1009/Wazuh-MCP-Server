#!/usr/bin/env python3

"""
SOC Pipeline - Main Entry Point

This is the entry point for the SOC alert processing pipeline.
The actual implementation has been modularized into separate files:

- config.py: Configuration and environment variables
- utils/persistence.py: File I/O for timestamps and cache
- integrations/: OpenSearch, VirusTotal, AbuseIPDB, TheHive integrations
- analysis/: IOC checking, playbooks, AI classifier, hybrid decision logic
- pipeline.py: Synchronous alert processing pipeline
- async_pipeline.py: Asynchronous alert processing pipeline (optimized)

To run synchronous pipeline: python3 soc-pipeline.py --sync
To run async pipeline (default): python3 soc-pipeline.py
"""

import sys
import asyncio
from pipeline import alert_streamer
from async_pipeline import async_alert_streamer

if __name__ == "__main__":
    # Check for sync flag
    use_sync = "--sync" in sys.argv
    
    if use_sync:
        print("Starting Wazuh -> Hybrid -> TheHive pipeline (SYNC mode)")
        alert_streamer()
    else:
        print("Starting Wazuh -> Hybrid -> TheHive pipeline (ASYNC mode - optimized)")
        asyncio.run(async_alert_streamer())
