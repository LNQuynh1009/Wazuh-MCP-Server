#!/usr/bin/env python3

"""
SOC Pipeline - Main Entry Point

This is the entry point for the SOC alert processing pipeline.
The actual implementation has been modularized into separate files:

- config.py: Configuration and environment variables
- utils/persistence.py: File I/O for timestamps and cache
- integrations/: OpenSearch, VirusTotal, AbuseIPDB, TheHive integrations
- analysis/: IOC checking, playbooks, AI classifier, hybrid decision logic
- pipeline.py: Main alert processing pipeline

To run: python3 soc-pipeline.py
"""

from pipeline import alert_streamer

if __name__ == "__main__":
    print("Starting Wazuh -> Hybrid -> TheHive pipeline")
    alert_streamer()
