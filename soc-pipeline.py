#!/usr/bin/env python3
from soc_pipeline.pipeline import alert_streamer


if __name__ == "__main__":
    print("Starting Wazuh -> Hybrid -> TheHive pipeline")
    alert_streamer()
