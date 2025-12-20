#!/usr/bin/env python3
"""
Quick test to verify async pipeline imports and basic structure
"""

import asyncio
import sys

def test_imports():
    """Test that all async modules import correctly."""
    print("[*] Testing imports...")
    
    try:
        from async_pipeline import async_alert_streamer
        print("✓ async_pipeline imports successfully")
    except ImportError as e:
        print(f"✗ Failed to import async_pipeline: {e}")
        return False
    
    try:
        from integrations.async_virustotal import (
            async_virustotal_check_ip,
            async_virustotal_check_file_hash,
            async_virustotal_check_url_safe
        )
        print("✓ async_virustotal imports successfully")
    except ImportError as e:
        print(f"✗ Failed to import async_virustotal: {e}")
        return False
    
    try:
        from integrations.async_abuseipdb import async_abuseipdb_check_ip
        print("✓ async_abuseipdb imports successfully")
    except ImportError as e:
        print(f"✗ Failed to import async_abuseipdb: {e}")
        return False
    
    try:
        from integrations.async_thehive import async_thehive_create_alert
        print("✓ async_thehive imports successfully")
    except ImportError as e:
        print(f"✗ Failed to import async_thehive: {e}")
        return False
    
    try:
        from analysis.async_ai_classifier import async_claude_classify_alert
        print("✓ async_ai_classifier imports successfully")
    except ImportError as e:
        print(f"✗ Failed to import async_ai_classifier: {e}")
        return False
    
    try:
        from analysis.async_ioc_checker import async_check_alert_iocs
        print("✓ async_ioc_checker imports successfully")
    except ImportError as e:
        print(f"✗ Failed to import async_ioc_checker: {e}")
        return False
    
    print("\n[✓] All async modules imported successfully!")
    return True


async def test_async_functions():
    """Test that async functions are properly defined."""
    import aiohttp
    from integrations.async_virustotal import async_virustotal_check_ip
    
    print("\n[*] Testing async function signatures...")
    
    # Check that functions are coroutines
    async with aiohttp.ClientSession() as session:
        coro = async_virustotal_check_ip("8.8.8.8", session)
        if asyncio.iscoroutine(coro):
            print("✓ async_virustotal_check_ip is a proper coroutine")
            # Close the coroutine without awaiting
            coro.close()
        else:
            print("✗ async_virustotal_check_ip is not a coroutine")
            return False
    
    print("\n[✓] Async functions are properly defined!")
    return True


def main():
    print("="*60)
    print("Async Pipeline - Import and Structure Test")
    print("="*60)
    
    # Test imports
    if not test_imports():
        print("\n[✗] Import tests failed!")
        sys.exit(1)
    
    # Test async functions
    if not asyncio.run(test_async_functions()):
        print("\n[✗] Async function tests failed!")
        sys.exit(1)
    
    print("\n" + "="*60)
    print("[✓] ALL TESTS PASSED!")
    print("="*60)
    print("\nThe async pipeline is ready to use.")
    print("To run it: python3 soc-pipeline.py")
    print("To use sync mode: python3 soc-pipeline.py --sync")


if __name__ == "__main__":
    main()
