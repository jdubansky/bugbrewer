import subprocess
import tempfile
from pathlib import Path
import base64
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import WebDriverException
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import os
import random
import asyncio
from playwright.async_api import async_playwright
from io import BytesIO

async def _take_screenshot_async(url, display=":99"):
    try:
        async with async_playwright() as p:
            # Launch browser with specific options
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-gpu',
                    '--ignore-certificate-errors',
                    '--disable-web-security',
                    f'--display={display}'
                ]
            )
            
            # Create a new context with specific options
            context = await browser.new_context(
                ignore_https_errors=True,  # Ignore SSL/HTTPS errors
                viewport={'width': 1280, 'height': 800}
            )
            
            page = await context.new_page()
            
            # Try HTTPS first, then HTTP if that fails
            try:
                await page.goto(f'https://{url}', 
                              wait_until='domcontentloaded',  # Changed from networkidle
                              timeout=30000)
            except Exception as e:
                print(f"HTTPS failed for {url}, trying HTTP: {str(e)}")
                try:
                    await page.goto(f'http://{url}', 
                                  wait_until='domcontentloaded',  # Changed from networkidle
                                  timeout=30000)
                except Exception as e:
                    print(f"HTTP also failed for {url}: {str(e)}")
                    # Continue anyway to try to get a screenshot of whatever loaded
                    pass

            # Wait a bit for any dynamic content
            await page.wait_for_timeout(2000)
            
            try:
                # Take screenshot and encode it
                screenshot_bytes = await page.screenshot()
                screenshot_base64 = base64.b64encode(screenshot_bytes).decode('utf-8')
                print(f"Screenshot captured for {url}:443 (https)")
                return screenshot_base64
            except Exception as e:
                print(f"Failed to capture screenshot for {url}: {str(e)}")
                return None
            finally:
                await context.close()
                await browser.close()

    except Exception as e:
        print(f"Error taking screenshot of {url}: {str(e)}")
        return None

def take_screenshot(url):
    """
    Take a screenshot of a URL using Playwright
    Returns base64 encoded screenshot or None if failed
    """
    try:
        # Run the async function
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        screenshot = loop.run_until_complete(_take_screenshot_async(url))
        loop.close()
        return screenshot
    except Exception as e:
        print(f"Failed to take screenshot of {url}: {str(e)}")
        return None

def check_port(host, port, timeout=2):
    """Check if a port is open on a host"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except:
        return None

def scan_ports(host, ports=[22, 66, 80, 81, 443, 445, 457, 1080, 1100, 
                            1241, 1352, 1433, 1434, 1521, 1944, 2301, 
                            3000, 3128, 3306, 4000, 4001, 4002, 4100, 
                            5000, 5432, 5800, 5801, 5802, 6346, 6347, 
                            7001, 7002, 8000, 8080, 8443, 8888, 30821], max_workers=10, timeout=2):
    """
    Scan multiple ports on a host concurrently.
    Returns list of open ports.
    """
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(check_port, host, port, timeout): port 
            for port in ports
        }
        for future in as_completed(future_to_port):
            if future.result():
                open_ports.append(future.result())
    return sorted(open_ports) if open_ports else []  # Return empty list instead of None 