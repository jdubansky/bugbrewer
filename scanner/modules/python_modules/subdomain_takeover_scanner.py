import requests
from scanner.models import Finding, Scan, Asset
from django.utils.timezone import now
import asyncio
from asgiref.sync import sync_to_async
import aiohttp
import socket
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
from functools import lru_cache

# Known takeover indicators
TAKEOVER_INDICATORS = [
    "The specified bucket does not exist",
    "Web Site Not Found",
    "Fastly error: unknown domain:"
]

# Connection pool settings
CONNECTION_POOL_SIZE = 100
TIMEOUT = aiohttp.ClientTimeout(total=5, connect=2)
MAX_CONCURRENT_REQUESTS = 50

@sync_to_async
def create_finding(asset, subdomain, scan, indicator, url, response_text):
    """Create a finding in the database"""
    Finding.objects.create(
        asset=asset,
        subdomain=subdomain,
        scan=scan,
        title=f"Potential Subdomain Takeover - {subdomain}",
        description=f"Subdomain takeover indicator found: {indicator}\nURL: {url}\nResponse: {response_text[:500]}...",
        severity="high"
    )

@lru_cache(maxsize=1000)
def resolve_dns(domain):
    """Cache DNS lookups to avoid repeated queries"""
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

async def check_subdomain_takeover(session, subdomain, asset, scan):
    """Check a single subdomain for takeover indicators"""
    # Skip if DNS resolution fails
    if not resolve_dns(subdomain):
        return False

    try:
        # Try both HTTP and HTTPS
        for protocol in ['http', 'https']:
            url = f"{protocol}://{subdomain}"
            try:
                async with session.get(url, timeout=TIMEOUT, ssl=False) as response:
                    response_text = await response.text()
                    
                    # Check for any takeover indicators in the response
                    for indicator in TAKEOVER_INDICATORS:
                        if indicator in response_text:
                            # Create a finding for this potential takeover
                            await create_finding(asset, subdomain, scan, indicator, url, response_text)
                            return True
            except (aiohttp.ClientError, asyncio.TimeoutError):
                continue
    except Exception as e:
        print(f"Error checking {subdomain}: {str(e)}")
    return False

async def run_subdomain_takeover_scan(asset, subdomains, scan):
    """Run the subdomain takeover scan on multiple subdomains"""
    connector = aiohttp.TCPConnector(limit=CONNECTION_POOL_SIZE, ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Process subdomains in batches to avoid overwhelming the system
        for i in range(0, len(subdomains), MAX_CONCURRENT_REQUESTS):
            batch = subdomains[i:i + MAX_CONCURRENT_REQUESTS]
            tasks = [
                check_subdomain_takeover(session, subdomain, asset, scan)
                for subdomain in batch
            ]
            await asyncio.gather(*tasks)

@sync_to_async
def get_subdomains(asset):
    """Get subdomains from the database"""
    return list(asset.domain_subdomains.all().values_list('name', flat=True))

def run(scan):
    """Main run function that matches the scanner interface"""
    # Get the asset
    asset = scan.asset
    
    # Run the scan
    asyncio.run(run_scan_async(asset, scan))
    
    return True

async def run_scan_async(asset, scan):
    """Async version of the run function"""
    subdomains = await get_subdomains(asset)
    await run_subdomain_takeover_scan(asset, subdomains, scan) 