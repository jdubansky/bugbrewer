from scanner.models import Subdomain, Finding, Port, PortScreenshot
from django.utils.timezone import now
from .shared_utils import take_screenshot, scan_ports
import concurrent.futures
import socket
from urllib.parse import urlparse
import psutil
import time

def check_system_resources():
    """Check if system has enough resources to continue scanning"""
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    memory_percent = memory.percent
    
    # Resource thresholds
    MAX_CPU_PERCENT = 80
    MAX_MEMORY_PERCENT = 80
    
    if cpu_percent > MAX_CPU_PERCENT:
        time.sleep(5)  # Wait for CPU to cool down
        return False
    if memory_percent > MAX_MEMORY_PERCENT:
        time.sleep(5)  # Wait for memory to free up
        return False
    
    return True

def process_subdomain(subdomain, asset, scan):
    """Process a single subdomain with port scanning and screenshots"""
    try:
        # Check system resources before processing
        if not check_system_resources():
            return None

        # Resolve IP
        try:
            ip = socket.gethostbyname(subdomain.name)
        except socket.gaierror:
            print(f"Could not resolve IP for {subdomain.name}")
            return None

        # Scan ports with reduced concurrency
        open_ports = scan_ports(ip, max_workers=5)  # Reduced from 10 to 5
        print(f"Found open ports for {subdomain.name}: {open_ports}")
        
        # Create a new subdomain object to avoid potential state issues
        subdomain_obj = Subdomain.objects.get(id=subdomain.id)
        
        # Create Port objects for each open port
        for port_number in open_ports:
            port_obj, _ = Port.objects.get_or_create(
                subdomain=subdomain_obj,
                port=int(port_number),
                protocol="tcp",
                defaults={'service': 'unknown'}  # We could enhance this later to detect services
            )
            
            # Take screenshot if it's a web port
            if port_number in [80, 443, 8080, 8443]:
                print(f"Taking screenshot of {subdomain.name}:{port_number}")
                
                # Determine which protocols to try based on port number
                protocols_to_try = []
                if port_number in [80, 8080]:
                    protocols_to_try = ['http']
                elif port_number in [443, 8443]:
                    protocols_to_try = ['https']
                else:
                    protocols_to_try = ['http', 'https']
                
                for protocol in protocols_to_try:
                    try:
                        screenshot = take_screenshot(subdomain.name)
                        if screenshot:
                            print(f"Screenshot captured for {subdomain.name}:{port_number} ({protocol})")
                            PortScreenshot.objects.create(
                                subdomain=subdomain_obj,
                                port=port_obj,
                                screenshot=screenshot,
                                protocol=protocol
                            )
                            # If we got a successful screenshot, no need to try other protocols for this port
                            break
                    except Exception as e:
                        print(f"Failed to capture screenshot for {subdomain.name}:{port_number} ({protocol}): {str(e)}")
        
        subdomain_obj.last_scanned = now()
        subdomain_obj.save()
        
        # Create finding for the subdomain
        timestamp = now().strftime("%Y-%m-%d %H:%M:%S.%f")
        severity = "info"
        if any(p in open_ports for p in [80, 443, 8080]):
            severity = "info"
        if 22 in open_ports:
            severity = "medium"
            
        Finding.objects.create(
            asset=asset,
            scan=scan,
            title=f"Subdomain Analysis: {subdomain.name} - {timestamp}",
            description=(
                f"Subdomain: {subdomain.name}\n"
                f"IP Address: {ip}\n"
                f"Open Ports: {', '.join(map(str, open_ports)) if open_ports else 'None'}\n"
                f"Web Ports: {', '.join(map(str, [p for p in open_ports if p in [80, 443, 8080]])) if any(p in open_ports for p in [80, 443, 8080]) else 'None'}\n"
                f"Screenshots: {'Captured' if subdomain_obj.screenshots.exists() else 'Failed'}"
            ),
            severity=severity
        )
        
        return subdomain_obj
        
    except Exception as e:
        print(f"Error processing subdomain {subdomain.name}: {str(e)}")
        return None

def run(scan):
    print("=====================================")
    print("Starting Subdomain Recon Scanner")
    
    asset = scan.asset
    subdomains = asset.domain_subdomains.all()
    total_subdomains = subdomains.count()
    processed_count = 0
    error_count = 0
    
    # Update scan status
    scan.status = "running"
    scan.save()
    
    try:
        # Process subdomains with reduced concurrency
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:  # Reduced from 5 to 3
            future_to_subdomain = {
                executor.submit(process_subdomain, subdomain, asset, scan): subdomain 
                for subdomain in subdomains
            }
            
            # Update scan status to show progress
            scan.output = f"Processing {total_subdomains} subdomains..."
            scan.save()
            
            for future in concurrent.futures.as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    if future.result():
                        processed_count += 1
                    else:
                        error_count += 1
                    print(f"Progress: {processed_count}/{total_subdomains} subdomains processed")
                    
                    # Update scan status with progress
                    scan.output = f"Processed {processed_count}/{total_subdomains} subdomains (errors: {error_count})"
                    scan.save()
                except Exception as e:
                    print(f"Error processing {subdomain.name}: {str(e)}")
                    error_count += 1
                    scan.output = f"Error processing {subdomain.name}: {str(e)}"
                    scan.save()
        
        # Update summary finding title to be unique
        timestamp = now().strftime("%Y-%m-%d %H:%M:%S.%f")
        Finding.objects.create(
            asset=asset,
            scan=scan,
            title=f"Subdomain Reconnaissance Summary - {timestamp}",  # Make title unique
            description=(
                f"Processed {processed_count} subdomains\n"
                f"Errors encountered: {error_count}\n\n"
                f"This scan performed:\n"
                f"- Port scanning (22, 80, 443, 8080)\n"
                f"- Web screenshots for HTTP/HTTPS ports\n"
                f"- IP resolution\n"
            ),
            severity="info"
        )
        
        # Only mark as completed when all processing is done
        scan.output = f"Successfully processed {processed_count} subdomains"
        scan.status = "completed"
        scan.completed_at = now()
        scan.save()
        
        print(f"Subdomain reconnaissance completed. Processed {processed_count} subdomains with {error_count} errors.")
        return scan.output
        
    except Exception as e:
        error_msg = f"Error during subdomain reconnaissance: {str(e)}"
        scan.output = error_msg
        scan.status = "failed"
        scan.completed_at = now()
        scan.save()
        print(f"Subdomain reconnaissance failed: {error_msg}")
        return error_msg 