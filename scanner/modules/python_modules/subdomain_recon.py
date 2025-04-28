from scanner.models import Subdomain, Finding, Port, PortScreenshot
from django.utils.timezone import now
from .shared_utils import take_screenshot, scan_ports
import concurrent.futures
import socket
from urllib.parse import urlparse

def process_subdomain(subdomain, asset, scan):
    """Process a single subdomain with port scanning and screenshots"""
    try:
        # Resolve IP
        try:
            ip = socket.gethostbyname(subdomain.name)
        except socket.gaierror:
            print(f"Could not resolve IP for {subdomain.name}")
            return None

        # Scan ports
        open_ports = scan_ports(ip)
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
            if port_number in [80, 443, 8080]:
                print(f"Taking screenshot of {subdomain.name}:{port_number}")
                # Try both HTTP and HTTPS
                for protocol in ['http', 'https']:
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
    print("Starting Subdomain Reconnaissance")
    
    asset = scan.asset
    
    # Update scan status
    scan.status = "running"
    scan.save()
    
    try:
        # First, try to find subdomains using the subdomain scanner
        from .subdomain_scanner import run as run_subdomain_scanner
        subdomain_output = run_subdomain_scanner(scan)
        
        # Now get the subdomains using the correct related name
        subdomains = asset.domain_subdomains.all()
        if not subdomains.exists():
            scan.status = "failed"
            scan.output = "No subdomains found to analyze"
            scan.save()
            return "No subdomains found"
            
        processed_count = 0
        error_count = 0
        total_subdomains = subdomains.count()
        
        print(f"Found {total_subdomains} subdomains to process")
        
        # Process subdomains concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
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