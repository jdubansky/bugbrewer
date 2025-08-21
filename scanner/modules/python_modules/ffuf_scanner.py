import subprocess
import os
from scanner.models import Finding, Endpoint
from django.utils.timezone import now
from urllib.parse import urlparse
import urllib.request
import ssl

def detect_protocols(target):
    """Detect if target responds to HTTP and/or HTTPS"""
    protocols = []
    
    # Remove any existing protocol from target
    target = target.replace('http://', '').replace('https://', '')
    
    # Create a context that doesn't verify certificates
    context = ssl._create_unverified_context()
    
    # Try both protocols
    for protocol in ['http', 'https']:
        url = f"{protocol}://{target}"
        try:
            # Use urllib.request with a timeout
            request = urllib.request.Request(url)
            response = urllib.request.urlopen(request, timeout=5, context=context)
            protocols.append(protocol)
        except Exception as e:
            print(f"Error checking {protocol}: {str(e)}")
            continue
    
    return protocols or ['http']  # Default to http if nothing responds

def clean_ffuf_output(output):
    """Clean the ffuf output by removing ANSI escape codes and extra whitespace"""
    cleaned_lines = []
    for line in output.splitlines():
        if line.strip():  # Skip empty lines
            # Remove [2K and [0m ANSI escape codes
            cleaned_line = line.replace('[2K', '').replace('[0m', '').strip()
            if cleaned_line:  # Only add non-empty lines
                cleaned_lines.append(cleaned_line)
    return '\n'.join(cleaned_lines)

def is_interesting_path(path):
    """Determine if a path is interesting based on common patterns"""
    interesting_patterns = [
        'admin', 'api', 'backup', 'config', 'debug', 'dev', 'git', 'logs',
        'php', 'sql', 'test', 'upload', 'wp', 'xmlrpc', 'console', 'manager',
        'phpmyadmin', 'phpinfo', 'server-status', 'server-info'
    ]
    return any(pattern in path.lower() for pattern in interesting_patterns)

def run(scan):
    print("=====================================")
    print("Starting FFUF Scanner")
    
    asset = scan.asset
    target = scan.subdomain.name if scan.subdomain else asset.name
    
    # Update scan status
    scan.status = "running"
    scan.save()
    
    # Load wordlist
    wordlist_path = "/app/scanner/wordlists/fuzzboom.txt"
    
    protocols = ['https', 'http']
    all_endpoints = []
    full_output = []
    
    for protocol in protocols:
        url = f"{protocol}://{target}/FUZZ"
        command = [
            "ffuf",
            "-w", wordlist_path,
            "-u", url,
            "-ac",  # Auto-calibrate
            "-mc", "200,201,202,203,204,301,302,307,401,405,500" # not looking 
        ]
        
        print(f"Executing command: {' '.join(command)}")
        
        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=300,
                env={"PATH": "/root/go/bin:/usr/local/bin:/usr/bin:/bin"}
            )
            
            output = process.stdout
            error = process.stderr
 
            # Clean the output before processing
            cleaned_output = clean_ffuf_output(output)
            
            print(f"STDOUT ({protocol}):", output)
            print(f"STDERR ({protocol}):", error)

            if process.returncode != 0:
                print(f"FFUF scan failed for {protocol}: {error}")
                continue

            # Process endpoints for this protocol
            for line in cleaned_output.splitlines():
                if "[Status:" in line:
                    try:
                        # Extract path - everything before the first "[Status:"
                        path = line.split("[Status:")[0].strip()
                        
                        # Extract status code - first number after "Status:"
                        status_parts = line.split("[Status:")[1].split(",")
                        status_code = int(status_parts[0].strip())
                        
                        # Extract content length - first number after "Size:"
                        content_length = None
                        for part in status_parts:
                            if "Size:" in part:
                                content_length = int(part.split("Size:")[1].strip())

                        # Create or update endpoint
                        endpoint, created = Endpoint.objects.update_or_create(
                            asset=asset,
                            subdomain=scan.subdomain,
                            path=path,
                            method='GET',  # FFUF only does GET requests
                            defaults={
                                'status_code': status_code,
                                'content_length': content_length,
                                'is_interesting': is_interesting_path(path)
                            }
                        )
                        
                        # Add the scan to the endpoint's scans
                        endpoint.scans.add(scan)
                        
                        all_endpoints.append(f"{protocol}://{target}{path}")
                    except Exception as e:
                        print(f"Error processing endpoint: {str(e)}")
                        print(f"Line that caused error: {line}")

            full_output.append(f"=== {protocol.upper()} Scan ===\n{cleaned_output}\n")

        except subprocess.TimeoutExpired:
            error_msg = f"Scan timed out after 300 seconds for {protocol}"
            print(error_msg)
            full_output.append(error_msg)
            continue
        except Exception as e:
            error_msg = f"Unexpected error scanning {protocol}: {str(e)}"
            print(error_msg)
            full_output.append(error_msg)
            continue

    # Create a summary finding
    timestamp = now().strftime("%Y-%m-%d %H:%M:%S")
    Finding.objects.create(
        asset=asset,
        scan=scan,
        title=f"FFUF Scan Summary - {timestamp}",
        description=(
            f"Protocols scanned: {', '.join(protocols)}\n"
            f"Found {len(all_endpoints)} endpoints\n\n"
            f"Full scan output:\n\n{''.join(full_output)}"
        ),
        severity="info"
    )

    # Update final scan status
    scan.output = '\n'.join(full_output)
    scan.status = "completed"
    scan.save()

    return '\n'.join(full_output) 