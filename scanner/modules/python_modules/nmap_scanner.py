import subprocess
import os
from datetime import datetime
from scanner.models import Finding, Port
from django.utils.timezone import now
import yaml
from pathlib import Path

OUTPUT_DIR = "scanner/scan_outputs"

def load_config():
    """Load module configuration from YAML file"""
    config_path = Path(__file__).parent.parent / 'config' / 'nmap_scanner.yaml'
    try:
        with open(config_path) as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        # Return default config if file doesn't exist
        return {
            'ports': "80,443,8080,22",
            'timing_template': 4,
            'scan_type': "-sS",
            'host_timeout': 30,
            'common_scripts': False,
            'output_format': "normal"
        }

def run(scan):
    print("=====================================")
    print("Starting Nmap Scanner")
    
    # Load configuration
    config = load_config()
    ports = config.get('ports', "80,443,8080,22")
    timing = config.get('timing_template', 4)
    scan_type = config.get('scan_type', "-sS")
    host_timeout = config.get('host_timeout', 30)
    common_scripts = config.get('common_scripts', False)
    output_format = config.get('output_format', 'normal')
    
    print(f"Using configuration: ports={ports}, timing={timing}, scan_type={scan_type}")
    
    asset = scan.asset
    subdomain = scan.subdomain  # This will be None for asset scans
    target = subdomain.name if subdomain else asset.value
    
    print(f"Target: {target}")
    
    # Update scan status
    scan.status = "running"
    scan.save()
    
    # Build nmap command
    command = [
        "nmap",
        "-p-",  # Scan all ports
        "--open",  # Only show open ports
        "-sV",   # Version detection
        "--host-timeout", f"{host_timeout}s",
        target
    ]
    
    try:
        print("Running subprocess...")
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=host_timeout + 30
        )
        print(f"Subprocess completed with return code: {process.returncode}")
        
        output = process.stdout
        error = process.stderr
        
        if process.returncode != 0:
            raise Exception(f"Nmap scan failed: {error}")

        # Parse output for open ports
        open_ports = []
        current_host = None
        for line in output.splitlines():
            if "Nmap scan report for" in line:
                current_host = line.split()[-1].strip('()')
            elif "tcp" in line and "open" in line:
                parts = line.split()
                port = parts[0].split('/')[0]
                service = parts[2] if len(parts) > 2 else "unknown"
                open_ports.append((int(port), service))
                
                if subdomain:
                    # Create port for subdomain
                    Port.objects.get_or_create(
                        subdomain=subdomain,
                        port=port,
                        protocol="tcp",
                        defaults={'service': service}
                    )
                else:
                    # Create port for asset
                    Port.objects.get_or_create(
                        asset=asset,
                        port=port,
                        protocol="tcp",
                        defaults={'service': service}
                    )

        # Create findings
        timestamp = now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Create individual findings for each port
        for port, service in open_ports:
            Finding.objects.create(
                asset=asset,
                subdomain=subdomain,  # Will be None for asset scans
                scan=scan,
                title=f"Open Port {port}/tcp - {service}",
                description=(
                    f"Port {port} is open running {service}\n\n"
                    f"Host: {current_host}\n"
                    f"Protocol: TCP\n"
                    f"Service: {service}"
                ),
                severity="low"  # Adjust severity based on port/service
            )

        # Create a summary finding
        Finding.objects.create(
            asset=asset,
            subdomain=subdomain,
            scan=scan,
            title=f"Nmap Scan Summary - {timestamp}",
            description=(
                f"Nmap scan completed for {target}. Found {len(open_ports)} open ports.\n\n"
                f"Open Ports:\n" + 
                "\n".join(f"- {port}/tcp ({service})" for port, service in open_ports) +
                f"\n\nFull scan output:\n{output}"
            ),
            severity="info"
        )

        # Update scan status
        scan.output = output
        scan.status = "completed"
        scan.save()

        # Update last_scanned timestamp for subdomain
        if subdomain:
            subdomain.last_scanned = now()
            subdomain.save()

        return output

    except subprocess.TimeoutExpired:
        error_msg = f"Nmap scan timed out after {host_timeout} seconds"
        scan.output = error_msg
        scan.status = "failed"
        scan.save()
        return error_msg
        
    except Exception as e:
        error_msg = f"Error running Nmap scan: {str(e)}"
        scan.output = error_msg
        scan.status = "failed"
        scan.save()
        return error_msg
