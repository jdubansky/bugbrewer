import subprocess
from scanner.models import Finding
from django.utils.timezone import now
import re
from concurrent.futures import ThreadPoolExecutor
import asyncio

def parse_severity(severity_str):
    """Map nuclei severity to our finding severity levels"""
    severity_map = {
        'critical': 'high',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'info': 'info'
    }
    return severity_map.get(severity_str.lower(), 'info')

def process_finding_line(line, asset, subdomain, scan):
    """Process a single line of nuclei output and create a finding"""
    try:
        match = re.match(r'\[(.*?)\] \[(.*?)\] \[(.*?)\] (.*?)(?:\s+\[(.*?)\])?$', line)
        if match:
            template, protocol, severity, target_info, details = match.groups()
            details = details or "No additional details"
            
            # Use string formatting instead of f-strings with newlines
            description_parts = [
                "Template: {}".format(template),
                "Protocol: {}".format(protocol),
                "Target: {}".format(target_info),
                "Details: {}".format(details),
                "Raw output: {}".format(line)
            ]
            description = "\n".join(description_parts)
            
            Finding.objects.create(
                asset=asset,
                subdomain=subdomain,
                scan=scan,
                title="{} ({})".format(template, protocol),
                description=description,
                severity=parse_severity(severity)
            )
            return True
    except Exception as e:
        print("Error processing finding: {}".format(str(e)))
        print("Line that caused error: {}".format(line))
    return False

def run(scan):
    print("=====================================")
    print("Starting Nuclei Scanner")
    
    asset = scan.asset
    subdomain = scan.subdomain
    target = subdomain.name if subdomain else asset.value
    
    # Update scan status
    scan.status = "running"
    scan.save()
    
    # Construct the nuclei command with optimized flags
    command = [
        "nuclei",
        "-u", target,
        "-silent",         # Reduce noise in output
        "-nc",            # No color output
        "-severity", "critical,high,medium,low,info",  # Include all severities
        "-timeout", "30",  # 30 second timeout per request
        "-retries", "2",   # Retry failed requests
        "-concurrency", "50",  # Concurrent requests
        "-rate-limit", "150",  # Rate limit requests
        "-no-interactsh",  # Disable interactsh for faster scanning
        #"-no-httpx",       # Disable httpx for faster scanning
    ]
    
    print("Executing command: {}".format(" ".join(command)))
    
    try:
        # Use Popen for better control over the process
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # Line buffered
            universal_newlines=True
        )
        
        findings_count = 0
        output_lines = []
        
        # Process output in real-time
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                output_lines.append(line)
                if process_finding_line(line.strip(), asset, subdomain, scan):
                    findings_count += 1
        
        # Get any remaining output
        output, error = process.communicate()
        output_lines.extend(output.splitlines())
        
        if process.returncode != 0:
            raise Exception("Nuclei scan failed: {}".format(error))

        # Create a summary finding
        timestamp = now().strftime("%Y-%m-%d %H:%M:%S")
        summary_parts = [
            "Completed nuclei scan of {}".format(target),
            "Found {} issues".format(findings_count),
            "Full scan output:",
            "\n".join(output_lines)
        ]
        summary_description = "\n".join(summary_parts)
        
        Finding.objects.create(
            asset=asset,
            subdomain=subdomain,
            scan=scan,
            title="Nuclei Scan Summary - {}".format(timestamp),
            description=summary_description,
            severity="info"
        )

        # Update scan status
        scan.output = "\n".join(output_lines)
        scan.status = "completed"
        scan.save()

        return scan.output

    except subprocess.TimeoutExpired:
        error_msg = "Nuclei scan timed out after 600 seconds"
        scan.output = error_msg
        scan.status = "failed"
        scan.save()
        return error_msg
    except Exception as e:
        error_msg = "Error running nuclei scan: {}".format(str(e))
        scan.output = error_msg
        scan.status = "failed"
        scan.save()
        return error_msg 