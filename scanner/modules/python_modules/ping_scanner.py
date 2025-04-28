import subprocess
from scanner.models import Finding
from django.utils.timezone import now
import yaml
import os
from pathlib import Path

def load_config():
    """Load module configuration from YAML file"""
    config_path = Path(__file__).parent.parent / 'config' / 'ping_scanner.yaml'
    try:
        with open(config_path) as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        # Return default config if file doesn't exist
        return {
            'packet_count': 4,
            'timeout': 30
        }

def run(scan):
    print("=====================================")
    print("Starting Ping Scanner")
    
    # Load configuration
    config = load_config()
    packet_count = config.get('packet_count', 4)  # Default to 4 if not specified
    timeout = config.get('timeout', 30)  # Default to 30 if not specified
    
    print(f"Using configuration: packets={packet_count}, timeout={timeout}")
    
    asset = scan.asset
    target = asset.value
    
    print(f"Target: {target}")
    
    # Update scan status to running
    scan.status = "running"
    scan.save()
    
    # Construct the ping command with configurable packet count
    command = [
        "ping",
        "-c", str(packet_count),
        target
    ]
    
    print(f"Executing command: {' '.join(command)}")
    
    try:
        print("Running subprocess...")
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        print(f"Subprocess completed with return code: {process.returncode}")
        
        output = process.stdout
        error = process.stderr
        
        print("STDOUT:", output)
        print("STDERR:", error)

        # Create a finding with the ping results
        timestamp = now().strftime("%Y-%m-%d %H:%M:%S")
        Finding.objects.create(
            asset=asset,
            scan=scan,
            title=f"Ping Results - {timestamp}",
            description=f"Ping output (packets={packet_count}):\n\n{output}",
            severity="info"
        )
        print("Created finding with ping results")

        # Update scan with output and status
        scan.output = output
        scan.status = "completed"
        scan.save()

        return output

    except subprocess.TimeoutExpired:
        error_msg = f"Ping timed out after {timeout} seconds"
        print(error_msg)
        scan.output = error_msg
        scan.status = "failed"
        scan.save()
        return error_msg
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        print(error_msg)
        scan.output = error_msg
        scan.status = "failed"
        scan.save()
        return error_msg 