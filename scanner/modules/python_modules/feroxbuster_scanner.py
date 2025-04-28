import subprocess
import os
from scanner.models import Finding

def run(scan):
    asset = scan.asset
    target = asset.value
    wordlist_path = "scanner/wordlists/fuzzboom.txt"

    # Ensure the wordlist exists
    if not os.path.exists(wordlist_path):
        return "Error: Wordlist not found at scanner/wordlists/fuzzboom.txt"

    # Construct the feroxbuster command
    command = [
        "feroxbuster",
        "-u", f"http://{target}",  # Use HTTPS by default
        "-w", wordlist_path,
        "-n",  # Don't extract links from response body
        "--status-codes", "200,204,301,302,307,308,401,403,405",  # Status codes to report
        "--silent"  # Reduce noise in output
    ]

    try:
        process = subprocess.run(command, capture_output=True, text=True)
        output = process.stdout

        # Process the output and create findings
        for line in output.splitlines():
            if line.strip() and "=>" not in line:  # Skip empty lines and summary lines
                try:
                    status_code = int(line.split()[0])
                    url = line.split()[1]
                    
                    # Determine severity based on status code
                    severity = "low"
                    if status_code in [401, 403]:
                        severity = "medium"
                    elif status_code == 500:
                        severity = "high"

                    # Create a finding for interesting endpoints
                    Finding.objects.create(
                        asset=asset,
                        scan=scan,
                        title=f"HTTP Endpoint Found: {url}",
                        description=f"Status Code: {status_code}\nURL: {url}",
                        severity=severity
                    )
                except (IndexError, ValueError):
                    continue  # Skip malformed lines

        return output

    except subprocess.CalledProcessError as e:
        return f"Error running feroxbuster: {str(e)}"
    except Exception as e:
        return f"Unexpected error: {str(e)}" 