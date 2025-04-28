import subprocess
from scanner.models import Subdomain, Finding
from django.utils.timezone import now

def run(scan):
    print("=====================================")
    print("Starting Subdomain Scanner")
    
    asset = scan.asset
    target = asset.name    
    print(f"Target: {target}")
    
    # Update scan status to running
    scan.status = "running"
    scan.save()

    try:
        # Run subfinder to find subdomains
        process = subprocess.run(
            ["subfinder", "-d", target], 
            capture_output=True, 
            text=True,
            timeout=300  # 5 minute timeout
        )
        
        output = process.stdout.strip()
        print(f"Raw subfinder output: {output}")
        
        # Extract subdomains
        subdomains = [s.strip() for s in output.split("\n") if s.strip()]
        print(f"Found {len(subdomains)} potential subdomains")
        
        added_count = 0
        existing_count = 0
        subdomain_data = []

        for subdomain in subdomains:
            # Check if subdomain already exists
            if asset.domain_subdomains.filter(name=subdomain).exists():
                print(f"Subdomain {subdomain} already exists")
                existing_count += 1
            else:
                print(f"Creating new subdomain: {subdomain}")
                Subdomain.objects.create(asset=asset, name=subdomain)
                added_count += 1
                subdomain_data.append({
                    'name': subdomain,
                    'source': 'subfinder',
                    'discovered_at': now()
                })

        print(f"Added {added_count} new subdomains, {existing_count} already existed")

        # Create a finding with the subdomain results
        timestamp = now().strftime("%Y-%m-%d %H:%M:%S")
        Finding.objects.create(
            asset=asset,
            scan=scan,
            title=f"Subdomain Scan Results - {timestamp}",
            description=(
                f"Found {added_count} new subdomains\n"
                f"Already had {existing_count} subdomains\n\n"
                f"Full output:\n{output}"
            ),
            severity="info"
        )

        # Update scan status and output
        scan.output = f"Found {added_count} new subdomains (already had {existing_count})"
        scan.status = "completed"
        scan.save()

        # Return results in the expected format
        return {
            'output': scan.output,
            'subdomains': subdomain_data,
            'findings': [{
                'title': f"Subdomain Scan Results - {timestamp}",
                'description': f"Found {added_count} new subdomains\nAlready had {existing_count} subdomains",
                'severity': 'info'
            }]
        }

    except subprocess.TimeoutExpired:
        error_msg = "Subdomain scan timed out after 300 seconds"
        scan.output = error_msg
        scan.status = "failed"
        scan.save()
        return {'output': error_msg, 'subdomains': [], 'findings': []}
    except Exception as e:
        error_msg = f"Error running subdomain scan: {str(e)}"
        scan.output = error_msg
        scan.status = "failed"
        scan.save()
        return {'output': error_msg, 'subdomains': [], 'findings': []}
