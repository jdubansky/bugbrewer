import importlib
from celery import shared_task
import subprocess
from .models import Scan, Module, Finding, Port, Subdomain, IgnoredAsset, ContinuousScan, Asset
from django.utils.timezone import now
import re
from django.utils import timezone
from .scanner import Scanner
import logging

logger = logging.getLogger(__name__)

@shared_task
def execute_scan(scan_id):
    scan = Scan.objects.get(id=scan_id)
    asset = scan.asset

    # Get applicable modules for the asset type
    modules = Module.objects.filter(asset_type=asset.asset_type)

    for module in modules:
        command = module.run(asset.value)
        process = subprocess.run(command, shell=True, capture_output=True, text=True)
        
        # Save results
        scan.results = { "module": module.name, "output": process.stdout }
        scan.status = "completed"
        scan.save()

        # Check determination logic
        if module.name == "nmap" and "80/tcp" in process.stdout:
            dirbuster = Module.objects.get(name="dirbuster")
            execute_scan.apply_async(args=[scan.id])  # Trigger dirbuster

    scan.status = "completed"
    scan.save()

@shared_task(bind=True)
def run_scan(self, scan_id):
    scan = Scan.objects.get(id=scan_id)
    scan.task_id = self.request.id
    scan.save()
    
    try:
        # Check if scan was cancelled before starting
        scan.refresh_from_db()
        if scan.status == 'canceled':
            return
        
        scan.status = 'running'
        scan.started_at = timezone.now()
        scan.save()
        
        # Import and run the module
        module_path = f"scanner.modules.python_modules.{scan.module.python_module}"
        scanner_module = importlib.import_module(module_path)
        
        # Check if the module has a Scanner class or just a run function
        if hasattr(scanner_module, 'Scanner'):
            scanner = scanner_module.Scanner(scan.asset)
            output = scanner.run()
        else:
            # Module uses a run function directly
            output = scanner_module.run(scan)
        
        # Check if scan was cancelled during execution
        scan.refresh_from_db()
        if scan.status == 'canceled':
            return
            
        scan.status = 'completed'
        scan.output = output
        scan.completed_at = timezone.now()
        scan.save()
        
    except Exception as e:
        scan.refresh_from_db()
        if scan.status != 'canceled':  # Only update status if not already canceled
            scan.status = 'failed'
            scan.output = str(e)
            scan.completed_at = timezone.now()
            scan.save()
        raise

def process_scan_results(scan, results):
    """Process scan results and update the database"""
    try:
        # Update scan status and output
        scan.status = 'completed'
        scan.output = results.get('output', '')
        scan.completed_at = timezone.now()
        scan.save()
        
        # Process findings
        if 'findings' in results:
            for finding_data in results['findings']:
                title = finding_data.get('title', '')
                description = finding_data.get('description', '')
                severity = finding_data.get('severity', 'info')
                
                # Update or create the finding
                Finding.objects.update_or_create(
                    asset=scan.asset,
                    title=title,
                    defaults={
                        'scan': scan,
                        'description': description,
                        'severity': severity
                    }
                )
        
        # Process subdomains
        if 'subdomains' in results:
            for subdomain_data in results['subdomains']:
                if isinstance(subdomain_data, dict):
                    subdomain_name = subdomain_data.get('name', '')
                    if subdomain_name:  # Only create if we have a name
                        Subdomain.objects.get_or_create(
                            asset=scan.asset,
                            name=subdomain_name
                        )
        
        # Process ports
        if 'ports' in results:
            for port_data in results['ports']:
                Port.objects.create(
                    asset=scan.asset,
                    number=port_data.get('number'),
                    protocol=port_data.get('protocol', 'tcp'),
                    service=port_data.get('service', ''),
                    state=port_data.get('state', 'open'),
                    discovered_at=timezone.now()
                )
                
    except Exception as e:
        logger.error(f"Error processing scan results: {str(e)}")
        scan.status = 'failed'
        scan.output = f"Error processing results: {str(e)}"
        scan.completed_at = timezone.now()
        scan.save()
        raise

def parse_findings(scan):
    """
    Extracts findings from the module output and launches new scans if triggers are met.
    """
    output = scan.output
    asset = scan.asset

    if scan.module.name.lower() == "nmap":
        print(f"Debug: Raw Nmap Output for {asset.name}:\n{output}")

        # Extract open ports and services from Nmap output
        open_ports = re.findall(r'(\d+)/tcp\s+open', output)
        services = re.findall(r'(\d+)/tcp\s+open\s+(\S+)', output)  # Extract services too

        for port, service in services:
            port = int(port)
            service = service if service else "Unknown"

            # Check if the port already exists
            existing_port = Port.objects.filter(asset=asset, port=port, protocol="tcp").exists()
            if not existing_port:
                Port.objects.create(asset=asset, port=port, service=service, protocol="tcp")

    elif scan.module.name.lower() == "subdomain-scanner":
        # Extract subdomains from the output
        subdomains = re.findall(r'(\S+\.' + re.escape(asset.name) + r')', output)

        for sub in set(subdomains):  # Use set() to avoid duplicates in output
            existing_sub = Subdomain.objects.filter(asset=asset, name=sub).exists()
            if not existing_sub:
                Subdomain.objects.create(asset=asset, name=sub)

@shared_task
def run_continuous_scan():
    """Task to run continuous scans that are due"""
    try:
        # Get all continuous scans that are due
        due_scans = ContinuousScan.objects.filter(status='running')
        
        for continuous_scan in due_scans:
            if continuous_scan.is_due():
                logger.info(f"Running continuous scan: {continuous_scan.name}")
                
                # Check system resources before starting
                from .views import check_system_resources
                can_run, reason = check_system_resources()
                if not can_run:
                    logger.warning(f"Cannot run continuous scan {continuous_scan.name}: {reason}")
                    continue
                
                # Get all assets
                assets = Asset.objects.all()
                
                # Run scans for each asset and module combination
                for asset in assets:
                    for module in continuous_scan.modules.all():
                        # Check if a scan for this asset-module combination already exists
                        existing_scan = Scan.objects.filter(
                            asset=asset,
                            module=module,
                            status__in=['running', 'queued']
                        ).first()
                        
                        if not existing_scan:
                            scan = Scan.objects.create(
                                asset=asset,
                                module=module,
                                status='queued',
                                started_at=timezone.now(),
                                output='Initializing scan...'
                            )
                            
                            try:
                                # Start the scan task
                                task = run_scan.delay(scan.id)
                                scan.task_id = task.id
                                scan.save()
                            except Exception as e:
                                logger.error(f"Error starting scan for {asset.name} with {module.name}: {str(e)}")
                                scan.status = 'failed'
                                scan.output = str(e)
                                scan.completed_at = timezone.now()
                                scan.save()
                
                # Update the next scan time
                continuous_scan.update_next_scan()
                
    except Exception as e:
        logger.error(f"Error in continuous scan task: {str(e)}")
        raise
