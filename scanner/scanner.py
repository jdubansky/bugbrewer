import subprocess
import json
import logging
from pathlib import Path
import importlib
from .models import Scan, Finding, Port, PortScreenshot
from playwright.sync_api import sync_playwright
import base64
from django.utils import timezone

logger = logging.getLogger(__name__)

class Scanner:
    def __init__(self, module, config):
        self.module = module
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.modules_dir = Path(__file__).parent / 'modules' / 'python_modules'
        self.config_dir = Path(__file__).parent / 'modules' / 'config'

    def run_scan(self, asset):
        """Run a scan for the given asset"""
        try:
            # Import the module dynamically
            module_name = f"scanner.modules.python_modules.{self.module.python_module}"
            module = importlib.import_module(module_name)
            
            # Create a scan object
            scan = Scan.objects.create(
                asset=asset,
                module=self.module,
                status='running',
                started_at=timezone.now()
            )
            
            # Run the scan
            results = module.run(scan)
            
            # Update scan status periodically for long-running scans
            if isinstance(results, dict) and results.get('status') == 'running':
                # For long-running scans, return intermediate results
                return {
                    'status': 'running',
                    'output': results.get('output', ''),
                    'progress': results.get('progress', 0)
                }
            
            # For completed scans, return full results
            return {
                'status': 'completed',
                'output': results.get('output', ''),
                'findings': results.get('findings', []),
                'subdomains': results.get('subdomains', []),
                'ports': results.get('ports', [])
            }
            
        except Exception as e:
            self.logger.error(f"Error running scan: {str(e)}")
            raise

    def scan_asset(self, asset, module, scan):
        """Run a scan on an asset using the specified module"""
        try:
            # Update scan status to running
            scan.status = 'running'
            scan.started_at = timezone.now()
            scan.save()

            # Load module configuration
            config_path = self.config_dir / f'{module.python_module}.yaml'
            if config_path.exists():
                with open(config_path) as f:
                    config = yaml.safe_load(f)
            else:
                config = {}

            # Import and run the module
            module_path = f"scanner.modules.python_modules.{module.python_module}"
            scanner_module = importlib.import_module(module_path)
            
            # Run the scan
            results = scanner_module.scan(asset.name, config)
            
            # Process results
            self._process_scan_results(asset, scan, results)
            
            # Update scan status
            scan.status = 'completed'
            scan.completed_at = timezone.now()
            scan.save()

        except Exception as e:
            logger.error(f"Error scanning {asset.name} with {module.name}: {str(e)}")
            scan.status = 'failed'
            scan.completed_at = timezone.now()
            scan.save()
            raise

    def _process_scan_results(self, asset, scan, results):
        """Process scan results and create findings/ports"""
        if isinstance(results, dict):
            # Process findings
            if 'findings' in results:
                for finding_data in results['findings']:
                    Finding.objects.create(
                        asset=asset,
                        scan=scan,
                        title=finding_data.get('title', 'Unknown Finding'),
                        description=finding_data.get('description', ''),
                        severity=finding_data.get('severity', 'low')
                    )

            # Process ports
            if 'ports' in results:
                for port_data in results['ports']:
                    port, created = Port.objects.get_or_create(
                        asset=asset,
                        port=port_data['port'],
                        protocol=port_data.get('protocol', 'tcp'),
                        defaults={
                            'service': port_data.get('service', '')
                        }
                    )

                    # Capture screenshots for web ports
                    if port_data.get('protocol') in ['http', 'https']:
                        self._capture_screenshot(asset, port, port_data['protocol'])

    def _capture_screenshot(self, asset, port, protocol):
        """Capture screenshot of a web service"""
        try:
            url = f"{protocol}://{asset.name}:{port.port}"
            
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_page()
                page.goto(url, timeout=10000)
                
                # Take screenshot
                screenshot = page.screenshot(type='jpeg', quality=80)
                
                # Convert to base64
                screenshot_b64 = base64.b64encode(screenshot).decode('utf-8')
                
                # Save screenshot
                PortScreenshot.objects.create(
                    port=port,
                    screenshot=screenshot_b64,
                    protocol=protocol
                )
                
                browser.close()
                
        except Exception as e:
            logger.error(f"Error capturing screenshot for {url}: {str(e)}")

    def scan_subdomain(self, subdomain, module, scan):
        """Run a scan on a subdomain using the specified module"""
        try:
            # Update scan status to running
            scan.status = 'running'
            scan.started_at = timezone.now()
            scan.save()

            # Load module configuration
            config_path = self.config_dir / f'{module.python_module}.yaml'
            if config_path.exists():
                with open(config_path) as f:
                    config = yaml.safe_load(f)
            else:
                config = {}

            # Import and run the module
            module_path = f"scanner.modules.python_modules.{module.python_module}"
            scanner_module = importlib.import_module(module_path)
            
            # Run the scan
            results = scanner_module.scan(subdomain.name, config)
            
            # Process results
            self._process_subdomain_scan_results(subdomain, scan, results)
            
            # Update scan status
            scan.status = 'completed'
            scan.completed_at = timezone.now()
            scan.save()

        except Exception as e:
            logger.error(f"Error scanning {subdomain.name} with {module.name}: {str(e)}")
            scan.status = 'failed'
            scan.completed_at = timezone.now()
            scan.save()
            raise

    def _process_subdomain_scan_results(self, subdomain, scan, results):
        """Process scan results for a subdomain"""
        if isinstance(results, dict):
            # Process findings
            if 'findings' in results:
                for finding_data in results['findings']:
                    Finding.objects.create(
                        subdomain=subdomain,
                        scan=scan,
                        title=finding_data.get('title', 'Unknown Finding'),
                        description=finding_data.get('description', ''),
                        severity=finding_data.get('severity', 'low')
                    )

            # Process ports
            if 'ports' in results:
                for port_data in results['ports']:
                    port, created = Port.objects.get_or_create(
                        subdomain=subdomain,
                        port=port_data['port'],
                        protocol=port_data.get('protocol', 'tcp'),
                        defaults={
                            'service': port_data.get('service', '')
                        }
                    )

                    # Capture screenshots for web ports
                    if port_data.get('protocol') in ['http', 'https']:
                        self._capture_subdomain_screenshot(subdomain, port, port_data['protocol'])

    def _capture_subdomain_screenshot(self, subdomain, port, protocol):
        """Capture screenshot of a subdomain web service"""
        try:
            url = f"{protocol}://{subdomain.name}:{port.port}"
            
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_page()
                page.goto(url, timeout=10000)
                
                # Take screenshot
                screenshot = page.screenshot(type='jpeg', quality=80)
                
                # Convert to base64
                screenshot_b64 = base64.b64encode(screenshot).decode('utf-8')
                
                # Save screenshot
                PortScreenshot.objects.create(
                    port=port,
                    screenshot=screenshot_b64,
                    protocol=protocol
                )
                
                browser.close()
                
        except Exception as e:
            logger.error(f"Error capturing screenshot for {url}: {str(e)}")

    def capture_screenshot(self, subdomain, port, protocol='http'):
        """Capture a screenshot of a subdomain on a specific port and protocol."""
        try:
            # Construct the URL based on protocol and port
            if protocol == 'https':
                url = f'https://{subdomain.name}:{port}'
            else:
                url = f'http://{subdomain.name}:{port}'
            
            # Use Playwright to capture the screenshot
            with sync_playwright() as p:
                browser = p.chromium.launch()
                page = browser.new_page()
                
                # Set a reasonable timeout
                page.set_default_timeout(30000)
                
                try:
                    # Navigate to the URL
                    response = page.goto(url, wait_until='networkidle')
                    
                    # Check if the page loaded successfully
                    if response and response.status < 400:
                        # Take the screenshot
                        screenshot = page.screenshot(type='png')
                        
                        # Get or create the Port object
                        port_obj, _ = Port.objects.get_or_create(
                            subdomain=subdomain,
                            port=port,
                            protocol="tcp",
                            defaults={'service': 'unknown'}
                        )
                        
                        # Create or update the PortScreenshot
                        PortScreenshot.objects.update_or_create(
                            subdomain=subdomain,
                            port=port_obj,
                            protocol=protocol,
                            defaults={
                                'screenshot': base64.b64encode(screenshot).decode('utf-8'),
                                'created_at': timezone.now()
                            }
                        )
                        
                        self.logger.info(f"Successfully captured screenshot for {url}")
                        return True
                    else:
                        self.logger.warning(f"Failed to load {url}: Status {response.status if response else 'unknown'}")
                        return False
                    
                except Exception as e:
                    self.logger.error(f"Error capturing screenshot for {url}: {str(e)}")
                    return False
                
                finally:
                    browser.close()
                
        except Exception as e:
            self.logger.error(f"Error in screenshot capture for {subdomain.name}:{port}: {str(e)}")
            return False

    def scan_subdomain(self, subdomain):
        """Scan a subdomain for open ports and vulnerabilities."""
        try:
            # Get all ports for this subdomain
            ports = subdomain.ports.all()
            
            # Try to capture screenshots for common web ports
            web_ports = [80, 443, 8080, 8443]
            for port in web_ports:
                if ports.filter(port=port).exists():
                    # Try both HTTP and HTTPS
                    self.capture_screenshot(subdomain, port, 'http')
                    self.capture_screenshot(subdomain, port, 'https')
            
            # Continue with other scanning logic... 
        except Exception as e:
            self.logger.error(f"Error in scan_subdomain for {subdomain.name}: {str(e)}")
            return False 