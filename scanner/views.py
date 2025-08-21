from django.shortcuts import render, redirect, get_object_or_404
from rest_framework import viewsets
from .models import Asset, Scan, Module, Finding, Subdomain, ScanQueue, IgnoredAsset, ContinuousScan
from .serializers import AssetSerializer, ScanSerializer
from .forms import BulkAssetForm, ModuleForm, AssetForm, ScanForm, IgnoredAssetForm, BulkIgnoredAssetForm, ContinuousScanForm
from .tasks import run_scan
from django.utils.timezone import now
from celery import current_app
from django.views.generic import DetailView, ListView
from django.http import HttpResponseBadRequest, HttpResponse, HttpResponseNotFound, JsonResponse
from pathlib import Path
from django.contrib import messages
from celery.app.control import Inspect
from django.db.models import Count, Q
from django.views.decorators.http import require_POST, require_http_methods
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.utils import timezone
from .scanner import Scanner
import threading
import logging
import yaml
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import psutil

logger = logging.getLogger(__name__)

class AssetViewSet(viewsets.ModelViewSet):
    queryset = Asset.objects.all()
    serializer_class = AssetSerializer

class ScanViewSet(viewsets.ModelViewSet):
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer

def index_view(request):
    # Get filter parameters
    asset_type = request.GET.get('type', '')
    search_query = request.GET.get('q', '')
    favorite = request.GET.get('favorite', '')
    
    # Start with all assets, ordered by name
    assets = Asset.objects.all().order_by('name')
    
    # Apply filters
    if asset_type:
        assets = assets.filter(asset_type=asset_type)
    if search_query:
        assets = assets.filter(
            Q(name__icontains=search_query) |
            Q(notes__icontains=search_query)
        )
    if favorite == 'true':
        assets = assets.filter(is_favorite=True)
    
    # Get subdomains and findings for each domain
    for asset in assets:
        asset.subdomain_list = asset.get_subdomains()
        asset.findings_count = asset.get_findings().count()
    
    # Check available modules
    available_modules = Module.objects.filter(enabled=True)
    print(f"DEBUG: Found {available_modules.count()} enabled modules")
    for module in available_modules:
        print(f"DEBUG: Available module: {module.name} (enabled: {module.enabled})")
    
    # Pagination with 200 items per page
    paginator = Paginator(assets, 250)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'assets': page_obj,
        'asset_types': Asset.ASSET_TYPES,
        'search_query': search_query,
        'selected_type': asset_type,
        'show_favorites': favorite == 'true',
        'scan_form': ScanForm()  # Add scan form to context
    }
    return render(request, 'scanner/index.html', context)

def bulk_asset_view(request):
    if request.method == 'POST':
        form = BulkAssetForm(request.POST)
        if form.is_valid():
            assets_data = form.cleaned_data['assets']
            created_assets = []
            
            # First pass: Create all domains
            domain_assets = {}
            for asset_data in assets_data:
                if asset_data['asset_type'] == 'domain':
                    asset, created = Asset.objects.get_or_create(
                        name=asset_data['value'],
                        asset_type=asset_data['asset_type']
                    )
                    domain_assets[asset_data['value']] = asset
                    if created:
                        created_assets.append(asset)
            
            # Second pass: Create subdomains with their parent relationships
            for asset_data in assets_data:
                if asset_data['asset_type'] == 'subdomain':
                    parent_domain = domain_assets.get(asset_data['parent'])
                    if parent_domain:
                        # Create the subdomain with the parent relationship
                        subdomain, created = Subdomain.objects.get_or_create(
                            name=asset_data['value'],
                            asset=parent_domain
                        )
                        if created:
                            created_assets.append(subdomain)
                    else:
                        # If parent domain wasn't created for some reason, create the subdomain without parent
                        subdomain, created = Subdomain.objects.get_or_create(
                            name=asset_data['value'],
                            asset=domain_assets.get(asset_data['value'].split('.', 1)[1])
                        )
                        if created:
                            created_assets.append(subdomain)
                elif asset_data['asset_type'] == 'ip':
                    # Handle IP addresses
                    asset, created = Asset.objects.get_or_create(
                        name=asset_data['value'],
                        asset_type=asset_data['asset_type']
                    )
                    if created:
                        created_assets.append(asset)
            
            messages.success(request, f"Successfully added {len(created_assets)} assets.")
            return redirect('index')
    else:
        form = BulkAssetForm()
    
    return render(request, 'scanner/bulk_asset_form.html', {'form': form})

def bulk_asset_success_view(request):
    return render(request, 'scanner/bulk_asset_success.html')

def scan_status_view(request):
    scans = Scan.objects.order_by('-started_at')
    return render(request, 'scanner/scan_status.html', {'scans': scans})

def scan_engine_view(request):
    if request.method == "POST":
        assets = Asset.objects.all()
        modules = Module.objects.all()

        for asset in assets:
            scan = Scan.objects.create(
                asset=asset,
                status="queued",
                started_at=now()
            )

            scan.status = "running"
            scan.save()

        return redirect('scan-status')

    return render(request, 'scanner/scan_engine.html')

@require_POST
def cancel_scan_view(request, scan_id):
    try:
        scan = get_object_or_404(Scan, id=scan_id)
        
        if scan.status not in ['running', 'queued']:
            return JsonResponse({
                'status': 'error', 
                'message': f'Scan is not in a running or queued state (current status: {scan.status})'
            }, status=400)
        
        # Revoke the Celery task if it exists
        if scan.task_id:
            try:
                app = current_app._get_current_object()
                app.control.revoke(scan.task_id, terminate=True)
            except Exception as e:
                logger.error(f"Error revoking task {scan.task_id}: {e}")
        
        # Update scan status
        scan.status = 'canceled'
        scan.completed_at = timezone.now()
        scan.output = 'Scan was manually canceled'
        scan.save()
        
        return JsonResponse({'status': 'success', 'message': 'Scan canceled successfully'})
        
    except Exception as e:
        logger.error(f"Error canceling scan {scan_id}: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

def module_list_view(request):
    modules = Module.objects.all()
    return render(request, 'scanner/modules.html', {'modules': modules})

def add_module_view(request, module_id=None):
    if module_id:
        module = get_object_or_404(Module, id=module_id)
        print(f"DEBUG: Editing existing module {module.name}")
    else:
        module = None
        print("DEBUG: Creating new module")

    if request.method == 'POST':
        form = ModuleForm(request.POST, instance=module)
        print(f"DEBUG: Form data: {request.POST}")
        if form.is_valid():
            module = form.save(commit=False)
            print(f"DEBUG: Form is valid, module name: {module.name}")
            print(f"DEBUG: Module enabled before save: {module.enabled}")
            
            # Handle YAML configuration
            yaml_file = form.cleaned_data.get('yaml_file')
            if yaml_file:
                config_path = Path(__file__).parent / 'modules' / 'config' / yaml_file
                try:
                    with open(config_path) as f:
                        module.config = yaml.safe_load(f)
                except Exception as e:
                    print(f"Error loading YAML config: {e}")
                    messages.error(request, f"Error loading YAML configuration: {str(e)}")
                    return render(request, 'scanner/add_module.html', {'form': form, 'module': module})
            
            # Set enabled to True by default for new modules
            if not module_id:
                module.enabled = True
                print(f"DEBUG: Setting enabled=True for new module {module.name}")
            
            # Save the module
            try:
                module.save()
                print(f"DEBUG: Module saved successfully. Enabled: {module.enabled}")
                
                # Verify the module was saved correctly
                saved_module = Module.objects.get(id=module.id)
                print(f"DEBUG: Module in database - Name: {saved_module.name}, Enabled: {saved_module.enabled}")
                
                messages.success(request, f"Module '{module.name}' {'updated' if module_id else 'added'} successfully!")
                return redirect('module-list')
            except Exception as e:
                print(f"Error saving module: {e}")
                messages.error(request, f"Error saving module: {str(e)}")
        else:
            print(f"Form errors: {form.errors}")
            messages.error(request, "Please correct the errors below.")
    else:
        form = ModuleForm(instance=module)
        # Set enabled to True by default for new modules
        if not module_id:
            form.initial['enabled'] = True
            print("DEBUG: Setting initial enabled=True for new module form")

    return render(request, 'scanner/add_module.html', {'form': form, 'module': module})

def edit_asset_view(request, asset_id):
    asset = get_object_or_404(Asset, id=asset_id)
    if request.method == 'POST':
        form = AssetForm(request.POST, instance=asset)
        if form.is_valid():
            asset = form.save()
            messages.success(request, f'Asset {asset.name} updated successfully!')
            return redirect('asset-detail', asset_id=asset.id)
    else:
        form = AssetForm(instance=asset)
    
    return render(request, 'scanner/edit_asset.html', {'form': form, 'asset': asset})

def delete_asset_view(request, asset_id):
    asset = get_object_or_404(Asset, id=asset_id)
    if request.method == 'POST':
        asset_name = asset.name
        asset.delete()
        messages.success(request, f'Asset {asset_name} deleted successfully!')
        return redirect('index')
    
    return render(request, 'scanner/delete_asset_form.html', {'asset': asset})

def scan_single_asset_view(request, asset_id):
    asset = get_object_or_404(Asset, id=asset_id)
    modules = Module.objects.all()

    # Create a new Scan entry for this asset
    scan = Scan.objects.create(
        asset=asset,
        status="queued",
        started_at=now()
    )

    scan.status = "running"
    scan.save()

    return redirect('scan-status')

def check_system_resources():
    """Check if system has enough resources to run a new scan"""
    cpu_percent = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory()
    memory_percent = memory.percent
    
    # Get number of running scans
    running_scans = Scan.objects.filter(status='running').count()
    
    # Resource thresholds
    MAX_CPU_PERCENT = 80
    MAX_MEMORY_PERCENT = 80
    MAX_CONCURRENT_SCANS = 3
    
    if cpu_percent > MAX_CPU_PERCENT:
        return False, f"CPU usage too high ({cpu_percent}%)"
    if memory_percent > MAX_MEMORY_PERCENT:
        return False, f"Memory usage too high ({memory_percent}%)"
    if running_scans >= MAX_CONCURRENT_SCANS:
        return False, f"Too many concurrent scans running ({running_scans})"
    
    return True, "System resources available"

def start_scan_view(request, asset_id):
    asset = get_object_or_404(Asset, id=asset_id)
    
    if request.method == 'POST':
        form = ScanForm(request.POST)
        if form.is_valid():
            # Check if the asset is ignored
            if asset.is_ignored():
                messages.warning(request, f"Asset {asset.name} is in the ignore list and will not be scanned.")
                return redirect('asset-detail', asset_id=asset.id)
            
            # Check system resources
            can_run, reason = check_system_resources()
            if not can_run:
                messages.warning(request, f"Cannot start scan: {reason}")
                return redirect('asset-detail', asset_id=asset.id)
            
            module = form.cleaned_data['module']
            
            # Create a new scan
            scan = Scan.objects.create(
                asset=asset,
                module=module,
                status='queued',
                started_at=timezone.now(),
                output='Initializing scan...'
            )
            
            # Start the scan task
            try:
                task = run_scan.delay(scan.id)
                scan.task_id = task.id
                scan.save()
                messages.success(request, f"Started {module.name} scan for {asset.name}")
            except Exception as e:
                scan.status = 'failed'
                scan.output = str(e)
                scan.completed_at = timezone.now()
                scan.save()
                messages.error(request, f"Failed to start scan: {str(e)}")
            
            return redirect('asset-detail', asset_id=asset.id)
        else:
            messages.error(request, "Please select a valid scan module")
            return redirect('asset-detail', asset_id=asset.id)
    else:
        return redirect('asset-detail', asset_id=asset.id)

def scan_output(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    return render(request, 'scanner/scan_output.html', {'scan': scan})

def toggle_favorite(request, model, object_id):
    if model == 'asset':
        obj = get_object_or_404(Asset, id=object_id)
    elif model == 'subdomain':
        obj = get_object_or_404(Subdomain, id=object_id)
    else:
        return JsonResponse({'success': False, 'error': 'Invalid model type'})
    
    obj.is_favorite = not obj.is_favorite
    obj.save()
    
    return JsonResponse({'success': True, 'is_favorite': obj.is_favorite})

def favorites_view(request):
    # Get favorite assets and subdomains
    favorite_assets = Asset.objects.filter(is_favorite=True)
    favorite_subdomains = Subdomain.objects.filter(is_favorite=True)
    
    context = {
        'favorites': {
            'assets': favorite_assets,
            'subdomains': favorite_subdomains
        }
    }
    return render(request, 'scanner/favorites.html', context)

def tag_list(request):
    tags = Tag.objects.all()
    return render(request, 'scanner/tag_list.html', {'tags': tags})

def add_tag(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        if name:
            Tag.objects.create(name=name)
            messages.success(request, f'Tag {name} added successfully!')
            return redirect('tag-list')
    
    return render(request, 'scanner/add_tag.html')

def edit_tag(request, tag_id):
    tag = get_object_or_404(Tag, id=tag_id)
    if request.method == 'POST':
        name = request.POST.get('name')
        if name:
            tag.name = name
            tag.save()
            messages.success(request, f'Tag {name} updated successfully!')
            return redirect('tag-list')
    
    return render(request, 'scanner/edit_tag.html', {'tag': tag})

def delete_tag(request, tag_id):
    tag = get_object_or_404(Tag, id=tag_id)
    if request.method == 'POST':
        tag_name = tag.name
        tag.delete()
        messages.success(request, f'Tag {tag_name} deleted successfully!')
        return redirect('tag-list')
    
    return render(request, 'scanner/delete_tag.html', {'tag': tag})

def tag_detail(request, tag_id):
    tag = get_object_or_404(Tag, id=tag_id)
    assets = tag.asset_set.all()
    return render(request, 'scanner/tag_detail.html', {'tag': tag, 'assets': assets})

def load_yaml_config(request, filename):
    """API endpoint to load YAML config file content"""
    if not filename:
        print("No filename provided")
        return HttpResponseBadRequest("No filename provided")
        
    # Use absolute path resolution
    config_path = Path(__file__).resolve().parent / 'modules' / 'config' / filename
    print(f"Looking for config file at: {config_path}")
    
    try:
        if not config_path.exists():
            print(f"File does not exist: {config_path}")
            return HttpResponseNotFound(f"Configuration file '{filename}' not found")
            
        with open(config_path) as f:
            content = f.read()
            print(f"Successfully read content ({len(content)} chars)")
            
            if not content.strip():
                print("Empty file, returning default content")
                default_content = (
                    "# Default configuration\n"
                    "packet_count: 4\n"
                    "timeout: 30"
                )
                return HttpResponse(default_content, content_type='text/plain')
            
            print("Returning file content")
            return HttpResponse(content, content_type='text/plain')
            
    except Exception as e:
        print(f"Error reading file: {str(e)}")
        return HttpResponseBadRequest(f"Error reading configuration: {str(e)}")

def cancel_stuck_scans(request, asset_id):
    """Cancel any scans that are stuck in queued or running state"""
    asset = get_object_or_404(Asset, id=asset_id)
    
    # Find all scans that are stuck
    stuck_scans = Scan.objects.filter(
        asset=asset,
        status__in=['queued', 'running']
    )
    
    count = stuck_scans.count()
    if count > 0:
        # Update all stuck scans to canceled
        stuck_scans.update(
            status='canceled',
            output='Scan was manually canceled due to being stuck'
        )
        messages.success(request, f'Successfully canceled {count} stuck scan(s)')
    else:
        messages.info(request, 'No stuck scans found')
    
    return redirect('asset-detail', pk=asset_id)

def add_asset(request):
    if request.method == 'POST':
        form = AssetForm(request.POST)
        if form.is_valid():
            asset = form.save()
            messages.success(request, f'Asset {asset.name} added successfully!')
            return redirect('asset-detail', asset_id=asset.id)
    else:
        form = AssetForm()
    
    return render(request, 'scanner/add_asset.html', {'form': form})

def asset_detail(request, asset_id):
    asset = get_object_or_404(Asset, id=asset_id)
    
    # Get all subdomains for this asset
    subdomains = asset.domain_subdomains.all()
    
    # Get all findings for this asset
    findings = asset.finding_set.all()
    
    # Get scan history
    scan_history = Scan.objects.filter(asset=asset).order_by('-started_at')
    
    # Get latest scan
    latest_scan = scan_history.first()
    
    # Get available modules
    modules = Module.objects.all()
    
    # Get scan statistics
    scan_stats = {
        'total': scan_history.count(),
        'completed': scan_history.filter(status='completed').count(),
        'running': scan_history.filter(status='running').count(),
        'failed': scan_history.filter(status='failed').count()
    }
    
    # Get endpoints
    endpoints = asset.endpoints.all().order_by('-discovered_at')
    
    # Create scan form
    scan_form = ScanForm()
    
    context = {
        'asset': asset,
        'subdomains': subdomains,
        'findings': findings,
        'scan_history': scan_history,
        'latest_scan': latest_scan,
        'modules': modules,
        'scan_stats': scan_stats,
        'scan_form': scan_form,
        'endpoints': endpoints
    }
    
    return render(request, 'scanner/asset_detail.html', context)

class SubdomainDetailView(DetailView):
    model = Subdomain
    template_name = 'scanner/subdomain_detail.html'
    context_object_name = 'subdomain'
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        subdomain = self.get_object()
        context['modules'] = Module.objects.all()
        context['endpoints'] = subdomain.endpoints.all().order_by('-discovered_at')
        context['scans'] = Scan.objects.filter(subdomain=subdomain).order_by('-started_at')[:10]
        context['findings'] = Finding.objects.filter(subdomain=subdomain).order_by('-created_at')
        return context

def start_subdomain_scan(request, subdomain_id):
    if request.method == 'POST':
        subdomain = get_object_or_404(Subdomain, id=subdomain_id)
        module_id = request.POST.get('module_id')
        if module_id:
            module = get_object_or_404(Module, id=module_id)  # Get the module
            scan = Scan.objects.create(
                asset=subdomain.asset,
                subdomain=subdomain,
                module=module,  # Add the module to the scan
                status='queued',
                started_at=now()
            )
            # Store the task ID
            task = run_scan.delay(scan.id)
            scan.task_id = task.id
            scan.save()
            
            return redirect('subdomain-detail', pk=subdomain_id)
    return HttpResponseBadRequest('Invalid request')

def ignored_assets_view(request):
    if request.method == 'POST':
        form = BulkIgnoredAssetForm(request.POST)
        if form.is_valid():
            assets_data = form.cleaned_data['assets']
            created_count = 0
            
            for asset_data in assets_data:
                # Create the ignored asset
                ignored_asset, created = IgnoredAsset.objects.get_or_create(
                    name=asset_data['value'],
                    asset_type=asset_data['asset_type']
                )
                if created:
                    created_count += 1
            
            messages.success(request, f"Successfully added {created_count} assets to ignore list.")
            return redirect('ignored_assets')
    else:
        form = BulkIgnoredAssetForm()

    ignored_assets = IgnoredAsset.objects.all()
    return render(request, 'scanner/ignored_assets.html', {
        'form': form,
        'ignored_assets': ignored_assets
    })

@require_POST
def delete_ignored_asset(request, asset_id):
    """Delete an ignored asset."""
    try:
        asset = get_object_or_404(IgnoredAsset, id=asset_id)
        asset.delete()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'success': False, 'error': str(e)}, status=400)

def continuous_scan_list(request):
    """View to list all continuous scans"""
    continuous_scans = ContinuousScan.objects.all()
    return render(request, 'scanner/continuous_scan_list.html', {
        'continuous_scans': continuous_scans
    })

def continuous_scan_detail(request, scan_id):
    """View to show details of a continuous scan"""
    continuous_scan = get_object_or_404(ContinuousScan, id=scan_id)
    scan_history = continuous_scan.get_scan_history()[:10]  # Get last 10 scans
    scan_stats = continuous_scan.get_scan_stats()
    
    return render(request, 'scanner/continuous_scan_detail.html', {
        'continuous_scan': continuous_scan,
        'scan_history': scan_history,
        'scan_stats': scan_stats
    })

def continuous_scan_create(request):
    if request.method == 'POST':
        form = ContinuousScanForm(request.POST)
        if form.is_valid():
            continuous_scan = form.save(commit=False)
            continuous_scan.save()
            form.save_m2m()  # Save the many-to-many relationships (modules)
            
            messages.success(request, 'Continuous scan created successfully.')
            return redirect('continuous-scan-detail', continuous_scan.id)
    else:
        form = ContinuousScanForm()
    
    return render(request, 'scanner/continuous_scan_form.html', {
        'form': form,
        'title': 'Create Continuous Scan'
    })

def continuous_scan_edit(request, scan_id):
    """View to edit an existing continuous scan"""
    continuous_scan = get_object_or_404(ContinuousScan, id=scan_id)
    
    if request.method == 'POST':
        form = ContinuousScanForm(request.POST, instance=continuous_scan)
        if form.is_valid():
            continuous_scan = form.save()
            messages.success(request, f'Continuous scan {continuous_scan.name} updated successfully!')
            return redirect('continuous-scan-detail', scan_id=continuous_scan.id)
    else:
        form = ContinuousScanForm(instance=continuous_scan)
    
    return render(request, 'scanner/continuous_scan_form.html', {
        'form': form,
        'title': 'Edit Continuous Scan',
        'continuous_scan': continuous_scan
    })

@require_http_methods(["POST"])
def continuous_scan_start(request, scan_id):
    continuous_scan = get_object_or_404(ContinuousScan, id=scan_id)
    
    if continuous_scan.start():
        # Create and run initial scans for each asset-module combination
        for asset in Asset.objects.all():
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
                        status='queued'
                    )
                    run_scan.delay(scan.id)
                    print(f"Created and queued scan for {asset.name} with {module.name}")
        
        messages.success(request, f"Continuous scan '{continuous_scan.name}' started successfully.")
    else:
        messages.warning(request, f"Continuous scan '{continuous_scan.name}' is already running or cannot be started.")
    
    return redirect('continuous-scan-detail', scan_id=scan_id)

@require_POST
def continuous_scan_pause(request, scan_id):
    """View to pause a continuous scan"""
    continuous_scan = get_object_or_404(ContinuousScan, id=scan_id)
    continuous_scan.pause()
    messages.success(request, f'Continuous scan {continuous_scan.name} paused successfully!')
    return redirect('continuous-scan-detail', scan_id=scan_id)

@require_POST
def continuous_scan_stop(request, scan_id):
    """View to stop a continuous scan"""
    continuous_scan = get_object_or_404(ContinuousScan, id=scan_id)
    
    if continuous_scan.stop():
        # Cancel any running or queued scans for this continuous scan
        running_scans = Scan.objects.filter(
            module__in=continuous_scan.modules.all(),
            status__in=['running', 'queued']
        )
        
        for scan in running_scans:
            if scan.task_id:
                try:
                    from celery.task.control import revoke
                    revoke(scan.task_id, terminate=True)
                except Exception as e:
                    print(f"Error revoking task {scan.task_id}: {e}")
            scan.status = 'canceled'
            scan.completed_at = timezone.now()
            scan.save()
        
        messages.success(request, f'Continuous scan {continuous_scan.name} stopped successfully!')
    else:
        messages.warning(request, f'Continuous scan {continuous_scan.name} is already stopped.')
    
    return redirect('continuous-scan-detail', scan_id=scan_id)