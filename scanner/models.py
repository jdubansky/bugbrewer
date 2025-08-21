from django.db import models
from django.utils import timezone
from pathlib import Path
import yaml
from django.contrib.postgres.fields import ArrayField
from django.urls import reverse
import math
from scipy import stats
from .utils import get_python_modules
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator, MaxValueValidator
import re
import ipaddress
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.db.models import Avg, F

class Tag(models.Model):
    name = models.CharField(max_length=50, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['name']

class Asset(models.Model):
    ASSET_TYPES = [
        ('domain', 'Domain'),
        ('subdomain', 'Subdomain'),
    ]
    
    name = models.CharField(max_length=255)
    asset_type = models.CharField(max_length=20, choices=ASSET_TYPES)
    parent = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, related_name='child_subdomains')
    is_favorite = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    # Common fields for all assets
    notes = models.TextField(blank=True)
    tags = models.ManyToManyField('Tag', blank=True)
    
    # Domain-specific fields (null=True for subdomains)
    registrar = models.CharField(max_length=255, null=True, blank=True)
    registration_date = models.DateField(null=True, blank=True)
    expiration_date = models.DateField(null=True, blank=True)
    
    class Meta:
        unique_together = ['name', 'asset_type']
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['asset_type']),
            models.Index(fields=['is_favorite']),
        ]

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse('asset-detail', args=[str(self.id)])

    def get_subdomains(self):
        return self.domain_subdomains.all()

    def get_findings(self):
        return Finding.objects.filter(asset=self)

    def get_scan_history(self):
        return Scan.objects.filter(asset=self).order_by('-started_at')

    def get_latest_scan(self):
        return self.get_scan_history().first()

    def get_open_findings(self):
        return self.get_findings().filter(status='open')

    def get_closed_findings(self):
        return self.get_findings().filter(status='closed')

    def get_finding_count(self):
        return self.get_findings().count()

    def get_open_finding_count(self):
        return self.get_open_findings().count()

    def get_closed_finding_count(self):
        return self.get_closed_findings().count()

    def get_scan_count(self):
        return self.get_scan_history().count()

    def get_last_scan_time(self):
        last_scan = self.get_latest_scan()
        return last_scan.started_at if last_scan else None

    def get_scan_status(self):
        last_scan = self.get_latest_scan()
        return last_scan.status if last_scan else 'never_scanned'

    def get_scan_duration(self):
        last_scan = self.get_latest_scan()
        if last_scan and last_scan.completed_at:
            return last_scan.completed_at - last_scan.started_at
        return None

    def get_scan_modules(self):
        return self.get_scan_history().values_list('module', flat=True).distinct()

    def get_scan_frequency(self):
        """Calculate average time between scans"""
        scans = self.get_scan_history()
        if len(scans) < 2:
            return None
        
        # Get all scan start times, filtering out None values
        start_times = [scan.started_at for scan in scans if scan.started_at is not None]
        
        if len(start_times) < 2:
            return None
        
        # Calculate time differences between consecutive scans
        time_diffs = []
        for i in range(1, len(start_times)):
            time_diff = start_times[i-1] - start_times[i]
            time_diffs.append(time_diff.total_seconds())
        
        if not time_diffs:
            return None
        
        # Calculate average in hours
        avg_seconds = sum(time_diffs) / len(time_diffs)
        return avg_seconds / 3600  # Convert to hours

    def get_scan_success_rate(self):
        scans = self.get_scan_history()
        if not scans:
            return 0
        successful_scans = scans.filter(status='completed').count()
        return (successful_scans / scans.count()) * 100

    def get_scan_failure_rate(self):
        scans = self.get_scan_history()
        if not scans:
            return 0
        failed_scans = scans.filter(status='failed').count()
        return (failed_scans / scans.count()) * 100

    def get_scan_cancel_rate(self):
        scans = self.get_scan_history()
        if not scans:
            return 0
        canceled_scans = scans.filter(status='canceled').count()
        return (canceled_scans / scans.count()) * 100

    def get_scan_average_duration(self):
        scans = self.get_scan_history().filter(completed_at__isnull=False)
        if not scans:
            return None
        total_duration = sum((scan.completed_at - scan.started_at).total_seconds() for scan in scans)
        return total_duration / scans.count()

    def get_scan_std_dev_duration(self):
        scans = self.get_scan_history().filter(completed_at__isnull=False)
        if not scans:
            return None
        durations = [(scan.completed_at - scan.started_at).total_seconds() for scan in scans]
        mean = sum(durations) / len(durations)
        variance = sum((x - mean) ** 2 for x in durations) / len(durations)
        return math.sqrt(variance)

    def get_scan_median_duration(self):
        scans = self.get_scan_history().filter(completed_at__isnull=False)
        if not scans:
            return None
        durations = sorted([(scan.completed_at - scan.started_at).total_seconds() for scan in scans])
        n = len(durations)
        if n % 2 == 0:
            return (durations[n//2 - 1] + durations[n//2]) / 2
        return durations[n//2]

    def get_scan_min_duration(self):
        scans = self.get_scan_history().filter(completed_at__isnull=False)
        if not scans:
            return None
        return min((scan.completed_at - scan.started_at).total_seconds() for scan in scans)

    def get_scan_max_duration(self):
        scans = self.get_scan_history().filter(completed_at__isnull=False)
        if not scans:
            return None
        return max((scan.completed_at - scan.started_at).total_seconds() for scan in scans)

    def get_scan_quartiles(self):
        scans = self.get_scan_history().filter(completed_at__isnull=False)
        if not scans:
            return None, None, None
        durations = sorted([(scan.completed_at - scan.started_at).total_seconds() for scan in scans])
        n = len(durations)
        q1 = durations[n//4] if n >= 4 else None
        q2 = self.get_scan_median_duration()
        q3 = durations[3*n//4] if n >= 4 else None
        return q1, q2, q3

    def get_scan_outliers(self):
        scans = self.get_scan_history().filter(completed_at__isnull=False)
        if not scans:
            return []
        durations = [(scan.completed_at - scan.started_at).total_seconds() for scan in scans]
        q1, q2, q3 = self.get_scan_quartiles()
        if not all([q1, q2, q3]):
            return []
        iqr = q3 - q1
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr
        return [scan for scan, duration in zip(scans, durations) 
                if duration < lower_bound or duration > upper_bound]

    def get_scan_trend(self):
        scans = self.get_scan_history().filter(completed_at__isnull=False)
        if not scans or scans.count() < 2:
            return None
        durations = [(scan.completed_at - scan.started_at).total_seconds() for scan in scans]
        x = range(len(durations))
        slope, _, _, _, _ = stats.linregress(x, durations)
        return slope

    def get_scan_prediction(self):
        trend = self.get_scan_trend()
        if not trend:
            return None
        last_scan = self.get_latest_scan()
        if not last_scan or not last_scan.completed_at:
            return None
        last_duration = (last_scan.completed_at - last_scan.started_at).total_seconds()
        return last_duration + trend

    def get_scan_efficiency(self):
        scans = self.get_scan_history().filter(completed_at__isnull=False)
        if not scans:
            return None
        total_duration = sum((scan.completed_at - scan.started_at).total_seconds() for scan in scans)
        total_findings = self.get_finding_count()
        if total_duration == 0:
            return float('inf') if total_findings > 0 else 0
        return total_findings / total_duration

    def get_scan_effectiveness(self):
        scans = self.get_scan_history()
        if not scans:
            return None
        total_scans = scans.count()
        successful_scans = scans.filter(status='completed').count()
        if total_scans == 0:
            return 0
        return (successful_scans / total_scans) * 100

    def get_scan_coverage(self):
        modules = Module.objects.all()
        if not modules:
            return 0
        scanned_modules = set(self.get_scan_modules())
        return (len(scanned_modules) / modules.count()) * 100

    def get_scan_gaps(self):
        modules = set(Module.objects.values_list('name', flat=True))
        scanned_modules = set(self.get_scan_modules())
        return modules - scanned_modules

    def get_scan_frequency_score(self):
        frequency = self.get_scan_frequency()
        if not frequency:
            return 0
        # Convert to days
        frequency_days = frequency / (24 * 60 * 60)
        if frequency_days <= 7:
            return 100
        elif frequency_days <= 14:
            return 80
        elif frequency_days <= 30:
            return 60
        elif frequency_days <= 90:
            return 40
        else:
            return 20

    def get_scan_completeness_score(self):
        coverage = self.get_scan_coverage()
        if coverage >= 90:
            return 100
        elif coverage >= 75:
            return 80
        elif coverage >= 50:
            return 60
        elif coverage >= 25:
            return 40
        else:
            return 20

    def get_scan_quality_score(self):
        effectiveness = self.get_scan_effectiveness()
        if effectiveness is None:
            return 0
        if effectiveness >= 90:
            return 100
        elif effectiveness >= 75:
            return 80
        elif effectiveness >= 50:
            return 60
        elif effectiveness >= 25:
            return 40
        else:
            return 20

    def get_overall_scan_score(self):
        frequency_score = self.get_scan_frequency_score()
        completeness_score = self.get_scan_completeness_score()
        quality_score = self.get_scan_quality_score()
        return (frequency_score + completeness_score + quality_score) / 3

    def is_ignored(self):
        """Check if this asset or any of its subdomains are in the ignored list."""
        # Check if the asset itself is ignored
        if IgnoredAsset.objects.filter(name=self.name).exists():
            return True
        
        # If it's a domain, check if any of its subdomains are ignored
        if self.asset_type == 'domain':
            subdomains = self.get_subdomains()
            for subdomain in subdomains:
                if IgnoredAsset.objects.filter(name=subdomain.name).exists():
                    return True
        
        return False

class Module(models.Model):
    name = models.CharField(max_length=100, unique=True)
    python_module = models.CharField(
        max_length=255,
        choices=get_python_modules(),
        help_text="Name of the Python module to run (e.g., 'ping_scanner')"
    )
    description = models.TextField(blank=True)
    command = models.CharField(max_length=255, blank=True)
    output_format = models.CharField(max_length=50, choices=[
        ('json', 'JSON'),
        ('text', 'Text'),
        ('xml', 'XML'),
        ('csv', 'CSV')
    ], default='json')
    enabled = models.BooleanField(default=True)
    config = models.JSONField(
        default=dict,
        blank=True,
        help_text="Module configuration (will be saved as YAML)"
    )

    def __str__(self):
        return f"{self.name} ({self.python_module})"

    def get_config_path(self):
        """Get the path to the module's config file"""
        return Path(__file__).parent / 'modules' / 'config' / f"{self.python_module}.yaml"

    def get_default_config(self):
        """Get the default configuration for this module"""
        config_path = self.get_config_path()
        if config_path.exists():
            with open(config_path) as f:
                return yaml.safe_load(f)
        return {}

    def save(self, *args, **kwargs):
        if not self.config:
            self.config = self.get_default_config()
        
        # Save config to YAML file
        config_path = self.get_config_path()
        config_path.parent.mkdir(parents=True, exist_ok=True)  # Ensure directory exists
        
        # Format YAML nicely
        with open(config_path, 'w') as f:
            yaml.dump(
                self.config,
                f,
                default_flow_style=False,
                sort_keys=False,
                indent=2
            )
        
        super().save(*args, **kwargs)

class Scan(models.Model):
    STATUS_CHOICES = [
        ('queued', 'Queued'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('ignored', 'Ignored'),
    ]
    
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE)
    subdomain = models.ForeignKey('Subdomain', on_delete=models.CASCADE, null=True, blank=True)
    module = models.ForeignKey('Module', on_delete=models.CASCADE, null=True, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='queued')
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    task_id = models.CharField(max_length=50, null=True, blank=True)
    output = models.TextField(null=True, blank=True)

    def __str__(self):
        return f"Scan of {self.asset.name} using {self.module.name if self.module else 'unknown module'}"


class ScanQueue(models.Model):
    scan = models.OneToOneField(Scan, on_delete=models.CASCADE)
    priority = models.IntegerField(default=0)
    added_at = models.DateTimeField(auto_now_add=True)

class Finding(models.Model):
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE)
    subdomain = models.ForeignKey('Subdomain', on_delete=models.CASCADE, null=True, blank=True)
    scan = models.ForeignKey('Scan', on_delete=models.CASCADE, null=True, blank=True)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True, null=True)
    severity = models.CharField(
        max_length=10, 
        choices=[('low', 'Low'), ('medium', 'Medium'), ('high', 'High')],
        default='low'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('asset', 'title')

    def __str__(self):
        return f"{self.title} ({self.severity}) - {self.asset.name}"

class Port(models.Model):
    asset = models.ForeignKey('Asset', on_delete=models.CASCADE, related_name='ports', null=True, blank=True)
    subdomain = models.ForeignKey('Subdomain', on_delete=models.CASCADE, related_name='ports', null=True, blank=True)
    port = models.IntegerField()
    protocol = models.CharField(max_length=10, choices=[("tcp", "TCP"), ("udp", "UDP")], default="tcp")
    service = models.CharField(max_length=100, blank=True, null=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    findings = models.ManyToManyField('Finding', related_name='ports', blank=True)
    scans = models.ManyToManyField('Scan', related_name='ports', blank=True)

    class Meta:
        unique_together = [
            ("asset", "port", "protocol"),
            ("subdomain", "port", "protocol")
        ]
        constraints = [
            models.CheckConstraint(
                check=(
                    models.Q(asset__isnull=False, subdomain__isnull=True) |
                    models.Q(asset__isnull=True, subdomain__isnull=False)
                ),
                name="port_belongs_to_either_asset_or_subdomain"
            )
        ]

    def __str__(self):
        target = self.asset.name if self.asset else self.subdomain.name
        return f"{self.port}/{self.protocol} ({self.service or 'Unknown'}) on {target}"

class Subdomain(models.Model):
    name = models.CharField(max_length=255)
    asset = models.ForeignKey(Asset, on_delete=models.CASCADE, related_name='domain_subdomains')
    is_favorite = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    notes = models.TextField(blank=True)
    tags = models.ManyToManyField('Tag', blank=True)

    class Meta:
        unique_together = ['name', 'asset']
        ordering = ['name']

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse('subdomain-detail', args=[str(self.id)])

    def get_findings(self):
        return Finding.objects.filter(subdomain=self)

    def get_scan_history(self):
        return Scan.objects.filter(subdomain=self).order_by('-started_at')

    def get_latest_scan(self):
        return self.get_scan_history().first()

    def get_open_findings(self):
        return self.get_findings().filter(status='open')

    def get_closed_findings(self):
        return self.get_findings().filter(status='closed')

    def get_finding_count(self):
        return self.get_findings().count()

    def get_open_finding_count(self):
        return self.get_open_findings().count()

    def get_closed_finding_count(self):
        return self.get_closed_findings().count()

    def get_scan_count(self):
        return self.get_scan_history().count()

    def get_last_scan_time(self):
        last_scan = self.get_latest_scan()
        return last_scan.started_at if last_scan else None

    def get_scan_status(self):
        last_scan = self.get_latest_scan()
        return last_scan.status if last_scan else 'never_scanned'

    def get_scan_duration(self):
        last_scan = self.get_latest_scan()
        if last_scan and last_scan.completed_at:
            return last_scan.completed_at - last_scan.started_at
        return None

    def get_scan_modules(self):
        return self.get_scan_history().values_list('module', flat=True).distinct()

    def get_scan_frequency(self):
        """Calculate average time between scans"""
        scans = self.get_scan_history()
        if len(scans) < 2:
            return None
        
        # Get all scan start times, filtering out None values
        start_times = [scan.started_at for scan in scans if scan.started_at is not None]
        
        if len(start_times) < 2:
            return None
        
        # Calculate time differences between consecutive scans
        time_diffs = []
        for i in range(1, len(start_times)):
            time_diff = start_times[i-1] - start_times[i]
            time_diffs.append(time_diff.total_seconds())
        
        if not time_diffs:
            return None
        
        # Calculate average in hours
        avg_seconds = sum(time_diffs) / len(time_diffs)
        return avg_seconds / 3600  # Convert to hours

    def get_scan_success_rate(self):
        scans = self.get_scan_history()
        if not scans:
            return 0
        successful_scans = scans.filter(status='completed').count()
        return (successful_scans / scans.count()) * 100

    def get_scan_failure_rate(self):
        scans = self.get_scan_history()
        if not scans:
            return 0
        failed_scans = scans.filter(status='failed').count()
        return (failed_scans / scans.count()) * 100

    def get_scan_cancel_rate(self):
        scans = self.get_scan_history()
        if not scans:
            return 0
        canceled_scans = scans.filter(status='canceled').count()
        return (canceled_scans / scans.count()) * 100

    def get_scan_average_duration(self):
        scans = self.get_scan_history().filter(completed_at__isnull=False)
        if not scans:
            return None
        total_duration = sum((scan.completed_at - scan.started_at).total_seconds() for scan in scans)
        return total_duration / scans.count()

    def get_scan_std_dev_duration(self):
        scans = self.get_scan_history().filter(completed_at__isnull=False)
        if not scans:
            return None
        durations = [(scan.completed_at - scan.started_at).total_seconds() for scan in scans]
        mean = sum(durations) / len(durations)
        variance = sum((x - mean) ** 2 for x in durations) / len(durations)
        return math.sqrt(variance)

    def get_scan_median_duration(self):
        scans = self.get_scan_history().filter(completed_at__isnull=False)
        if not scans:
            return None
        durations = sorted([(scan.completed_at - scan.started_at).total_seconds() for scan in scans])
        n = len(durations)
        if n % 2 == 0:
            return (durations[n//2 - 1] + durations[n//2]) / 2
        return durations[n//2]

    def get_scan_min_duration(self):
        scans = self.get_scan_history().filter(completed_at__isnull=False)
        if not scans:
            return None
        return min((scan.completed_at - scan.started_at).total_seconds() for scan in scans)

    def get_scan_max_duration(self):
        scans = self.get_scan_history().filter(completed_at__isnull=False)
        if not scans:
            return None
        return max((scan.completed_at - scan.started_at).total_seconds() for scan in scans)

    def get_scan_quartiles(self):
        scans = self.get_scan_history().filter(completed_at__isnull=False)
        if not scans:
            return None, None, None
        durations = sorted([(scan.completed_at - scan.started_at).total_seconds() for scan in scans])
        n = len(durations)
        q1 = durations[n//4] if n >= 4 else None
        q2 = self.get_scan_median_duration()
        q3 = durations[3*n//4] if n >= 4 else None
        return q1, q2, q3

    def get_scan_outliers(self):
        scans = self.get_scan_history().filter(completed_at__isnull=False)
        if not scans:
            return []
        durations = [(scan.completed_at - scan.started_at).total_seconds() for scan in scans]
        q1, q2, q3 = self.get_scan_quartiles()
        if not all([q1, q2, q3]):
            return []
        iqr = q3 - q1
        lower_bound = q1 - 1.5 * iqr
        upper_bound = q3 + 1.5 * iqr
        return [scan for scan, duration in zip(scans, durations) 
                if duration < lower_bound or duration > upper_bound]

    def get_scan_trend(self):
        scans = self.get_scan_history().filter(completed_at__isnull=False)
        if not scans or scans.count() < 2:
            return None
        durations = [(scan.completed_at - scan.started_at).total_seconds() for scan in scans]
        x = range(len(durations))
        slope, _, _, _, _ = stats.linregress(x, durations)
        return slope

    def get_scan_prediction(self):
        trend = self.get_scan_trend()
        if not trend:
            return None
        last_scan = self.get_latest_scan()
        if not last_scan or not last_scan.completed_at:
            return None
        last_duration = (last_scan.completed_at - last_scan.started_at).total_seconds()
        return last_duration + trend

    def get_scan_efficiency(self):
        scans = self.get_scan_history().filter(completed_at__isnull=False)
        if not scans:
            return None
        total_duration = sum((scan.completed_at - scan.started_at).total_seconds() for scan in scans)
        total_findings = self.get_finding_count()
        if total_duration == 0:
            return float('inf') if total_findings > 0 else 0
        return total_findings / total_duration

    def get_scan_effectiveness(self):
        scans = self.get_scan_history()
        if not scans:
            return None
        total_scans = scans.count()
        successful_scans = scans.filter(status='completed').count()
        if total_scans == 0:
            return 0
        return (successful_scans / total_scans) * 100

    def get_scan_coverage(self):
        modules = Module.objects.all()
        if not modules:
            return 0
        scanned_modules = set(self.get_scan_modules())
        return (len(scanned_modules) / modules.count()) * 100

    def get_scan_gaps(self):
        modules = set(Module.objects.values_list('name', flat=True))
        scanned_modules = set(self.get_scan_modules())
        return modules - scanned_modules

    def get_scan_frequency_score(self):
        frequency = self.get_scan_frequency()
        if not frequency:
            return 0
        # Convert to days
        frequency_days = frequency / (24 * 60 * 60)
        if frequency_days <= 7:
            return 100
        elif frequency_days <= 14:
            return 80
        elif frequency_days <= 30:
            return 60
        elif frequency_days <= 90:
            return 40
        else:
            return 20

    def get_scan_completeness_score(self):
        coverage = self.get_scan_coverage()
        if coverage >= 90:
            return 100
        elif coverage >= 75:
            return 80
        elif coverage >= 50:
            return 60
        elif coverage >= 25:
            return 40
        else:
            return 20

    def get_scan_quality_score(self):
        effectiveness = self.get_scan_effectiveness()
        if effectiveness is None:
            return 0
        if effectiveness >= 90:
            return 100
        elif effectiveness >= 75:
            return 80
        elif effectiveness >= 50:
            return 60
        elif effectiveness >= 25:
            return 40
        else:
            return 20

    def get_overall_scan_score(self):
        frequency_score = self.get_scan_frequency_score()
        completeness_score = self.get_scan_completeness_score()
        quality_score = self.get_scan_quality_score()
        return (frequency_score + completeness_score + quality_score) / 3

class PortScreenshot(models.Model):
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name='screenshots')
    port = models.ForeignKey(Port, on_delete=models.CASCADE, related_name='screenshots')
    screenshot = models.TextField()  # Base64 encoded screenshot
    created_at = models.DateTimeField(auto_now_add=True)
    protocol = models.CharField(max_length=10, choices=[("http", "HTTP"), ("https", "HTTPS")], default="http")

    class Meta:
        unique_together = ('subdomain', 'port', 'protocol')
        ordering = ['-created_at']

    def __str__(self):
        return f"Screenshot of {self.subdomain.name}:{self.port.port} ({self.protocol})"

class IgnoredAsset(models.Model):
    name = models.CharField(max_length=255, unique=True)
    asset_type = models.CharField(max_length=20, choices=Asset.ASSET_TYPES)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']
        verbose_name = 'Ignored Asset'
        verbose_name_plural = 'Ignored Assets'

    def __str__(self):
        return f"{self.name} ({self.get_asset_type_display()})"

    def is_ignored(asset_name, asset_type):
        """Check if an asset should be ignored based on its name and type"""
        return IgnoredAsset.objects.filter(
            name=asset_name,
            asset_type=asset_type
        ).exists()

    def get_ignored_assets():
        """Get all ignored assets grouped by type"""
        return {
            'domains': IgnoredAsset.objects.filter(asset_type='domain'),
            'subdomains': IgnoredAsset.objects.filter(asset_type='subdomain'),
            'ips': IgnoredAsset.objects.filter(asset_type='ip')
        }

class Endpoint(models.Model):
    """Model for storing discovered endpoints (URLs, paths, etc.)"""
    asset = models.ForeignKey('Asset', on_delete=models.CASCADE, related_name='endpoints', null=True, blank=True)
    subdomain = models.ForeignKey('Subdomain', on_delete=models.CASCADE, related_name='endpoints', null=True, blank=True)
    path = models.CharField(max_length=2048)  # The endpoint path (e.g., "/index.php", "/.git")
    method = models.CharField(max_length=10, choices=[
        ('GET', 'GET'),
        ('POST', 'POST'),
        ('PUT', 'PUT'),
        ('DELETE', 'DELETE'),
        ('HEAD', 'HEAD'),
        ('OPTIONS', 'OPTIONS'),
        ('PATCH', 'PATCH')
    ], default='GET')
    status_code = models.IntegerField(null=True, blank=True)
    content_length = models.IntegerField(null=True, blank=True)
    content_type = models.CharField(max_length=255, null=True, blank=True)
    discovered_at = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    is_interesting = models.BooleanField(default=False)  # Mark interesting endpoints (e.g., admin panels, API endpoints)
    notes = models.TextField(blank=True)
    tags = models.ManyToManyField('Tag', blank=True)
    findings = models.ManyToManyField('Finding', related_name='endpoints', blank=True)
    scans = models.ManyToManyField('Scan', related_name='endpoints', blank=True)

    class Meta:
        unique_together = [
            ('asset', 'path', 'method'),
            ('subdomain', 'path', 'method')
        ]
        indexes = [
            models.Index(fields=['path']),
            models.Index(fields=['status_code']),
            models.Index(fields=['is_interesting']),
            models.Index(fields=['discovered_at']),
        ]
        ordering = ['-discovered_at']

    def __str__(self):
        if self.subdomain:
            return f"{self.subdomain.name}{self.path}"
        return f"{self.asset.name}{self.path}"

    def get_absolute_url(self):
        if self.subdomain:
            return f"http{'s' if self.subdomain.ports.filter(port=443).exists() else ''}://{self.subdomain.name}{self.path}"
        return f"http{'s' if self.asset.ports.filter(port=443).exists() else ''}://{self.asset.name}{self.path}"

    def get_findings(self):
        return self.findings.all()

    def get_scan_history(self):
        return self.scans.all().order_by('-started_at')

    def get_latest_scan(self):
        return self.get_scan_history().first()

    def get_open_findings(self):
        return self.get_findings().filter(status='open')

    def get_closed_findings(self):
        return self.get_findings().filter(status='closed')

    def get_finding_count(self):
        return self.get_findings().count()

    def get_open_finding_count(self):
        return self.get_open_findings().count()

    def get_closed_finding_count(self):
        return self.get_closed_findings().count()

    def get_scan_count(self):
        return self.get_scan_history().count()

    def get_last_scan_time(self):
        last_scan = self.get_latest_scan()
        return last_scan.started_at if last_scan else None

    def get_scan_status(self):
        last_scan = self.get_latest_scan()
        return last_scan.status if last_scan else 'never_scanned'

    def get_scan_duration(self):
        last_scan = self.get_latest_scan()
        if last_scan and last_scan.completed_at:
            return last_scan.completed_at - last_scan.started_at
        return None

class ContinuousScan(models.Model):
    STATUS_CHOICES = [
        ('stopped', 'Stopped'),
        ('running', 'Running'),
        ('paused', 'Paused'),
    ]

    name = models.CharField(max_length=100)
    description = models.TextField(blank=True)
    scan_interval = models.IntegerField(validators=[MinValueValidator(1), MaxValueValidator(24)])
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='stopped')
    last_scan = models.DateTimeField(null=True, blank=True)
    next_scan = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    modules = models.ManyToManyField(Module)

    def start(self):
        if self.status == 'stopped':
            self.status = 'running'
            self.next_scan = timezone.now()
            self.save()
            return True
        return False

    def pause(self):
        if self.status == 'running':
            self.status = 'paused'
            self.next_scan = None
            self.save()
            return True
        return False

    def stop(self):
        if self.status in ['running', 'paused']:
            self.status = 'stopped'
            self.next_scan = None
            self.save()
            return True
        return False

    def update_next_scan(self):
        if self.status == 'running':
            self.last_scan = timezone.now()
            self.next_scan = timezone.now() + timezone.timedelta(hours=self.scan_interval)
            self.save()

    def is_due(self):
        if self.status != 'running':
            return False
        if not self.next_scan:
            return True
        return timezone.now() >= self.next_scan

    def get_scan_history(self):
        """Get the scan history for this continuous scan"""
        return Scan.objects.filter(
            module__in=self.modules.all()
        ).order_by('-started_at')

    def get_scan_stats(self):
        """Get statistics about the continuous scan"""
        scans = self.get_scan_history()
        return {
            'total': scans.count(),
            'completed': scans.filter(status='completed').count(),
            'failed': scans.filter(status='failed').count(),
            'avg_duration': scans.filter(completed_at__isnull=False).aggregate(
                avg=Avg(F('completed_at') - F('started_at'))
            )['avg']
        }

    def __str__(self):
        return self.name
