from django import forms
from .models import Asset, Module, Tag, IgnoredAsset
from django.shortcuts import render, redirect
from .models import Module
import os
import yaml
from pathlib import Path
from urllib.parse import urlparse
from .utils import get_python_modules
import re

def get_python_modules():
    """Retrieve available Python module filenames (without .py extension)."""
    module_dir = Path(__file__).parent / "modules" / "python_modules"
    
    try:
        # Filter out __init__.py, __pycache__, and shared_utils.py
        files = os.listdir(module_dir)
        modules = [
            (f[:-3], f[:-3])  # (value, display_name) without .py extension
            for f in files
            if f.endswith(".py") and not f.startswith("__") and not f == "shared_utils.py"
        ]
        return sorted(modules)  # Sort alphabetically
    except FileNotFoundError:
        return []
    except Exception as e:
        return []

def get_yaml_files():
    """Get list of available YAML config files"""
    config_dir = Path(__file__).parent / 'modules' / 'config'
    
    try:
        files = [(f.name, f.name) for f in config_dir.glob('*.yaml')]
        return [('', 'Custom Configuration')] + sorted(files)
    except Exception as e:
        return [('', 'Custom Configuration')]

class BulkAssetForm(forms.Form):
    assets = forms.CharField(
        widget=forms.Textarea(attrs={'placeholder': 'Enter one IP or domain per line'}),
        help_text="Enter one IP or domain per line"
    )

    def clean_domain(self, value):
        """Clean domain input by removing protocol, path, and @ symbol"""
        # Remove @ symbol if present at start
        value = value.lstrip('@')
        
        # Parse URL to extract domain
        parsed = urlparse(value)
        # If there's a netloc (domain), use it, otherwise use the original value
        domain = parsed.netloc if parsed.netloc else parsed.path
        
        # Remove any remaining path or query parameters
        domain = domain.split('/')[0]
        
        return domain.strip()

    def clean_assets(self):
        assets_text = self.cleaned_data['assets']
        asset_list = [line.strip() for line in assets_text.splitlines() if line.strip()]
        
        if not asset_list:
            raise forms.ValidationError("Please enter at least one domain or IP.")

        # Classify each input as IP or domain and clean the values
        cleaned_assets = []
        domains = set()  # Track unique domains
        subdomains = {}  # Track subdomains for each domain
        
        for value in asset_list:
            # Check if it's an IP address (simple check)
            if value.replace('.', '').isdigit():
                asset_type = "ip"
                cleaned_value = value
                cleaned_assets.append({
                    "asset_type": asset_type, 
                    "value": cleaned_value
                })
            else:
                # Clean the domain
                cleaned_value = self.clean_domain(value)
                
                # Check if it's a subdomain (has more than one dot)
                parts = cleaned_value.split('.')
                if len(parts) > 2:
                    # It's a subdomain
                    domain = '.'.join(parts[-2:])  # Get the TLD domain
                    subdomain = cleaned_value
                    domains.add(domain)
                    if domain not in subdomains:
                        subdomains[domain] = []
                    subdomains[domain].append(subdomain)
                else:
                    # It's a domain
                    domains.add(cleaned_value)
                    cleaned_assets.append({
                        "asset_type": "domain", 
                        "value": cleaned_value
                    })

        # Add domains first
        for domain in domains:
            cleaned_assets.append({
                "asset_type": "domain",
                "value": domain
            })

        # Then add subdomains
        for domain, subdomain_list in subdomains.items():
            for subdomain in subdomain_list:
                cleaned_assets.append({
                    "asset_type": "subdomain",
                    "value": subdomain,
                    "parent": domain
                })

        return cleaned_assets

class AssetForm(forms.ModelForm):
    class Meta:
        model = Asset
        fields = ['name', 'asset_type', 'parent', 'notes', 'tags', 'registrar', 'registration_date', 'expiration_date']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'asset_type': forms.Select(attrs={'class': 'form-control'}),
            'parent': forms.Select(attrs={'class': 'form-control'}),
            'notes': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'tags': forms.SelectMultiple(attrs={'class': 'form-control'}),
            'registrar': forms.TextInput(attrs={'class': 'form-control'}),
            'registration_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'expiration_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'})
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Only show domains as possible parents
        self.fields['parent'].queryset = Asset.objects.filter(asset_type='domain')
        # Make parent field optional
        self.fields['parent'].required = False

class ModuleForm(forms.ModelForm):
    python_module = forms.ChoiceField(
        choices=get_python_modules(),
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    
    yaml_file = forms.ChoiceField(
        choices=get_yaml_files(),
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'}),
        help_text="Select a configuration template or use custom configuration"
    )
    
    config_yaml = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 10}),
        required=False,
        help_text="YAML configuration for the module"
    )

    class Meta:
        model = Module
        fields = ['name', 'python_module', 'yaml_file', 'config_yaml', 'description', 'command', 'output_format', 'enabled']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'command': forms.TextInput(attrs={'class': 'form-control'}),
            'output_format': forms.Select(attrs={'class': 'form-control'}),
            'enabled': forms.CheckboxInput(attrs={'class': 'form-check-input'})
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make output_format optional
        self.fields['output_format'].required = False
        # Set default value for output_format
        if not self.instance.output_format:
            self.initial['output_format'] = 'json'

    def clean(self):
        cleaned_data = super().clean()
        yaml_file = cleaned_data.get('yaml_file')
        config_yaml = cleaned_data.get('config_yaml')
        
        # If a YAML file is selected, load its content
        if yaml_file:
            config_path = Path(__file__).parent / 'modules' / 'config' / yaml_file
            try:
                with open(config_path) as f:
                    cleaned_data['config'] = yaml.safe_load(f)
            except Exception as e:
                raise forms.ValidationError(f"Error loading YAML configuration: {str(e)}")
        # If custom YAML is provided, parse it
        elif config_yaml:
            try:
                cleaned_data['config'] = yaml.safe_load(config_yaml)
            except Exception as e:
                raise forms.ValidationError(f"Invalid YAML configuration: {str(e)}")
        
        # Set default output_format if not provided
        if not cleaned_data.get('output_format'):
            cleaned_data['output_format'] = 'json'
        
        return cleaned_data

class ScanForm(forms.Form):
    module = forms.ModelChoiceField(
        queryset=Module.objects.none(),  # Start with empty queryset
        widget=forms.Select(attrs={'class': 'form-control'}),
        help_text="Select a scan module to run",
        label="Module",  # Add a label
        to_field_name="name"  # Use the name field for display
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Set the queryset dynamically in __init__
        self.fields['module'].queryset = Module.objects.filter(enabled=True).order_by('name')
        # Set empty label to None to remove the "--------" option
        self.fields['module'].empty_label = None

class TagForm(forms.ModelForm):
    class Meta:
        model = Tag
        fields = ['name']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'})
        }

class IgnoredAssetForm(forms.ModelForm):
    class Meta:
        model = IgnoredAsset
        fields = ['name', 'asset_type', 'notes']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'asset_type': forms.Select(attrs={'class': 'form-select'}),
            'notes': forms.Textarea(attrs={'class': 'form-control', 'rows': 3})
        }

class BulkIgnoredAssetForm(forms.Form):
    assets = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 10, 'class': 'form-control'}),
        help_text="Enter one asset per line. Assets can be domains, subdomains, or IP addresses."
    )

    def clean_assets(self):
        assets_text = self.cleaned_data['assets']
        asset_list = [line.strip() for line in assets_text.splitlines() if line.strip()]
        
        if not asset_list:
            raise forms.ValidationError("Please enter at least one asset.")

        # Clean and validate each asset
        cleaned_assets = []
        for value in asset_list:
            # Check if it's an IP address (simple check)
            if value.replace('.', '').isdigit():
                asset_type = "ip"
                cleaned_value = value
            else:
                # Clean the domain
                cleaned_value = self.clean_domain(value)
                # Check if it's a subdomain (has more than one dot)
                parts = cleaned_value.split('.')
                if len(parts) > 2:
                    asset_type = "subdomain"
                else:
                    asset_type = "domain"
            
            cleaned_assets.append({
                "asset_type": asset_type,
                "value": cleaned_value
            })

        return cleaned_assets

    def clean_domain(self, value):
        """Clean and validate domain name."""
        value = value.strip().lower()
        if not value:
            raise forms.ValidationError("Domain cannot be empty.")
        if not re.match(r'^[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)*$', value):
            raise forms.ValidationError(f"Invalid domain format: {value}")
        return value
