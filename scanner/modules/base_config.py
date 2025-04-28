import yaml
from pathlib import Path

class ModuleConfig:
    def __init__(self, module_name):
        self.module_name = module_name
        self.config = self.load_config()

    def load_config(self):
        """Load module configuration from YAML file"""
        config_path = Path(__file__).parent / 'config' / f'{self.module_name}.yaml'
        try:
            with open(config_path) as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            return {}  # Return empty dict if no config file exists

    def get(self, key, default=None):
        """Get configuration value with fallback to default"""
        return self.config.get(key, default) 