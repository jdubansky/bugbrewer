import os
from pathlib import Path

def get_python_modules():
    """Retrieve available Python module filenames (without .py extension)."""
    module_dir = Path(__file__).parent / "modules" / "python_modules"
    print(f"DEBUG: Looking for modules in {module_dir}")
    print(f"DEBUG: Directory exists: {module_dir.exists()}")
    
    try:
        # Filter out __init__.py, __pycache__, and shared_utils.py
        files = os.listdir(module_dir)
        print(f"DEBUG: Found files: {files}")
        
        modules = [
            (f[:-3], f[:-3])  # (value, display_name) without .py extension
            for f in files
            if f.endswith(".py") and not f.startswith("__") and not f == "shared_utils.py"
        ]
        print(f"DEBUG: Filtered modules: {modules}")
        return sorted(modules)  # Sort alphabetically
    except FileNotFoundError:
        print(f"Warning: Module directory not found at {module_dir}")
        return []
    except Exception as e:
        print(f"Error getting python modules: {e}")
        return [] 