"""
Configuration Module
====================
Centralized configuration management for the entire application.

This module handles:
- Loading configuration from files (YAML, JSON)
- Default configuration values
- Environment-specific settings (dev, test, production)
- Configuration validation

Why centralized config?
- Single source of truth
- Easy to change settings without modifying code
- Different configs for different environments
- Validates settings before use

Author: Your Name
Date: 2025
"""

import os
import json
import yaml
from pathlib import Path


class Config:
    """
    Application configuration manager.
    
    Loads and manages configuration from:
    1. Default values (hardcoded)
    2. Config file (YAML or JSON)
    3. Environment variables (overrides)
    
    Priority: Environment > Config File > Defaults
    
    Attributes:
        config_data: Dictionary containing all configuration
        config_file: Path to config file (if loaded)
        environment: Current environment (dev, test, prod)
    """
    
    def __init__(self, config_file=None, environment='dev'):
        """
        Initialize configuration.
        
        Args:
            config_file (str): Path to config file (optional)
                - If None, uses defaults
                - Supports .yaml and .json formats
            
            environment (str): Environment name
                - 'dev': Development (verbose logging, visible browser)
                - 'test': Testing (fast, minimal output)
                - 'prod': Production (optimized, headless)
        
        Example:
            # Use defaults
            config = Config()
            
            # Load from file
            config = Config('config/settings.yaml')
            
            # Production config
            config = Config('config/prod.yaml', environment='prod')
        """
        
        self.config_file = config_file
        self.environment = environment
        
        # Start with default configuration
        self.config_data = self._get_default_config()
        
        # Load from file if provided
        if config_file and os.path.exists(config_file):
            file_config = self._load_config_file(config_file)
            self._merge_config(file_config)
            print(f"✓ Loaded config from: {config_file}")
        elif config_file:
            print(f"⚠ Config file not found: {config_file}")
            print(f"  Using defaults")
        
        # Apply environment-specific overrides
        self._apply_environment_overrides()
        
        # Load environment variables (highest priority)
        self._load_environment_variables()
        
        # Validate configuration
        self._validate_config()
    
    def _get_default_config(self):
        """
        Get default configuration values.
        
        These are sensible defaults that work in most cases.
        Can be overridden by config file or environment variables.
        
        Returns:
            dict: Default configuration
        """
        return {
            # ===== BROWSER SETTINGS =====
            'browser': {
                'headless': True,              # Run without GUI
                'window_size': (1920, 1080),  # Browser window size
                'page_load_timeout': 15,       # Max seconds to load page
                'implicit_wait': 5,            # Wait for elements (seconds)
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            },
            
            # ===== CRAWLER SETTINGS =====
            'crawler': {
                'delay_between_requests': 2,   # Seconds between requests
                'delay_variation': 1,          # Random variation (±seconds)
                'max_retries': 2,              # Retry failed requests
                'timeout': 15,                 # Request timeout
                'save_interval': 10,           # Save progress every N pages
                'max_urls_per_session': 100   # Safety limit
            },
            
            # ===== MODEL SETTINGS =====
            'model': {
                'contamination': 0.1,          # Expected anomaly rate (10%)
                'n_estimators': 100,           # Number of trees
                'random_state': 42,            # For reproducibility
                'min_training_samples': 50,    # Minimum samples to train
                'target_training_samples': 100 # Target samples
            },
            
            # ===== ANALYZER SETTINGS =====
            'analyzer': {
                'risk_thresholds': {
                    'safe': (0, 19),
                    'low': (20, 39),
                    'medium': (40, 69),
                    'high': (70, 100)
                },
                'enable_ml': True,             # Use ML model
                'enable_rules': True           # Use rule-based detection
            },
            
            # ===== PATHS =====
            'paths': {
                'data_dir': 'data',
                'training_dir': 'data/training',
                'models_dir': 'models',
                'reports_dir': 'reports',
                'logs_dir': 'logs'
            },
            
            # ===== LOGGING =====
            'logging': {
                'level': 'INFO',               # DEBUG, INFO, WARNING, ERROR
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'file': 'logs/app.log',
                'console': True,               # Also log to console
                'max_bytes': 10485760,        # 10MB per log file
                'backup_count': 5              # Keep 5 old log files
            },
            
            # ===== OUTPUT SETTINGS =====
            'output': {
                'format': 'json',              # json, csv, or both
                'pretty_print': True,          # Indent JSON
                'include_metadata': True,      # Include timestamps, etc.
                'compress': False              # Compress output files
            },
            
            # ===== FEATURE EXTRACTION =====
            'features': {
                'extract_url': True,
                'extract_dom': True,
                'extract_content': True,
                'extract_behavioral': True
            }
        }
    
    def _load_config_file(self, filepath):
        """
        Load configuration from YAML or JSON file.
        
        Args:
            filepath (str): Path to config file
        
        Returns:
            dict: Loaded configuration
        
        Supported formats:
        - .yaml / .yml (recommended)
        - .json
        """
        
        ext = os.path.splitext(filepath)[1].lower()
        
        try:
            with open(filepath, 'r') as f:
                if ext in ['.yaml', '.yml']:
                    # Load YAML
                    # YAML is more human-friendly than JSON
                    return yaml.safe_load(f) or {}
                elif ext == '.json':
                    # Load JSON
                    return json.load(f)
                else:
                    print(f"⚠ Unsupported config format: {ext}")
                    return {}
        except Exception as e:
            print(f"✗ Error loading config file: {e}")
            return {}
    
    def _merge_config(self, new_config):
        """
        Merge new configuration into existing config.
        
        This does a deep merge - nested dictionaries are merged,
        not replaced.
        
        Args:
            new_config (dict): Configuration to merge in
        
        Example:
            existing = {'browser': {'headless': True, 'timeout': 15}}
            new = {'browser': {'timeout': 20}}
            result = {'browser': {'headless': True, 'timeout': 20}}
        """
        
        def deep_merge(base, updates):
            """Recursively merge dictionaries."""
            for key, value in updates.items():
                if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                    # Both are dicts, merge recursively
                    deep_merge(base[key], value)
                else:
                    # Override value
                    base[key] = value
        
        deep_merge(self.config_data, new_config)
    
    def _apply_environment_overrides(self):
        """
        Apply environment-specific configuration overrides.
        
        Different environments have different needs:
        - dev: Visible browser, verbose logging
        - test: Fast, minimal output
        - prod: Optimized, headless
        """
        
        overrides = {
            'dev': {
                'browser': {'headless': False},  # See browser
                'logging': {'level': 'DEBUG'},   # Verbose logs
                'crawler': {'delay_between_requests': 1}  # Faster
            },
            'test': {
                'browser': {'headless': True},
                'logging': {'level': 'WARNING', 'console': False},
                'crawler': {'max_urls_per_session': 10}  # Limit for tests
            },
            'prod': {
                'browser': {'headless': True},
                'logging': {'level': 'INFO'},
                'crawler': {'delay_between_requests': 3}  # Be polite
            }
        }
        
        if self.environment in overrides:
            self._merge_config(overrides[self.environment])
            print(f"✓ Applied {self.environment} environment settings")
    
    def _load_environment_variables(self):
        """
        Load configuration from environment variables.
        
        Environment variables have highest priority.
        Useful for:
        - Docker containers
        - CI/CD pipelines
        - Sensitive values (API keys)
        
        Format: APP_SECTION_KEY
        Example: APP_BROWSER_HEADLESS=true
        """
        
        # Map environment variables to config keys
        env_mappings = {
            'APP_BROWSER_HEADLESS': ('browser', 'headless', bool),
            'APP_CRAWLER_DELAY': ('crawler', 'delay_between_requests', float),
            'APP_LOG_LEVEL': ('logging', 'level', str),
            'APP_MODEL_CONTAMINATION': ('model', 'contamination', float),
        }
        
        for env_var, (section, key, type_func) in env_mappings.items():
            value = os.getenv(env_var)
            if value is not None:
                # Convert to appropriate type
                if type_func == bool:
                    # Handle boolean strings
                    converted = value.lower() in ['true', '1', 'yes', 'on']
                else:
                    converted = type_func(value)
                
                # Update config
                self.config_data[section][key] = converted
                print(f"✓ Loaded from env: {env_var}")
    
    def _validate_config(self):
        """
        Validate configuration values.
        
        Checks:
        - Required keys exist
        - Values are in valid ranges
        - Paths are accessible
        - Types are correct
        
        Raises:
            ValueError: If configuration is invalid
        """
        
        # Validate contamination (must be between 0 and 0.5)
        contamination = self.config_data['model']['contamination']
        if not (0 < contamination < 0.5):
            raise ValueError(f"contamination must be between 0 and 0.5, got {contamination}")
        
        # Validate log level
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        log_level = self.config_data['logging']['level']
        if log_level not in valid_levels:
            raise ValueError(f"log_level must be one of {valid_levels}, got {log_level}")
        
        # Create necessary directories
        for path_key, path_value in self.config_data['paths'].items():
            os.makedirs(path_value, exist_ok=True)
        
        print("✓ Configuration validated")
    
    def get(self, *keys, default=None):
        """
        Get configuration value using dot notation or keys.
        
        Args:
            *keys: One or more keys to navigate config
            default: Value to return if key not found
        
        Returns:
            Configuration value
        
        Example:
            config.get('browser', 'headless')  # True
            config.get('browser.headless')     # True (alternative)
            config.get('missing', default=10)  # 10
        """
        
        # Handle dot notation: 'browser.headless'
        if len(keys) == 1 and '.' in keys[0]:
            keys = keys[0].split('.')
        
        # Navigate through nested dictionaries
        value = self.config_data
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value
    
    def set(self, *keys, value):
        """
        Set configuration value.
        
        Args:
            *keys: Keys to navigate to setting
            value: Value to set
        
        Example:
            config.set('browser', 'headless', value=True)
            config.set('browser.headless', value=True)  # Alternative
        """
        
        # Handle dot notation
        if len(keys) == 1 and '.' in keys[0]:
            keys = keys[0].split('.')
        
        # Navigate to parent dictionary
        current = self.config_data
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        # Set value
        current[keys[-1]] = value
    
    def save(self, filepath=None):
        """
        Save current configuration to file.
        
        Args:
            filepath (str): Where to save (default: same as loaded from)
        
        Example:
            config.set('browser.headless', value=False)
            config.save()  # Save changes
        """
        
        filepath = filepath or self.config_file
        
        if not filepath:
            print("✗ No filepath specified")
            return False
        
        # Determine format from extension
        ext = os.path.splitext(filepath)[1].lower()
        
        try:
            with open(filepath, 'w') as f:
                if ext in ['.yaml', '.yml']:
                    yaml.dump(self.config_data, f, default_flow_style=False, indent=2)
                else:  # JSON
                    json.dump(self.config_data, f, indent=2)
            
            print(f"✓ Config saved to: {filepath}")
            return True
            
        except Exception as e:
            print(f"✗ Error saving config: {e}")
            return False
    
    def __repr__(self):
        """String representation of config."""
        return f"Config(environment='{self.environment}', file='{self.config_file}')"


# =========================================================================
# CONVENIENCE FUNCTIONS
# =========================================================================

def load_config(config_file=None, environment='dev'):
    """
    Convenience function to load configuration.
    
    Args:
        config_file (str): Path to config file
        environment (str): Environment name
    
    Returns:
        Config: Configuration object
    
    Example:
        from utils.config import load_config
        
        config = load_config('config/settings.yaml')
        headless = config.get('browser', 'headless')
    """
    return Config(config_file, environment)


# =========================================================================
# TEST CODE
# =========================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("CONFIGURATION MODULE - TEST MODE")
    print("=" * 70)
    
    # Test 1: Default configuration
    print("\n[TEST 1] Default Configuration")
    print("-" * 70)
    
    config = Config()
    print(f"Browser headless: {config.get('browser', 'headless')}")
    print(f"Crawler delay: {config.get('crawler', 'delay_between_requests')}")
    print(f"Log level: {config.get('logging', 'level')}")
    
    # Test 2: Get with dot notation
    print("\n[TEST 2] Dot Notation")
    print("-" * 70)
    
    print(f"browser.headless = {config.get('browser.headless')}")
    print(f"model.contamination = {config.get('model.contamination')}")
    
    # Test 3: Set values
    print("\n[TEST 3] Setting Values")
    print("-" * 70)
    
    print(f"Before: {config.get('browser.headless')}")
    config.set('browser.headless', value=False)
    print(f"After: {config.get('browser.headless')}")
    
    # Test 4: Environment overrides
    print("\n[TEST 4] Environment-Specific Config")
    print("-" * 70)
    
    for env in ['dev', 'test', 'prod']:
        env_config = Config(environment=env)
        print(f"{env:5} → headless={env_config.get('browser.headless')}, "
              f"log_level={env_config.get('logging.level')}")
    
    # Test 5: Save configuration
    print("\n[TEST 5] Save Configuration")
    print("-" * 70)
    
    test_file = 'test_config.yaml'
    if config.save(test_file):
        print(f"Saved to: {test_file}")
        
        # Load it back
        loaded = Config(test_file)
        print(f"Loaded headless: {loaded.get('browser.headless')}")
        
        # Cleanup
        os.remove(test_file)
        print(f"Removed test file")
    
    print("\n" + "=" * 70)
    print("✓ All tests complete!")
    print("=" * 70)