"""Configuration management for the reconnaissance suite."""

import os
import yaml
from typing import Dict, Any, Optional
from pathlib import Path
from dotenv import load_dotenv


class Config:
    """Configuration manager for the reconnaissance suite."""

    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration.

        Args:
            config_file: Path to YAML configuration file (optional)
        """
        # Load environment variables
        load_dotenv()

        # Default configuration
        self._config = {
            # API Keys
            'api_keys': {
                'shodan': os.getenv('SHODAN_API_KEY', ''),
                'virustotal': os.getenv('VIRUSTOTAL_API_KEY', ''),
                'censys_id': os.getenv('CENSYS_API_ID', ''),
                'censys_secret': os.getenv('CENSYS_API_SECRET', ''),
            },

            # Database
            'database': {
                'url': os.getenv('DATABASE_URL', 'sqlite:///recon_suite.db'),
            },

            # Flask Configuration
            'flask': {
                'secret_key': os.getenv('FLASK_SECRET_KEY', os.urandom(24).hex()),
                'debug': os.getenv('FLASK_DEBUG', 'False').lower() == 'true',
                'host': os.getenv('FLASK_HOST', '127.0.0.1'),
                'port': int(os.getenv('FLASK_PORT', '5000')),
            },

            # Scanning Configuration
            'scanning': {
                'max_concurrent_scans': int(os.getenv('MAX_CONCURRENT_SCANS', '10')),
                'scan_timeout': int(os.getenv('SCAN_TIMEOUT', '3600')),
                'max_threads': int(os.getenv('MAX_THREADS', '50')),
                'rate_limit_delay': float(os.getenv('RATE_LIMIT_DELAY', '0.1')),
                'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'socket_timeout': 5,
                'max_retries': 3,
            },

            # CVE Database
            'cve': {
                'database_path': os.getenv('CVE_DATABASE_PATH', 'data/cve_database.json'),
                'auto_update': True,
                'update_interval_days': 7,
            },

            # Logging
            'logging': {
                'level': os.getenv('LOG_LEVEL', 'INFO'),
                'file': os.getenv('LOG_FILE', 'logs/recon_suite.log'),
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'max_bytes': 10485760,  # 10MB
                'backup_count': 5,
            },

            # Security
            'security': {
                'session_timeout': int(os.getenv('SESSION_TIMEOUT', '3600')),
                'max_login_attempts': int(os.getenv('MAX_LOGIN_ATTEMPTS', '5')),
                'require_authentication': os.getenv('REQUIRE_AUTHENTICATION', 'True').lower() == 'true',
            },

            # Scan Profiles
            'scan_profiles': {
                'quick': {
                    'ports': '21-25,80,443,3306,3389,8080',
                    'timing': 'aggressive',
                    'service_detection': True,
                    'os_detection': False,
                },
                'standard': {
                    'ports': '1-1000',
                    'timing': 'normal',
                    'service_detection': True,
                    'os_detection': True,
                },
                'comprehensive': {
                    'ports': '1-65535',
                    'timing': 'normal',
                    'service_detection': True,
                    'os_detection': True,
                    'vulnerability_scan': True,
                },
                'stealth': {
                    'ports': '1-1000',
                    'timing': 'paranoid',
                    'service_detection': True,
                    'os_detection': False,
                    'randomize': True,
                },
            },

            # OSINT Sources
            'osint': {
                'enabled_sources': [
                    'dns',
                    'whois',
                    'ssl_certificates',
                    'certificate_transparency',
                    'wayback_machine',
                    'search_engines',
                    'shodan',
                ],
                'subdomain_wordlist': 'data/subdomains.txt',
                'dns_resolvers': ['8.8.8.8', '1.1.1.1', '8.8.4.4'],
            },

            # Technology Fingerprinting
            'fingerprinting': {
                'signatures_file': 'data/technology_signatures.json',
                'favicon_hashes': 'data/favicon_hashes.json',
                'http_headers_check': True,
                'javascript_libraries': True,
            },
        }

        # Load custom configuration file if provided
        if config_file and Path(config_file).exists():
            self._load_config_file(config_file)

    def _load_config_file(self, config_file: str):
        """Load configuration from YAML file."""
        try:
            with open(config_file, 'r') as f:
                custom_config = yaml.safe_load(f)
                self._deep_update(self._config, custom_config)
        except Exception as e:
            print(f"Warning: Failed to load config file {config_file}: {e}")

    def _deep_update(self, base: Dict, update: Dict):
        """Deep update of nested dictionaries."""
        for key, value in update.items():
            if isinstance(value, dict) and key in base and isinstance(base[key], dict):
                self._deep_update(base[key], value)
            else:
                base[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation.

        Args:
            key: Configuration key (e.g., 'scanning.max_threads')
            default: Default value if key not found

        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self._config

        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default

        return value

    def set(self, key: str, value: Any):
        """
        Set configuration value using dot notation.

        Args:
            key: Configuration key (e.g., 'scanning.max_threads')
            value: Value to set
        """
        keys = key.split('.')
        config = self._config

        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]

        config[keys[-1]] = value

    def get_all(self) -> Dict[str, Any]:
        """Get all configuration as dictionary."""
        return self._config.copy()

    def save(self, output_file: str):
        """Save configuration to YAML file."""
        try:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w') as f:
                yaml.dump(self._config, f, default_flow_style=False)
        except Exception as e:
            raise Exception(f"Failed to save configuration: {e}")

    def validate(self) -> bool:
        """
        Validate configuration.

        Returns:
            True if valid, raises exception otherwise
        """
        # Check required directories exist
        required_dirs = ['logs', 'data', 'templates', 'static']
        for dir_name in required_dirs:
            Path(dir_name).mkdir(parents=True, exist_ok=True)

        # Validate critical settings
        if self.get('scanning.max_threads') < 1:
            raise ValueError("max_threads must be at least 1")

        if self.get('scanning.scan_timeout') < 1:
            raise ValueError("scan_timeout must be at least 1 second")

        return True
