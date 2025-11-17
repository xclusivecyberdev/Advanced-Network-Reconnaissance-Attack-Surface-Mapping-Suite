"""Base scanner class for all reconnaissance modules."""

from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging


class BaseScanner(ABC):
    """Abstract base class for all scanner modules."""

    def __init__(self, name: str, version: str = "1.0", config: Optional[Any] = None):
        """
        Initialize base scanner.

        Args:
            name: Scanner name
            version: Scanner version
            config: Configuration object
        """
        self.name = name
        self.version = version
        self.config = config
        self.logger = logging.getLogger(f"recon_suite.{name}")
        self.results = []
        self.errors = []
        self.start_time = None
        self.end_time = None

    @abstractmethod
    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform scan on target.

        Args:
            target: Target to scan (IP, domain, URL, etc.)
            options: Scanner-specific options

        Returns:
            Scan results dictionary
        """
        pass

    def pre_scan(self, target: str) -> bool:
        """
        Pre-scan validation and preparation.

        Args:
            target: Target to validate

        Returns:
            True if validation passes
        """
        self.start_time = datetime.utcnow()
        self.logger.info(f"Starting {self.name} scan on {target}")
        return True

    def post_scan(self) -> Dict[str, Any]:
        """
        Post-scan cleanup and result formatting.

        Returns:
            Formatted results
        """
        self.end_time = datetime.utcnow()
        duration = (self.end_time - self.start_time).total_seconds()

        return {
            'scanner': self.name,
            'version': self.version,
            'start_time': self.start_time.isoformat(),
            'end_time': self.end_time.isoformat(),
            'duration': duration,
            'results': self.results,
            'errors': self.errors,
        }

    def add_result(self, result: Dict[str, Any]):
        """Add result to results list."""
        self.results.append(result)

    def add_error(self, error: str):
        """Add error to errors list."""
        self.errors.append({
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(error),
        })
        self.logger.error(f"{self.name}: {error}")

    def validate_target(self, target: str) -> bool:
        """
        Validate target format.

        Args:
            target: Target to validate

        Returns:
            True if valid
        """
        if not target or not isinstance(target, str):
            return False
        return True


class ScanResult:
    """Container for scan results."""

    def __init__(self, target: str, scan_type: str):
        """Initialize scan result."""
        self.target = target
        self.scan_type = scan_type
        self.timestamp = datetime.utcnow()
        self.hosts = []
        self.ports = []
        self.services = []
        self.vulnerabilities = []
        self.technologies = []
        self.subdomains = []
        self.certificates = []
        self.dns_records = []
        self.whois_data = {}
        self.metadata = {}

    def add_host(self, host: Dict[str, Any]):
        """Add discovered host."""
        self.hosts.append(host)

    def add_port(self, port: Dict[str, Any]):
        """Add discovered port."""
        self.ports.append(port)

    def add_service(self, service: Dict[str, Any]):
        """Add detected service."""
        self.services.append(service)

    def add_vulnerability(self, vulnerability: Dict[str, Any]):
        """Add identified vulnerability."""
        self.vulnerabilities.append(vulnerability)

    def add_technology(self, technology: Dict[str, Any]):
        """Add detected technology."""
        self.technologies.append(technology)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary."""
        return {
            'target': self.target,
            'scan_type': self.scan_type,
            'timestamp': self.timestamp.isoformat(),
            'hosts': self.hosts,
            'ports': self.ports,
            'services': self.services,
            'vulnerabilities': self.vulnerabilities,
            'technologies': self.technologies,
            'subdomains': self.subdomains,
            'certificates': self.certificates,
            'dns_records': self.dns_records,
            'whois_data': self.whois_data,
            'metadata': self.metadata,
        }
