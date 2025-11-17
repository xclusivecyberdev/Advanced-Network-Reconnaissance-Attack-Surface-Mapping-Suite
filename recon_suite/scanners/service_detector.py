"""Service detection and version identification module."""

import socket
import re
from typing import Dict, Any, List, Optional
import logging

from ..core.scanner_base import BaseScanner


class ServiceDetector(BaseScanner):
    """Service detection and version identification scanner."""

    def __init__(self, config):
        """Initialize service detector."""
        super().__init__(name="ServiceDetector", version="1.0", config=config)

        # Service signatures for detection
        self.service_signatures = {
            'http': [
                (b'HTTP/', 'HTTP'),
                (b'Server:', 'HTTP'),
                (b'<html', 'HTTP'),
            ],
            'ssh': [
                (b'SSH-', 'SSH'),
                (b'OpenSSH', 'OpenSSH'),
            ],
            'ftp': [
                (b'220', 'FTP'),
                (b'FTP', 'FTP'),
            ],
            'smtp': [
                (b'220', 'SMTP'),
                (b'ESMTP', 'ESMTP'),
            ],
            'mysql': [
                (b'mysql', 'MySQL'),
                (b'\x00\x00\x00\x0a', 'MySQL'),
            ],
            'postgresql': [
                (b'PostgreSQL', 'PostgreSQL'),
            ],
            'redis': [
                (b'REDIS', 'Redis'),
                (b'-ERR', 'Redis'),
            ],
            'mongodb': [
                (b'MongoDB', 'MongoDB'),
            ],
            'telnet': [
                (b'Telnet', 'Telnet'),
                (b'\xff\xfd', 'Telnet'),
            ],
            'smb': [
                (b'SMB', 'SMB'),
            ],
            'rdp': [
                (b'\x03\x00', 'RDP'),
            ],
        }

        # Common service ports
        self.common_services = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            143: 'imap',
            443: 'https',
            445: 'smb',
            3306: 'mysql',
            3389: 'rdp',
            5432: 'postgresql',
            6379: 'redis',
            8080: 'http-proxy',
            8443: 'https-alt',
            27017: 'mongodb',
        }

    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Detect services on target.

        Args:
            target: Target IP or hostname
            options: Scan options (ports list, timeout, etc.)

        Returns:
            Service detection results
        """
        options = options or {}
        ports = options.get('open_ports', [])

        if not ports:
            # If no ports provided, try common ports
            ports = list(self.common_services.keys())

        results = []

        for port in ports:
            try:
                service_info = self.detect_service(target, port)
                if service_info:
                    self.add_result({'service': service_info})
                    results.append(service_info)

            except Exception as e:
                self.logger.debug(f"Service detection failed on {target}:{port} - {e}")

        return {'scanner': self.name, 'results': results}

    def detect_service(self, host: str, port: int, timeout: float = 3.0) -> Optional[Dict[str, Any]]:
        """
        Detect service on specific port.

        Args:
            host: Target host
            port: Target port
            timeout: Connection timeout

        Returns:
            Service information dictionary
        """
        try:
            # Connect to port
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Send probe if needed
            banner = b''

            # For HTTP-like services
            if port in [80, 8080, 8000, 8888]:
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n\r\n')

            # Receive banner
            try:
                banner = sock.recv(4096)
            except socket.timeout:
                pass

            sock.close()

            # Analyze banner
            service_info = self._analyze_banner(host, port, banner)

            return service_info

        except Exception as e:
            self.logger.debug(f"Failed to detect service on {host}:{port} - {e}")
            return None

    def _analyze_banner(self, host: str, port: int, banner: bytes) -> Dict[str, Any]:
        """
        Analyze banner to identify service.

        Args:
            host: Target host
            port: Target port
            banner: Received banner

        Returns:
            Service information
        """
        service_info = {
            'host': host,
            'port': port,
            'service': self.common_services.get(port, 'unknown'),
            'banner': banner.decode('utf-8', errors='ignore')[:200],
            'version': '',
            'product': '',
            'cpe': '',
        }

        # Check signatures
        for service_type, signatures in self.service_signatures.items():
            for pattern, service_name in signatures:
                if pattern in banner:
                    service_info['service'] = service_name
                    break

        # Extract version information
        service_info['version'] = self._extract_version(banner)

        # Extract product information
        service_info['product'] = self._extract_product(banner)

        # Generate CPE (Common Platform Enumeration)
        if service_info['product'] and service_info['version']:
            service_info['cpe'] = self._generate_cpe(
                service_info['product'],
                service_info['version']
            )

        return service_info

    def _extract_version(self, banner: bytes) -> str:
        """Extract version from banner."""
        banner_str = banner.decode('utf-8', errors='ignore')

        # Common version patterns
        patterns = [
            r'(\d+\.\d+\.\d+)',  # X.Y.Z
            r'(\d+\.\d+)',  # X.Y
            r'Version\s+(\S+)',
            r'v(\d+\.\d+)',
        ]

        for pattern in patterns:
            match = re.search(pattern, banner_str, re.IGNORECASE)
            if match:
                return match.group(1)

        return ''

    def _extract_product(self, banner: bytes) -> str:
        """Extract product name from banner."""
        banner_str = banner.decode('utf-8', errors='ignore')

        # Common product patterns
        products = {
            'Apache': 'apache',
            'nginx': 'nginx',
            'Microsoft-IIS': 'iis',
            'OpenSSH': 'openssh',
            'MySQL': 'mysql',
            'PostgreSQL': 'postgresql',
            'Redis': 'redis',
            'MongoDB': 'mongodb',
            'ProFTPD': 'proftpd',
            'vsftpd': 'vsftpd',
        }

        for product, name in products.items():
            if product.lower() in banner_str.lower():
                return name

        return ''

    def _generate_cpe(self, product: str, version: str) -> str:
        """
        Generate CPE (Common Platform Enumeration) string.

        Args:
            product: Product name
            version: Version string

        Returns:
            CPE string
        """
        # Basic CPE format: cpe:/a:vendor:product:version
        cpe_map = {
            'apache': 'cpe:/a:apache:http_server',
            'nginx': 'cpe:/a:nginx:nginx',
            'openssh': 'cpe:/a:openbsd:openssh',
            'mysql': 'cpe:/a:mysql:mysql',
            'postgresql': 'cpe:/a:postgresql:postgresql',
            'redis': 'cpe:/a:redis:redis',
        }

        base_cpe = cpe_map.get(product, f'cpe:/a:unknown:{product}')

        if version:
            return f'{base_cpe}:{version}'

        return base_cpe
