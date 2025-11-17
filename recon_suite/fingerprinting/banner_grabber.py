"""Banner grabbing module for service identification."""

import socket
import ssl
from typing import Dict, Any, List, Optional
import logging

from ..core.scanner_base import BaseScanner


class BannerGrabber(BaseScanner):
    """Banner grabbing scanner for service identification."""

    def __init__(self, config):
        """Initialize banner grabber."""
        super().__init__(name="BannerGrabber", version="1.0", config=config)

        # Service-specific probes
        self.probes = {
            'http': b'GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\n\r\n',
            'ftp': b'',  # FTP sends banner automatically
            'smtp': b'EHLO scanner\r\n',
            'ssh': b'',  # SSH sends banner automatically
            'telnet': b'',  # Telnet sends banner automatically
            'pop3': b'',  # POP3 sends banner automatically
            'imap': b'',  # IMAP sends banner automatically
            'mysql': b'',  # MySQL sends banner automatically
            'redis': b'INFO\r\n',
            'mongodb': b'',  # MongoDB sends banner automatically
        }

    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Grab banners from target services.

        Args:
            target: Target IP or hostname
            options: Scan options (ports, services, etc.)

        Returns:
            Banner grabbing results
        """
        options = options or {}
        ports = options.get('open_ports', [])

        if not ports:
            # Default common ports
            ports = [21, 22, 23, 25, 80, 110, 143, 443, 3306, 5432, 6379, 8080]

        results = []

        for port in ports:
            try:
                banner = self.grab_banner(target, port)

                if banner:
                    banner_info = {
                        'host': target,
                        'port': port,
                        'banner': banner,
                        'service': self._identify_service(banner, port),
                    }

                    self.add_result(banner_info)
                    results.append(banner_info)

            except Exception as e:
                self.logger.debug(f"Banner grab failed for {target}:{port} - {e}")

        return {'scanner': self.name, 'results': results}

    def grab_banner(self, host: str, port: int, timeout: float = 5.0,
                    use_ssl: bool = None) -> Optional[str]:
        """
        Grab banner from specific port.

        Args:
            host: Target host
            port: Target port
            timeout: Connection timeout
            use_ssl: Force SSL/TLS connection (auto-detect if None)

        Returns:
            Banner string
        """
        try:
            # Auto-detect SSL ports
            if use_ssl is None:
                use_ssl = port in [443, 8443, 465, 993, 995]

            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((host, port))

            # Wrap with SSL if needed
            if use_ssl:
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    sock = context.wrap_socket(sock, server_hostname=host)
                except Exception as e:
                    self.logger.debug(f"SSL wrapping failed: {e}")
                    sock.close()
                    return None

            # Send probe based on port
            probe = self._get_probe_for_port(host, port)
            if probe:
                sock.send(probe)

            # Receive banner
            banner = sock.recv(4096)
            sock.close()

            return banner.decode('utf-8', errors='ignore').strip()

        except socket.timeout:
            self.logger.debug(f"Banner grab timeout for {host}:{port}")
        except Exception as e:
            self.logger.debug(f"Banner grab error for {host}:{port} - {e}")

        return None

    def _get_probe_for_port(self, host: str, port: int) -> bytes:
        """Get appropriate probe for port."""
        if port in [80, 8080, 8000, 8888]:
            return self.probes['http'].replace(b'{host}', host.encode())
        elif port == 25:
            return self.probes['smtp']
        elif port == 6379:
            return self.probes['redis']
        else:
            return b''  # Empty probe for services that send banner automatically

    def _identify_service(self, banner: str, port: int) -> str:
        """
        Identify service from banner.

        Args:
            banner: Banner string
            port: Port number

        Returns:
            Service name
        """
        banner_lower = banner.lower()

        # Service signatures
        signatures = {
            'ssh': ['ssh', 'openssh'],
            'ftp': ['ftp', '220'],
            'http': ['http/', 'server:', '<html'],
            'smtp': ['smtp', 'esmtp', 'postfix', 'sendmail'],
            'pop3': ['pop3', '+ok'],
            'imap': ['imap', '* ok'],
            'mysql': ['mysql', '\x00\x00\x00\x0a'],
            'postgresql': ['postgresql'],
            'redis': ['redis'],
            'mongodb': ['mongodb'],
            'telnet': ['telnet'],
        }

        for service, patterns in signatures.items():
            for pattern in patterns:
                if pattern in banner_lower:
                    return service

        # Fallback to common services by port
        common_services = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            80: 'http',
            110: 'pop3',
            143: 'imap',
            443: 'https',
            3306: 'mysql',
            5432: 'postgresql',
            6379: 'redis',
            8080: 'http-proxy',
            27017: 'mongodb',
        }

        return common_services.get(port, 'unknown')

    def grab_http_headers(self, host: str, port: int = 80, use_ssl: bool = False) -> Optional[Dict[str, str]]:
        """
        Grab HTTP headers.

        Args:
            host: Target host
            port: Target port
            use_ssl: Use HTTPS

        Returns:
            Dictionary of HTTP headers
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))

            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)

            # Send HTTP request
            request = f'GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n'
            sock.send(request.encode())

            # Receive response
            response = b''
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                # Stop after headers
                if b'\r\n\r\n' in response:
                    break

            sock.close()

            # Parse headers
            response_str = response.decode('utf-8', errors='ignore')
            headers = {}

            lines = response_str.split('\r\n')
            for line in lines[1:]:  # Skip status line
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

            return headers

        except Exception as e:
            self.logger.debug(f"HTTP header grab failed: {e}")
            return None

    def extract_version_info(self, banner: str) -> Dict[str, str]:
        """
        Extract version information from banner.

        Args:
            banner: Banner string

        Returns:
            Version information dictionary
        """
        import re

        version_info = {
            'product': '',
            'version': '',
            'os': '',
        }

        # Common patterns
        patterns = {
            'product': [
                r'Server:\s*(\S+)',
                r'^(\S+)\s+',
            ],
            'version': [
                r'(\d+\.\d+\.\d+)',
                r'(\d+\.\d+)',
                r'Version\s+(\S+)',
            ],
            'os': [
                r'\(([^)]+)\)',
                r'Ubuntu|Debian|CentOS|RedHat|Windows',
            ],
        }

        for key, pattern_list in patterns.items():
            for pattern in pattern_list:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    version_info[key] = match.group(1)
                    break

        return version_info
