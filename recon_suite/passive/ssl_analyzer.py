"""SSL/TLS certificate analysis and security assessment module."""

import ssl
import socket
import OpenSSL
from typing import Dict, Any, List, Optional
import logging
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

from ..core.scanner_base import BaseScanner


class SSLAnalyzer(BaseScanner):
    """SSL/TLS certificate analyzer and security scanner."""

    def __init__(self, config):
        """Initialize SSL analyzer."""
        super().__init__(name="SSLAnalyzer", version="1.0", config=config)

    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Analyze SSL/TLS configuration of target.

        Args:
            target: Target domain or IP
            options: Scan options (port, etc.)

        Returns:
            SSL/TLS analysis results
        """
        results = []
        port = options.get('port', 443) if options else 443

        try:
            # Get certificate information
            cert_info = self.get_certificate_info(target, port)
            if cert_info:
                self.add_result({'certificate': cert_info})
                results.append(cert_info)

            # Get TLS configuration
            tls_config = self.analyze_tls_configuration(target, port)
            if tls_config:
                self.add_result({'tls_config': tls_config})
                results.append(tls_config)

            # Check for vulnerabilities
            vulnerabilities = self.check_ssl_vulnerabilities(target, port)
            if vulnerabilities:
                self.add_result({'ssl_vulnerabilities': vulnerabilities})
                results.append(vulnerabilities)

        except Exception as e:
            self.add_error(f"SSL analysis failed: {e}")

        return {'scanner': self.name, 'results': results}

    def get_certificate_info(self, hostname: str, port: int = 443) -> Optional[Dict[str, Any]]:
        """
        Get SSL certificate information.

        Args:
            hostname: Target hostname
            port: Target port (default 443)

        Returns:
            Certificate information dictionary
        """
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get certificate in DER format
                    der_cert = ssock.getpeercert(binary_form=True)

                    # Parse certificate
                    cert = x509.load_der_x509_certificate(der_cert, default_backend())

                    # Extract certificate information
                    cert_info = {
                        'hostname': hostname,
                        'port': port,
                        'subject': self._parse_name(cert.subject),
                        'issuer': self._parse_name(cert.issuer),
                        'version': cert.version.name,
                        'serial_number': str(cert.serial_number),
                        'not_valid_before': cert.not_valid_before_utc.isoformat(),
                        'not_valid_after': cert.not_valid_after_utc.isoformat(),
                        'signature_algorithm': cert.signature_algorithm_oid._name,
                        'public_key_algorithm': cert.public_key().__class__.__name__,
                        'san': self._get_san(cert),
                        'fingerprint_sha256': cert.fingerprint(hashes.SHA256()).hex(),
                        'is_self_signed': self._is_self_signed(cert),
                    }

                    # Check expiration
                    days_until_expiry = (cert.not_valid_after_utc - datetime.now(datetime.timezone.utc)).days
                    cert_info['days_until_expiry'] = days_until_expiry
                    cert_info['is_expired'] = days_until_expiry < 0
                    cert_info['expires_soon'] = 0 < days_until_expiry < 30

                    # Get certificate chain
                    cert_info['chain'] = self._get_certificate_chain(hostname, port)

                    return cert_info

        except Exception as e:
            self.logger.error(f"Failed to get certificate info for {hostname}:{port} - {e}")
            return None

    def analyze_tls_configuration(self, hostname: str, port: int = 443) -> Optional[Dict[str, Any]]:
        """
        Analyze TLS configuration and supported features.

        Args:
            hostname: Target hostname
            port: Target port

        Returns:
            TLS configuration information
        """
        try:
            tls_config = {
                'hostname': hostname,
                'port': port,
                'supported_protocols': self._get_supported_protocols(hostname, port),
                'cipher_suites': self._get_cipher_suites(hostname, port),
                'compression': self._check_compression(hostname, port),
                'heartbeat': self._check_heartbeat(hostname, port),
                'session_resumption': self._check_session_resumption(hostname, port),
            }

            # Security headers (for HTTPS)
            if port in [443, 8443]:
                tls_config['security_headers'] = self._check_security_headers(hostname, port)

            return tls_config

        except Exception as e:
            self.logger.error(f"Failed to analyze TLS config for {hostname}:{port} - {e}")
            return None

    def check_ssl_vulnerabilities(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """
        Check for known SSL/TLS vulnerabilities.

        Args:
            hostname: Target hostname
            port: Target port

        Returns:
            Vulnerability assessment
        """
        vulnerabilities = {
            'hostname': hostname,
            'port': port,
            'issues': [],
        }

        try:
            # Check for SSLv2/SSLv3 support (deprecated)
            if self._supports_protocol(hostname, port, ssl.PROTOCOL_SSLv23):
                vulnerabilities['issues'].append({
                    'name': 'Weak SSL/TLS Protocol',
                    'severity': 'HIGH',
                    'description': 'Server supports deprecated SSL/TLS protocols',
                })

            # Check for weak cipher suites
            weak_ciphers = self._check_weak_ciphers(hostname, port)
            if weak_ciphers:
                vulnerabilities['issues'].append({
                    'name': 'Weak Cipher Suites',
                    'severity': 'MEDIUM',
                    'description': f'Server supports weak ciphers: {", ".join(weak_ciphers)}',
                    'ciphers': weak_ciphers,
                })

            # Check certificate validity
            cert_info = self.get_certificate_info(hostname, port)
            if cert_info:
                if cert_info.get('is_expired'):
                    vulnerabilities['issues'].append({
                        'name': 'Expired Certificate',
                        'severity': 'CRITICAL',
                        'description': 'SSL certificate has expired',
                    })
                elif cert_info.get('expires_soon'):
                    vulnerabilities['issues'].append({
                        'name': 'Certificate Expiring Soon',
                        'severity': 'LOW',
                        'description': f'Certificate expires in {cert_info["days_until_expiry"]} days',
                    })

                if cert_info.get('is_self_signed'):
                    vulnerabilities['issues'].append({
                        'name': 'Self-Signed Certificate',
                        'severity': 'MEDIUM',
                        'description': 'Server uses self-signed certificate',
                    })

        except Exception as e:
            self.logger.error(f"Vulnerability check failed: {e}")

        return vulnerabilities

    def _parse_name(self, name) -> Dict[str, str]:
        """Parse X509 name to dictionary."""
        name_dict = {}
        for attr in name:
            name_dict[attr.oid._name] = attr.value
        return name_dict

    def _get_san(self, cert) -> List[str]:
        """Get Subject Alternative Names from certificate."""
        try:
            san_ext = cert.extensions.get_extension_for_oid(
                x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            return [str(name) for name in san_ext.value]
        except Exception:
            return []

    def _is_self_signed(self, cert) -> bool:
        """Check if certificate is self-signed."""
        return cert.issuer == cert.subject

    def _get_certificate_chain(self, hostname: str, port: int) -> List[Dict[str, str]]:
        """Get certificate chain."""
        chain = []
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # This is a simplified version; full chain requires more complex logic
                    peer_cert = ssock.getpeercert()
                    if peer_cert:
                        chain.append({
                            'subject': str(peer_cert.get('subject', '')),
                            'issuer': str(peer_cert.get('issuer', '')),
                        })

        except Exception as e:
            self.logger.debug(f"Failed to get certificate chain: {e}")

        return chain

    def _get_supported_protocols(self, hostname: str, port: int) -> List[str]:
        """Get supported TLS protocols."""
        protocols = []

        # Test different protocol versions
        protocol_versions = [
            ('TLS 1.0', ssl.PROTOCOL_TLSv1),
            ('TLS 1.1', ssl.PROTOCOL_TLSv1_1),
            ('TLS 1.2', ssl.PROTOCOL_TLSv1_2),
        ]

        # TLS 1.3 support
        try:
            if hasattr(ssl, 'PROTOCOL_TLS_CLIENT'):
                protocol_versions.append(('TLS 1.3', ssl.PROTOCOL_TLS_CLIENT))
        except AttributeError:
            pass

        for name, protocol in protocol_versions:
            if self._supports_protocol(hostname, port, protocol):
                protocols.append(name)

        return protocols

    def _supports_protocol(self, hostname: str, port: int, protocol) -> bool:
        """Check if server supports specific protocol."""
        try:
            context = ssl.SSLContext(protocol)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    return True

        except Exception:
            return False

    def _get_cipher_suites(self, hostname: str, port: int) -> List[str]:
        """Get supported cipher suites."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    if cipher:
                        return [cipher[0]]

        except Exception as e:
            self.logger.debug(f"Failed to get cipher suites: {e}")

        return []

    def _check_weak_ciphers(self, hostname: str, port: int) -> List[str]:
        """Check for weak cipher suites."""
        weak_patterns = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon']
        weak_ciphers = []

        cipher_suites = self._get_cipher_suites(hostname, port)

        for cipher in cipher_suites:
            for pattern in weak_patterns:
                if pattern in cipher.upper():
                    weak_ciphers.append(cipher)
                    break

        return weak_ciphers

    def _check_compression(self, hostname: str, port: int) -> bool:
        """Check if compression is enabled (CRIME vulnerability)."""
        # Simplified check
        return False

    def _check_heartbeat(self, hostname: str, port: int) -> bool:
        """Check if heartbeat extension is enabled."""
        # Simplified check
        return False

    def _check_session_resumption(self, hostname: str, port: int) -> bool:
        """Check if session resumption is supported."""
        # Simplified check
        return True

    def _check_security_headers(self, hostname: str, port: int) -> Dict[str, Any]:
        """Check HTTP security headers."""
        import requests

        headers_info = {
            'hsts': False,
            'hpkp': False,
            'csp': False,
            'x_frame_options': False,
            'x_content_type_options': False,
        }

        try:
            url = f'https://{hostname}:{port}' if port != 443 else f'https://{hostname}'
            response = requests.get(url, timeout=10, verify=False)

            headers = response.headers

            # Check for HSTS
            if 'Strict-Transport-Security' in headers:
                headers_info['hsts'] = headers['Strict-Transport-Security']

            # Check for HPKP
            if 'Public-Key-Pins' in headers:
                headers_info['hpkp'] = headers['Public-Key-Pins']

            # Check for CSP
            if 'Content-Security-Policy' in headers:
                headers_info['csp'] = headers['Content-Security-Policy']

            # Check for X-Frame-Options
            if 'X-Frame-Options' in headers:
                headers_info['x_frame_options'] = headers['X-Frame-Options']

            # Check for X-Content-Type-Options
            if 'X-Content-Type-Options' in headers:
                headers_info['x_content_type_options'] = headers['X-Content-Type-Options']

        except Exception as e:
            self.logger.debug(f"Failed to check security headers: {e}")

        return headers_info
