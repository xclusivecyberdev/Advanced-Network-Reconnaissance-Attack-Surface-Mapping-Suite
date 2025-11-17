"""Subdomain enumeration using bruteforce and OSINT sources."""

import dns.resolver
import requests
from typing import Dict, Any, List, Optional, Set
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

from ..core.scanner_base import BaseScanner


class SubdomainEnumerator(BaseScanner):
    """Subdomain enumeration scanner."""

    def __init__(self, config):
        """Initialize subdomain enumerator."""
        super().__init__(name="SubdomainEnumerator", version="1.0", config=config)

        # Common subdomains for bruteforce
        self.common_subdomains = self._load_wordlist()

        # DNS resolvers
        self.resolvers = config.get('osint.dns_resolvers', ['8.8.8.8', '1.1.1.1'])

    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Enumerate subdomains for target domain.

        Args:
            target: Target domain
            options: Scan options (bruteforce, osint, etc.)

        Returns:
            Subdomain enumeration results
        """
        options = options or {}
        use_bruteforce = options.get('bruteforce', True)
        use_osint = options.get('osint', True)

        discovered_subdomains: Set[str] = set()

        # Bruteforce enumeration
        if use_bruteforce:
            bruteforce_results = self._bruteforce_subdomains(target)
            discovered_subdomains.update(bruteforce_results)

        # OSINT sources
        if use_osint:
            osint_results = self._osint_enumeration(target)
            discovered_subdomains.update(osint_results)

        # Certificate Transparency logs
        ct_results = self._certificate_transparency(target)
        discovered_subdomains.update(ct_results)

        # Format results
        results = []
        for subdomain in discovered_subdomains:
            # Verify and get IP
            ip_addresses = self._resolve_subdomain(subdomain)
            if ip_addresses:
                result = {
                    'subdomain': subdomain,
                    'ip_addresses': ip_addresses,
                    'verified': True,
                }
                self.add_result(result)
                results.append(result)

        return {'scanner': self.name, 'results': results}

    def _bruteforce_subdomains(self, domain: str) -> List[str]:
        """Bruteforce subdomains using wordlist."""
        discovered = []

        self.logger.info(f"Bruteforcing subdomains for {domain}")

        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = {
                executor.submit(self._check_subdomain, f"{sub}.{domain}"): sub
                for sub in self.common_subdomains
            }

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        discovered.append(result)
                except Exception as e:
                    self.logger.debug(f"Subdomain check failed: {e}")

        return discovered

    def _check_subdomain(self, subdomain: str) -> Optional[str]:
        """Check if subdomain exists."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.resolvers
            resolver.timeout = 2
            resolver.lifetime = 2

            answers = resolver.resolve(subdomain, 'A')
            if answers:
                return subdomain

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            pass
        except Exception as e:
            self.logger.debug(f"DNS resolution failed for {subdomain}: {e}")

        return None

    def _resolve_subdomain(self, subdomain: str) -> List[str]:
        """Resolve subdomain to IP addresses."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.resolvers
            answers = resolver.resolve(subdomain, 'A')
            return [str(rdata) for rdata in answers]
        except Exception:
            return []

    def _osint_enumeration(self, domain: str) -> List[str]:
        """Enumerate subdomains using OSINT sources."""
        discovered = []

        # Use multiple OSINT sources
        sources = [
            self._crtsh_search,
            self._hackertarget_search,
            self._threatcrowd_search,
        ]

        for source in sources:
            try:
                results = source(domain)
                discovered.extend(results)
            except Exception as e:
                self.logger.debug(f"OSINT source failed: {e}")

        return list(set(discovered))

    def _certificate_transparency(self, domain: str) -> List[str]:
        """Search Certificate Transparency logs."""
        return self._crtsh_search(domain)

    def _crtsh_search(self, domain: str) -> List[str]:
        """Search crt.sh for subdomains."""
        subdomains = []

        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name:
                        # Handle wildcard and multiple domains
                        for subdomain in name.split('\n'):
                            subdomain = subdomain.strip().replace('*.', '')
                            if subdomain and subdomain.endswith(domain):
                                subdomains.append(subdomain)

        except Exception as e:
            self.logger.debug(f"crt.sh search failed: {e}")

        return list(set(subdomains))

    def _hackertarget_search(self, domain: str) -> List[str]:
        """Search HackerTarget API."""
        subdomains = []

        try:
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                lines = response.text.split('\n')
                for line in lines:
                    if ',' in line:
                        subdomain = line.split(',')[0]
                        if subdomain and subdomain.endswith(domain):
                            subdomains.append(subdomain)

        except Exception as e:
            self.logger.debug(f"HackerTarget search failed: {e}")

        return subdomains

    def _threatcrowd_search(self, domain: str) -> List[str]:
        """Search ThreatCrowd API."""
        subdomains = []

        try:
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
            response = requests.get(url, timeout=10)

            if response.status_code == 200:
                data = response.json()
                subdomains = data.get('subdomains', [])

        except Exception as e:
            self.logger.debug(f"ThreatCrowd search failed: {e}")

        return subdomains

    def _load_wordlist(self) -> List[str]:
        """Load subdomain wordlist."""
        # Default common subdomains
        common = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'imap', 'test', 'dev',
            'staging', 'api', 'admin', 'portal', 'blog', 'shop', 'store', 'mobile',
            'vpn', 'remote', 'git', 'svn', 'cdn', 'backup', 'mysql', 'demo', 'beta',
        ]

        # Try to load from file if configured
        wordlist_file = self.config.get('osint.subdomain_wordlist')
        if wordlist_file:
            try:
                with open(wordlist_file, 'r') as f:
                    common.extend([line.strip() for line in f if line.strip()])
            except Exception as e:
                self.logger.debug(f"Failed to load wordlist: {e}")

        return list(set(common))
