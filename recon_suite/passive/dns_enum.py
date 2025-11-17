"""DNS enumeration and analysis module."""

import dns.resolver
import dns.zone
import dns.query
from typing import Dict, Any, List, Optional
import logging

from ..core.scanner_base import BaseScanner


class DNSEnumerator(BaseScanner):
    """DNS enumeration and reconnaissance scanner."""

    def __init__(self, config):
        """Initialize DNS enumerator."""
        super().__init__(name="DNSEnumerator", version="1.0", config=config)

        # DNS record types to query
        self.record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'PTR']

        # DNS resolvers
        self.resolvers = config.get('osint.dns_resolvers', ['8.8.8.8', '1.1.1.1'])

    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Enumerate DNS records for target domain.

        Args:
            target: Target domain
            options: Scan options

        Returns:
            DNS enumeration results
        """
        results = []

        # Query all record types
        for record_type in self.record_types:
            try:
                records = self.query_dns(target, record_type)
                if records:
                    result = {
                        'domain': target,
                        'record_type': record_type,
                        'records': records,
                    }
                    self.add_result(result)
                    results.append(result)

            except Exception as e:
                self.logger.debug(f"DNS query failed for {target} ({record_type}): {e}")

        # Try zone transfer
        zone_transfer = self.attempt_zone_transfer(target)
        if zone_transfer:
            results.append({
                'domain': target,
                'zone_transfer': zone_transfer,
            })

        return {'scanner': self.name, 'results': results}

    def query_dns(self, domain: str, record_type: str) -> List[str]:
        """
        Query DNS records.

        Args:
            domain: Domain name
            record_type: DNS record type

        Returns:
            List of DNS records
        """
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = self.resolvers
            resolver.timeout = 5
            resolver.lifetime = 5

            answers = resolver.resolve(domain, record_type)
            return [str(rdata) for rdata in answers]

        except dns.resolver.NXDOMAIN:
            self.logger.debug(f"Domain does not exist: {domain}")
        except dns.resolver.NoAnswer:
            self.logger.debug(f"No {record_type} records for {domain}")
        except dns.resolver.Timeout:
            self.logger.debug(f"DNS query timeout for {domain}")
        except Exception as e:
            self.logger.debug(f"DNS query error for {domain}: {e}")

        return []

    def attempt_zone_transfer(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Attempt DNS zone transfer (AXFR).

        Args:
            domain: Target domain

        Returns:
            Zone transfer data if successful
        """
        try:
            # Get nameservers
            ns_records = self.query_dns(domain, 'NS')

            for ns in ns_records:
                try:
                    # Try zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=10))

                    if zone:
                        records = []
                        for name, node in zone.nodes.items():
                            for rdataset in node.rdatasets:
                                records.append({
                                    'name': str(name),
                                    'type': dns.rdatatype.to_text(rdataset.rdtype),
                                    'data': [str(rdata) for rdata in rdataset],
                                })

                        return {
                            'nameserver': ns,
                            'records': records,
                            'vulnerable': True,
                        }

                except Exception as e:
                    self.logger.debug(f"Zone transfer failed for {ns}: {e}")

        except Exception as e:
            self.logger.debug(f"Zone transfer attempt failed: {e}")

        return None

    def reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """
        Perform reverse DNS lookup.

        Args:
            ip: IP address

        Returns:
            Hostname if found
        """
        try:
            import socket
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except Exception:
            return None

    def get_dns_security_info(self, domain: str) -> Dict[str, Any]:
        """
        Get DNS security information (DNSSEC, etc.).

        Args:
            domain: Target domain

        Returns:
            DNS security information
        """
        security_info = {
            'dnssec_enabled': False,
            'spf_records': [],
            'dmarc_records': [],
            'dkim_records': [],
        }

        # Check for SPF records
        try:
            txt_records = self.query_dns(domain, 'TXT')
            for record in txt_records:
                if record.startswith('v=spf1'):
                    security_info['spf_records'].append(record)
                elif record.startswith('v=DMARC1'):
                    security_info['dmarc_records'].append(record)

        except Exception as e:
            self.logger.debug(f"Failed to get security info: {e}")

        # Check DMARC
        try:
            dmarc_records = self.query_dns(f'_dmarc.{domain}', 'TXT')
            security_info['dmarc_records'].extend(dmarc_records)
        except Exception:
            pass

        return security_info
