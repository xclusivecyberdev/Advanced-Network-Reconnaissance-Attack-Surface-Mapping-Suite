"""WHOIS lookup and domain information module."""

import whois
from typing import Dict, Any, Optional
import logging
from datetime import datetime

from ..core.scanner_base import BaseScanner


class WhoisLookup(BaseScanner):
    """WHOIS information lookup scanner."""

    def __init__(self, config):
        """Initialize WHOIS lookup."""
        super().__init__(name="WhoisLookup", version="1.0", config=config)

    def scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform WHOIS lookup on target domain.

        Args:
            target: Target domain or IP
            options: Scan options

        Returns:
            WHOIS information
        """
        results = []

        try:
            whois_data = self.lookup_whois(target)

            if whois_data:
                self.add_result({'whois': whois_data})
                results.append(whois_data)

        except Exception as e:
            self.add_error(f"WHOIS lookup failed: {e}")

        return {'scanner': self.name, 'results': results}

    def lookup_whois(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Lookup WHOIS information.

        Args:
            domain: Domain name or IP

        Returns:
            WHOIS information dictionary
        """
        try:
            w = whois.whois(domain)

            # Parse and structure WHOIS data
            whois_info = {
                'domain': domain,
                'registrar': self._safe_get(w, 'registrar'),
                'whois_server': self._safe_get(w, 'whois_server'),
                'creation_date': self._format_date(self._safe_get(w, 'creation_date')),
                'expiration_date': self._format_date(self._safe_get(w, 'expiration_date')),
                'updated_date': self._format_date(self._safe_get(w, 'updated_date')),
                'status': self._safe_get(w, 'status'),
                'name_servers': self._safe_get(w, 'name_servers'),
                'emails': self._safe_get(w, 'emails'),
                'org': self._safe_get(w, 'org'),
                'country': self._safe_get(w, 'country'),
                'state': self._safe_get(w, 'state'),
                'city': self._safe_get(w, 'city'),
                'address': self._safe_get(w, 'address'),
                'dnssec': self._safe_get(w, 'dnssec'),
            }

            # Calculate days until expiration
            if whois_info['expiration_date']:
                try:
                    if isinstance(whois_info['expiration_date'], str):
                        exp_date = datetime.fromisoformat(whois_info['expiration_date'])
                    else:
                        exp_date = whois_info['expiration_date']

                    days_until_expiry = (exp_date - datetime.now()).days
                    whois_info['days_until_expiry'] = days_until_expiry

                    if days_until_expiry < 30:
                        whois_info['expiry_warning'] = f'Domain expires in {days_until_expiry} days!'

                except Exception:
                    pass

            return whois_info

        except Exception as e:
            self.logger.error(f"WHOIS lookup failed for {domain}: {e}")
            return None

    def _safe_get(self, whois_obj, key: str) -> Any:
        """Safely get attribute from WHOIS object."""
        try:
            value = getattr(whois_obj, key, None)

            # Convert lists to simple format
            if isinstance(value, list):
                # Filter out None values
                value = [v for v in value if v is not None]
                if len(value) == 1:
                    value = value[0]
                elif len(value) == 0:
                    value = None

            return value

        except Exception:
            return None

    def _format_date(self, date_value: Any) -> Optional[str]:
        """Format date value to ISO string."""
        if date_value is None:
            return None

        try:
            # Handle list of dates
            if isinstance(date_value, list):
                date_value = date_value[0] if date_value else None

            # Convert to ISO format
            if isinstance(date_value, datetime):
                return date_value.isoformat()
            elif isinstance(date_value, str):
                return date_value

        except Exception:
            pass

        return None

    def get_registrar_info(self, domain: str) -> Optional[Dict[str, str]]:
        """
        Get detailed registrar information.

        Args:
            domain: Domain name

        Returns:
            Registrar information
        """
        try:
            w = whois.whois(domain)

            return {
                'registrar': self._safe_get(w, 'registrar'),
                'registrar_url': self._safe_get(w, 'registrar_url'),
                'registrar_abuse_contact_email': self._safe_get(w, 'registrar_abuse_contact_email'),
                'registrar_abuse_contact_phone': self._safe_get(w, 'registrar_abuse_contact_phone'),
            }

        except Exception as e:
            self.logger.error(f"Failed to get registrar info: {e}")
            return None
