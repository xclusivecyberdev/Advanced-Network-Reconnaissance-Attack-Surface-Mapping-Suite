"""Network utility functions."""

import socket
import ipaddress
from typing import List, Optional, Tuple
import dns.resolver
from netaddr import IPNetwork, IPAddress


def is_private_ip(ip: str) -> bool:
    """
    Check if IP address is private.

    Args:
        ip: IP address string

    Returns:
        True if private IP
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def is_valid_ipv4(ip: str) -> bool:
    """Check if string is valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def is_valid_ipv6(ip: str) -> bool:
    """Check if string is valid IPv6 address."""
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ValueError:
        return False


def expand_cidr(cidr: str, max_hosts: int = 1024) -> List[str]:
    """
    Expand CIDR notation to list of IP addresses.

    Args:
        cidr: CIDR notation (e.g., '192.168.1.0/24')
        max_hosts: Maximum number of hosts to return

    Returns:
        List of IP addresses
    """
    try:
        network = IPNetwork(cidr)
        hosts = list(network)

        # Limit number of hosts
        if len(hosts) > max_hosts:
            hosts = hosts[:max_hosts]

        return [str(ip) for ip in hosts]
    except Exception:
        return []


def resolve_hostname(hostname: str, record_type: str = 'A') -> List[str]:
    """
    Resolve hostname to IP addresses.

    Args:
        hostname: Hostname to resolve
        record_type: DNS record type (A, AAAA, etc.)

    Returns:
        List of resolved IP addresses
    """
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(hostname, record_type)
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


def reverse_dns(ip: str) -> Optional[str]:
    """
    Perform reverse DNS lookup.

    Args:
        ip: IP address

    Returns:
        Hostname or None
    """
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None


def get_ip_from_hostname(hostname: str) -> Optional[str]:
    """
    Get IP address from hostname.

    Args:
        hostname: Hostname

    Returns:
        IP address or None
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def get_local_ip() -> str:
    """
    Get local machine IP address.

    Returns:
        Local IP address
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def check_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """
    Check if port is open on host.

    Args:
        host: Target host
        port: Port number
        timeout: Connection timeout

    Returns:
        True if port is open
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def get_cidr_from_ip_range(start_ip: str, end_ip: str) -> List[str]:
    """
    Get CIDR notation from IP range.

    Args:
        start_ip: Start IP address
        end_ip: End IP address

    Returns:
        List of CIDR notations
    """
    try:
        start = IPAddress(start_ip)
        end = IPAddress(end_ip)
        cidrs = ipaddress.summarize_address_range(
            ipaddress.ip_address(start_ip),
            ipaddress.ip_address(end_ip)
        )
        return [str(cidr) for cidr in cidrs]
    except Exception:
        return []


def get_asn_info(ip: str) -> Optional[dict]:
    """
    Get ASN information for IP address.

    Args:
        ip: IP address

    Returns:
        ASN information dictionary
    """
    try:
        from ipwhois import IPWhois
        obj = IPWhois(ip)
        results = obj.lookup_rdap()
        return {
            'asn': results.get('asn'),
            'asn_description': results.get('asn_description'),
            'asn_country_code': results.get('asn_country_code'),
            'network': results.get('network', {}).get('cidr'),
        }
    except Exception:
        return None


def calculate_subnet_info(cidr: str) -> dict:
    """
    Calculate subnet information from CIDR.

    Args:
        cidr: CIDR notation

    Returns:
        Subnet information dictionary
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        return {
            'network_address': str(network.network_address),
            'broadcast_address': str(network.broadcast_address),
            'netmask': str(network.netmask),
            'prefix_length': network.prefixlen,
            'num_addresses': network.num_addresses,
            'first_host': str(list(network.hosts())[0]) if network.num_addresses > 2 else str(network.network_address),
            'last_host': str(list(network.hosts())[-1]) if network.num_addresses > 2 else str(network.broadcast_address),
        }
    except Exception:
        return {}
