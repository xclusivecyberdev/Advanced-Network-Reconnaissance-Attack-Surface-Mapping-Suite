"""Input validation utilities."""

import re
import ipaddress
import validators as validator_lib
from typing import Union
from urllib.parse import urlparse


def validate_ip(ip: str) -> bool:
    """
    Validate IP address (IPv4 or IPv6).

    Args:
        ip: IP address string

    Returns:
        True if valid IP address
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_cidr(cidr: str) -> bool:
    """
    Validate CIDR notation.

    Args:
        cidr: CIDR string (e.g., '192.168.1.0/24')

    Returns:
        True if valid CIDR
    """
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def validate_domain(domain: str) -> bool:
    """
    Validate domain name.

    Args:
        domain: Domain name string

    Returns:
        True if valid domain
    """
    return validator_lib.domain(domain) is True


def validate_url(url: str) -> bool:
    """
    Validate URL.

    Args:
        url: URL string

    Returns:
        True if valid URL
    """
    return validator_lib.url(url) is True


def validate_port(port: Union[int, str]) -> bool:
    """
    Validate port number.

    Args:
        port: Port number

    Returns:
        True if valid port (1-65535)
    """
    try:
        port_num = int(port)
        return 1 <= port_num <= 65535
    except (ValueError, TypeError):
        return False


def validate_port_range(port_range: str) -> bool:
    """
    Validate port range (e.g., '1-1000', '80,443,8080').

    Args:
        port_range: Port range string

    Returns:
        True if valid port range
    """
    # Single port
    if port_range.isdigit():
        return validate_port(port_range)

    # Range (e.g., '1-1000')
    if '-' in port_range:
        parts = port_range.split('-')
        if len(parts) == 2:
            try:
                start, end = int(parts[0]), int(parts[1])
                return validate_port(start) and validate_port(end) and start <= end
            except ValueError:
                return False

    # List (e.g., '80,443,8080')
    if ',' in port_range:
        ports = port_range.split(',')
        return all(validate_port(p.strip()) for p in ports)

    return False


def validate_target(target: str) -> bool:
    """
    Validate scan target (IP, CIDR, domain, or URL).

    Args:
        target: Target string

    Returns:
        True if valid target
    """
    if not target or not isinstance(target, str):
        return False

    target = target.strip()

    # Check if IP
    if validate_ip(target):
        return True

    # Check if CIDR
    if validate_cidr(target):
        return True

    # Check if URL
    if validate_url(target):
        return True

    # Check if domain
    if validate_domain(target):
        return True

    return False


def normalize_target(target: str) -> str:
    """
    Normalize target to standard format.

    Args:
        target: Target string

    Returns:
        Normalized target
    """
    target = target.strip()

    # If URL, extract hostname
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        return parsed.hostname or target

    return target


def parse_target_type(target: str) -> str:
    """
    Determine target type.

    Args:
        target: Target string

    Returns:
        Target type ('ip', 'cidr', 'domain', 'url')
    """
    if validate_ip(target):
        return 'ip'
    elif validate_cidr(target):
        return 'cidr'
    elif validate_url(target):
        return 'url'
    elif validate_domain(target):
        return 'domain'
    else:
        return 'unknown'


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename to remove dangerous characters.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename
    """
    # Remove path separators and dangerous characters
    filename = re.sub(r'[/\\:*?"<>|]', '_', filename)
    # Limit length
    if len(filename) > 255:
        filename = filename[:255]
    return filename


def is_safe_path(path: str, base_dir: str) -> bool:
    """
    Check if path is safe (no directory traversal).

    Args:
        path: Path to check
        base_dir: Base directory

    Returns:
        True if path is safe
    """
    from pathlib import Path
    try:
        base = Path(base_dir).resolve()
        target = (base / path).resolve()
        return str(target).startswith(str(base))
    except Exception:
        return False
